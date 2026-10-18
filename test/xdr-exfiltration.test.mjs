import assert from 'node:assert/strict';
import { copyFile, mkdir, mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { createAuthApi } from '../src/auth-api.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { EXFILTRATION_RULES_FILE, findBlock, loadBlockRules } from '../src/xdr-block.mjs';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { buildBlockRules, decideAll, respond } from '../xdr/exfiltration/respond.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/exfiltration.json', import.meta.url), 'utf8'));
const decideSource = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');

const ids = (from, to) => Array.from({ length: to - from + 1 }, (_, i) => `ex-${String(from + i).padStart(2, '0')}`);
const CLEAR = ids(1, 10);
const AMBIGUOUS = ids(11, 20);
const NORMAL = ids(21, 30);
const byId = (id) => fixture.alerts.find((a) => a.id === id);
const ipsOf = (list) => new Set(list.map((id) => byId(id).data.srcip));
const NOW = Date.parse('2026-10-18T00:00:00Z');

test('decide: 명확한 공격 block, 애매한 건 alert, 정상은 record, import 문이 없다', () => {
  assert.ok(!/^\s*import\s/mu.test(decideSource));
  assert.ok(!/\bimport\s*\(|\brequire\s*\(|node:|\bfetch\s*\(|readFile|writeFile|process\./u.test(decideSource));
  for (const id of CLEAR) assert.equal(decide(byId(id)).action, 'block', id);
  for (const id of AMBIGUOUS) assert.equal(decide(byId(id)).action, 'alert', id);
  for (const id of NORMAL) assert.equal(decide(byId(id)).action, 'record', id);
});

test('연결: 규칙에는 만료 시각·근거 경보 번호가 붙은 공격 주소만 들어가고, 정상 사용자와 겹치는 주소는 빠진다', () => {
  const rules = buildBlockRules({ alerts: fixture.alerts, decisions: decideAll(fixture.alerts), now: NOW });
  assert.equal(rules.length, ipsOf(CLEAR).size);
  for (const r of rules) {
    assert.equal(r.ruleId, 'xdr.ex.deny-ip');
    assert.equal(r.decision, 'deny');
    assert.ok(CLEAR.includes(r.evidenceAlertId));
    assert.equal(byId(r.evidenceAlertId).data.srcip, r.srcip);
    assert.equal(Date.parse(r.expiresAt) - Date.parse(r.createdAt), 3600000);
  }
  const blocked = new Set(rules.map((r) => r.srcip));
  for (const ip of [...ipsOf(NORMAL), ...ipsOf(AMBIGUOUS)]) assert.ok(!blocked.has(ip), ip);
  const shared = [byId('ex-01'), { ...byId('ex-21'), id: 'ex-97', data: { ...byId('ex-21').data, srcip: byId('ex-01').data.srcip } }];
  assert.equal(buildBlockRules({ alerts: shared, decisions: decideAll(shared), now: NOW }).length, 0);
  const bad = [{ ...byId('ex-01'), data: { ...byId('ex-01').data, srcip: 'not-an-ip' } }];
  assert.equal(buildBlockRules({ alerts: bad, decisions: decideAll(bad), now: NOW }).length, 0);
});

async function temp(run) {
  const dir = await mkdtemp(join(tmpdir(), 'ex-respond-'));
  try {
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await copyFile(new URL('../xdr/fixtures/exfiltration.json', import.meta.url), join(dir, 'xdr', 'fixtures', 'exfiltration.json'));
    return await run({ dir, rulesFile: join(dir, 'block-rules.json'), logFile: join(dir, 'alerts.log') });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('연결: 알림 로그에는 block·alert 만 한 줄씩 쌓이고 다시 흘리면 이어진다', async () => {
  await temp(async ({ dir, rulesFile, logFile }) => {
    const first = await respond({ root: dir, now: NOW, rulesFile, logFile });
    assert.equal(first.logged, 20);
    const log = (await readFile(logFile, 'utf8')).trimEnd().split('\n');
    assert.equal(log.filter((l) => / BLOCK /u.test(l)).length, 10);
    assert.equal(log.filter((l) => / ALERT /u.test(l)).length, 10);
    assert.ok(!log.some((l) => / RECORD /u.test(l)));
    await respond({ root: dir, now: NOW + 1000, rulesFile, logFile });
    assert.equal((await readFile(logFile, 'utf8')).trimEnd().split('\n').length, 40);
  });
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

const callAuth = (rulesList, ip) => createAuthApi({
  getSettings: () => ({ url: 'https://example.invalid', secretKey: 'x' }),
  fetchImpl: async () => ({ ok: false, status: 400, json: async () => ({ error_code: 'invalid_credentials' }) }),
  getBlockRules: () => rulesList,
  now: () => NOW,
}).login({ method: 'POST', headers: { 'x-forwarded-for': ip }, body: { email: 'a@b.co', password: 'pw' } }, {
  setHeader() {},
  status(code) { return { json: (body) => ({ code, body }) }; },
});

test('경보를 다시 흘리면: 공격 주소는 403, 정상·애매한 주소는 기존대로 통과', async () => {
  await temp(async ({ dir, rulesFile, logFile }) => {
    await respond({ root: dir, now: NOW, rulesFile, logFile });
    const live = loadBlockRules(rulesFile);
    for (const ip of ipsOf(CLEAR)) {
      assert.equal((await callAuth(live, ip)).code, 403, `로그인 ${ip}`);
      assert.equal((await callNotes(live, ip)).code, 403, `자료 ${ip}`);
    }
    for (const ip of [...ipsOf(NORMAL), ...ipsOf(AMBIGUOUS)]) {
      assert.equal((await callAuth(live, ip)).code, 401, `로그인 ${ip}`);
      assert.equal((await callNotes(live, ip)).code, 401, `자료 ${ip}`);
    }
  });
});

test('ZTNA 거부 규칙 읽기: 기본 경로가 exfiltration 규칙 파일도 읽고, 만료된 규칙은 막지 않는다', async () => {
  assert.ok(EXFILTRATION_RULES_FILE.endsWith(join('xdr', 'exfiltration', 'block-rules.json')));
  const probe = { ruleId: 'xdr.ex.deny-ip', decision: 'deny', srcip: '198.51.100.251', evidenceAlertId: 'ex-01', createdAt: new Date(NOW).toISOString(), expiresAt: new Date(NOW + 3600000).toISOString() };
  assert.equal(findBlock([probe], '198.51.100.251', NOW)?.evidenceAlertId, 'ex-01');
  assert.equal(findBlock([probe], '198.51.100.251', NOW + 3600001), null);
  assert.equal(findBlock([probe], '198.51.100.252', NOW), null);
});

test('decide: 표현을 바꾼 경보도 같은 답이고, 부정하는 문장은 막지 않는다', () => {
  const ask = (level, description, data = {}) => decide({ id: 'x', rule: { level, description }, data: { srcip: '192.0.2.1', srcuser: 'u', ...data } }).action;
  const attacks = [
    [12, '처음 보는 목적지로 자료 500건이 한꺼번에 나갔습니다.'],
    [12, '처음 보는 외부 서버로 고객 자료 1000건이 한꺼번에 전송됐습니다.'],
    [12, '처음 보는 목적지로 대용량 파일이 업로드됐습니다.'],
    [11, '새벽에 처음 보는 주소로 메모 묶음이 나갔습니다.'],
    [12, '수업 시간 밖에 압축 파일이 외부로 올라갔습니다.'],
    [11, '업무 시간 밖에 압축 파일이 외부로 반출됐습니다.'],
    [12, '새벽에 압축 파일이 처음 보는 주소로 전송됐습니다.'],
    [12, '평소 쓰지 않는 목적지로 큰 전송이 있었습니다.'],
    [11, '알 수 없는 주소로 데이터 수십 GB가 나갔습니다.'],
    [12, 'DNS 터널로 자료가 계속 빠져나갔습니다.'],
    [11, '명령 통로로 큰 파일이 반복해서 나갔습니다.'],
    [11, '명령 통로를 통해 큰 파일이 반복 유출됐습니다.'],
    [12, '처음 보는 클라우드 저장소로 자료 전체가 올라갔습니다.'],
    [12, 'Large archive was sent to a first-seen external destination.'],
    [12, '평소와 다른 포트로 파일이 연속 전송됐습니다.'],
  ];
  for (const [level, text] of attacks) assert.equal(ask(level, text), 'block', text);
  const notBlocked = [
    '처음 보는 목적지로 자료 500건이 나가지 않았습니다.',
    '수업 시간 밖 압축 파일 전송은 차단되어 나가지 않았습니다.',
    '새벽에 압축 파일 외부 전송이 차단되어 나가지 않았습니다.',
    '처음 보는 외부 서버로 큰 전송이 있었으나 막혔습니다.',
    '명령 통로에 짧은 자료 이름이 3번 보였습니다. 큰 파일은 아닙니다.',
    '처음 보는 주소로 작은 파일이 2건 나갔습니다.',
    '수업 시간에 압축 파일 1건을 만들었습니다. 외부 전송은 아직 없습니다.',
  ];
  for (const text of notBlocked) assert.notEqual(ask(12, text), 'block', text);
  assert.equal(ask(3, '내 메모 한 건을 읽었습니다.'), 'record');
  assert.equal(ask(3, '수업 자료 주소로 작은 동기화가 끝났습니다.'), 'record');
  assert.equal(ask(4, '평소 목적지로 백업 전송 1건이 있었습니다.'), 'record');
});
