import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import vm from 'node:vm';
import { createAuthApi } from '../src/auth-api.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { WEB_INJECTION_RULES_FILE, findBlock, loadBlockRules } from '../src/xdr-block.mjs';
import { PATTERNS, createDecide, decide } from '../xdr/web-injection/decide.mjs';
import { alertLine, buildBlockRules, linkResults } from '../xdr/web-injection/link.mjs';
import { extractAlert, readAlerts, scrub } from '../xdr/web-injection/read-alerts.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8'));
const patternsFile = JSON.parse(await readFile(new URL('../xdr/web-injection/patterns.json', import.meta.url), 'utf8'));
const decideSource = await readFile(new URL('../xdr/web-injection/decide.mjs', import.meta.url), 'utf8');

// 경보 묶음의 설명(N번 반복됐습니다 / 반복은 없습니다 / 정상 조회)을 읽고 나눈 기대 값입니다. 정답표가 아닙니다.
const CLEAR = ['wi-01', 'wi-02', 'wi-03', 'wi-04', 'wi-05', 'wi-06', 'wi-07', 'wi-08'];
const AMBIGUOUS = ['wi-09', 'wi-10', 'wi-11', 'wi-12', 'wi-13', 'wi-14', 'wi-15', 'wi-16', 'wi-17'];
const NORMAL = ['wi-18', 'wi-19', 'wi-20', 'wi-21', 'wi-22', 'wi-23', 'wi-24', 'wi-25', 'wi-26'];
const byId = (id) => fixture.alerts.find((a) => a.id === id);

test('경보 건수와 뽑은 줄 수가 같다', async () => {
  const { alertCount, rows } = await readAlerts();
  assert.equal(alertCount, 26);
  assert.equal(rows.length, alertCount);
});

test('명확한 공격 block, 애매한 건 alert, 정상은 record (Jev 없음)', async () => {
  for (const id of CLEAR) assert.equal((await decide(byId(id))).action, 'block', id);
  for (const id of AMBIGUOUS) assert.equal((await decide(byId(id))).action, 'alert', id);
  for (const id of NORMAL) assert.equal((await decide(byId(id))).action, 'record', id);
  assert.equal(CLEAR.length + AMBIGUOUS.length + NORMAL.length, fixture.alerts.length);
});

test('reason 은 한 줄이고, 막은 건 근거 패턴 이름을 적는다', async () => {
  const names = new Set(PATTERNS.map((p) => p.name));
  for (const id of CLEAR) {
    const out = await decide(byId(id));
    assert.ok(!out.reason.includes('\n'));
    assert.ok([...names].some((n) => out.reason.includes(n)), `${id}: ${out.reason}`);
  }
  assert.match((await decide(byId('wi-05'))).reason, /sql-in-request-args, script-tag-in-request-args/u);
  assert.match((await decide(byId('wi-06'))).reason, /command-separator-in-request-args/u);
});

test('확신도 경계: 0.85 이상 block, 0.5 이상 alert, 그 아래 record (애매한 건만 Jev 에게 묻는다)', async () => {
  const ambiguous = byId('wi-16');
  const asked = [];
  const ask = (value) => createDecide({ askJev: (summary) => { asked.push(summary); return value; } });
  const cases = [[1, 'block'], [0.9, 'block'], [0.85, 'block'], [0.84, 'alert'], [0.5, 'alert'], [0.49, 'record'], [0.1, 'record'], [0, 'record']];
  for (const [value, action] of cases) {
    const out = await ask(value)(ambiguous);
    assert.equal(out.action, action, String(value));
    assert.equal(out.confidence, value);
  }
  assert.equal((await ask({ confidence: 0.9 })(ambiguous)).action, 'block');
  // 명확한 공격과 정상 이벤트는 Jev 에게 묻지 않는다.
  const before = asked.length;
  await ask(0)(byId('wi-01'));
  await ask(1)(byId('wi-18'));
  assert.equal(asked.length, before);
});

test('Jev 가 응답하지 않거나 이상한 값을 주면 alert 로 떨어진다', async () => {
  const ambiguous = byId('wi-09');
  const bad = [
    () => { throw new Error('down'); },
    () => Promise.reject(new Error('down')),
    () => undefined, () => null, () => NaN, () => '0.9', () => 1.5, () => -0.1, () => ({}), () => ({ confidence: 'x' }), () => Infinity,
  ];
  for (const askJev of bad) {
    const out = await createDecide({ askJev })(ambiguous);
    assert.equal(out.action, 'alert');
    assert.equal(out.confidence, 0.5);
    assert.match(out.reason, /Jev 응답 없음/u);
  }
  assert.equal((await createDecide()(ambiguous)).action, 'alert');
});

test('Jev 가 3초 안에 답하지 않으면 alert 로 떨어진다', async () => {
  const started = Date.now();
  const out = await createDecide({ askJev: () => new Promise(() => {}) })(byId('wi-12'));
  assert.equal(out.action, 'alert');
  assert.ok(Date.now() - started < 4500);
});

test('Jev 에게 가는 요약에는 비밀값이 없다', async () => {
  let sent;
  const alert = { id: 'x', timestamp: 't', rule: { level: 8, description: '주입처럼 보이는 표기 1건 password=hunter2' }, data: { srcip: '203.0.113.9', url: '/search?q=a&token=abcdef123456 Bearer abcdefgh12345', count: '1' } };
  await createDecide({ askJev: (summary) => { sent = JSON.stringify(summary); return 0.7; } })(alert);
  assert.doesNotMatch(sent, /hunter2|abcdef123456|abcdefgh12345/u);
  assert.match(sent, /가림/u);
});

test('실제 요청 인자의 공격 표기는 count·수준을 채우면 block, 한 번뿐이면 alert', async () => {
  const mk = (url, count, level = 11) => ({ id: 'r', timestamp: 't', rule: { level, description: '요청 확인' }, data: { srcip: '198.51.100.1', url, count: String(count) } });
  const attacks = [
    '/notes?q=x%27%20UNION%20SELECT%20a%20FROM%20t--', '/notes?id=1%20or%201=1', "/notes?q='; DROP TABLE notes",
    '/search?q=%3Cscript%3Ealert(1)%3C/script%3E', '/search?q=<script>x</script>',
    '/files?path=../../etc/passwd', '/files?path=%2e%2e%2f%2e%2e%2fa', '/files?path=..\\..\\a',
    '/ping?host=1.1.1.1;cat%20x', '/ping?host=1.1.1.1%7Cwhoami', '/ping?h=$(id)',
  ];
  for (const url of attacks) {
    assert.equal((await decide(mk(url, 6))).action, 'block', url);
    assert.equal((await decide(mk(url, 1))).action, 'alert', `${url} (1번)`);
    assert.equal((await decide(mk(url, 6, 8))).action, 'alert', `${url} (수준 8)`);
  }
  for (const url of ['/search?q=select-course', '/search?q=sql-class-notice', '/search?q=script-class', '/files?path=up-notes', '/files?path=../a', '/notes?q=user01-note', '/search?q=a;b']) {
    assert.notEqual((await decide(mk(url, 6))).action, 'block', url);
  }
});

test('경계: 반복 1번은 block 이 아니고 2번부터 block, 수준 9는 block 이 아니고 10부터 block', async () => {
  const mk = (count, level) => ({ id: 'b', timestamp: 't', rule: { level, description: '같은 주소에서 SQL 구문 표기가 반복됐습니다.' }, data: { srcip: '203.0.113.5', url: '/notes?q=doc-sql-chain', count: String(count) } });
  assert.equal((await decide(mk(1, 12))).action, 'alert');
  assert.equal((await decide(mk(2, 12))).action, 'block');
  assert.equal((await decide(mk(2, 9))).action, 'alert');
  assert.equal((await decide(mk(2, 10))).action, 'block');
});

test('patterns.json 과 decide.mjs 안의 패턴 값이 같고, 패턴마다 근거 한 줄이 있다', () => {
  assert.deepEqual(patternsFile.patterns.map((p) => [p.name, p.mitre, p.match]), PATTERNS.map((p) => [p.name, p.mitre, p.match]));
  for (const p of patternsFile.patterns) {
    assert.equal(p.mitre, 'T1190');
    assert.ok(p.evidence.startsWith('근거:') && !p.evidence.includes('\n') && p.evidence.includes('T1190'), p.name);
    assert.ok(p.condition.length > 0);
    assert.doesNotThrow(() => new RegExp(p.match.regex, p.match.flags));
    assert.doesNotThrow(() => new RegExp(p.match.descriptionRegex, p.match.flags));
  }
  assert.equal(new Set(patternsFile.patterns.map((p) => p.name)).size, patternsFile.patterns.length);
});

test('심판 격리 환경: decide.mjs 는 어떤 모듈도 import·require 하지 않는다(주석 제외한 코드 기준)', () => {
  const code = decideSource.replace(/\/\/.*$/gmu, '');
  assert.doesNotMatch(code, /^\s*import\s/mu);
  assert.doesNotMatch(code, /^\s*export\s[^\n]*\sfrom\s/mu);
  assert.doesNotMatch(code, /\bimport\s*\(|\brequire\s*\(|node:|process\./u);
});

test('심판 격리 환경: 내장 모듈·require·setTimeout 이 없는 빈 환경에서도 같은 결과가 나온다', async () => {
  const source = decideSource.replace(/^export /gmu, '');
  const box = vm.runInNewContext(`${source}\n;({ decide, createDecide })`, {});
  const out = [];
  for (const alert of fixture.alerts) out.push(await box.decide(alert));
  const expected = [];
  for (const alert of fixture.alerts) expected.push(await decide(alert));
  assert.deepEqual(out.map((d) => [d.action, d.confidence, d.reason]), expected.map((d) => [d.action, d.confidence, d.reason]));
  const counts = { block: 0, alert: 0, record: 0 };
  for (const d of out) counts[d.action] += 1;
  assert.deepEqual(counts, { block: 8, alert: 9, record: 9 });
  // setTimeout 이 없어도 Jev 가 있으면 물어보고, 없어도 오류 없이 alert 로 떨어진다.
  const withJev = vm.runInNewContext(`${source}\n;createDecide({ askJev: () => 0.9 })`, {});
  assert.equal((await withJev(byId('wi-16'))).action, 'block');
});

test('심판 배치 그대로: 실행기·경보 묶음·decide.mjs 하나만 빈 폴더에 두고 돌려도 26건이 오류 없이 나온다', async () => {
  const { mkdtemp, mkdir, cp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { spawn } = await import('node:child_process');
  const { join } = await import('node:path');
  const root = new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/u, '$1');
  const dir = await mkdtemp(join(tmpdir(), 'xdr-judge-'));
  try {
    await mkdir(join(dir, 'scripts'), { recursive: true });
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await mkdir(join(dir, 'xdr', 'web-injection'), { recursive: true });
    await cp(join(root, 'scripts', 'xdr-run.mjs'), join(dir, 'scripts', 'xdr-run.mjs'));
    await cp(join(root, 'xdr', 'fixtures', 'web-injection.json'), join(dir, 'xdr', 'fixtures', 'web-injection.json'));
    await cp(join(root, 'xdr', 'web-injection', 'decide.mjs'), join(dir, 'xdr', 'web-injection', 'decide.mjs'));
    const child = spawn(process.execPath, ['scripts/xdr-run.mjs', 'web-injection'], { cwd: dir, windowsHide: true });
    let stderr = '';
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const code = await new Promise((resolve, reject) => { child.on('error', reject); child.on('exit', resolve); });
    assert.equal(code, 0);
    assert.equal(stderr.trim(), '');
    const result = JSON.parse(await readFile(join(dir, 'xdr', 'web-injection', 'result.json'), 'utf8'));
    assert.deepEqual(result.counts, { block: 8, alert: 9, record: 9 });
    assert.equal(result.decisions.length, fixture.alerts.length);
    assert.deepEqual(result.decisions.filter((d) => d.action === 'block').map((d) => d.alertId), CLEAR);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});

test('이상한 경보가 와도 decide 는 오류를 던지지 않고 올바른 모양을 돌려준다', async () => {
  const circular = { id: 'c', rule: { level: 12, description: 'SQL 구문 12번' }, data: { srcip: '203.0.113.1', url: '/x', count: '12' } };
  circular.self = circular;
  const thrower = { toString() { throw new Error('x'); }, valueOf() { throw new Error('v'); } };
  const odd = [undefined, null, 0, 'text', [], {}, { id: 5 }, { rule: null }, { rule: { level: 'x' } }, { rule: { level: NaN, description: 7 } },
    { rule: { level: 99, description: 'SQL 구문' }, data: { count: 'abc', url: 5 } },
    { id: 'a', timestamp: 'not-a-date', rule: { level: 11, description: '스크립트 삽입 30번' }, data: { srcip: '1.1.1.1', url: '%E0%A4%A', count: '30' } },
    { id: 'e', rule: { level: 11, description: '경로 이탈' }, data: { srcip: '2.2.2.2', count: '1e309' } },
    { id: 'big', rule: { level: 11, description: 'x'.repeat(100000) }, data: { url: '../'.repeat(100000), count: 9 } },
    circular, Object.create(null), () => 1, Symbol('s'),
    // 접근하는 순간 오류를 던지는 경보: decide 안의 보호막이 막아야 합니다.
    new Proxy({}, { get() { throw new Error('get'); } }),
    { get rule() { throw new Error('rule'); }, id: 'g' },
    { id: 'h', rule: { level: 10, description: thrower }, data: { srcip: thrower, url: thrower, count: thrower } }];
  for (const value of odd) {
    const out = await decide(value);
    assert.deepEqual(Object.keys(out).sort(), ['action', 'confidence', 'reason']);
    assert.ok(['block', 'alert', 'record'].includes(out.action));
    assert.ok(Number.isFinite(out.confidence) && out.confidence >= 0 && out.confidence <= 1);
    assert.equal(typeof out.reason, 'string');
    assert.ok(!out.reason.includes('\n'));
  }
});

test('경보 읽기: 비밀값처럼 보이는 값은 가리고, 원본 경보 파일은 고치지 않는다', async () => {
  const before = await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8');
  const row = extractAlert({ id: 'x', timestamp: 't', rule: { level: 5, description: 'password=hunter2 ok' }, data: { srcip: '1.2.3.4', srcuser: `sb_${'secret'}_${'a'.repeat(16)}` } });
  assert.equal(row.user, '[가림]');
  assert.doesNotMatch(row.description, /hunter2/u);
  assert.equal(scrub('평범한 문장'), '평범한 문장');
  await readAlerts();
  assert.equal(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8'), before);
});

// ---- 제작 4: 알림과 차단 ----
const decisions = [];
for (const alert of fixture.alerts) decisions.push({ alertId: alert.id, ...(await decide(alert)) });
const NOW = Date.parse('2026-10-08T00:00:00Z');
const rules = buildBlockRules({ alerts: fixture.alerts, decisions, now: NOW });
const ipsOf = (ids) => new Set(ids.map((id) => byId(id).data.srcip));

test('차단 규칙은 명확한 공격 주소만, 만료 시각·근거 경보 번호가 있고 정상·애매한 주소는 없다', () => {
  const attackIps = ipsOf(CLEAR);
  assert.equal(rules.length, attackIps.size); // wi-01·02 는 같은 주소라 7개
  assert.deepEqual(new Set(rules.map((r) => r.srcip)), attackIps);
  for (const rule of rules) {
    assert.equal(rule.decision, 'deny');
    assert.equal(rule.ruleId, 'xdr.wi.deny-ip');
    assert.ok(CLEAR.includes(rule.evidenceAlertId), rule.evidenceAlertId);
    assert.equal(byId(rule.evidenceAlertId).data.srcip, rule.srcip);
    assert.ok(Date.parse(rule.expiresAt) > NOW);
    assert.equal(Date.parse(rule.createdAt), NOW);
  }
  for (const ip of [...ipsOf(NORMAL), ...ipsOf(AMBIGUOUS)]) assert.ok(!rules.some((r) => r.srcip === ip), ip);
});

test('차단 규칙: 정상 이벤트에도 나온 주소, 확신도가 낮은 block, 주소 모양이 아닌 값, 모르는 경보 번호는 넣지 않는다', () => {
  const mk = (id, srcip) => ({ id, data: { srcip } });
  const alerts = [mk('a', '203.0.113.1'), mk('b', '203.0.113.1'), mk('c', '203.0.113.2'), mk('d', 'not-an-ip'), mk('e', '203.0.113.3'), mk('f', '203.0.113.4')];
  const ds = [
    { alertId: 'a', action: 'block', confidence: 0.95 }, { alertId: 'b', action: 'record', confidence: 0.05 },
    { alertId: 'c', action: 'block', confidence: 0.84 }, { alertId: 'd', action: 'block', confidence: 0.95 },
    { alertId: 'zzz', action: 'block', confidence: 0.95 }, { alertId: 'e', action: 'alert', confidence: 0.9 },
    { alertId: 'f', action: 'block', confidence: 0.85 }, { alertId: 'f', action: 'block', confidence: 0.99 },
    null, { alertId: 5, action: 'block', confidence: 1 }, { action: 'block', confidence: 1 },
  ];
  const out = buildBlockRules({ alerts, decisions: ds, now: NOW });
  assert.deepEqual(out.map((r) => [r.srcip, r.evidenceAlertId]), [['203.0.113.4', 'f']]);
});

test('만료된 규칙은 막지 않는다', () => {
  assert.ok(findBlock(rules, rules[0].srcip, NOW + 30 * 60 * 1000));
  assert.equal(findBlock(rules, rules[0].srcip, NOW + 2 * 60 * 60 * 1000), null);
});

test('알림 한 줄: 한 줄이고 비밀값은 가리며, 줄바꿈이 섞여도 한 줄을 지킨다', () => {
  const alert = byId('wi-01');
  const line = alertLine({ alertId: 'wi-01', action: 'block', confidence: 0.95, reason: '패턴 일치: x\npassword=hunter2\r\n다음 줄' }, alert, NOW);
  assert.ok(!/[\r\n]/u.test(line));
  assert.doesNotMatch(line, /hunter2/u);
  assert.match(line, /^2026-10-08T00:00:00\.000Z BLOCK wi-01 203\.0\.113\.10 - 0\.95 /u);
});

// 판정 결과를 담은 임시 폴더 하나를 만들고 연결을 돌립니다(저장소의 실제 규칙·로그 파일은 건드리지 않습니다).
async function linked(run) {
  const dir = await mkdtemp(join(tmpdir(), 'xdr-link-'));
  try {
    await mkdir(join(dir, 'xdr', 'fixtures'), { recursive: true });
    await mkdir(join(dir, 'xdr', 'web-injection'), { recursive: true });
    await writeFile(join(dir, 'xdr', 'fixtures', 'web-injection.json'), JSON.stringify(fixture));
    await writeFile(join(dir, 'xdr', 'web-injection', 'result.json'), JSON.stringify({ schema: 'aleph.xdr.result.v1', moduleKey: 'web-injection', decisions, counts: {} }));
    return await run({ dir, rulesFile: join(dir, 'rules.json'), logFile: join(dir, 'alerts.log') });
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

test('연결: 규칙 파일에는 block 주소만, 알림 로그에는 block·alert 만 한 줄씩 쌓이고 다시 흘리면 로그가 이어진다', async () => {
  await linked(async ({ dir, rulesFile, logFile }) => {
    const first = await linkResults({ root: dir, now: NOW, rulesFile, logFile });
    assert.equal(first.rules.length, 7);
    assert.equal(first.logged, 17); // block 8 + alert 9, record 9 는 남기지 않음
    const file = JSON.parse(await readFile(rulesFile, 'utf8'));
    assert.equal(file.schema, 'aleph.xdr.block-rules.v1');
    assert.deepEqual(file.rules, first.rules);
    const log = (await readFile(logFile, 'utf8')).trimEnd().split('\n');
    assert.equal(log.length, 17);
    assert.equal(log.filter((l) => / BLOCK /u.test(l)).length, 8);
    assert.equal(log.filter((l) => / ALERT /u.test(l)).length, 9);
    assert.ok(!log.some((l) => / RECORD /u.test(l)));
    assert.ok(log.every((l) => /^\d{4}-\d\d-\d\dT[\d:.]+Z (?:BLOCK|ALERT) wi-\d\d \S+ \S+ [\d.]+ \S/u.test(l)));
    await linkResults({ root: dir, now: NOW + 1000, rulesFile, logFile });
    assert.equal((await readFile(logFile, 'utf8')).trimEnd().split('\n').length, 34); // 알림은 쌓이고
    assert.equal(JSON.parse(await readFile(rulesFile, 'utf8')).rules.length, 7); // 규칙은 같은 주소를 두 번 넣지 않는다
  });
});

test('연결: 판정 결과가 없거나 형식이 틀리면 안내 문구로 멈추고 규칙·로그를 만들지 않는다', async () => {
  await linked(async ({ dir, rulesFile, logFile }) => {
    await rm(join(dir, 'xdr', 'web-injection', 'result.json'));
    await assert.rejects(linkResults({ root: dir, rulesFile, logFile }), /npm run xdr:run -- web-injection/u);
    await writeFile(join(dir, 'xdr', 'web-injection', 'result.json'), JSON.stringify({ schema: 'x', decisions: [] }));
    await assert.rejects(linkResults({ root: dir, rulesFile, logFile }), /형식이 아닙니다/u);
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

test('경보를 다시 흘리면: 명확한 공격 주소는 로그인·자료 API 에서 403, 정상·애매한 주소는 기존대로 통과', async () => {
  await linked(async ({ dir, rulesFile, logFile }) => {
    await linkResults({ root: dir, now: Date.now(), rulesFile, logFile });
    const live = loadBlockRules(rulesFile);
    assert.equal(live.length, 7);
    const calls = { n: 0 };
    for (const ip of ipsOf(CLEAR)) {
      assert.equal((await callAuth(live, ip, calls)).code, 403, `로그인 ${ip}`);
      assert.deepEqual((await callAuth(live, ip, calls)).body, { error: 'BLOCKED_BY_XDR' });
      assert.equal((await callNotes(live, ip)).code, 403, `자료 ${ip}`);
    }
    assert.equal(calls.n, 0); // 막힌 주소의 요청은 Supabase 로 보내지 않는다
    for (const ip of [...ipsOf(NORMAL), ...ipsOf(AMBIGUOUS)]) {
      assert.equal((await callAuth(live, ip, calls)).code, 401, `로그인 ${ip}`); // 막히지 않고 기존 로그인 검사까지 간다
      assert.equal((await callNotes(live, ip)).code, 401, `자료 ${ip}`); // 막히지 않고 기존 로그인 요구까지 간다
    }
    assert.equal(calls.n, ipsOf(NORMAL).size + ipsOf(AMBIGUOUS).size);
  });
});

test('ZTNA 거부 규칙 읽기: 규칙 파일이 없거나 깨져 있으면 아무도 막지 않고, 웹 주입 규칙 파일도 함께 읽는다', async () => {
  assert.deepEqual(loadBlockRules(join(tmpdir(), 'xdr-no-such-rules.json')), []);
  const dir = await mkdtemp(join(tmpdir(), 'xdr-rules-'));
  try {
    await writeFile(join(dir, 'broken.json'), '{ not json');
    assert.deepEqual(loadBlockRules(join(dir, 'broken.json')), []);
    await writeFile(join(dir, 'odd.json'), JSON.stringify({ rules: 'x' }));
    assert.deepEqual(loadBlockRules(join(dir, 'odd.json')), []);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
  // 기본 경로: 웹 주입 규칙 파일(생성 파일, Git 제외)을 임시로 두고 읽히는지 본 뒤 원래대로 되돌립니다.
  let original = null;
  try { original = await readFile(WEB_INJECTION_RULES_FILE, 'utf8'); } catch { /* 없음 */ }
  const probe = { ruleId: 'xdr.wi.deny-ip', decision: 'deny', srcip: '198.51.100.250', evidenceAlertId: 'wi-01', createdAt: new Date(NOW).toISOString(), expiresAt: new Date(NOW + 3600000).toISOString() };
  try {
    await writeFile(WEB_INJECTION_RULES_FILE, JSON.stringify({ schema: 'aleph.xdr.block-rules.v1', rules: [probe] }));
    const found = loadBlockRules();
    assert.ok(found.some((r) => r.srcip === '198.51.100.250'));
    assert.equal(findBlock(found, '198.51.100.250', NOW)?.evidenceAlertId, 'wi-01');
  } finally {
    if (original === null) await rm(WEB_INJECTION_RULES_FILE, { force: true });
    else await writeFile(WEB_INJECTION_RULES_FILE, original);
  }
});
