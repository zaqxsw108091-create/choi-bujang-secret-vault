import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import vm from 'node:vm';
import { PATTERNS, createDecide, decide } from '../xdr/web-injection/decide.mjs';
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
