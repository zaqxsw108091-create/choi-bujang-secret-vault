import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createAuthApi } from '../src/auth-api.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { findBlock } from '../src/xdr-block.mjs';
import { createDecide, decide } from '../xdr/brute-force/decide.mjs';
import { buildBlockRules } from '../xdr/brute-force/link.mjs';
import { readAlerts } from '../xdr/brute-force/read-alerts.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const decisions = [];
for (const alert of fixture.alerts) decisions.push({ alertId: alert.id, ...(await decide(alert)) });
const NOW = Date.parse('2026-10-08T00:00:00Z');
const rules = buildBlockRules({ alerts: fixture.alerts, decisions, now: NOW });

test('경보 건수와 뽑은 줄 수가 같다', async () => {
  const { alertCount, rows } = await readAlerts();
  assert.equal(rows.length, alertCount);
});

test('명확한 공격 block, 애매한 건 alert, 정상은 record', () => {
  const action = (id) => decisions.find((d) => d.alertId === id).action;
  for (let n = 1; n <= 10; n += 1) assert.equal(action(`bf-${String(n).padStart(2, '0')}`), 'block');
  assert.equal(action('bf-12'), 'alert');
  assert.equal(action('bf-20'), 'record');
});

test('정상 이벤트(bf-20~28)는 block 되지 않는다', () => {
  const normal = decisions.filter((d) => Number(d.alertId.slice(3)) >= 20);
  assert.ok(normal.every((d) => d.action === 'record'));
});

test('Jev 가 없으면 애매한 건 alert, 응답해도 성공 뒤 실패는 block 까지 가지 않는다', async () => {
  const ambiguous = fixture.alerts.find((a) => a.id === 'bf-12');
  assert.equal((await createDecide({ askJev: () => null })(ambiguous)).action, 'alert');
  assert.equal((await createDecide({ askJev: () => new Promise(() => {}) })(ambiguous)).action, 'alert');
  assert.equal((await createDecide({ askJev: () => 0.99 })(ambiguous)).action, 'alert');
});

test('차단 규칙은 block 주소만, 만료 시각·근거 경보 번호가 있고 정상 주소는 없다', () => {
  const normalIps = new Set(fixture.alerts.filter((a) => Number(a.id.slice(3)) >= 11).map((a) => a.data.srcip));
  assert.ok(rules.length > 0);
  for (const rule of rules) {
    assert.equal(rule.decision, 'deny');
    assert.match(rule.evidenceAlertId, /^bf-\d+$/u);
    assert.ok(Date.parse(rule.expiresAt) > NOW);
    assert.ok(!normalIps.has(rule.srcip));
  }
});

const login = (rulesList, ip, calls) => createAuthApi({
  getSettings: () => ({ url: 'https://example.invalid', secretKey: 'x' }),
  fetchImpl: async () => { calls.n += 1; return { ok: false, status: 400, json: async () => ({ error_code: 'invalid_credentials' }) }; },
  getBlockRules: () => rulesList,
  now: () => NOW,
}).login({ method: 'POST', headers: { 'x-forwarded-for': ip }, body: { email: 'a@b.co', password: 'pw' } }, {
  setHeader() {},
  status(code) { return { json: (body) => ({ code, body }) }; },
});

test('로그인: 차단된 주소는 403, 정상 주소는 기존대로 통과', async () => {
  const calls = { n: 0 };
  const blocked = await login(rules, rules[0].srcip, calls);
  assert.equal(blocked.code, 403);
  assert.equal(calls.n, 0);
  const normal = await login(rules, '192.0.2.60', calls);
  assert.equal(normal.code, 401);
  assert.equal(calls.n, 1);
});

test('만료된 규칙은 막지 않는다', () => {
  assert.equal(findBlock(rules, rules[0].srcip, NOW + 2 * 60 * 60 * 1000), null);
});

test('같은 종류의 다른 경보도 수준·신호로 나뉜다', async () => {
  const make = (level, description, data) => ({ id: 'x', timestamp: 't', rule: { level, description }, data: { srcip: '203.0.113.99', srcuser: 'user09', ...data } });
  assert.equal((await decide(make(11, '같은 주소에서 로그인 실패 12건이 이어졌습니다.', { count: '12' }))).action, 'block');
  assert.equal((await decide(make(11, '여러 계정에 같은 비밀번호 실패가 이어졌습니다.', {}))).action, 'block');
  assert.equal((await decide(make(11, '로그인 실패 12건 뒤에 성공했습니다.', { count: '12' }))).action, 'alert');
  assert.equal((await decide(make(8, '로그인 실패 9건이 있습니다.', { count: '9' }))).action, 'alert');
  assert.equal((await decide(make(3, '로그인이 성공했습니다.', {}))).action, 'record');
  assert.equal((await decide({})).action, 'record');
});


test('자료 API: 차단된 주소는 로그인 확인 전에 403, 다른 주소는 기존대로 로그인을 요구한다', async () => {
  const api = createNotesApi({
    getVerifier: () => async () => null,
    getSupabase: () => ({}),
    getBlockRules: () => rules,
    now: () => NOW,
  });
  const call = async (ip) => {
    let out;
    await api.collection({ method: 'GET', headers: { 'x-forwarded-for': ip } }, {
      setHeader() {},
      status(code) { return { json: (body) => { out = { code, body }; } }; },
    });
    return out;
  };
  assert.equal((await call(rules[0].srcip)).code, 403);
  assert.equal((await call('192.0.2.60')).code, 401);
});


const burst = (id, at, level, count, extra = {}) => ({
  id, timestamp: at, rule: { level, description: `로그인 실패 ${count}건이 있습니다.` },
  data: { srcip: '203.0.113.77', srcuser: 'user09', count: String(count), ...extra },
});

test('모아 보기: 같은 주소·계정의 실패를 10분 안에서 합쳐 기준을 넘으면 알린다', async () => {
  const a = burst('a', '2026-09-27T10:00:00+09:00', 8, 6);
  const b = burst('b', '2026-09-27T10:04:00+09:00', 8, 6);
  const out = await createDecide({ history: [a, b] })(a);
  assert.equal(out.action, 'alert');
  assert.match(out.reason, /합산 12건/u);
  // 한 건만 있으면 합산이 없고 같은 alert 입니다.
  assert.doesNotMatch((await createDecide({ history: [a] })(a)).reason, /합산/u);
});

test('모아 보기: 수준이 높고 합산이 기준을 넘으면 명확한 공격으로 막는다', async () => {
  const a = burst('a', '2026-09-27T10:00:00+09:00', 11, 6);
  const b = burst('b', '2026-09-27T10:03:00+09:00', 11, 6);
  assert.equal((await createDecide({ history: [a, b] })(a)).action, 'block');
  assert.equal((await createDecide({ history: [a] })(a)).action, 'alert');
});

test('모아 보기: 10분을 넘으면 합치지 않고, 경보 순서가 바뀌어도 결과가 같다', async () => {
  const a = burst('a', '2026-09-27T10:00:00+09:00', 11, 6);
  const far = burst('far', '2026-09-27T10:30:00+09:00', 11, 6);
  assert.equal((await createDecide({ history: [a, far] })(a)).action, 'alert');
  const b = burst('b', '2026-09-27T10:03:00+09:00', 11, 6);
  const one = await createDecide({ history: [a, b] })(a);
  const two = await createDecide({ history: [b, a] })(a);
  assert.deepEqual(one, two);
});

test('모아 보기: 다른 주소의 실패나 성공 뒤 실패는 합치지 않는다', async () => {
  const a = burst('a', '2026-09-27T10:00:00+09:00', 11, 6);
  const other = burst('o', '2026-09-27T10:01:00+09:00', 11, 6, { srcip: '198.51.100.77' });
  const ok = { ...burst('s', '2026-09-27T10:01:00+09:00', 11, 6), rule: { level: 11, description: '로그인 실패 6건 뒤에 성공했습니다.' } };
  assert.equal((await createDecide({ history: [a, other, ok] })(a)).action, 'alert');
});

test('차단 규칙: 주소 모양이 아닌 값은 규칙으로 만들지 않는다', () => {
  const alerts = ['cafe', '999.999.999.999', '', '203.0.113.5', '2001:db8::1'].map((ip, i) => ({ id: `z${i}`, data: { srcip: ip } }));
  const decisions = alerts.map((a) => ({ alertId: a.id, action: 'block' }));
  const out = buildBlockRules({ alerts, decisions, now: NOW }).map((r) => r.srcip);
  assert.deepEqual(out, ['203.0.113.5', '2001:db8::1']);
});

test('이유 문구: 한 계정의 실패에는 여러 계정 패턴 이름을 붙이지 않는다', async () => {
  const one = { id: 'o', timestamp: 't', rule: { level: 6, description: '같은 계정 로그인 실패 4건 뒤에 성공했습니다.' }, data: { srcip: '192.0.2.5', srcuser: 'user01', count: '4' } };
  const two = { id: 't', timestamp: 't', rule: { level: 7, description: '두 계정에 실패가 2건씩 있고 주소는 같습니다.' }, data: { srcip: '192.0.2.6', srcuser: 'user02', count: '4' } };
  const d = createDecide({ history: [] });
  assert.doesNotMatch((await d(one)).reason, /many-accounts/u);
  assert.match((await d(two)).reason, /many-accounts/u);
});
