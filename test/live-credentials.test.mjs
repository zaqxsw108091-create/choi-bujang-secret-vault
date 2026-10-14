import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { loginForTokens } from '../src/live-credentials.mjs';
import { findSecrets } from '../scripts/secret-scan.mjs';

const APP = new URL('https://example-app.vercel.app');
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString('base64url');
const jwt = (sub) => `${b64({ alg: 'ES256' })}.${b64({ sub, email: 'x@example.com' })}.c2lnbmF0dXJl`;
const accounts = [{ name: 'OWNER', email: 'b@example.com', password: 'pw-B-secret' }, { name: 'OTHER', email: 'a@example.com', password: 'pw-A-secret' }];
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

const fake = (sent, answer) => async (url, init) => {
  const body = JSON.parse(init.body);
  sent.push({ path: new URL(url).pathname, method: init.method, email: body.email, hasPassword: typeof body.password === 'string' });
  return answer(body);
};
const okAnswer = (body) => json({ access_token: jwt(body.email), refresh_token: 'r', expires_at: 1, email: body.email });

test('성공: 로그인 요청은 계정마다 정확히 한 번, /api/login POST로만', async () => {
  const sent = [];
  const result = await loginForTokens({ app: APP, accounts, fetchFn: fake(sent, okAnswer) });
  assert.equal(result.ok, true);
  assert.equal(result.requests, 2);
  assert.deepEqual(sent.map(s => [s.path, s.method, s.email]), [['/api/login', 'POST', 'b@example.com'], ['/api/login', 'POST', 'a@example.com']]);
  assert.deepEqual(Object.keys(result.tokens).sort(), ['OTHER', 'OWNER']);
});

test('첫 계정이 거절되면 두 번째는 보내지 않고 재시도도 없다(횟수 1)', async () => {
  const sent = [];
  const result = await loginForTokens({ app: APP, accounts, fetchFn: fake(sent, () => json({ error: 'LOGIN_FAILED', reason: 'invalid_credentials' }, 401)) });
  assert.equal(result.ok, false);
  assert.equal(result.requests, 1);
  assert.equal(sent.length, 1);
  assert.match(result.message, /HTTP 401, invalid_credentials/u);
});

test('발급 횟수 제한(429)이면 그 자리에서 멈추고 기다리라고 알린다', async () => {
  const sent = [];
  const result = await loginForTokens({ app: APP, accounts, fetchFn: fake(sent, () => json({ error: 'LOGIN_FAILED', reason: 'over_request_rate_limit' }, 429)) });
  assert.equal(result.ok, false);
  assert.equal(sent.length, 1);
  assert.match(result.message, /횟수 제한/u);
});

test('두 번째 계정이 거절돼도 전체는 실패이고 총 2번만 보낸다', async () => {
  const sent = [];
  let n = 0;
  const result = await loginForTokens({ app: APP, accounts, fetchFn: fake(sent, (b) => (++n === 1 ? okAnswer(b) : json({ error: 'LOGIN_FAILED' }, 401))) });
  assert.deepEqual([result.ok, result.requests, sent.length], [false, 2, 2]);
});

test('접속 실패·JSON 아닌 응답·토큰 모양이 아닌 응답은 멈춘다', async () => {
  const down = await loginForTokens({ app: APP, accounts, fetchFn: async () => { throw new TypeError('fetch failed'); } });
  assert.deepEqual([down.ok, down.requests], [false, 1]);
  const text = await loginForTokens({ app: APP, accounts, fetchFn: async () => new Response('Host not in allowlist', { status: 403 }) });
  assert.equal(text.ok, false);
  const shape = await loginForTokens({ app: APP, accounts, fetchFn: async () => json({ access_token: 'short' }) });
  assert.equal(shape.ok, false);
});

test('같은 계정이면 요청을 보내기 전에 거부하고, 같은 sub의 토큰이면 쓰지 않는다', async () => {
  const sent = [];
  const same = await loginForTokens({ app: APP, accounts: [accounts[0], { ...accounts[1], email: ' B@example.com ' }], fetchFn: fake(sent, okAnswer) });
  assert.deepEqual([same.ok, same.requests, sent.length], [false, 0, 0]);
  const sub = await loginForTokens({ app: APP, accounts, fetchFn: async () => json({ access_token: jwt('same-user'), refresh_token: 'r', expires_at: 1 }) });
  assert.equal(sub.ok, false);
  assert.match(sub.message, /같은 계정/u);
});

test('잘못된 입력(빈 비밀번호, 이메일 모양 틀림, 계정 수)은 요청을 보내지 않는다', async () => {
  const sent = [];
  for (const bad of [[{ ...accounts[0], password: '' }, accounts[1]], [{ ...accounts[0], email: 'abc' }, accounts[1]], [accounts[0]]]) {
    const result = await loginForTokens({ app: APP, accounts: bad, fetchFn: fake(sent, okAnswer) });
    assert.deepEqual([result.ok, result.requests], [false, 0]);
  }
  assert.equal(sent.length, 0);
});

test('결과(message·requests·tokens 이외)에 비밀번호가 없고, 실패 메시지에도 비밀번호·토큰이 없다', async () => {
  const fail = await loginForTokens({ app: APP, accounts, fetchFn: fake([], () => json({ error: 'LOGIN_FAILED', reason: 'invalid_credentials' }, 401)) });
  const ok = await loginForTokens({ app: APP, accounts, fetchFn: fake([], okAnswer) });
  for (const result of [fail, ok]) assert.ok(!JSON.stringify({ ...result, tokens: undefined }).includes('pw-'));
  assert.ok(!fail.message.includes('pw-'));
});

test('코드·시험 파일에 키·토큰 모양의 실제 값이 없다', () => {
  const files = ['../src/live-credentials.mjs', './live-credentials.test.mjs'].map(path => [path, readFileSync(new URL(path, import.meta.url), 'utf8')]);
  assert.deepEqual(findSecrets(files), []);
  assert.ok(existsSync(new URL('../src/live-credentials.mjs', import.meta.url)));
});
