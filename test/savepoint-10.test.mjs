import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { runAttackChecks } from '../src/attack-check.mjs';
import { RULE_IDS, decide } from '../src/decider.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const config = JSON.parse(read('aleph.config.json'));
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

test('설정: step 10 이상이고 심판 접수 주소·로그인 발급자·복구 경로가 그대로다', () => {
  assert.ok(config.step >= 10);
  assert.equal(config.judgeIssuer, 'https://aleph-judge-production.up.railway.app/defense/judge');
  assert.equal(config.identityProvider.issuer, 'https://vskaxngivuhucmbnoagz.supabase.co/auth/v1');
  assert.equal(config.restoreRoute, 'POST /api/restore');
  assert.equal(config.publicAppUrl, 'https://choi-bujang-secret-vault-tr33.vercel.app');
  const env = { VERCEL_GIT_PROVIDER: 'github', VERCEL_GIT_REPO_OWNER: 'Student-A', VERCEL_GIT_REPO_SLUG: 'aleph-defense',
    VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40), VERCEL_URL: 'student-defense-123.vercel.app' };
  assert.equal(deploymentIdentity(env, { ...config, step: 10 }).step, 10);
});

// 가짜 배포: restoreStatus가 401이면 앱의 거부, 200이면 거부되지 않음, 'text'이면 앱이 아닌 곳의 응답
const fakeFetch = (sent, restore) => async (url, init = {}) => {
  const { pathname } = new URL(String(url));
  sent.push({ method: init.method ?? 'GET', pathname, auth: init.headers?.Authorization ?? null, body: init.body ?? null });
  if (restore === 'throw' && pathname === '/api/restore') throw new TypeError('fetch failed');
  if (pathname === '/data.json') return new Response('Not found', { status: 404 });
  if (pathname === '/aleph.json') return json({ step: 10 });
  if (pathname === '/api/login') return json({ error: 'LOGIN_FAILED' }, 401);
  if (pathname === '/api/restore') {
    if (restore === 'text') return new Response('Host not in allowlist', { status: 403, headers: { 'content-type': 'text/plain' } });
    return restore === 200 ? json({ id: 'x', restored: true }) : json({ error: 'LOGIN_REQUIRED' }, 401);
  }
  return json({ error: 'LOGIN_REQUIRED' }, 401);
};
async function run(restore = 401) {
  const sent = [];
  const real = globalThis.fetch;
  globalThis.fetch = fakeFetch(sent, restore);
  try { return { results: await runAttackChecks(config), sent }; } finally { globalThis.fetch = real; }
}
const observed = (results, id) => results.find(r => r.attackId === id)?.observed;

test('10단계 점검: 로그인 없는 복구 요청만 보내고, 다른 계정 복구는 미실행으로 남긴다', async () => {
  const { results, sent } = await run();
  assert.equal(observed(results, 'anonymous_restore_refused'), '거부됨 (HTTP 401)');
  assert.match(observed(results, 'other_owner_restore_refused'), /^미실행/u);
  const restores = sent.filter(s => s.pathname === '/api/restore');
  assert.equal(restores.length, 1);
  assert.deepEqual([restores[0].method, restores[0].auth], ['POST', null], '로그인 값 없이 POST 한 번');
  assert.deepEqual(JSON.parse(restores[0].body), { id: '00000000-0000-4000-8000-000000000000' });
  assert.ok(results.length <= 20 && new Set(results.map(r => r.attackId)).size === results.length);
  assert.ok(results.every(r => Object.keys(r).sort().join() === 'attackId,expected,observed'));
});

test('10단계 점검: 거부되지 않으면 그대로 적고, 앱 응답이 아니거나 접속 실패면 지어내지 않는다', async () => {
  assert.match(observed((await run(200)).results, 'anonymous_restore_refused'), /^거부되지 않음 또는 예상 밖 응답 \(HTTP 200\)$/u);
  assert.match(observed((await run('text')).results, 'anonymous_restore_refused'), /^확인하지 못함 \(HTTP 403/u);
  assert.equal(observed((await run('throw')).results, 'anonymous_restore_refused'), '확인하지 못함 (요청을 보내지 못함)');
});

// ---- 판정기: 계약의 요청 이름만 읽고, 모든 가상 요청에 다섯 항목 응답을 돌려준다 ----
const CONTRACT = ['schema', 'requestId', 'classId', 'projectId', 'subjectId', 'deviceId', 'service', 'method', 'path', 'route',
  'queryLength', 'querySha256', 'at', 'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals'];
const DEVICE = 'a1b2c3d4e5f60718';
const base = (over = {}) => ({
  schema: 'aleph.decision.v1', requestId: randomUUID(), classId: 'class', projectId: 'project', subjectId: 'subject1', deviceId: DEVICE,
  service: 'notes', method: 'GET', path: '/notes/44444444-4444-4444-8444-444444444444', route: 'GET /notes/:id', queryLength: 0, querySha256: 'e'.repeat(64),
  at: new Date().toISOString(), policyRevision: 'rev1', deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null },
  recentEvents: [], signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 12 }, ...over });

test('판정기 소스는 계약의 18개 이름만 요청에서 읽는다(identity·device·geo·role 등은 읽지 않음)', () => {
  const code = read('src/decider.mjs').replace(/\/\/.*$/gmu, '');
  const dotted = [...code.matchAll(/\brequest\??\.([A-Za-z_]\w*)/gu)].map(m => m[1]);
  const destructured = [...code.matchAll(/const \{([^}]*)\} = request\b/gu)].flatMap(m => m[1].split(',').map(n => n.trim().split(':')[0].trim()).filter(Boolean));
  const readNames = new Set([...dotted, ...destructured]);
  assert.ok(readNames.size > 0);
  for (const name of readNames) assert.ok(CONTRACT.includes(name), `계약에 없는 request.${name}`);
  for (const forbidden of ['identity', 'device', 'geo', 'role']) assert.ok(!readNames.has(forbidden));
});

test('판정기는 모든 가상 요청에 형식이 맞는 다섯 항목 응답을 돌려주고 ruleIds는 RULE_IDS 안에 있다', async () => {
  const requests = [
    base(), base({ method: 'POST', route: 'POST /notes' }), base({ deviceRegistered: false }), base({ deviceRegistered: 'true' }),
    base({ path: '/notes/export', route: 'GET /notes/:id' }), base({ method: 'PUT', path: '/notices/week-1', route: 'PUT /notices/:id' }),
    base({ method: 'POST', path: '/restore', route: 'POST /restore' }), base({ route: 'GET /unknown', path: '/unknown' }),
    base({ signals: { source: 'judge_fixture', region: 'far', network: 'other', hour: 3 }, recentEvents: [{ kind: 'login', ageSeconds: 1, count: 9 }] }),
    base({ subjectId: undefined }), null, undefined, {}, 'x', 7, [], { requestId: randomUUID() },
  ];
  for (const request of requests) {
    const response = await decide(request);
    assert.deepEqual(Object.keys(response).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    assert.equal(response.schema, 'aleph.decision.v1');
    assert.ok(['allow', 'deny', 'step_up'].includes(response.decision));
    assert.match(response.reasonCode, /^[a-z][a-z0-9_]*$/u);
    assert.ok(Array.isArray(response.ruleIds) && response.ruleIds.length >= 1 && response.ruleIds.every(id => RULE_IDS.includes(id)));
    if (request?.requestId) assert.equal(response.requestId, request.requestId);
  }
  assert.equal((await decide(base())).decision, 'allow');
  // 8단계 결정: 자기 메모는 한 건 읽기·수정만 알고, 목록은 알지 못하는 경로로 거부합니다(판정기는 바꾸지 않음).
  assert.equal((await decide(base({ path: '/notes', route: 'GET /notes' }))).reasonCode, 'route_not_allowed');
  assert.equal((await decide(base({ path: '/restore', route: 'POST /restore', method: 'POST' }))).reasonCode, 'route_not_allowed');
  assert.equal((await decide(base({ deviceRegistered: false }))).decision, 'deny');
});
