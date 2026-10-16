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

test('10단계 점검: 복구 요청(POST)은 격리된 제출 환경에서 보내지 않고 미실행으로 남긴다', async () => {
  const { results, sent } = await run();
  assert.match(observed(results, 'anonymous_restore_refused'), /^not_run$/u);
  assert.match(observed(results, 'other_owner_restore_refused'), /^not_run$/u);
  assert.equal(sent.filter(s => s.pathname === '/api/restore').length, 0, '복구 경로로는 아무 요청도 보내지 않음');
  assert.deepEqual(sent.filter(s => s.method !== 'GET'), [], '쓰기 요청은 보내지 않음');
  assert.ok(results.length <= 20 && new Set(results.map(r => r.attackId)).size === results.length);
  assert.ok(results.every(r => Object.keys(r).sort().join() === 'attackId,expected,observed'));
});

test('10단계 점검: 서버가 어떻게 답하든 복구 점검은 요청하지 않으므로 같은 미실행으로 남는다', async () => {
  for (const mode of [200, 'text', 'throw']) {
    const { results, sent } = await run(mode);
    assert.match(observed(results, 'anonymous_restore_refused'), /^not_run$/u, String(mode));
    assert.equal(sent.filter(s => s.pathname === '/api/restore').length, 0, String(mode));
  }
});

// ---- 판정기: 계약의 요청 이름만 읽고, 모든 가상 요청에 다섯 항목 응답을 돌려준다 ----
// 계약의 요청 이름은 문서(docs/DECIDER_REQUEST.md)의 표 첫 칸에서 직접 읽습니다. 문서가 바뀌면 이 시험이 바로 알려 줍니다.
const CONTRACT = read('docs/DECIDER_REQUEST.md').split('## 응답')[0].split('\n').filter(line => /^\| `/u.test(line))
  .flatMap(line => [...line.split('|')[1].matchAll(/`([A-Za-z][A-Za-z0-9]*)`/gu)].map(m => m[1]));
const DEVICE = 'a1b2c3d4e5f60718';
const base = (over = {}) => ({
  schema: 'aleph.decision.v1', requestId: randomUUID(), classId: 'class', projectId: 'project', subjectId: 'subject1', deviceId: DEVICE,
  service: 'notes', method: 'GET', path: '/notes/44444444-4444-4444-8444-444444444444', route: 'GET /notes/:id', queryLength: 0, querySha256: 'e'.repeat(64),
  at: new Date().toISOString(), policyRevision: 'rev1', deviceRegistered: true, stepUp: { verified: false, authAgeSeconds: null },
  recentEvents: [], signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 12 }, ...over });

test('계약 이름은 문서에서 18개를 읽고, 판정기 소스는 그 이름만 요청에서 읽는다(identity·device·geo·role 등은 읽지 않음)', () => {
  const code = read('src/decider.mjs').replace(/\/\/.*$/gmu, '');
  const dotted = [...code.matchAll(/\brequest\??\.([A-Za-z_]\w*)/gu)].map(m => m[1]);
  const destructured = [...code.matchAll(/const \{([^}]*)\} = request\b/gu)].flatMap(m => m[1].split(',').map(n => n.trim().split(':')[0].trim()).filter(Boolean));
  const readNames = new Set([...dotted, ...destructured]);
  assert.equal(CONTRACT.length, 18);
  assert.ok(['querySha256', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals'].every(name => CONTRACT.includes(name)));
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

// 시드를 고정한 무작위입니다: 실행할 때마다 같은 요청이 나와서, 통과·실패가 확률에 흔들리지 않습니다.
function seeded(seed) {
  let a = seed >>> 0;
  return () => { a = (a + 0x6D2B79F5) >>> 0; let t = a; t = Math.imul(t ^ (t >>> 15), t | 1); t ^= t + Math.imul(t ^ (t >>> 7), t | 61); return ((t ^ (t >>> 14)) >>> 0) / 4294967296; };
}

test('step_up까지 포함한 고정 시드 무작위 요청 3000건에서도 응답 형식이 맞고 allow·deny·step_up이 모두 나온다', async () => {
  const random = seeded(10);
  const pick = list => list[Math.floor(random() * list.length)];
  const NOTE = '/notes/44444444-4444-4444-8444-444444444444';
  const seen = { allow: 0, deny: 0, step_up: 0 };
  for (let i = 0; i < 3000; i++) {
    const request = base({
      deviceRegistered: pick([true, true, true, true, true, false]),
      signals: pick([{ source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: pick([0, 3, 5, 6, 14]) },
        { source: 'judge_fixture', region: 'foreign', network: 'unusual', hour: 3 }, { source: 'judge_fixture', region: 'local', network: 'usual', hour: 14 },
        { source: 'none', region: 'unknown', network: 'unknown', hour: 3 }, null, 'x']),
      recentEvents: pick([[{ kind: 'risk_signal', ageSeconds: 60, count: pick([1, 19, 20, 50]) }], [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }],
        [], [{ kind: 'login', ageSeconds: 1, count: 99 }], 'x']),
      stepUp: pick([{ verified: false, authAgeSeconds: null }, { verified: false, authAgeSeconds: null }, { verified: true, authAgeSeconds: pick([0, 60, 900, 901, -1]) }, null]),
      path: pick([NOTE, NOTE, NOTE, NOTE, '/notes', '/restore', '/notices/week-1']),
    });
    if (request.path === '/notes') request.route = 'GET /notes';
    if (request.path === '/restore') Object.assign(request, { method: 'POST', route: 'POST /restore' });
    if (request.path === '/notices/week-1') Object.assign(request, { method: 'PUT', route: 'PUT /notices/:id' });
    const response = await decide(request);
    assert.deepEqual(Object.keys(response).sort(), ['decision', 'reasonCode', 'requestId', 'ruleIds', 'schema']);
    assert.ok(response.ruleIds.length >= 1 && response.ruleIds.every(id => RULE_IDS.includes(id)));
    assert.equal(response.requestId, request.requestId);
    seen[response.decision] += 1;
  }
  assert.ok(seen.allow > 0 && seen.deny > 0 && seen.step_up > 0, JSON.stringify(seen));
  console.log('   결정 분포(고정 시드 10):', JSON.stringify(seen));
});
