import './helpers/server-id.mjs';
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runAttackChecks } from '../src/attack-check.mjs';
import { findSecrets } from '../scripts/secret-scan.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const OWNER = 'ownerhead.ownerbody.ownersig';
const OTHER = 'otherhead.otherbody.othersig';
const ANON = 'sb_publishable_TESTKEY123456';
const NOTE = 'dddddddd-dddd-4ddd-8ddd-ddddddddddd1';
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

// 가짜 배포. mode: 'refuse'(403) | 'open'(200) | 'same'(A도 같은 메모를 가진 같은 계정) | 'empty'(B에게 메모가 없음)
function fakeDeployment(sent, mode = 'refuse', needDevice = false) {
  return async (url, init = {}) => {
    const u = new URL(String(url));
    const auth = init.headers?.Authorization ?? null;
    sent.push({ host: u.host, method: init.method ?? 'GET', path: u.pathname, auth, apikey: init.headers?.apikey ?? null, body: init.body ?? null });
    if (u.host.endsWith('.supabase.co')) return json({ code: '42501', message: 'permission denied for table notes' }, 401);
    if (u.pathname === '/data.json') return new Response('Not found', { status: 404 });
    if (u.pathname === '/aleph.json') return json({ step: 10 });
    if (u.pathname === '/') return new Response('<html>화면</html>');
    if (u.pathname === '/api/login') return json({ error: 'LOGIN_FAILED' }, 401);
    if (!auth) return json({ error: 'LOGIN_REQUIRED' }, 401);
    if (needDevice && !init.headers?.['X-Device-Key'] && (u.pathname.startsWith('/api/notes') || u.pathname === '/api/restore')) return json({ error: 'DEVICE_REQUIRED' }, 403);
    if (u.pathname === '/api/notes' && (init.method ?? 'GET') === 'GET') {
      if (auth === `Bearer ${OWNER}`) return json(mode === 'empty' ? [] : [{ id: NOTE, title: '가상 제목', body: '가상 본문' }]);
      return json(mode === 'same' ? [{ id: NOTE, title: '가상 제목', body: '가상 본문' }] : []);
    }
    return mode === 'open' ? json({ id: NOTE }) : json({ error: 'FORBIDDEN' }, 403);
  };
}

async function run({ env = {}, mode = 'refuse', step = 10, needDevice = false } = {}) {
  const sent = [];
  const real = globalThis.fetch;
  const saved = {};
  for (const name of ['ATTACK_TOKEN_OWNER', 'ATTACK_TOKEN_OTHER', 'ATTACK_ANON_KEY']) { saved[name] = process.env[name]; delete process.env[name]; }
  Object.assign(process.env, env);
  globalThis.fetch = fakeDeployment(sent, mode, needDevice);
  try { return { results: await runAttackChecks({ ...config, step }), sent }; } finally {
    globalThis.fetch = real;
    for (const [name, value] of Object.entries(saved)) { if (value === undefined) delete process.env[name]; else process.env[name] = value; }
  }
}
const observed = (results, id) => results.find(r => r.attackId === id)?.observed;
const CROSS = ['other_owner_read_refused', 'other_owner_update_refused', 'other_owner_delete_refused', 'other_owner_restore_refused'];
const READ = 'other_owner_read_refused';
const WRITES = ['other_owner_update_refused', 'other_owner_delete_refused', 'other_owner_restore_refused'];
const isUnrun = (results, ids) => ids.every(id => /^not_run$/u.test(observed(results, id) ?? ''));
const BOTH = { ATTACK_TOKEN_OWNER: OWNER, ATTACK_TOKEN_OTHER: OTHER, ATTACK_ANON_KEY: ANON };

test('환경변수가 없으면 5개 모두 이전과 같은 미실행이고, 로그인 값은 보내지 않는다', async () => {
  const { results, sent } = await run();
  for (const id of [...CROSS, 'anon_data_api_notes_refused']) assert.match(observed(results, id), /^not_run$/u, id);
  assert.equal(results.length, 19);
  assert.ok(sent.every(s => s.auth !== `Bearer ${OWNER}` && s.auth !== `Bearer ${OTHER}` && s.apikey === null));
  assert.ok(!sent.some(s => s.path.includes(NOTE)));
});

test('토큰·키를 넣으면 읽기(GET) 2개만 보내 거부됨으로 적고, 쓰기가 필요한 3개는 미실행으로 남긴다', async () => {
  const { results } = await run({ env: BOTH });
  assert.equal(observed(results, READ), '거부됨 (HTTP 403)');
  assert.ok(isUnrun(results, WRITES));
  assert.equal(observed(results, 'anon_data_api_notes_refused'), '거부됨 (HTTP 401, 권한 없음 42501)');
  assert.equal(results.length, 19);
  assert.ok(results.every(r => Object.keys(r).sort().join() === 'attackId,expected,observed' && r.observed.length <= 300));
});

test('보낸 요청: 모두 GET이고, 주인 토큰은 목록 읽기에만, 다른 계정 토큰은 목록과 남의 메모 읽기에만 쓴다', async () => {
  const { sent } = await run({ env: BOTH });
  const ownerUses = sent.filter(s => s.auth === `Bearer ${OWNER}`);
  assert.deepEqual(ownerUses.map(s => `${s.method} ${s.path}`), ['GET /api/notes']);
  const otherUses = sent.filter(s => s.auth === `Bearer ${OTHER}`).map(s => `${s.method} ${s.path}`);
  assert.deepEqual(otherUses, ['GET /api/notes', `GET /api/notes/${NOTE}`]);
  assert.deepEqual(sent.filter(s => s.method !== 'GET'), [], '쓰기 요청은 보내지 않음');
  assert.equal(sent.find(s => s.host.endsWith('.supabase.co')).apikey, ANON);
});

test('결과 어디에도 토큰·키·메모 id·제목·본문이 없다', async () => {
  const { results } = await run({ env: BOTH });
  const text = JSON.stringify(results);
  for (const secret of [OWNER, OTHER, ANON, 'ownerbody', 'otherbody', NOTE, '가상 제목', '가상 본문']) assert.ok(!text.includes(secret), secret);
});

test('거부되지 않으면(200) 그대로 적는다', async () => {
  const { results } = await run({ env: BOTH, mode: 'open' });
  assert.equal(observed(results, READ), '거부되지 않음 (HTTP 200)');
  assert.ok(isUnrun(results, WRITES));
});

test('두 토큰이 같은 계정이면 남의 메모 읽기를 보내지 않고 확인하지 못함으로 적는다', async () => {
  const { results, sent } = await run({ env: BOTH, mode: 'same' });
  assert.match(observed(results, READ), /^확인하지 못함 \(두 토큰이 같은 계정/u);
  assert.ok(isUnrun(results, WRITES));
  assert.ok(!sent.some(s => s.path.includes(NOTE) || (s.path === '/api/restore' && s.auth === `Bearer ${OTHER}`)));
});

test('B에게 메모가 없으면 보내지 않고 확인하지 못함으로 적는다', async () => {
  const { results, sent } = await run({ env: BOTH, mode: 'empty' });
  assert.match(observed(results, READ), /^확인하지 못함 \(B 계정의 메모 목록을 읽지 못함/u);
  assert.ok(isUnrun(results, WRITES));
  assert.ok(!sent.some(s => s.path.includes(NOTE) || (s.path === '/api/restore' && s.auth === `Bearer ${OTHER}`)));
});

test('모양이 틀린 토큰·키, 하나만 있는 경우는 미실행으로 남는다', async () => {
  for (const env of [{ ATTACK_TOKEN_OWNER: OWNER }, { ATTACK_TOKEN_OTHER: OTHER }, { ATTACK_TOKEN_OWNER: 'abc', ATTACK_TOKEN_OTHER: OTHER }]) {
    const { results, sent } = await run({ env });
    for (const id of CROSS) assert.match(observed(results, id), /^not_run$/u);
    assert.ok(!sent.some(s => s.path.includes(NOTE)));
  }
  const bad = await run({ env: { ATTACK_ANON_KEY: 'not a key' } });
  assert.match(observed(bad.results, 'anon_data_api_notes_refused'), /^not_run$/u);
});

test('9단계 설정에서는 복구 점검이 없다', async () => {
  const { results } = await run({ env: BOTH, step: 9 });
  assert.equal(observed(results, 'other_owner_restore_refused'), undefined);
  assert.match(observed(results, 'other_owner_update_refused'), /^not_run$/u);
});

test('점검 코드와 이 시험 파일에 키·토큰 모양의 실제 값이 없다(프로젝트 비밀값 검사기 기준)', () => {
  const files = ['../src/attack-check.mjs', './attack-check-live.test.mjs']
    .map(path => [path, readFileSync(new URL(path, import.meta.url), 'utf8')]);
  assert.deepEqual(findSecrets(files), []);
});

test('11단계 이후: 기기 서명이 없으면 확인하지 못함(원인 안내), 승인된 기기의 서명을 걸면 거부됨으로 적는다', async () => {
  const without = await run({ env: BOTH, step: 12, needDevice: true });
  assert.match(observed(without.results, READ), /^확인하지 못함 \(B 계정의 메모 목록을 읽지 못함: HTTP 403, 11단계부터는 승인된 기기의 서명이 필요함\)$/u);
  const key = Symbol.for('aleph.attack.devices');
  globalThis[key] = { OWNER: { proof: async () => ({ 'X-Device-Key': 'owner-device' }) }, OTHER: { proof: async () => ({ 'X-Device-Key': 'other-device' }) } };
  try {
    const withDevice = await run({ env: BOTH, step: 12, needDevice: true });
    assert.equal(observed(withDevice.results, READ), '거부됨 (HTTP 403)');
    assert.ok(isUnrun(withDevice.results, WRITES));
  } finally { delete globalThis[key]; }
});
