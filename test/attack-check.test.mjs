import './helpers/server-id.mjs';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = JSON.parse(await readFile(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const json = (body, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });

// 배포 주소 대신 가짜 응답을 돌려주는 fetch 입니다. throwOn 에 든 경로는 접속 실패(오류)로 만듭니다.
const fakeFetch = ({ throwOn = [], marker = false } = {}) => async (url, init = {}) => {
  const { pathname } = new URL(String(url));
  if (throwOn.includes('ALL') || throwOn.includes(pathname)) throw new TypeError('fetch failed');
  if (pathname === '/data.json') return new Response('Not found', { status: 404 });
  if (pathname === '/aleph.json') return json(marker ? { sampleMarker: config.sampleMarker } : { step: config.step });
  if (pathname === '/') return new Response('<html>화면</html>');
  if (pathname === '/api/login' && init.method === 'POST') return json({ error: 'LOGIN_FAILED' }, 401);
  return json({ error: 'LOGIN_REQUIRED' }, 401);
};

async function check(options) {
  const real = globalThis.fetch;
  globalThis.fetch = fakeFetch(options);
  try {
    return await runAttackChecks(config);
  } finally {
    globalThis.fetch = real;
  }
}
const observed = (results, id) => results.find((r) => r.attackId === id)?.observed;

test('접속이 되면 실제 응답대로 적는다(거부됨·없음)', async () => {
  const results = await check();
  assert.equal(observed(results, 'public_data_json_no_notes'), '비로그인 /data.json이 없음 (HTTP 404)');
  assert.match(observed(results, 'static_marker_absent'), /^확인 표시가 보이지 않음 \(\/data\.json HTTP 404, \/aleph\.json HTTP 200\)$/u);
  assert.equal(observed(results, 'anonymous_notes_list_refused'), '거부됨 (HTTP 401)');
  assert.match(observed(results, 'wrong_password_login_refused'), /^not_run$/u);
  assert.match(observed(await check({ marker: true }), 'static_marker_absent'), /^확인 표시가 보임: \/aleph\.json$/u);
});

test('배포 주소에 접속하지 못하면 오류로 멈추지 않고, 지어내지 않고 확인하지 못함·미실행으로만 적는다', async () => {
  const results = await check({ throwOn: ['ALL'] });
  assert.ok(results.length >= 15);
  for (const r of results) {
    assert.match(r.observed, /^(?:확인하지 못함|not_run)/u, `${r.attackId}: ${r.observed}`);
    assert.doesNotMatch(r.observed, /거부됨|보이지 않음|없음 \(HTTP/u, r.attackId);
  }
});

test('일부 요청만 접속하지 못하면 된 것은 사실대로, 안 된 것만 미실행으로 적는다', async () => {
  const results = await check({ throwOn: ['/aleph.json', '/api/login'] });
  assert.equal(observed(results, 'public_data_json_no_notes'), '비로그인 /data.json이 없음 (HTTP 404)');
  assert.equal(observed(results, 'anonymous_notes_list_refused'), '거부됨 (HTTP 401)');
  assert.equal(observed(results, 'static_marker_absent'), 'not_run');
  assert.match(observed(results, 'wrong_password_login_refused'), /^not_run$/u);
});

test('격리된 제출 환경을 위해 GET 말고는 아무 요청도 보내지 않고, 쓰기가 필요한 점검은 미실행으로 남긴다', async () => {
  const methods = [];
  const real = globalThis.fetch;
  const inner = fakeFetch();
  globalThis.fetch = async (url, init = {}) => { methods.push(init.method ?? 'GET'); return inner(url, init); };
  try {
    const results = await runAttackChecks(config);
    assert.deepEqual([...new Set(methods)], ['GET']);
    for (const id of ['anonymous_note_create_refused', 'anonymous_note_update_refused', 'anonymous_note_delete_refused',
      'wrong_password_login_refused', 'anonymous_restore_refused', 'anonymous_device_approval_refused',
      'other_owner_update_refused', 'other_owner_delete_refused', 'other_owner_restore_refused']) {
      assert.match(observed(results, id), /^not_run$/u, id);
    }
    assert.equal(results.length, 20);
  } finally { globalThis.fetch = real; }
});

const VARIANTS = ['anonymous_note_read_refused', 'forged_token_refused', 'expired_token_refused', 'other_issuer_token_refused',
  'anon_role_query_refused', 'notice_route_serves_nothing'];

test('변형 요청 6개(없는 id 읽기, 가짜·만료·다른 발급자 토큰, role 쿼리, 공지 경로)는 보내지 않고 not_run으로 기록하며 가장 단순한 GET만 실제로 보낸다', async () => {
  const seen = [];
  const real = globalThis.fetch;
  const inner = fakeFetch();
  globalThis.fetch = async (url, init = {}) => { const u = new URL(String(url)); seen.push(`${u.pathname}${u.search}${init.headers?.Authorization ? ' +auth' : ''}`); return inner(url, init); };
  try {
    const results = await runAttackChecks(config);
    for (const id of VARIANTS) assert.equal(observed(results, id), 'not_run', id);
    assert.equal(observed(results, 'public_data_json_no_notes'), '비로그인 /data.json이 없음 (HTTP 404)');
    assert.equal(observed(results, 'anonymous_notes_list_refused'), '거부됨 (HTTP 401)');
    assert.deepEqual([...new Set(seen)].sort(), ['/', '/aleph.json', '/api/notes', '/data.json']);
    assert.equal(seen.some((p) => p.includes('+auth') || p.includes('?') || p.includes('/api/notices')), false);
    assert.match(observed(results, 'other_owner_read_refused'), /^not_run$/u);
  } finally { globalThis.fetch = real; }
});
