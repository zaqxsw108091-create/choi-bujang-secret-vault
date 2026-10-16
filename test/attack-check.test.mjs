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

test('8단계 직접 요청 점검: 로그인 없는 role 쿼리와 공지 경로는 거부로 적고, 접속 실패는 지어내지 않는다', async () => {
  const results = await check();
  assert.equal(observed(results, 'anon_role_query_refused'), '거부됨 (HTTP 401)');
  assert.equal(observed(results, 'notice_route_serves_nothing'), '거부됨 (HTTP 401)');
  assert.match(observed(results, 'other_owner_read_refused'), /^not_run$/u);
  const down = await check({ throwOn: ['ALL'] });
  assert.match(observed(down, 'anon_role_query_refused'), /^not_run$/u);
  assert.match(observed(down, 'notice_route_serves_nothing'), /^not_run$/u);
});

test('8단계 직접 요청 점검: 플랫폼의 JSON 형식 404(오류 객체)는 자료가 아니라 거부로 적고, 2xx 자료는 거부되지 않음으로 적는다', async () => {
  const real = globalThis.fetch;
  const run = async (notices) => {
    globalThis.fetch = async (url, init = {}) => {
      const { pathname } = new URL(String(url));
      if (pathname === '/api/notices') return notices();
      return fakeFetch()(url, init);
    };
    try { return await runAttackChecks(config); } finally { globalThis.fetch = real; }
  };
  const platform404 = await run(() => json({ error: { code: 'NOT_FOUND', message: 'The page could not be found' } }, 404));
  assert.equal(observed(platform404, 'notice_route_serves_nothing'), '거부됨 (HTTP 404)');
  const leaked = await run(() => json([{ title: '공지' }], 200));
  assert.match(observed(leaked, 'notice_route_serves_nothing'), /^거부되지 않음/u);
});

test('배포된 서버의 x-vercel-id가 없는 응답(가짜 응답)은 실제 요청의 결과로 보지 않고 20개 모두 not_run으로 적는다', async () => {
  const real = globalThis.fetch;
  const raw = async () => new Response(JSON.stringify({ error: 'LOGIN_REQUIRED' }), { status: 401, headers: { 'content-type': 'application/json' } });
  raw.__raw = true;
  globalThis.fetch = raw;
  try {
    const results = await runAttackChecks(config);
    assert.equal(results.length, 20);
    for (const r of results) assert.equal(r.observed, 'not_run', r.attackId);
  } finally { globalThis.fetch = real; }
});
