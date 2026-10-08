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
  assert.equal(observed(results, 'wrong_password_login_refused'), '거부됨 (HTTP 401)');
  assert.match(observed(await check({ marker: true }), 'static_marker_absent'), /^확인 표시가 보임: \/aleph\.json$/u);
});

test('배포 주소에 접속하지 못하면 오류로 멈추지 않고, 지어내지 않고 확인하지 못함·미실행으로만 적는다', async () => {
  const results = await check({ throwOn: ['ALL'] });
  assert.ok(results.length >= 15);
  for (const r of results) {
    assert.match(r.observed, /^(?:확인하지 못함|미실행)/u, `${r.attackId}: ${r.observed}`);
    assert.doesNotMatch(r.observed, /거부됨|보이지 않음|없음 \(HTTP/u, r.attackId);
  }
});

test('일부 요청만 접속하지 못하면 된 것은 사실대로, 안 된 것만 확인하지 못함으로 적는다', async () => {
  const results = await check({ throwOn: ['/aleph.json', '/api/login'] });
  assert.equal(observed(results, 'public_data_json_no_notes'), '비로그인 /data.json이 없음 (HTTP 404)');
  assert.equal(observed(results, 'anonymous_notes_list_refused'), '거부됨 (HTTP 401)');
  assert.equal(observed(results, 'static_marker_absent'), '확인하지 못함 (요청을 보내지 못함)');
  assert.equal(observed(results, 'wrong_password_login_refused'), '확인하지 못함 (요청을 보내지 못함)');
});
