import test from 'node:test';
import assert from 'node:assert/strict';
import { buildOpsSummary } from '../src/ops-summary.mjs';
import { RULE_IDS } from '../src/decider.mjs';
import { createNotesApi } from '../src/notes-api.mjs';

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const SECRET = 'SECRET_BODY_TEXT';
const SHA = 'a'.repeat(64);
const NOW = 1_800_000_000_000;

// select·eq·gt·limit만 받는 가짜 표 읽기. fail에 표 이름을 넣으면 그 표만 오류를 돌려줍니다.
function fakeSupabase(tables, fail = []) {
  return { from: (name) => {
    const q = { filters: [] };
    q.select = () => q;
    q.eq = (c, v) => { q.filters.push(r => r[c] === v); return q; };
    q.gt = (c, v) => { q.filters.push(r => r[c] > v); return q; };
    q.limit = () => q;
    q.then = (res, rej) => Promise.resolve(fail.includes(name) ? { data: null, error: { code: 'XX000' } }
      : { data: (tables[name] ?? []).filter(r => q.filters.every(f => f(r))), error: null }).then(res, rej);
    return q;
  } };
}
const tables = () => ({
  xdr_block_rules: [{ rule_id: 'r', srcip: '203.0.113.9', expires_at: new Date(NOW + 60_000).toISOString() }, { rule_id: 'r', srcip: '203.0.113.8', expires_at: new Date(NOW - 60_000).toISOString() }],
  devices: [{ key_id: 'k1', owner_id: A, status: 'approved' }, { key_id: 'k2', owner_id: A, status: 'pending' }, { key_id: 'k3', owner_id: A, status: 'revoked' }, { key_id: 'k4', owner_id: B, status: 'approved' }],
  notes_backup: [{ note_id: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', owner_id: A, content_sha256: SHA, title: SECRET, content: SECRET }, { note_id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1', owner_id: B, content_sha256: SHA }],
  notes_restore_audit: [{ actor_id: A, event: 'requested' }, { actor_id: A, event: 'updated' }, { actor_id: B, event: 'requested' }],
});

test('본인 기록만 세고, 확인됨과 미실행을 나눠 담는다', async () => {
  const { body, logLine } = await buildOpsSummary({ supabase: fakeSupabase(tables()), userId: A, now: () => NOW });
  assert.equal(body.decider.ruleCount, RULE_IDS.length);
  assert.deepEqual(body.decider.ruleIds, [...RULE_IDS]);
  assert.equal(body.decider.engineDecisions.state, 'not_run');
  assert.equal(body.detection.engineEvents.state, 'not_run');
  assert.equal(body.revocation.engineRevocation.state, 'not_run');
  assert.deepEqual(body.detection.activeBlockRules, { state: 'verified', count: 1 });
  assert.deepEqual(body.revocation.devices, { state: 'verified', approved: 1, pending: 1, revoked: 1 });
  assert.equal(body.restore.backups.count, 1);
  assert.deepEqual(body.restore.backups.versions, [{ note: 'aaaaaaaa', version: 'a'.repeat(12) }]);
  assert.equal(body.restore.audit.count, 2);
  assert.equal(body.restore.audit.byEvent.updated, 1);
  assert.equal(body.logLine, logLine);
  assert.equal(logLine, `ops 요약: rules=${RULE_IDS.length} blockRules=1 devices=approved:1,pending:1,revoked:1 backups=1 audit=2`);
});

test('응답과 로그 줄에 메모 본문·접속 주소·사용자 ID·기기 키가 없다', async () => {
  const { body } = await buildOpsSummary({ supabase: fakeSupabase(tables()), userId: A, now: () => NOW });
  const text = JSON.stringify(body);
  for (const secret of [SECRET, '203.0.113', A, B, 'k1', 'content_sha256']) assert.equal(text.includes(secret), false, secret);
});

test('표를 읽지 못하면 그 항목만 unread이고 숫자를 지어내지 않는다', async () => {
  const { body, logLine } = await buildOpsSummary({ supabase: fakeSupabase(tables(), ['devices', 'notes_backup']), userId: A, now: () => NOW });
  assert.deepEqual(body.revocation.devices, { state: 'unread' });
  assert.deepEqual(body.restore.backups, { state: 'unread' });
  assert.equal(body.restore.audit.state, 'verified');
  assert.match(logLine, /devices=unread backups=unread audit=2/u);
});

test('GET /api/ops: 로그인 없으면 401, 로그인하면 200과 로그 한 줄이 같다', async () => {
  const lines = [];
  const original = console.info; console.info = (line) => lines.push(line);
  try {
    const api = createNotesApi({ getVerifier: () => async (h) => (h === 'Bearer ok' ? { userId: A } : null), getSupabase: () => fakeSupabase(tables()), now: () => NOW });
    const reply = () => { const r = { headers: {}, setHeader(k, v) { r.headers[k] = v; }, status(c) { r.code = c; return r; }, json(b) { r.body = b; return r; } }; return r; };
    const denied = reply();
    await api.ops({ method: 'GET', url: '/api/ops', headers: {} }, denied);
    assert.equal(denied.code, 401);
    const wrong = reply();
    await api.ops({ method: 'POST', url: '/api/ops', headers: { authorization: 'Bearer ok' } }, wrong);
    assert.equal(wrong.code, 405);
    const ok = reply();
    await api.ops({ method: 'GET', url: '/api/ops', headers: { authorization: 'Bearer ok' } }, ok);
    assert.equal(ok.code, 200);
    assert.equal(ok.body.logLine, lines.at(-1));
  } finally { console.info = original; }
});
