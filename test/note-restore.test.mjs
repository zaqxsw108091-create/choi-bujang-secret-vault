import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createNotesApi } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { noteContentHash, readRestoreId } from '../src/note-restore.mjs';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const config = JSON.parse(read('aleph.config.json'));
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const B_NOTE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1';
const B_OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2';
const A_NOTE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';

const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const bearer = sub => `Bearer ${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({
  iss: config.identityProvider.issuer, aud: config.identityProvider.audience, role: 'authenticated', sub, exp: Math.floor(Date.now() / 1000) + 600,
})}.c2ln`;

// 표 여러 개를 흉내 내는 가짜 DB입니다. fail: 표·동작별 오류 주입, dropUpdates: 수정이 반영되지 않는 DB.
class Query {
  constructor(db, table) { this.db = db; this.table = table; this.rows = db.tables[table]; this.op = 'select'; this.filters = []; }
  select() { return this; }
  insert(p) { this.op = 'insert'; this.payload = p; return this; }
  update(p) { this.op = 'update'; this.payload = p; return this; }
  eq(c, v) { this.filters.push([c, v]); return this; }
  maybeSingle() { this.one = true; return this; }
  then(res, rej) { return Promise.resolve(this.run()).then(res, rej); }
  run() {
    this.db.log.push(`${this.op} ${this.table}`);
    if (this.db.fail?.[`${this.table}:${this.op}`]) return { data: null, error: { code: 'XX000' } };
    const hit = () => this.rows.filter(r => this.filters.every(([c, v]) => r[c] === v));
    let data;
    if (this.op === 'insert') {
      if (this.payload.id && this.table === 'notes' && this.rows.some(r => r.id === this.payload.id)) return { data: null, error: { code: '23505' } };
      this.rows.push({ ...this.payload }); data = [this.payload];
    } else if (this.op === 'update') { data = hit(); if (!this.db.dropUpdates) data.forEach(r => Object.assign(r, this.payload)); }
    else data = hit();
    return { data: this.one ? data[0] ?? null : data, error: null };
  }
}

const noteRow = (id, owner, title, content, position) => ({ id, owner_id: owner, title, content, position });
function world(overrides = {}) {
  const b = noteRow(B_NOTE, B, 'B의 가상 메모', 'B 본문 가상', 4);
  const tables = {
    notes: [noteRow(A_NOTE, A, 'A 가상 메모', 'A 본문 가상', 1), { ...b }, noteRow(B_OTHER, B, 'B의 다른 메모', '다른 본문', 5)],
    notes_backup: [{ note_id: B_NOTE, owner_id: B, position: 4, title: b.title, content: b.content, content_sha256: noteContentHash(b.title, b.content) }],
    notes_restore_audit: [{ id: 1, event: 'older_entry', note_id: B_NOTE, actor_id: B }],
  };
  return { tables, log: [], ...overrides };
}

function apiFor(db) {
  const verify = createLoginVerifier({ config, supabaseClient: { auth: { getClaims: async token => ({ data: { claims: JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) }, error: null }) } } });
  const api = createNotesApi({ getVerifier: () => verify, getSupabase: () => ({ from: table => new Query(db, table) }) });
  return async ({ method = 'POST', authorization, body } = {}) => {
    const out = { headers: {} };
    const response = { setHeader: (n, v) => { out.headers[n] = v; }, status: c => { out.status = c; return response; }, json: p => { out.body = p; return response; } };
    await api.restore({ method, headers: authorization ? { authorization } : {}, body, url: '/api/restore' }, response);
    return out;
  };
}
const snapshot = db => JSON.stringify(db.tables);
const only = (db, ids) => db.tables.notes.filter(r => ids.includes(r.id));

test('B가 변조한 자기 메모 한 건이 사본으로 되돌아오고 ID·소유자·내용 해시가 사본과 같다', async () => {
  const db = world();
  const backup = db.tables.notes_backup[0];
  Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { title: '변조됨', content: '변조 본문' });
  const others = JSON.stringify(only(db, [A_NOTE, B_OTHER]));
  const result = await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
  assert.equal(result.status, 200);
  const { policy, audit, auditRecorded, ...rest } = result.body;
  assert.deepEqual([audit.recorded, audit.priorEntries, audit.entries, audit.preserved, auditRecorded], [true, 1, 3, true, true], '이전 기록 1줄은 그대로, 요청·결과 2줄이 덧붙음');
  assert.deepEqual(audit.events, ['older_entry', 'requested', 'updated']);
  assert.equal(policy.verified, true, '정책 사본 검증 결과가 함께 옴');
  assert.deepEqual(rest, { id: B_NOTE, restored: true, action: 'updated', contentSha256: backup.content_sha256,
    restoreVersion: backup.content_sha256.slice(0, 12), changes: ['title', 'content'], backupVerified: true, verified: true });
  const live = db.tables.notes.find(r => r.id === B_NOTE);
  assert.equal(live.id, backup.note_id);
  assert.equal(live.owner_id, backup.owner_id);
  assert.equal(noteContentHash(live.title, live.content), backup.content_sha256);
  assert.equal(live.position, 4);
  assert.equal(JSON.stringify(only(db, [A_NOTE, B_OTHER])), others, '다른 메모는 그대로');
  assert.equal(db.tables.notes.length, 3);
});

test('B가 지운 메모는 같은 ID·소유자·내용으로 다시 만들어지고 표시 순서도 돌아온다', async () => {
  const db = world();
  db.tables.notes = db.tables.notes.filter(r => r.id !== B_NOTE);
  const result = await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
  assert.deepEqual([result.status, result.body.action, result.body.restored], [200, 'inserted', true]);
  const live = db.tables.notes.find(r => r.id === B_NOTE);
  assert.deepEqual([live.owner_id, live.title, live.content, live.position], [B, 'B의 가상 메모', 'B 본문 가상', 4]);
  assert.equal(noteContentHash(live.title, live.content), db.tables.notes_backup[0].content_sha256);
  assert.equal(db.tables.notes.length, 3);
});

test('이미 같으면 아무것도 쓰지 않고 unchanged로 답한다', async () => {
  const db = world();
  const result = await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
  assert.deepEqual([result.status, result.body.action, result.body.restored], [200, 'unchanged', false]);
  assert.ok(!db.log.some(l => l === 'update notes' || l === 'insert notes'));
});

test('감사 기록은 앞 기록을 그대로 두고 두 줄(요청·결과)만 덧붙는다. 수정·삭제는 하지 않는다', async () => {
  const db = world();
  Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { content: '변조' });
  const older = JSON.stringify(db.tables.notes_restore_audit[0]);
  await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
  const audit = db.tables.notes_restore_audit;
  assert.equal(JSON.stringify(audit[0]), older, '앞 기록은 그대로');
  assert.deepEqual(audit.slice(1).map(r => r.event), ['requested', 'updated']);
  assert.ok(audit.slice(1).every(r => r.note_id === B_NOTE && r.actor_id === B && /^[a-f0-9]{64}$/u.test(r.content_sha256)));
  assert.ok(!db.log.some(l => /^(update|delete) notes_restore_audit|^(update|delete) notes_backup/u.test(l)));
  assert.ok(!JSON.stringify(audit).match(/변조|본문|title|content"/u));
});

test('요청에 사본과 다른 title·content·owner_id가 실려 오면 멈추고, 복원은 항상 서버 사본에서만 한다', async () => {
  const db = world();
  Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { content: '변조' });
  const send = body => apiFor(db)({ authorization: bearer(B), body: JSON.stringify(body) });
  const injected = await send({ id: B_NOTE, title: '주입', content: '주입 본문' });
  assert.deepEqual([injected.status, injected.body], [409, { error: 'BACKUP_INVALID' }]);
  const wrongOwner = await send({ id: B_NOTE, owner_id: A, userId: A, role: 'admin' });
  assert.equal(wrongOwner.status, 409);
  assert.equal(db.tables.notes.find(r => r.id === B_NOTE).content, '변조', '아무것도 바뀌지 않음');
  const ok = await send({ id: B_NOTE, userId: A, role: 'admin' });
  assert.equal(ok.status, 200);
  const live = db.tables.notes.find(r => r.id === B_NOTE);
  assert.deepEqual([live.owner_id, live.title, live.content], [B, 'B의 가상 메모', 'B 본문 가상']);
});

test('거부: 로그인 없음 401, 잘못된 방법 405, 잘못된 id·본문 400, 사본 없음 404 — 아무것도 바뀌지 않는다', async () => {
  const db = world();
  const api = apiFor(db);
  const before = snapshot(db);
  assert.equal((await api({ body: { id: B_NOTE } })).status, 401);
  assert.equal((await api({ authorization: 'Bearer a.b.c', body: { id: B_NOTE } })).status, 401);
  assert.equal((await api({ method: 'GET', authorization: bearer(B) })).status, 405);
  for (const body of [undefined, 'x', {}, { id: 'abc' }, { id: 7 }, [B_NOTE]]) assert.equal((await api({ authorization: bearer(B), body })).status, 400);
  const none = await api({ authorization: bearer(B), body: { id: 'cccccccc-cccc-4ccc-8ccc-ccccccccccc1' } });
  assert.deepEqual([none.status, none.body], [404, { error: 'BACKUP_NOT_FOUND' }]);
  assert.equal(snapshot(db), before);
});

test('A가 B의 사본으로 복구를 요청하면 403이고 아무 표도 바뀌지 않는다', async () => {
  const db = world();
  Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { content: '변조' });
  const before = snapshot(db);
  const result = await apiFor(db)({ authorization: bearer(A), body: { id: B_NOTE } });
  assert.deepEqual([result.status, result.body], [403, { error: 'FORBIDDEN' }]);
  assert.equal(snapshot(db), before, '메모도 감사 기록도 그대로');
});

test('사본의 내용·소유자·해시가 서로 맞지 않으면 409로 중단하고 메모를 바꾸지 않는다', async () => {
  for (const tamper of [b => { b.content = '사본 변조'; }, b => { b.title = '사본 제목 변조'; }, b => { b.content_sha256 = 'f'.repeat(64); }, b => { b.content_sha256 = 'zz'; }]) {
    const db = world();
    tamper(db.tables.notes_backup[0]);
    Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { content: '변조' });
    const before = snapshot(db);
    const result = await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
    assert.deepEqual([result.status, result.body], [409, { error: 'BACKUP_INVALID' }]);
    assert.equal(snapshot(db), before);
  }
});

test('현재 행의 소유자가 바뀌어 있으면 덮어쓰지 않고 409, 거부 사실만 감사 기록에 덧붙인다', async () => {
  const db = world();
  db.tables.notes.find(r => r.id === B_NOTE).owner_id = A;
  const notesBefore = JSON.stringify(db.tables.notes);
  const result = await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
  assert.deepEqual([result.status, result.body], [409, { error: 'OWNER_CONFLICT' }]);
  assert.equal(JSON.stringify(db.tables.notes), notesBefore);
  assert.deepEqual(db.tables.notes_restore_audit.slice(1).map(r => r.event), ['requested', 'refused_owner_conflict']);
});

test('앞 감사 기록을 쓰지 못하면 메모를 바꾸지 않는다(503)', async () => {
  const db = world({ fail: { 'notes_restore_audit:insert': true } });
  Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { content: '변조' });
  const notesBefore = JSON.stringify(db.tables.notes);
  const result = await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
  assert.deepEqual([result.status, result.body], [503, { error: 'AUDIT_UNAVAILABLE' }]);
  assert.equal(JSON.stringify(db.tables.notes), notesBefore);
});

test('되살린 뒤 다시 읽어 사본과 다르면 성공이라고 하지 않고 verify_failed를 남긴다', async () => {
  const db = world({ dropUpdates: true });
  Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { content: '변조' });
  const result = await apiFor(db)({ authorization: bearer(B), body: { id: B_NOTE } });
  assert.deepEqual([result.status, result.body], [500, { error: 'RESTORE_VERIFY_FAILED' }]);
  assert.equal(db.tables.notes_restore_audit.at(-1).event, 'verify_failed');
});

test('응답과 로그에 메모 제목·본문·토큰·사용자 ID가 없다', async () => {
  const lines = [];
  const original = { warn: console.warn, error: console.error };
  console.warn = (...a) => lines.push(a.join(' ')); console.error = (...a) => lines.push(a.join(' '));
  try {
    const db = world();
    Object.assign(db.tables.notes.find(r => r.id === B_NOTE), { content: '변조' });
    const api = apiFor(db);
    const responses = [await api({ authorization: bearer(A), body: { id: B_NOTE } }), await api({ authorization: bearer(B), body: { id: B_NOTE } })];
    const text = JSON.stringify(responses) + lines.join('\n');
    assert.ok(lines.length > 0);
    assert.ok(!text.match(/가상|본문|변조|Bearer|ES256/u));
    assert.ok(!text.includes(A) && !text.includes(B));
  } finally { Object.assign(console, original); }
});

test('경로·SQL·해시 정의: restoreRoute, api 파일, 본문 없는 SQL, 코드와 같은 해시', () => {
  assert.equal(config.restoreRoute, 'POST /api/restore');
  assert.ok(!config.allowedRoutes.includes('POST /api/restore'), '정책 사본 범위인 allowedRoutes는 바꾸지 않았다');
  assert.match(read('api/restore.js'), /notesApi\.restore/u);
  const sql = read('sql/10-notes-backup.sql');
  assert.ok(sql.includes(noteContentHash('abc', '한글')), 'SQL의 확인 해시가 코드의 해시와 같다');
  assert.match(sql, /revoke all on table public\.notes_backup, public\.notes_restore_audit from public, anon, authenticated/u);
  assert.match(sql, /revoke update, delete, truncate on table public\.notes_restore_audit from service_role/u);
  assert.match(sql, /<<B_EMAIL>>/u);
  assert.ok(!sql.match(/@[a-z0-9-]+\.[a-z]{2,}/iu), '실제 이메일 없음');
  assert.equal(readRestoreId({ id: B_NOTE.toUpperCase() }), B_NOTE);
});
