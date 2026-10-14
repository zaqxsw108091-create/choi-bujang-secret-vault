import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { createNotesApi } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { noteContentHash } from '../src/note-restore.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const B = '22222222-2222-4222-8222-222222222222';
const A = '11111111-1111-4111-8111-111111111111';
const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const bearer = sub => `Bearer ${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({ iss: config.identityProvider.issuer, aud: config.identityProvider.audience, role: 'authenticated', sub, exp: Math.floor(Date.now() / 1000) + 600 })}.c2ln`;

// 표 여러 개를 흉내 내는 가짜 DB(upsert의 ignoreDuplicates 지원). fail: 표:동작 오류 주입
class Query {
  constructor(db, table) { this.db = db; this.table = table; this.rows = db.tables[table]; this.op = 'select'; this.filters = []; }
  select() { return this; }
  insert(p) { this.op = 'insert'; this.payload = p; return this; }
  upsert(p, opts) { this.op = 'upsert'; this.payload = p; this.opts = opts; return this; }
  update(p) { this.op = 'update'; this.payload = p; return this; }
  delete() { this.op = 'delete'; return this; }
  eq(c, v) { this.filters.push([c, v]); return this; }
  order() { return this; }
  single() { this.one = true; return this; }
  maybeSingle() { this.one = true; return this; }
  then(res, rej) { return Promise.resolve(this.run()).then(res, rej); }
  run() {
    this.db.log.push(`${this.op} ${this.table}`);
    if (this.db.fail?.[`${this.table}:${this.op}`]) return { data: null, error: { code: 'XX000' } };
    const hit = () => this.rows.filter(r => this.filters.every(([c, v]) => r[c] === v));
    let data;
    if (this.op === 'insert') {
      if (this.payload.id && this.table === 'notes' && this.rows.some(r => r.id === this.payload.id)) return { data: null, error: { code: '23505' } };
      const row = { id: randomUUID(), ...this.payload }; this.rows.push(row); data = [row];
    } else if (this.op === 'upsert') {
      const key = this.opts?.onConflict ?? 'id';
      if (!this.rows.some(r => r[key] === this.payload[key])) this.rows.push({ ...this.payload });
      data = [];
    } else if (this.op === 'update') { data = hit(); data.forEach(r => Object.assign(r, this.payload)); }
    else if (this.op === 'delete') { data = hit(); this.rows.splice(0, this.rows.length, ...this.rows.filter(r => !data.includes(r))); }
    else data = hit();
    return { data: this.one ? data[0] ?? null : data, error: null };
  }
}
const world = (fail) => ({ tables: { notes: [], notes_backup: [], notes_restore_audit: [] }, log: [], fail });

function api(db) {
  const verify = createLoginVerifier({ config, supabaseClient: { auth: { getClaims: async token => ({ data: { claims: JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) }, error: null }) } } });
  const handlers = createNotesApi({ getVerifier: () => verify, getSupabase: () => ({ from: table => new Query(db, table) }) });
  const call = async (handler, { method, authorization, body, id, url }) => {
    const out = {};
    const response = { setHeader() {}, status: c => { out.status = c; return response; }, json: p => { out.body = p; return response; } };
    await handler({ method, headers: { authorization }, body, query: id === undefined ? {} : { id }, url }, response);
    return out;
  };
  return {
    create: (user, body) => call(handlers.collection, { method: 'POST', authorization: bearer(user), body, url: '/api/notes' }),
    edit: (user, id, body) => call(handlers.item, { method: 'PUT', authorization: bearer(user), id, body, url: `/api/notes/${id}` }),
    remove: (user, id) => call(handlers.item, { method: 'DELETE', authorization: bearer(user), id, url: `/api/notes/${id}` }),
    restore: (user, id) => call(handlers.restore, { method: 'POST', authorization: bearer(user), body: { id }, url: '/api/restore' }),
    restoreWith: (user, body) => call(handlers.restore, { method: 'POST', authorization: bearer(user), body, url: '/api/restore' }),
    restoreAt: (user, id, url) => call(handlers.restore, { method: 'POST', authorization: bearer(user), id, url }),
  };
}
const liveOf = (db, id) => db.tables.notes.find(r => r.id === id);

test('심판 시나리오: B가 메모를 만들고 → 변조한 뒤 → 복구하면 만든 때의 상태로 돌아오고 ID·소유자·해시가 사본과 같다', async () => {
  const db = world(); const a = api(db);
  const created = await a.create(B, { title: '원래 제목', body: '원래 본문' });
  assert.equal(created.status, 201);
  const id = created.body.id;
  const backup = db.tables.notes_backup[0];
  assert.deepEqual([backup.note_id, backup.owner_id, backup.content_sha256], [id, B, noteContentHash('원래 제목', '원래 본문')]);
  assert.equal((await a.edit(B, id, { title: '변조됨', body: '변조 본문' })).status, 200);
  assert.equal(liveOf(db, id).title, '변조됨');
  assert.equal(db.tables.notes_backup.length, 1);
  assert.equal(db.tables.notes_backup[0].title, '원래 제목', '사본은 변조 뒤에도 그대로');
  const restored = await a.restore(B, id);
  assert.deepEqual([restored.status, restored.body.action, restored.body.verified], [200, 'updated', true]);
  const live = liveOf(db, id);
  assert.deepEqual([live.id, live.owner_id, live.title, live.content], [id, B, '원래 제목', '원래 본문']);
  assert.equal(noteContentHash(live.title, live.content), backup.content_sha256);
});

test('심판 시나리오: B가 만든 메모를 지운 뒤 복구하면 같은 ID로 다시 만들어진다', async () => {
  const db = world(); const a = api(db);
  const id = (await a.create(B, { title: '지울 메모', body: '지울 본문' })).body.id;
  assert.equal((await a.remove(B, id)).status, 200);
  assert.equal(liveOf(db, id), undefined);
  const restored = await a.restore(B, id);
  assert.deepEqual([restored.status, restored.body.action, restored.body.verified], [200, 'inserted', true]);
  assert.deepEqual([liveOf(db, id).owner_id, liveOf(db, id).title], [B, '지울 메모']);
});

test('사본이 없던 메모는 처음 고치기 직전의 상태가 사본이 되고, 두 번째 수정은 사본을 덮어쓰지 않는다', async () => {
  const db = world(); const a = api(db);
  const id = randomUUID();
  db.tables.notes.push({ id, owner_id: B, title: '옛 제목', content: '옛 본문', position: 3 });
  assert.equal((await a.edit(B, id, { title: '수정 1', body: '본문 1' })).status, 200);
  assert.deepEqual([db.tables.notes_backup[0].title, db.tables.notes_backup[0].position], ['옛 제목', 3]);
  assert.equal((await a.edit(B, id, { title: '수정 2', body: '본문 2' })).status, 200);
  assert.equal(db.tables.notes_backup.length, 1);
  assert.equal(db.tables.notes_backup[0].title, '옛 제목');
});

test('이미 있는 사본은 만들기·고치기·지우기 어느 것으로도 덮어쓰지 않는다(검증한 사본 보존)', async () => {
  const db = world(); const a = api(db);
  const id = randomUUID();
  const keep = { note_id: id, owner_id: B, position: null, title: '검증한 사본', content: '검증한 본문', content_sha256: noteContentHash('검증한 사본', '검증한 본문') };
  db.tables.notes_backup.push({ ...keep });
  db.tables.notes.push({ id, owner_id: B, title: '지금 제목', content: '지금 본문' });
  await a.edit(B, id, { title: '다른 제목', body: '다른 본문' });
  await a.remove(B, id);
  assert.deepEqual(db.tables.notes_backup, [keep]);
});

test('남의 메모를 고치거나 지우려는 요청(403)은 사본을 만들지 않고 메모도 바꾸지 않는다', async () => {
  const db = world(); const a = api(db);
  const id = (await a.create(B, { title: 'B의 메모', body: 'B 본문' })).body.id;
  const before = JSON.stringify(db.tables);
  assert.equal((await a.edit(A, id, { title: '가로챔', body: 'x' })).status, 403);
  assert.equal((await a.remove(A, id)).status, 403);
  assert.equal(JSON.stringify(db.tables), before);
  assert.equal(db.tables.notes_backup.every(r => r.owner_id === B), true);
});

test('사본 저장이 실패해도(표 없음·권한 오류) 만들기·고치기·지우기는 그대로 성공한다', async () => {
  const db = world({ 'notes_backup:upsert': true }); const a = api(db);
  const created = await a.create(B, { title: '제목', body: '본문' });
  assert.equal(created.status, 201);
  const id = created.body.id;
  assert.equal((await a.edit(B, id, { title: '수정', body: '본문' })).status, 200);
  assert.equal((await a.remove(B, id)).status, 200);
  assert.equal(db.tables.notes_backup.length, 0);
  const noisy = world(); noisy.tables.notes_backup = null;
  assert.equal((await api(noisy).create(B, { title: '제목', body: '본문' })).status, 201);
});

test('로그에는 제목·본문·사용자 ID가 없다(사본 저장 실패 사유 코드만)', async () => {
  const lines = []; const warn = console.warn; console.warn = (...x) => lines.push(x.join(' '));
  try {
    const db = world({ 'notes_backup:upsert': true });
    await api(db).create(B, { title: '비밀 제목', body: '비밀 본문' });
  } finally { console.warn = warn; }
  assert.ok(lines.length > 0);
  assert.ok(!lines.join('\n').match(/비밀|2222|Bearer/u));
});

test('요청 본문의 owner_id·id 같은 값은 사본에 쓰지 않는다', async () => {
  const db = world(); const a = api(db);
  const created = await a.create(B, { title: '제목', body: '본문', owner_id: A, userId: A });
  assert.equal(created.status, 201);
  assert.equal(db.tables.notes_backup[0].owner_id, B);
});

async function tampered() {
  const db = world(); const a = api(db);
  const id = (await a.create(B, { title: '원래 제목', body: '원래 본문' })).body.id;
  await a.edit(B, id, { title: '변조됨', body: '변조 본문' });
  return { db, a, id, hash: noteContentHash('원래 제목', '원래 본문') };
}

test('요청에 실린 해시가 사본과 다르면 복원하지 않고 409로 멈춘다(메모·감사 기록 그대로)', async () => {
  const { db, a, id } = await tampered();
  const before = JSON.stringify(db.tables);
  for (const bad of ['f'.repeat(64), '0'.repeat(64), 'tampered', 12345, noteContentHash('변조됨', '변조 본문')]) {
    const result = await a.restoreWith(B, { id, contentSha256: bad });
    assert.deepEqual([result.status, result.body], [409, { error: 'BACKUP_INVALID' }], String(bad));
  }
  assert.equal(JSON.stringify(db.tables), before);
});

test('해시가 사본과 같으면(대문자·sha256: 머리말 포함) 복원한다', async () => {
  for (const make of [h => h, h => h.toUpperCase(), h => `sha256:${h}`]) {
    const { db, a, id, hash } = await tampered();
    const result = await a.restoreWith(B, { id, sha256: make(hash) });
    assert.deepEqual([result.status, result.body.verified], [200, true]);
    assert.equal(liveOf(db, id).title, '원래 제목');
  }
});

test('사본 소유자와 다른 UUID owner가 실려 오면 멈추고, 같은 owner·모양이 다른 표시는 통과한다', async () => {
  const { db, a, id } = await tampered();
  assert.equal((await a.restoreWith(B, { id, ownerId: A })).status, 409);
  assert.equal(liveOf(db, id).title, '변조됨');
  assert.equal((await a.restoreWith(B, { id, owner: 'b' })).status, 200);
  const second = await tampered();
  assert.equal((await second.a.restoreWith(B, { id: second.id, owner_id: B, contentHash: second.hash })).status, 200);
});

test('id는 noteId·note_id로 와도 읽고, 없거나 UUID가 아니면 400이다', async () => {
  for (const key of ['noteId', 'note_id']) {
    const { a, id } = await tampered();
    assert.equal((await a.restoreWith(B, { [key]: id })).status, 200, key);
  }
  const { a } = await tampered();
  for (const body of [{}, { noteId: 'abc' }, { hash: 'x' }]) assert.equal((await a.restoreWith(B, body)).status, 400);
});

test('요청에 실린 owner는 권한이 되지 않는다: A가 B의 사본을 B의 해시·owner와 함께 보내도 403', async () => {
  const { db, a, id, hash } = await tampered();
  const before = JSON.stringify(db.tables);
  const result = await a.restoreWith(A, { id, ownerId: B, contentSha256: hash });
  assert.deepEqual([result.status, result.body], [403, { error: 'FORBIDDEN' }]);
  assert.equal(JSON.stringify(db.tables), before);
});

test('로그에는 요청의 필드 이름만 남고 값(id·해시·소유자)은 없다', async () => {
  const lines = []; const info = console.info; console.info = (...x) => lines.push(x.join(' '));
  try {
    const { a, id, hash } = await tampered();
    await a.restoreWith(B, { id, contentSha256: hash, ownerId: B });
  } finally { console.info = info; }
  const text = lines.join('\n');
  assert.match(text, /notes 복구 요청 필드: id,contentSha256,ownerId/u);
  assert.ok(!text.includes(B) && !text.includes('2222') && !/[a-f0-9]{16}/u.test(text));
});

test('미리보기(dryRun·mode:plan)는 아무것도 바꾸지 않고(감사 기록도 없음) 버전과 바뀔 항목만 보여 준다', async () => {
  for (const body of [{ dryRun: true }, { mode: 'plan' }, { mode: 'dry-run' }, { preview: true }]) {
    const { db, a, id, hash } = await tampered();
    const before = JSON.stringify(db.tables);
    const result = await a.restoreWith(B, { id, ...body });
    assert.equal(result.status, 200);
    assert.deepEqual([result.body.planned, result.body.restored, result.body.action, result.body.backupVerified], [true, false, 'plan', true]);
    assert.deepEqual(result.body.changes, ['title', 'content']);
    assert.equal(result.body.restoreVersion, hash.slice(0, 12));
    assert.equal(JSON.stringify(db.tables), before, JSON.stringify(body));
  }
});

test('삭제된 메모의 미리보기는 create 하나를 보여 주고, 틀린 해시·남의 사본·사본 없음은 미리보기도 멈춘다', async () => {
  const del = world(); const d = api(del);
  const id = (await d.create(B, { title: '지울 메모', body: '본문' })).body.id;
  await d.remove(B, id);
  const plan = await d.restoreWith(B, { id, dryRun: true });
  assert.deepEqual([plan.status, plan.body.changes], [200, ['create']]);
  assert.equal(del.tables.notes.length, 0);
  const { a, id: id2 } = await tampered();
  assert.equal((await a.restoreWith(B, { id: id2, dryRun: true, contentSha256: 'f'.repeat(64) })).status, 409);
  assert.equal((await a.restoreWith(A, { id: id2, dryRun: true })).status, 403);
  assert.equal((await a.restoreWith(B, { id: randomUUID(), dryRun: true })).status, 404);
});

test('실제 복구 응답에도 검증 증거(backupVerified·restoreVersion·바뀐 항목)가 들어 있다', async () => {
  const { a, id, hash } = await tampered();
  const result = await a.restoreWith(B, { id });
  assert.deepEqual([result.status, result.body.backupVerified, result.body.verified, result.body.restoreVersion, result.body.changes],
    [200, true, true, hash.slice(0, 12), ['title', 'content']]);
  const again = await a.restoreWith(B, { id });
  assert.deepEqual([again.body.action, again.body.changes], ['unchanged', []]);
});

test('해시·소유자가 backup 같은 중첩 객체로 와도 대조한다(틀리면 409, 맞으면 복원)', async () => {
  const { db, a, id, hash } = await tampered();
  assert.equal((await a.restoreWith(B, { id, backup: { contentSha256: 'e'.repeat(64) } })).status, 409);
  assert.equal((await a.restoreWith(B, { id, snapshot: { ownerId: A } })).status, 409);
  assert.equal(liveOf(db, id).title, '변조됨');
  assert.equal((await a.restoreWith(B, { backup: { id, ownerId: B, contentSha256: hash } })).status, 200);
  assert.equal(liveOf(db, id).title, '원래 제목');
});

test('id를 memoId·targetId·resourceId로 보내거나, 본문 없이 ?id= 또는 /api/restore/<id> 주소로 보내도 읽는다', async () => {
  for (const key of ['memoId', 'targetId', 'resourceId']) {
    const { a, id } = await tampered();
    assert.equal((await a.restoreWith(B, { [key]: id })).status, 200, key);
  }
  const viaQuery = await tampered();
  assert.equal((await viaQuery.a.restoreAt(B, viaQuery.id, '/api/restore')).status, 200);
  const viaPath = await tampered();
  assert.equal((await viaPath.a.restoreAt(B, viaPath.id, `/api/restore/${viaPath.id}`)).status, 200);
  const none = await tampered();
  assert.equal((await none.a.restoreWith(B, {})).status, 400);
});
