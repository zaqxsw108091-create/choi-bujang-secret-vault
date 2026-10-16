import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createNotesApi } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createDeviceGate, codeOf } from '../src/device-gate.mjs';
import { createMatrix, prepareLiveDevices, renderTable, runRegression } from '../src/regression-table.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const APP = new URL('https://example.test/');
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const SECRET_TOKEN_PART = 'c2lnc2lnc2ln';
const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const token = sub => `${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({ iss: config.identityProvider.issuer, aud: config.identityProvider.audience, role: 'authenticated', sub, exp: Math.floor(Date.now() / 1000) + 600 })}.${SECRET_TOKEN_PART}`;

// 실제 서버 코드(createNotesApi)를 가짜 DB 위에서 돌립니다. 정적 파일·로그인 같은 서버 밖 경로만 고정 응답입니다.
class Query {
  constructor(db, table) { this.db = db; this.rows = db[table]; this.op = 'select'; this.filters = []; }
  select() { return this; }
  insert(p) { this.op = 'insert'; this.payload = p; return this; }
  upsert(p, opts) { this.op = 'upsert'; this.payload = p; this.opts = opts; return this; }
  update(p) { this.op = 'update'; this.payload = p; return this; }
  delete() { this.op = 'delete'; return this; }
  eq(c, v) { this.filters.push([c, v]); return this; }
  order() { return this; }
  maybeSingle() { this.one = true; return this; }
  single() { this.one = true; return this; }
  then(res, rej) { return Promise.resolve(this.run()).then(res, rej); }
  run() {
    const hit = () => this.rows.filter(r => this.filters.every(([c, v]) => r[c] === v));
    let data;
    if (this.op === 'insert') { const row = { id: randomUUID(), ...this.payload }; this.rows.push(row); data = [row]; }
    else if (this.op === 'upsert') {
      const key = this.opts?.onConflict;
      if (!(this.opts?.ignoreDuplicates && this.rows.some(r => r[key] === this.payload[key]))) this.rows.push({ ...this.payload });
      data = [];
    } else if (this.op === 'update') { data = hit(); data.forEach(r => Object.assign(r, this.payload)); }
    else if (this.op === 'delete') { data = hit(); this.rows.splice(0, this.rows.length, ...this.rows.filter(r => !data.includes(r))); }
    else data = hit();
    return { data: this.one ? data[0] ?? null : data, error: null };
  }
}

function server(db, { offline = false } = {}) {
  const verify = createLoginVerifier({ config, supabaseClient: { auth: { getClaims: async t => ({ data: { claims: JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()) }, error: null }) } } });
  const api = createNotesApi({ getVerifier: () => verify, getSupabase: () => ({ from: t => new Query(db, t) }), deviceGate: createDeviceGate() });
  let n = 0;
  const reply = (status, body, headers = {}) => new Response(typeof body === 'string' ? body : JSON.stringify(body), { status, headers: { 'x-vercel-id': `fake::req-${++n}`, ...headers } });
  const fetchFn = async (url, init = {}) => {
    if (offline) throw new TypeError('fetch failed');
    const { pathname, search } = new URL(url);
    const staticReply = { '/': () => reply(200, '<html></html>'), '/aleph.json': () => reply(200, { step: 11 }), '/manifest.webmanifest': () => reply(200, {}),
      '/data.json': () => reply(404, 'nope'), '/api/notices': () => reply(404, 'nope'), '/api/login': () => reply(401, { error: 'LOGIN_FAILED' }),
      '/rest/v1/notes': () => reply(401, { error: 'x' }) }[pathname];
    if (staticReply) return staticReply();
    const headers = Object.fromEntries(Object.entries(init.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
    const item = pathname.match(/^\/api\/notes\/([^/]+)$/u);
    const handler = item ? api.item : pathname === '/api/notes' ? api.collection : pathname === '/api/restore' ? api.restore : pathname === '/api/device' ? api.device : null;
    if (!handler) return reply(404, 'nope');
    const out = { headers: {} };
    const response = { setHeader: (k, v) => { out.headers[k] = v; }, status: c => { out.status = c; return response; }, json: p => { out.body = p; return response; } };
    await handler({ method: init.method, url: `${pathname}${search}`, query: item ? { id: item[1] } : {}, headers: { authorization: headers.authorization, 'x-device-key': headers['x-device-key'], 'x-device-ts': headers['x-device-ts'], 'x-device-sig': headers['x-device-sig'] }, body: init.body ? JSON.parse(init.body) : undefined }, response);
    return reply(out.status, out.body ?? {}, out.headers);
  };
  return fetchFn;
}
const world = () => ({ notes: [], notes_backup: [], notes_restore_audit: [], devices: [] });
const approveByCode = (db) => async ({ devices }) => {
  for (const { code } of devices) for (const row of db.devices) if (codeOf(row.key_id) === code) row.status = 'approved';
};
const tokens = { A: token(A), B: token(B) };

test('실제 서버 코드에 보낸 정상·금지 요청이 모두 기대대로 통과 줄이 된다', async () => {
  const db = world();
  const rows = await runRegression({ app: APP, config, tokens, anonKey: 'anon-test-key', fetchFn: server(db), waitForApproval: approveByCode(db) });
  const bad = rows.filter(r => r.result === '실패' || r.result === '확인하지 못함');
  assert.deepEqual(bad, [], JSON.stringify(bad));
  const kinds = new Set(rows.filter(r => r.result === '통과').map(r => r.kind));
  assert.ok(kinds.has('정상') && kinds.has('금지'));
  assert.ok(rows.filter(r => r.result === '통과').every(r => r.requestId?.startsWith('fake::req-') && /^\d{4}-\d\d-\d\dT/u.test(r.checkedAt)));
  assert.ok(rows.filter(r => r.result === '통과').length >= 30);
  assert.equal(db.notes.length, 0, '시험이 만든 가상 메모는 정리됨');
});

test('판정기·탐지·41종은 항상 미실행이고 통과로 바뀌지 않는다', async () => {
  const db = world();
  const rows = await runRegression({ app: APP, config, tokens, anonKey: 'k', fetchFn: server(db), waitForApproval: approveByCode(db) });
  for (const step of ['6', '7', '9', '12']) {
    const row = rows.find(r => r.step === step && r.result === '미실행');
    assert.ok(row, `${step}단계 줄`);
    assert.equal(row.requestId, null);
    assert.equal(row.checkedAt, null);
  }
  assert.match(rows.find(r => r.step === '12').request, /41종/u);
  assert.match(renderTable(rows), /41종 공격 방어 시험[^\n]*미실행/u);
});

test('anon 키가 없으면 그 줄은 미실행, 기기가 승인되지 않으면 서명 요청들은 미실행으로 남는다', async () => {
  const db = world();
  const rows = await runRegression({ app: APP, config, tokens, fetchFn: server(db), waitForApproval: async () => {} });
  assert.ok(rows.some(r => r.request.includes('anon') && r.result === '미실행'));
  assert.ok(rows.some(r => r.request.startsWith('A: 메모 목록') && r.result === '미실행'));
  assert.ok(rows.some(r => r.request.includes('GET /api/device') && r.result === '실패'), '승인 안 된 기기 상태는 approved가 아니라 실패로 적힘');
  assert.equal(db.notes.length, 0);
});

test('서버가 기대와 다르게 답하면 실패, 접속하지 못하면 확인하지 못함으로 적고 통과로 바꾸지 않는다', async () => {
  const wrong = createMatrix({ app: APP, fetchFn: async () => new Response('{}', { status: 200 }) });
  await wrong.check({ step: '3', kind: '금지', request: 'GET /api/notes', expect: { status: 401, error: 'LOGIN_REQUIRED' }, send: () => wrong.call('GET', '/api/notes') });
  assert.equal(wrong.rows[0].result, '실패');
  assert.equal(wrong.rows[0].requestId, null);
  const offline = await runRegression({ app: APP, config, tokens, fetchFn: server(world(), { offline: true }), waitForApproval: async () => {} });
  assert.ok(offline.some(r => r.result === '확인하지 못함'));
  assert.equal(offline.filter(r => r.result === '통과').length, 0);
});

test('표와 JSON에 토큰·비밀번호·메모 제목·사용자 ID가 없다', async () => {
  const db = world();
  const rows = await runRegression({ app: APP, config, tokens, anonKey: 'anon-secret-value', fetchFn: server(db), waitForApproval: approveByCode(db) });
  const text = renderTable(rows) + JSON.stringify(rows);
  for (const secret of [tokens.A, tokens.B, SECRET_TOKEN_PART, 'anon-secret-value', 'wrong-password-for-matrix', '회귀표 가상 메모', A, B]) {
    assert.equal(text.includes(secret), false, secret);
  }
});

test('attack:live 준비: 두 계정의 기기를 승인받아 실제 서버 코드에 대한 남의 메모 읽기 점검이 거부됨으로 나오고 쓰기 점검 3개는 미실행으로 남는다', async () => {
  const db = world();
  db.notes.push({ id: 'dddddddd-dddd-4ddd-8ddd-ddddddddddd1', owner_id: B, title: 'B 가상', content: 'B 본문', position: 1 });
  db.notes_backup.push({ note_id: 'dddddddd-dddd-4ddd-8ddd-ddddddddddd1', owner_id: B, title: 'B 가상', content: 'B 본문', content_sha256: 'a'.repeat(64) });
  const fetchFn = server(db);
  const prepared = await prepareLiveDevices({ app: APP, tokens: { OWNER: tokens.B, OTHER: tokens.A }, fetchFn, waitForApproval: approveByCode(db) });
  assert.deepEqual(prepared.notes, []);
  assert.deepEqual(Object.keys(prepared.devices).sort(), ['OTHER', 'OWNER']);
  const savedFetch = globalThis.fetch;
  const keys = ['ATTACK_TOKEN_OWNER', 'ATTACK_TOKEN_OTHER'];
  const savedEnv = keys.map(k => process.env[k]);
  const sym = Symbol.for('aleph.attack.devices');
  globalThis.fetch = fetchFn; process.env.ATTACK_TOKEN_OWNER = tokens.B; process.env.ATTACK_TOKEN_OTHER = tokens.A; globalThis[sym] = prepared.devices;
  try {
    const results = await runAttackChecks({ ...config, step: 12, publicAppUrl: APP.href });
    assert.equal(results.find(r => r.attackId === 'other_owner_read_refused')?.observed, '거부됨 (HTTP 403)');
    for (const id of ['other_owner_update_refused', 'other_owner_delete_refused', 'other_owner_restore_refused']) {
      assert.match(results.find(r => r.attackId === id)?.observed ?? '', /^미실행/u, id);
    }
    assert.equal(db.notes[0].title, 'B 가상', 'B의 메모는 바뀌지 않음');
  } finally {
    globalThis.fetch = savedFetch; delete globalThis[sym];
    keys.forEach((k, i) => { if (savedEnv[i] === undefined) delete process.env[k]; else process.env[k] = savedEnv[i]; });
  }
});

test('attack:live 준비: 승인하지 않으면 그 기기는 빠지고 이유가 남는다', async () => {
  const db = world();
  const prepared = await prepareLiveDevices({ app: APP, tokens: { OWNER: tokens.B, OTHER: tokens.A }, fetchFn: server(db), waitForApproval: async () => {} });
  assert.deepEqual(prepared.devices, {});
  assert.equal(prepared.notes.length, 2);
  assert.ok(prepared.notes.every(n => n.includes('승인되지 않음')));
});
