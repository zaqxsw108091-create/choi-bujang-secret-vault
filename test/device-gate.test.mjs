import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createNotesApi } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { codeOf, createDeviceGate, keyIdOf, readPublicKey, sha256Hex, signedText } from '../src/device-gate.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const A_NOTE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';
const NOW = 1_800_000_000_000;

const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const bearer = sub => `Bearer ${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({
  iss: config.identityProvider.issuer, aud: config.identityProvider.audience, role: 'authenticated', sub, exp: Math.floor(Date.now() / 1000) + 600,
})}.c2ln`;

class Query {
  constructor(db, table) { this.db = db; this.table = table; this.rows = db.tables[table]; this.op = 'select'; this.filters = []; }
  select() { return this; }
  insert(p) { this.op = 'insert'; this.payload = p; return this; }
  upsert(p) { this.op = 'upsert'; this.payload = p; return this; }
  update(p) { this.op = 'update'; this.payload = p; return this; }
  delete() { this.op = 'delete'; return this; }
  eq(c, v) { this.filters.push([c, v]); return this; }
  order() { return this; }
  maybeSingle() { this.one = true; return this; }
  single() { this.one = true; return this; }
  then(res, rej) { return Promise.resolve(this.run()).then(res, rej); }
  run() {
    if (this.db.fail?.[`${this.table}:${this.op}`]) return { data: null, error: { code: 'XX000' } };
    const hit = () => this.rows.filter(r => this.filters.every(([c, v]) => r[c] === v));
    let data;
    if (this.op === 'insert') { this.rows.push({ ...this.payload }); data = [this.payload]; }
    else if (this.op === 'upsert') { data = []; }
    else if (this.op === 'update') { data = hit(); data.forEach(r => Object.assign(r, this.payload)); }
    else if (this.op === 'delete') { data = hit(); this.rows.splice(0, this.rows.length, ...this.rows.filter(r => !data.includes(r))); }
    else data = hit();
    return { data: this.one ? data[0] ?? null : data, error: null };
  }
}

// 브라우저와 같은 WebCrypto로 기기 키를 만들고 서명합니다(개인키는 이 시험 안에서만 삼).
async function newDevice() {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const publicKey = readPublicKey(await crypto.subtle.exportKey('jwk', pair.publicKey));
  const keyId = keyIdOf(publicKey);
  const sign = async ({ method, url, body, ts = NOW }) => {
    const text = signedText({ method, target: url, ts, body: body === undefined ? '' : JSON.stringify(body) });
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(text));
    return { 'x-device-key': keyId, 'x-device-ts': String(ts), 'x-device-sig': Buffer.from(sig).toString('base64url') };
  };
  return { publicKey, keyId, sign };
}

function world(devices = []) {
  return { tables: { notes: [{ id: A_NOTE, owner_id: A, title: 'A 가상', content: 'A 본문', position: 1 }], notes_backup: [], notes_restore_audit: [], devices }, log: [] };
}
function apiFor(db) {
  const verify = createLoginVerifier({ config, supabaseClient: { auth: { getClaims: async token => ({ data: { claims: JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) }, error: null }) } } });
  const api = createNotesApi({
    getVerifier: () => verify, getSupabase: () => ({ from: table => new Query(db, table) }),
    deviceGate: createDeviceGate({ now: () => NOW }),
  });
  return (handler) => async ({ method = 'GET', url, serverUrl, query, authorization, headers = {}, body } = {}) => {
    const out = { headers: {} };
    const response = { setHeader: (n, v) => { out.headers[n] = v; }, status: c => { out.status = c; return response; }, json: p => { out.body = p; return response; } };
    await api[handler]({ method, url: serverUrl ?? url, query, headers: { ...(authorization ? { authorization } : {}), ...headers }, body }, response);
    return out;
  };
}
const row = (d, owner, status) => ({ key_id: d.keyId, owner_id: owner, public_key: d.publicKey, status });

test('기기 승인 전에는 목록을 읽을 수 없고 자료가 응답에 없다', async () => {
  const d = await newDevice();
  for (const [label, db, headers] of [
    ['기기 증명 없음', world(), {}],
    ['승인 요청도 안 한 기기', world(), await d.sign({ method: 'GET', url: '/api/notes' })],
    ['승인 대기(pending) 기기', world([row(d, A, 'pending')]), await d.sign({ method: 'GET', url: '/api/notes' })],
    ['회수된 기기', world([row(d, A, 'revoked')]), await d.sign({ method: 'GET', url: '/api/notes' })],
  ]) {
    const out = await apiFor(db)('collection')({ url: '/api/notes', authorization: bearer(A), headers });
    assert.equal(out.status, 403, label);
    assert.ok(['DEVICE_REQUIRED', 'DEVICE_NOT_APPROVED'].includes(out.body.error), label);
    assert.doesNotMatch(JSON.stringify(out.body), /가상|본문/u, label);
  }
});

test('승인된 기기의 서명 요청은 기존처럼 읽기·추가·수정·삭제가 된다', async () => {
  const d = await newDevice();
  const db = world([row(d, A, 'approved')]);
  const call = apiFor(db);
  const list = await call('collection')({ url: '/api/notes', authorization: bearer(A), headers: await d.sign({ method: 'GET', url: '/api/notes' }) });
  assert.equal(list.status, 200);
  assert.deepEqual(list.body, [{ id: A_NOTE, title: 'A 가상', body: 'A 본문' }]);
  const body = { title: '새', body: '본문' };
  const created = await call('collection')({ method: 'POST', url: '/api/notes', authorization: bearer(A), body, headers: await d.sign({ method: 'POST', url: '/api/notes', body }) });
  assert.equal(created.status, 201);
  const url = `/api/notes/${A_NOTE}`;
  const edit = { title: '고침', body: '고침 본문' };
  const put = await call('item')({ method: 'PUT', url, authorization: bearer(A), body: edit, headers: await d.sign({ method: 'PUT', url, body: edit }) });
  assert.equal(put.status, 200);
  const del = await call('item')({ method: 'DELETE', url, authorization: bearer(A), headers: await d.sign({ method: 'DELETE', url }) });
  assert.equal(del.status, 200);
});

test('서명 뒤에 경로·방법·본문을 바꾸거나 오래된·위조 서명은 거부된다', async () => {
  const d = await newDevice();
  const other = await newDevice();
  const db = world([row(d, A, 'approved')]);
  const call = apiFor(db)('item');
  const url = `/api/notes/${A_NOTE}`;
  const edit = { title: '고침', body: '본문' };
  const good = await d.sign({ method: 'PUT', url, body: edit });
  const cases = [
    ['경로 변경', { method: 'PUT', url: `/api/notes/${A_NOTE}?x=1`, body: edit, headers: good }],
    ['방법 변경', { method: 'DELETE', url, headers: good }],
    ['본문 변경', { method: 'PUT', url, body: { title: '바꿈', body: '본문' }, headers: good }],
    ['오래된 시각', { method: 'PUT', url, body: edit, headers: await d.sign({ method: 'PUT', url, body: edit, ts: NOW - 120_000 }) }],
    ['다른 기기의 서명', { method: 'PUT', url, body: edit, headers: { ...good, 'x-device-sig': (await other.sign({ method: 'PUT', url, body: edit }))['x-device-sig'] } }],
    ['깨진 헤더', { method: 'PUT', url, body: edit, headers: { ...good, 'x-device-sig': 'abc' } }],
  ];
  for (const [label, request] of cases) {
    const out = await call({ ...request, authorization: bearer(A) });
    assert.equal(out.status, 403, label);
    assert.equal(out.body.error, 'DEVICE_PROOF_INVALID', label);
  }
  assert.equal(db.tables.notes[0].title, 'A 가상', '거부된 요청은 자료를 바꾸지 않는다');
});

test('다른 사용자의 승인 기기로는 쓸 수 없고, 로그인 없는 요청은 먼저 401이다', async () => {
  const d = await newDevice();
  const call = apiFor(world([row(d, A, 'approved')]));
  const headers = await d.sign({ method: 'GET', url: '/api/notes' });
  const asB = await call('collection')({ url: '/api/notes', authorization: bearer(B), headers });
  assert.deepEqual([asB.status, asB.body.error], [403, 'DEVICE_NOT_APPROVED']);
  const anon = await call('collection')({ url: '/api/notes', headers });
  assert.deepEqual([anon.status, anon.body.error], [401, 'LOGIN_REQUIRED']);
});

test('기기 확인 중 DB 오류는 열지 않고 503으로 닫는다', async () => {
  const d = await newDevice();
  const db = world([row(d, A, 'approved')]);
  db.fail = { 'devices:select': true };
  const out = await apiFor(db)('collection')({ url: '/api/notes', authorization: bearer(A), headers: await d.sign({ method: 'GET', url: '/api/notes' }) });
  assert.deepEqual([out.status, out.body.error], [503, 'DEVICE_CHECK_FAILED']);
});

test('승인 요청은 항상 pending이고, 본문의 status·owner_id로 승인되지 않으며, 승인은 이 경로로 할 수 없다', async () => {
  const d = await newDevice();
  const db = world();
  const call = apiFor(db)('device');
  const forged = { publicKey: d.publicKey, status: 'approved', owner_id: B, approved_at: 'now' };
  const made = await call({ method: 'POST', url: '/api/device', authorization: bearer(A), body: forged });
  assert.equal(made.status, 201);
  assert.deepEqual(made.body, { status: 'pending', code: codeOf(d.keyId), keyId: d.keyId });
  assert.deepEqual([db.tables.devices.length, db.tables.devices[0].status, db.tables.devices[0].owner_id], [1, 'pending', A]);
  // 같은 요청을 다시 보내도 상태가 그대로이고, 승인 전이라 자료는 여전히 거부된다.
  const again = await call({ method: 'POST', url: '/api/device', authorization: bearer(A), body: forged });
  assert.deepEqual([again.status, again.body.status], [200, 'pending']);
  const read = await apiFor(db)('collection')({ url: '/api/notes', authorization: bearer(A), headers: await d.sign({ method: 'GET', url: '/api/notes' }) });
  assert.equal(read.status, 403);
  // 승인 요청 경로는 PUT/DELETE를 받지 않는다.
  const put = await call({ method: 'PUT', url: '/api/device', authorization: bearer(A), body: forged });
  assert.equal(put.status, 405);
  // 서버 쪽에서 승인(SQL Editor)한 뒤에만 열린다.
  db.tables.devices[0].status = 'approved';
  const open = await apiFor(db)('collection')({ url: '/api/notes', authorization: bearer(A), headers: await d.sign({ method: 'GET', url: '/api/notes' }) });
  assert.equal(open.status, 200);
});

test('승인 요청·상태 경로: 로그인 필요, 남의 기기 상태는 안 보이고, 개인키가 든 키나 모양이 틀린 키는 거부된다', async () => {
  const d = await newDevice();
  const db = world([row(d, A, 'pending')]);
  const call = apiFor(db)('device');
  assert.equal((await call({ url: `/api/device?keyId=${d.keyId}` })).status, 401);
  assert.deepEqual((await call({ url: `/api/device?keyId=${d.keyId}`, authorization: bearer(A) })).body.status, 'pending');
  assert.equal((await call({ url: `/api/device?keyId=${d.keyId}`, authorization: bearer(B) })).status, 404);
  assert.equal((await call({ url: '/api/device?keyId=zz', authorization: bearer(A) })).status, 400);
  for (const publicKey of [{ ...d.publicKey, d: 'x'.repeat(43) }, { ...d.publicKey, crv: 'P-384' }, { kty: 'EC' }, 'abc']) {
    const out = await call({ method: 'POST', url: '/api/device', authorization: bearer(A), body: { publicKey } });
    assert.equal(out.status, 400);
  }
  const stolen = await call({ method: 'POST', url: '/api/device', authorization: bearer(B), body: { publicKey: d.publicKey } });
  assert.deepEqual([stolen.status, stolen.body.error], [409, 'DEVICE_CONFLICT']);
  // 대기 5건이 차면 더 받지 않는다.
  const full = world(Array.from({ length: 5 }, (_, i) => ({ key_id: String(i).repeat(64), owner_id: A, status: 'pending' })));
  const six = await apiFor(full)('device')({ method: 'POST', url: '/api/device', authorization: bearer(A), body: { publicKey: (await newDevice()).publicKey } });
  assert.deepEqual([six.status, six.body.error], [429, 'TOO_MANY_PENDING']);
});

test('운영용 notesApi는 기기 확인을 켠 채로 만들어진다', () => {
  const source = readFileSync(new URL('../src/notes-api.mjs', import.meta.url), 'utf8');
  assert.match(source, /deviceGate: createDeviceGate\(\)/u);
  assert.equal(sha256Hex('a').length, 64);
});

// 실제 배포(Vercel)에서 메모 한 건 경로가 서명 검사에서 떨어졌던 사고의 재현: 서버가 보는 주소에는 ?id=<id>가 덧붙거나 [id]가 쓰입니다.
test('Vercel이 [id] 경로에 덧붙이는 id 쿼리가 있어도 승인된 기기의 수정·삭제는 통과하고, 다른 id나 다른 쿼리는 거부된다', async () => {
  const d = await newDevice();
  const edit = { title: '고침', body: '본문' };
  const path = `/api/notes/${A_NOTE}`;
  const shapes = [
    ['?id= 덧붙임', { serverUrl: `${path}?id=${A_NOTE}`, query: { id: A_NOTE } }],
    ['[id] 글자와 ?id=', { serverUrl: `/api/notes/[id]?id=${A_NOTE}`, query: { id: A_NOTE } }],
    ['query 객체만', { serverUrl: path, query: { id: A_NOTE } }],
    ['%5Bid%5D 인코딩', { serverUrl: `/api/notes/%5Bid%5D?id=${A_NOTE}`, query: { id: A_NOTE } }],
    ['id 자리가 [id]만, 쿼리 없음', { serverUrl: '/api/notes/[id]', query: { id: A_NOTE } }],
  ];
  for (const [label, shape] of shapes) {
    const db = world([row(d, A, 'approved')]);
    const call = apiFor(db)('item');
    const put = await call({ method: 'PUT', url: path, authorization: bearer(A), body: edit, headers: await d.sign({ method: 'PUT', url: path, body: edit }), ...shape });
    assert.equal(put.status, 200, `PUT ${label}`);
    const del = await call({ method: 'DELETE', url: path, authorization: bearer(A), headers: await d.sign({ method: 'DELETE', url: path }), ...shape });
    assert.equal(del.status, 200, `DELETE ${label}`);
  }
  // 걷어내기가 서명을 우회하는 길이 되지 않는지: 서명한 id와 다른 id, 다른 쿼리가 덧붙은 경우는 거부된다.
  const other = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb2';
  const db = world([row(d, A, 'approved')]);
  const call = apiFor(db)('item');
  const signedFor = await d.sign({ method: 'DELETE', url: path });
  for (const [label, shape] of [
    ['다른 id', { serverUrl: `/api/notes/${other}?id=${other}`, query: { id: other } }],
    ['경로는 서명과 같고 쿼리 id만 다름', { serverUrl: `${path}?id=${other}`, query: { id: other } }],
    ['서명에 없는 쿼리 추가', { serverUrl: `${path}?id=${A_NOTE}&x=1`, query: { id: A_NOTE } }],
  ]) {
    const out = await call({ method: 'DELETE', url: path, authorization: bearer(A), headers: signedFor, ...shape });
    assert.equal(out.status, 403, label);
  }
  assert.equal(db.tables.notes.length, 1, '거부된 요청은 자료를 지우지 않는다');
});

test('서명이 맞지 않으면 403 본문에 서버가 받은 요청(방법·주소)이 들어가고, 키나 서명 값은 들어가지 않는다', async () => {
  const d = await newDevice();
  const call = apiFor(world([row(d, A, 'approved')]))('item');
  const url = `/api/notes/${A_NOTE}`;
  const out = await call({ method: 'DELETE', url, serverUrl: `${url}?x=1`, query: { id: A_NOTE }, authorization: bearer(A), headers: await d.sign({ method: 'DELETE', url }) });
  assert.deepEqual([out.status, out.body.error, out.body.seen], [403, 'DEVICE_PROOF_INVALID', `DELETE ${url}?x=1`]);
  assert.doesNotMatch(JSON.stringify(out.body), /sig|[0-9a-f]{40}/iu);
});

// 공격자 시점 점검: 앞선 시험이 다루지 않은 변칙 입력은 모두 열지 않고 닫혀야 한다.
test('기기 증명 헤더의 변칙(일부 누락·대문자·배열·미래/음수 시각·잘린 서명)은 모두 403으로 거부되고 자료를 바꾸지 않는다', async () => {
  const d = await newDevice();
  const url = `/api/notes/${A_NOTE}`;
  const edit = { title: '바꿈', body: '본문' };
  const good = await d.sign({ method: 'PUT', url, body: edit });
  const cases = [
    ['키만 있고 시각·서명 없음', { 'x-device-key': good['x-device-key'] }],
    ['서명만 있음', { 'x-device-sig': good['x-device-sig'] }],
    ['키 지문 대문자', { ...good, 'x-device-key': good['x-device-key'].toUpperCase() }],
    ['헤더가 배열(중복 전송)', { ...good, 'x-device-sig': [good['x-device-sig'], good['x-device-sig']] }],
    ['먼 미래 시각', await d.sign({ method: 'PUT', url, body: edit, ts: NOW + 3_600_000 })],
    ['12자리 시각', { ...good, 'x-device-ts': String(NOW).slice(1) }],
    ['서명 한 글자 변조', { ...good, 'x-device-sig': (good['x-device-sig'][0] === 'A' ? 'B' : 'A') + good['x-device-sig'].slice(1) }],
    ['지문이 다른(존재하지 않는) 키', { ...good, 'x-device-key': 'f'.repeat(64) }],
  ];
  for (const [label, headers] of cases) {
    const db = world([row(d, A, 'approved')]);
    const out = await apiFor(db)('item')({ method: 'PUT', url, authorization: bearer(A), body: edit, headers });
    assert.equal(out.status, 403, label);
    assert.equal(db.tables.notes[0].title, 'A 가상', `${label}: 자료 불변`);
  }
  // 승인 상태가 pending으로 되돌려졌거나 소유자가 바뀐 행도 같은 서명으로 열리지 않는다.
  for (const [label, mutate] of [['pending', r => { r.status = 'pending'; }], ['소유자 변경', r => { r.owner_id = B; }]]) {
    const dev = row(d, A, 'approved'); mutate(dev);
    const out = await apiFor(world([dev]))('item')({ method: 'PUT', url, authorization: bearer(A), body: edit, headers: good });
    assert.equal(out.status, 403, label);
  }
});
