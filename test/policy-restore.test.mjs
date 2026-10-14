import test from 'node:test';
import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { RULE_IDS } from '../src/decider.mjs';
import { PolicySnapshotError, currentPolicy } from '../src/policy-diff.mjs';
import { AUDIT_FILE, runRestore } from '../src/policy-restore.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';

const repo = new URL('../', import.meta.url).pathname;
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const A_NOTE = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1';

// 저장소의 정책 파일을 임시 폴더에 복사한 뒤 시험 정책을 변조합니다. 실제 저장소 파일은 건드리지 않습니다.
async function sandbox({ tamper = true, audit = '{"event":"older_entry"}\n' } = {}) {
  const root = await mkdtemp(join(tmpdir(), 'policy-restore-'));
  await mkdir(join(root, 'policy'));
  for (const file of ['aleph.config.json', 'vercel.json', 'policy/policy-snapshot.json']) await cp(join(repo, file), join(root, file));
  await writeFile(join(root, AUDIT_FILE), audit);
  if (tamper) {
    const config = JSON.parse(await readFile(join(root, 'aleph.config.json'), 'utf8'));
    config.allowedRoutes.push('GET /api/export');
    config.identityProvider.audience = 'attacker-audience';
    config.originalApiUrl = 'https://attacker.example.net/rest/v1/notes';
    await writeFile(join(root, 'aleph.config.json'), `${JSON.stringify(config, null, 2)}\n`);
    const vercel = JSON.parse(await readFile(join(root, 'vercel.json'), 'utf8'));
    vercel.headers[0].headers[0].value = 'sniff';
    vercel.headers.push({ source: '/other-service/(.*)', headers: [{ key: 'X-Other-Service', value: 'keep-me' }] });
    await writeFile(join(root, 'vercel.json'), `${JSON.stringify(vercel, null, 2)}\n`);
  }
  return root;
}
const readJson = async (root, file) => JSON.parse(await readFile(join(root, file), 'utf8'));

test('계획만 실행하면 바뀔 항목·버전·확인 코드를 보여 주고 아무것도 쓰지 않는다', async () => {
  const root = await sandbox();
  const before = await Promise.all(['aleph.config.json', 'vercel.json', AUDIT_FILE].map(f => readFile(join(root, f), 'utf8')));
  const { status, plan } = await runRestore({ root, ruleIds: RULE_IDS });
  assert.equal(status, 'planned');
  assert.equal(plan.restoreVersion, 'step9-2026-10-14');
  assert.deepEqual([...new Set(plan.changes.map(c => c.path))].sort(), ['allowedRoutes', 'identityProvider.audience', 'originalApiUrl', 'securityHeaders']);
  assert.match(plan.confirm, /^[a-f0-9]{12}$/u);
  assert.deepEqual(plan.preservedHeaders, ['/other-service/(.*) X-Other-Service: keep-me']);
  const after = await Promise.all(['aleph.config.json', 'vercel.json', AUDIT_FILE].map(f => readFile(join(root, f), 'utf8')));
  assert.deepEqual(after, before);
});

test('확인 코드가 없거나 틀리면 거부하고 아무것도 쓰지 않는다', async () => {
  const root = await sandbox();
  const config = await readFile(join(root, 'aleph.config.json'), 'utf8');
  for (const confirm of [null, '', 'deadbeef0000']) {
    assert.equal((await runRestore({ root, ruleIds: RULE_IDS, apply: true, confirm })).status, 'refused');
  }
  assert.equal(await readFile(join(root, 'aleph.config.json'), 'utf8'), config);
  assert.equal(await readFile(join(root, AUDIT_FILE), 'utf8'), '{"event":"older_entry"}\n');
});

test('계획을 본 뒤 상태가 달라지면 예전 확인 코드는 맞지 않는다', async () => {
  const root = await sandbox();
  const { plan } = await runRestore({ root, ruleIds: RULE_IDS });
  const config = await readJson(root, 'aleph.config.json');
  config.allowedRoutes.push('DELETE /api/export');
  await writeFile(join(root, 'aleph.config.json'), `${JSON.stringify(config, null, 2)}\n`);
  assert.equal((await runRestore({ root, ruleIds: RULE_IDS, apply: true, confirm: plan.confirm })).status, 'refused');
});

test('확인 코드가 맞으면 정책 항목만 되돌리고 다른 설정·다른 서비스 헤더·기존 감사 이력은 보존한다', async () => {
  const root = await sandbox();
  const original = await readJson(repo.replace(/\/$/u, ''), 'aleph.config.json');
  const { plan } = await runRestore({ root, ruleIds: RULE_IDS });
  const result = await runRestore({ root, ruleIds: RULE_IDS, apply: true, confirm: plan.confirm, now: () => new Date('2026-10-15T00:00:00Z') });
  assert.equal(result.status, 'restored');
  const config = await readJson(root, 'aleph.config.json');
  assert.deepEqual(config, original, '변조 전 설정과 같아졌다(정책 밖 항목 포함 전부)');
  const vercel = await readJson(root, 'vercel.json');
  assert.equal(vercel.headers[0].headers[0].value, 'nosniff');
  assert.deepEqual(vercel.headers[1], { source: '/other-service/(.*)', headers: [{ key: 'X-Other-Service', value: 'keep-me' }] });
  assert.equal(vercel.buildCommand, 'npm run build');
  // 감사 이력: 기존 줄이 그대로 앞에 있고 새 줄이 덧붙었다. 메모·토큰·ID가 없다.
  const audit = (await readFile(join(root, AUDIT_FILE), 'utf8')).split('\n');
  assert.equal(audit[0], '{"event":"older_entry"}');
  const entry = JSON.parse(audit[1]);
  assert.deepEqual([entry.event, entry.restoreVersion, entry.at], ['policy_restore', 'step9-2026-10-14', '2026-10-15T00:00:00.000Z']);
  assert.deepEqual(entry.changedPaths.sort(), ['allowedRoutes', 'identityProvider.audience', 'originalApiUrl', 'securityHeaders']);
  assert.ok(!/token|password|owner_id|content/iu.test(audit[1]));
  // 되돌린 뒤에는 다시 계획해도 바꿀 것이 없고, 이력은 한 줄 더 늘지 않는다.
  assert.equal((await runRestore({ root, ruleIds: RULE_IDS })).status, 'nothing_to_restore');
  assert.equal((await readFile(join(root, AUDIT_FILE), 'utf8')).split('\n').length, 3);
});

test('판정기 규칙(ruleIds) 차이는 자동 복원 불가로 보여 주기만 하고 코드는 건드리지 않는다', async () => {
  const root = await sandbox({ tamper: false });
  const { status, plan } = await runRestore({ root, ruleIds: RULE_IDS.filter(r => r !== 'route_unknown') });
  assert.equal(status, 'nothing_to_restore');
  assert.deepEqual(plan.unrestorable.map(c => [c.kind, c.before ?? c.after]), [['removed', 'route_unknown']]);
});

test('사본이 없거나 바뀌었으면 중단하고 아무것도 쓰지 않는다', async () => {
  const gone = await sandbox();
  await writeFile(join(gone, 'policy/policy-snapshot.json'), '');
  await assert.rejects(runRestore({ root: gone, ruleIds: RULE_IDS }), e => e instanceof PolicySnapshotError && e.code === 'snapshot_missing');
  const bad = await sandbox();
  const snap = await readJson(bad, 'policy/policy-snapshot.json');
  snap.policy.allowedRoutes.push('GET /api/export');
  await writeFile(join(bad, 'policy/policy-snapshot.json'), JSON.stringify(snap));
  const config = await readFile(join(bad, 'aleph.config.json'), 'utf8');
  await assert.rejects(runRestore({ root: bad, ruleIds: RULE_IDS, apply: true, confirm: 'x' }), e => e.code === 'snapshot_digest');
  assert.equal(await readFile(join(bad, 'aleph.config.json'), 'utf8'), config);
  await assert.rejects(runRestore({ root: await mkdtemp(join(tmpdir(), 'policy-restore-')), ruleIds: RULE_IDS }), e => e.code === 'snapshot_missing');
});

// ---- 확인: 되돌린 정책으로 B의 A 자료 요청은 거부되고, A의 정상 요청은 유지됩니다 ----
const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const bearer = (config, sub) => `Bearer ${b64({ alg: 'ES256', typ: 'JWT' })}.${b64({
  iss: config.identityProvider.issuer, aud: 'authenticated', role: 'authenticated', sub, exp: Math.floor(Date.now() / 1000) + 600,
})}.c2ln`;

class FakeQuery {
  constructor(rows) { this.rows = rows; this.op = 'select'; this.filters = []; }
  select() { return this; }
  insert(p) { this.op = 'insert'; this.payload = p; return this; }
  update(p) { this.op = 'update'; this.payload = p; return this; }
  delete() { this.op = 'delete'; return this; }
  eq(c, v) { this.filters.push([c, v]); return this; }
  order() { return this; }
  single() { this.mode = 'one'; return this; }
  maybeSingle() { this.mode = 'one'; return this; }
  then(res, rej) { return Promise.resolve(this.run()).then(res, rej); }
  run() {
    const hit = () => this.rows.filter(r => this.filters.every(([c, v]) => r[c] === v));
    let data;
    if (this.op === 'insert') { const row = { id: randomUUID(), ...this.payload }; this.rows.push(row); data = [row]; }
    else if (this.op === 'update') { data = hit(); data.forEach(r => Object.assign(r, this.payload)); }
    else if (this.op === 'delete') { data = hit(); this.rows.splice(0, this.rows.length, ...this.rows.filter(r => !data.includes(r))); }
    else data = hit();
    return { data: this.mode === 'one' ? data[0] ?? null : data, error: null };
  }
}

function notesApiFor(config, rows) {
  const verify = createLoginVerifier({ config, supabaseClient: { auth: { getClaims: async token => ({ data: { claims: JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString()) }, error: null }) } } });
  const api = createNotesApi({ getVerifier: () => verify, getSupabase: () => ({ from: () => new FakeQuery(rows) }) });
  const call = async (handler, { method = 'GET', authorization, body, id }) => {
    const out = {};
    const response = { setHeader() {}, status: c => { out.status = c; return response; }, json: p => { out.body = p; return response; } };
    await handler({ method, headers: { authorization }, body, query: id === undefined ? {} : { id }, url: id === undefined ? '/api/notes' : `/api/notes/${id}` }, response);
    return out;
  };
  return { list: o => call(api.collection, o), item: o => call(api.item, o) };
}

test('변조된 정책에서는 A의 정상 요청도 거부되고, 되돌린 뒤에는 A는 열리고 B의 A 자료 요청은 읽기·수정·삭제 모두 403이다', async () => {
  const root = await sandbox();
  const rows = () => [{ id: A_NOTE, owner_id: A, title: 'A의 메모', content: 'A 본문' }, { id: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1', owner_id: B, title: 'B', content: 'b' }];
  const tampered = await readJson(root, 'aleph.config.json');
  assert.equal((await notesApiFor(tampered, rows()).list({ authorization: bearer(tampered, A) })).status, 401, '변조 상태: 정상 사용자가 막힌다');

  const { plan } = await runRestore({ root, ruleIds: RULE_IDS });
  await runRestore({ root, ruleIds: RULE_IDS, apply: true, confirm: plan.confirm });
  const restored = await readJson(root, 'aleph.config.json');
  assert.deepEqual(currentPolicy({ config: restored, vercel: await readJson(root, 'vercel.json'), ruleIds: RULE_IDS }).allowedRoutes.includes('GET /api/export'), false);

  const data = rows();
  const before = JSON.stringify(data);
  const api = notesApiFor(restored, data);
  // A 정상 요청 유지
  assert.deepEqual((await api.list({ authorization: bearer(restored, A) })).body, [{ id: A_NOTE, title: 'A의 메모', body: 'A 본문' }]);
  assert.deepEqual((await api.item({ authorization: bearer(restored, A), id: A_NOTE })).body, { id: A_NOTE, title: 'A의 메모', body: 'A 본문' });
  // B의 A 자료 요청 거부
  const asB = { authorization: bearer(restored, B), id: A_NOTE };
  for (const request of [{ ...asB }, { ...asB, method: 'PUT', body: { title: '가로챔', body: 'x', owner_id: B } }, { ...asB, method: 'DELETE' }]) {
    const result = await api.item(request);
    assert.deepEqual([result.status, result.body], [403, { error: 'FORBIDDEN' }]);
  }
  assert.equal(JSON.stringify(data), before, 'A의 메모는 바뀌지 않았다');
  // A의 수정은 여전히 된다
  assert.equal((await api.item({ method: 'PUT', authorization: bearer(restored, A), id: A_NOTE, body: { title: '수정', body: '본문' } })).status, 200);
});

test('바뀐 것이 없어도 --apply 실행은 확인 사실만 감사 이력에 덧붙이고 정책은 쓰지 않는다', async () => {
  const root = await sandbox({ tamper: false });
  const before = await readFile(join(root, 'aleph.config.json'), 'utf8');
  const result = await runRestore({ root, ruleIds: RULE_IDS, apply: true });
  assert.equal(result.status, 'nothing_to_restore');
  const lines = (await readFile(join(root, AUDIT_FILE), 'utf8')).trim().split('\n').map(line => JSON.parse(line));
  assert.deepEqual(lines.map(line => [line.event, line.changeCount]), [['older_entry', undefined], ['policy_restore_checked', 0]]);
  assert.equal(await readFile(join(root, 'aleph.config.json'), 'utf8'), before);
});
