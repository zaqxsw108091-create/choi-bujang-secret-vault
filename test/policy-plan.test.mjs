import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { policyPlan } from '../src/policy-plan.mjs';
import { snapshotDigest } from '../src/policy-diff.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { noteContentHash } from '../src/note-restore.mjs';

const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
const snapshot = JSON.parse(readFileSync(new URL('../policy/policy-snapshot.json', import.meta.url), 'utf8'));
const B = '22222222-2222-4222-8222-222222222222';
const NOTE = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1';
const b64 = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const bearer = sub => `Bearer ${b64({ alg: 'ES256' })}.${b64({ iss: config.identityProvider.issuer, aud: config.identityProvider.audience, role: 'authenticated', sub, exp: Math.floor(Date.now() / 1000) + 600 })}.c2ln`;

test('정책 사본은 검증을 통과하고 현재 정책과의 차이가 없으며 운영에는 적용하지 않는다', () => {
  const plan = policyPlan();
  assert.equal(plan.ok, true);
  assert.deepEqual([plan.body.verified, plan.body.changed, plan.body.changes, plan.body.appliedToOperation], [true, false, [], false]);
  assert.equal(plan.body.restoreVersion, snapshot.version);
  assert.equal(plan.body.sha256, snapshot.sha256);
});

test('현재 정책이 사본과 다르면 바뀔 항목(경로·종류)만 보여 주고, 사본이 바뀌었거나 없으면 멈춘다', () => {
  const current = { config: { ...config, allowedRoutes: [...config.allowedRoutes, 'GET /api/export'] }, vercel: {}, ruleIds: [] };
  const changed = policyPlan({ current });
  assert.equal(changed.ok, true);
  assert.ok(changed.body.changed && changed.body.changes.some(c => c.path === 'allowedRoutes' && c.kind === 'added'));
  assert.ok(changed.body.changes.every(c => Object.keys(c).sort().join() === 'kind,path'));
  const tampered = structuredClone(snapshot); tampered.policy.allowedRoutes.push('GET /api/export');
  assert.equal(policyPlan({ snapshot: tampered }).ok, false);
  assert.equal(policyPlan({ snapshot: null }).ok, false);
  const resigned = structuredClone(tampered); resigned.sha256 = snapshotDigest(resigned);
  assert.equal(policyPlan({ snapshot: resigned }).ok, true, '다시 서명한 사본은 형식상 통과(서명 주체는 Git 기록으로 확인)');
});

class Query {
  constructor(db, table) { this.db = db; this.rows = db[table]; this.filters = []; this.op = 'select'; }
  select() { return this; } update(p) { this.op = 'update'; this.p = p; return this; } insert(p) { this.op = 'insert'; this.p = p; return this; }
  eq(c, v) { this.filters.push([c, v]); return this; } maybeSingle() { this.one = true; return this; }
  then(res, rej) { return Promise.resolve(this.run()).then(res, rej); }
  run() {
    const hit = this.rows.filter(r => this.filters.every(([c, v]) => r[c] === v));
    if (this.op === 'insert') { this.rows.push({ ...this.p }); return { data: null, error: null }; }
    if (this.op === 'update') { hit.forEach(r => Object.assign(r, this.p)); return { data: hit, error: null }; }
    return { data: this.one ? hit[0] ?? null : hit, error: null };
  }
}
function restoreApi(getPolicyPlan) {
  const db = { notes: [{ id: NOTE, owner_id: B, title: '변조됨', content: '변조 본문' }],
    notes_backup: [{ note_id: NOTE, owner_id: B, position: null, title: '원래 제목', content: '원래 본문', content_sha256: noteContentHash('원래 제목', '원래 본문') }], notes_restore_audit: [] };
  const verify = createLoginVerifier({ config, supabaseClient: { auth: { getClaims: async t => ({ data: { claims: JSON.parse(Buffer.from(t.split('.')[1], 'base64url').toString()) }, error: null }) } } });
  const api = createNotesApi({ getVerifier: () => verify, getSupabase: () => ({ from: t => new Query(db, t) }), ...(getPolicyPlan ? { getPolicyPlan } : {}) });
  const call = async (body) => {
    const out = {}; const response = { setHeader() {}, status: c => { out.status = c; return response; }, json: p => { out.body = p; return response; } };
    await api.restore({ method: 'POST', headers: { authorization: bearer(B) }, body, url: '/api/restore' }, response);
    return out;
  };
  return { db, call };
}

test('복구 응답과 미리보기에 정책 사본의 검증·버전·바뀔 항목이 실행 전 정보로 들어 있다', async () => {
  const { db, call } = restoreApi();
  const plan = await call({ id: NOTE, dryRun: true });
  assert.deepEqual([plan.status, plan.body.planned, plan.body.policy.verified, plan.body.policy.restoreVersion, plan.body.policy.changes], [200, true, true, snapshot.version, []]);
  assert.equal(db.notes[0].title, '변조됨', '미리보기는 아무것도 바꾸지 않음');
  const done = await call({ id: NOTE });
  assert.deepEqual([done.status, done.body.verified, done.body.policy.verified, done.body.policy.appliedToOperation], [200, true, true, false]);
  assert.equal(db.notes[0].title, '원래 제목');
});

test('정책 사본 검증이 실패하면 자료도 복원하지 않고 409로 멈춘다', async () => {
  const { db, call } = restoreApi(() => ({ ok: false }));
  const before = JSON.stringify(db);
  const result = await call({ id: NOTE });
  assert.deepEqual([result.status, result.body], [409, { error: 'BACKUP_INVALID' }]);
  assert.equal(JSON.stringify(db), before);
});
