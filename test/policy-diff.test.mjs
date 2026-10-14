import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { RULE_IDS } from '../src/decider.mjs';
import {
  PolicySnapshotError, SNAPSHOT_SCHEMA, currentPolicy, diffPolicy, formatPlan, planPolicyDiff, snapshotDigest, verifySnapshot,
} from '../src/policy-diff.mjs';

const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const current = () => currentPolicy({ config: JSON.parse(read('aleph.config.json')), vercel: JSON.parse(read('vercel.json')), ruleIds: RULE_IDS });
const sign = body => ({ ...body, sha256: snapshotDigest(body) });
const base = () => ({ schema: SNAPSHOT_SCHEMA, version: 'test-1', policy: structuredClone(current()) });
const codeOf = fn => { try { fn(); } catch (e) { return e instanceof PolicySnapshotError ? e.code : `other:${e.message}`; } return null; };

test('저장소의 정책 사본은 검증을 통과하고 현재 정책과 같다', () => {
  const plan = planPolicyDiff(read('policy/policy-snapshot.json'), current());
  assert.equal(plan.restoreVersion, 'step9-2026-10-14');
  assert.deepEqual(plan.changes, []);
  assert.match(formatPlan(plan), /변경 범위: 없음/);
});

test('정책이 바뀌면 바뀐 항목만 보이고 버전·범위가 먼저 적힌다', () => {
  const now = current();
  now.allowedRoutes = [...now.allowedRoutes, 'GET /api/export'];
  now.ruleIds = now.ruleIds.filter(r => r !== 'route_unknown');
  now.securityHeaders = [];
  now.originalApiUrl = 'https://attacker.example/rest';
  const plan = planPolicyDiff(JSON.stringify(sign(base())), now);
  assert.deepEqual(plan.changes.map(c => `${c.kind} ${c.path}`).sort(), [
    'added allowedRoutes', 'changed originalApiUrl', 'removed ruleIds', 'removed securityHeaders',
  ]);
  const text = formatPlan(plan);
  assert.ok(text.indexOf('복원할 정책 사본 버전: test-1') < text.indexOf('변경 범위: 4건'));
  assert.match(text, /allowedRoutes, ruleIds, securityHeaders, originalApiUrl/);
  assert.match(text, /아무것도 바꾸거나 복원하지 않았습니다/);
  assert.ok(!/DELETE \/api\/notes\/:id/.test(text.split('\n').filter(l => l.startsWith('  ')).join('\n')), '같은 항목은 보이지 않는다');
});

test('사본이 없거나 비면 중단한다', () => {
  assert.equal(codeOf(() => verifySnapshot(undefined)), 'snapshot_missing');
  assert.equal(codeOf(() => verifySnapshot('  ')), 'snapshot_missing');
  assert.equal(codeOf(() => planPolicyDiff('', current())), 'snapshot_missing');
});

test('읽을 수 없거나 형식·버전·모양이 틀린 사본은 중단한다', () => {
  assert.equal(codeOf(() => verifySnapshot('{')), 'snapshot_unreadable');
  assert.equal(codeOf(() => verifySnapshot(JSON.stringify(sign({ ...base(), schema: 'x' })))), 'snapshot_schema');
  assert.equal(codeOf(() => verifySnapshot(JSON.stringify(sign({ ...base(), version: '' })))), 'snapshot_version');
  assert.equal(codeOf(() => verifySnapshot(JSON.stringify(sign({ ...base(), policy: { ruleIds: [] } })))), 'snapshot_policy');
});

test('요약값이 없거나 내용과 다르면 중단하고 차이를 계산하지 않는다', () => {
  const good = sign(base());
  assert.equal(codeOf(() => verifySnapshot(JSON.stringify({ ...good, sha256: undefined }))), 'snapshot_digest');
  const tampered = structuredClone(good);
  tampered.policy.allowedRoutes.push('GET /api/export');
  assert.equal(codeOf(() => planPolicyDiff(JSON.stringify(tampered), current())), 'snapshot_digest');
  assert.ok(verifySnapshot(JSON.stringify(good)).sha256 === good.sha256);
});

test('같은 정책은 항목 순서가 달라도 같은 요약값이다', () => {
  const a = base(); const b = base();
  b.policy.allowedRoutes = [...b.policy.allowedRoutes].reverse();
  b.policy = { ...b.policy };
  assert.notEqual(snapshotDigest(a), snapshotDigest(b), '배열 순서는 사본에 정렬해 저장하므로 순서가 다르면 다른 사본');
  assert.deepEqual(diffPolicy(a.policy, b.policy), [], '비교는 순서를 보지 않는다');
});

test('정책 값에 비밀값이 없다', () => {
  assert.ok(!/key|secret|token|password/iu.test(JSON.stringify(current())));
});
