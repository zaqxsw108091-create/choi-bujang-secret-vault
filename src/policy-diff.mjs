// 10단계 제작 1: 침해 전에 검증한 안전 정책 사본과 현재 시험 정책의 차이만 계산합니다.
// 읽기 전용입니다. 파일·DB·배포 정책을 쓰거나 바꾸지 않고, 사본이 없거나 검증에 실패하면 차이를 계산하지 않고 중단합니다.
// 정책 값에는 비밀값이 없습니다: 허용 경로, 판정기 규칙 이름, 응답 보안 헤더, 로그인 발급자·대상, 원본 API 주소만 봅니다.
import { createHash } from 'node:crypto';

export const SNAPSHOT_SCHEMA = 'aleph.policy-snapshot.v1';
const SHA256 = /^[a-f0-9]{64}$/u;

export class PolicySnapshotError extends Error {
  constructor(code, message) { super(message); this.name = 'PolicySnapshotError'; this.code = code; }
}

const isObject = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const sortedStrings = list => [...list].sort();

// 현재 시험 정책: 설정·판정기·배포 헤더에서 정책 값만 뽑습니다.
export function currentPolicy({ config, vercel, ruleIds }) {
  const headers = (vercel?.headers ?? []).flatMap(rule =>
    (rule.headers ?? []).map(h => `${rule.source} ${h.key}: ${h.value}`));
  return {
    allowedRoutes: sortedStrings(config?.allowedRoutes ?? []),
    ruleIds: sortedStrings(ruleIds ?? []),
    securityHeaders: sortedStrings(headers),
    identityProvider: {
      issuer: config?.identityProvider?.issuer ?? null,
      audience: config?.identityProvider?.audience ?? null,
    },
    originalApiUrl: config?.originalApiUrl ?? null,
  };
}

// 키 순서를 고정한 JSON으로 만들어, 같은 내용이면 항상 같은 요약값이 나오게 합니다.
export function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isObject(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  return JSON.stringify(value);
}

export const snapshotDigest = ({ schema, version, policy }) =>
  createHash('sha256').update(canonicalJson({ schema, version, policy })).digest('hex');

// 사본 검증. 어느 하나라도 틀리면 PolicySnapshotError(code)를 던집니다. 통과하면 { version, sha256, policy }를 돌려줍니다.
export function verifySnapshot(text) {
  if (typeof text !== 'string' || text.trim() === '') {
    throw new PolicySnapshotError('snapshot_missing', '정책 사본이 없거나 비어 있습니다.');
  }
  let snapshot;
  try { snapshot = JSON.parse(text); } catch {
    throw new PolicySnapshotError('snapshot_unreadable', '정책 사본을 JSON으로 읽을 수 없습니다.');
  }
  if (!isObject(snapshot) || snapshot.schema !== SNAPSHOT_SCHEMA) {
    throw new PolicySnapshotError('snapshot_schema', `정책 사본 형식이 ${SNAPSHOT_SCHEMA}이 아닙니다.`);
  }
  if (typeof snapshot.version !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/u.test(snapshot.version)) {
    throw new PolicySnapshotError('snapshot_version', '정책 사본의 version이 없거나 모양이 틀립니다.');
  }
  const { policy } = snapshot;
  if (!isObject(policy) || !Array.isArray(policy.allowedRoutes) || !Array.isArray(policy.ruleIds)
    || !Array.isArray(policy.securityHeaders) || !isObject(policy.identityProvider)
    || ![policy.allowedRoutes, policy.ruleIds, policy.securityHeaders].every(l => l.every(v => typeof v === 'string'))) {
    throw new PolicySnapshotError('snapshot_policy', '정책 사본의 policy 모양이 틀립니다.');
  }
  if (typeof snapshot.sha256 !== 'string' || !SHA256.test(snapshot.sha256)
    || snapshot.sha256 !== snapshotDigest(snapshot)) {
    throw new PolicySnapshotError('snapshot_digest', '정책 사본의 sha256이 내용과 맞지 않습니다. 사본이 바뀌었을 수 있습니다.');
  }
  return { version: snapshot.version, sha256: snapshot.sha256, policy };
}

// 사본(before)과 현재(after)의 차이만 돌려줍니다. 같은 항목은 담지 않습니다.
// 항목: { path, kind: 'added'|'removed'|'changed', before, after } — 목록은 값 하나씩, 단일 값은 바뀐 값 하나.
export function diffPolicy(before, after) {
  const changes = [];
  for (const key of ['allowedRoutes', 'ruleIds', 'securityHeaders']) {
    const was = new Set(before[key]); const now = new Set(after[key]);
    for (const v of sortedStrings(was)) if (!now.has(v)) changes.push({ path: key, kind: 'removed', before: v, after: null });
    for (const v of sortedStrings(now)) if (!was.has(v)) changes.push({ path: key, kind: 'added', before: null, after: v });
  }
  const single = [
    ['identityProvider.issuer', before.identityProvider?.issuer ?? null, after.identityProvider?.issuer ?? null],
    ['identityProvider.audience', before.identityProvider?.audience ?? null, after.identityProvider?.audience ?? null],
    ['originalApiUrl', before.originalApiUrl ?? null, after.originalApiUrl ?? null],
  ];
  for (const [path, was, now] of single) if (was !== now) changes.push({ path, kind: 'changed', before: was, after: now });
  return changes;
}

// 실행 전 보여 줄 보고서: 복원할 버전(사본)·요약값·변경 범위를 먼저 적습니다.
export function planPolicyDiff(snapshotText, current) {
  const snapshot = verifySnapshot(snapshotText);
  const changes = diffPolicy(snapshot.policy, current);
  return { restoreVersion: snapshot.version, sha256: snapshot.sha256, changes, paths: [...new Set(changes.map(c => c.path))] };
}

export function formatPlan(plan) {
  const lines = [
    `복원할 정책 사본 버전: ${plan.restoreVersion}`,
    `사본 sha256: ${plan.sha256} (검증 통과)`,
    `변경 범위: ${plan.changes.length === 0 ? '없음 (현재 정책이 사본과 같습니다)' : `${plan.changes.length}건 · ${plan.paths.join(', ')}`}`,
  ];
  const mark = { added: '+ 현재에만 있음', removed: '- 사본에만 있음', changed: '~ 값이 다름' };
  for (const c of plan.changes) {
    lines.push(c.kind === 'changed'
      ? `  ${mark.changed}  ${c.path}: 사본 ${c.before ?? '(없음)'} → 현재 ${c.after ?? '(없음)'}`
      : `  ${mark[c.kind]}  ${c.path}: ${c.before ?? c.after}`);
  }
  lines.push('이 화면은 차이를 보여 주기만 했습니다. 아무것도 바꾸거나 복원하지 않았습니다.');
  return lines.join('\n');
}
