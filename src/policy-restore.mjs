// 10단계 제작 2: 검증한 정책 사본(policy/policy-snapshot.json)의 버전으로 시험 정책을 되돌립니다.
// - 사본이 없거나 검증에 실패하면 아무것도 쓰지 않고 중단합니다(제작 1의 verifySnapshot 사용).
// - 기본은 계획만 보여 줍니다. 실제 쓰기는 apply와 확인 코드가 모두 맞을 때만 합니다.
//   확인 코드는 "사본 sha256 + 지금 바뀔 항목 목록"에서 만들어서, 계획을 본 뒤 상태가 달라졌으면 맞지 않습니다.
// - 고치는 곳: aleph.config.json의 allowedRoutes·identityProvider(issuer, audience)·originalApiUrl,
//   vercel.json 헤더 중 사본에 있는 (경로, 이름) 짝. 그 밖의 설정(step, repoUrl, judgeIssuer …), 사본에 없는 다른 헤더,
//   src/·api/ 코드, DB·RLS, 기존 감사 이력은 바꾸지 않습니다.
// - 판정기 규칙 이름(ruleIds)은 코드에 있어서 이 절차가 되돌리지 못합니다. 차이가 있으면 "자동 복원 불가"로 보여 주기만 합니다.
// - 감사 이력(policy/restore-audit.jsonl)은 한 줄씩 덧붙이기만 합니다. 정책 값 요약만 적고 메모·토큰·사용자 ID는 적지 않습니다.
import { createHash } from 'node:crypto';
import { appendFile, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { PolicySnapshotError, canonicalJson, currentPolicy, diffPolicy, verifySnapshot } from './policy-diff.mjs';

export const AUDIT_FILE = 'policy/restore-audit.jsonl';
const SNAPSHOT_FILE = 'policy/policy-snapshot.json';
const sha = value => createHash('sha256').update(canonicalJson(value)).digest('hex');
export const policyDigest = policy => sha(policy);

// "<경로> <이름>: <값>" 한 줄을 { source, key, value }로 읽습니다. 모양이 틀리면 null.
export function parseHeaderLine(line) {
  const match = /^(\S+) ([^:\s]+): (.*)$/u.exec(line);
  return match ? { source: match[1], key: match[2], value: match[3] } : null;
}

// 사본 정책으로 되돌린 새 설정·배포 정책 객체를 만듭니다(원본은 바꾸지 않음).
export function buildRestored({ config, vercel }, snapshotPolicy) {
  const next = structuredClone(config);
  const now = new Set(next.allowedRoutes ?? []);
  const keep = new Set(snapshotPolicy.allowedRoutes);
  // 사본에 없는 경로는 빼고, 사본에만 있는 경로는 사본 순서로 뒤에 붙입니다. 남는 경로의 현재 순서는 지킵니다.
  next.allowedRoutes = [...(next.allowedRoutes ?? []).filter(route => keep.has(route)),
    ...snapshotPolicy.allowedRoutes.filter(route => !now.has(route))];
  const idp = { ...(next.identityProvider ?? {}) };
  const wantIssuer = snapshotPolicy.identityProvider?.issuer ?? null;
  const wantAudience = snapshotPolicy.identityProvider?.audience ?? null;
  if (idp.issuer !== wantIssuer) {
    idp.issuer = wantIssuer;
    idp.jwksUrl = wantIssuer ? `${wantIssuer}/.well-known/jwks.json` : null;
  }
  idp.audience = wantAudience;
  next.identityProvider = idp;
  next.originalApiUrl = snapshotPolicy.originalApiUrl ?? null;

  const nextVercel = structuredClone(vercel);
  nextVercel.headers = nextVercel.headers ?? [];
  for (const line of snapshotPolicy.securityHeaders) {
    const want = parseHeaderLine(line);
    if (!want) continue;
    let rule = nextVercel.headers.find(r => r.source === want.source);
    if (!rule) { rule = { source: want.source, headers: [] }; nextVercel.headers.push(rule); }
    rule.headers = rule.headers ?? [];
    const found = rule.headers.find(h => h.key.toLowerCase() === want.key.toLowerCase());
    if (found) { found.key = want.key; found.value = want.value; } else rule.headers.push({ key: want.key, value: want.value });
  }
  return { config: next, vercel: nextVercel };
}

// 계획: 바뀔 항목, 보존할 것, 자동 복원 불가 항목, 확인 코드를 돌려줍니다. 아무것도 쓰지 않습니다.
export function planRestore({ snapshotText, config, vercel, ruleIds }) {
  const snapshot = verifySnapshot(snapshotText);
  const before = currentPolicy({ config, vercel, ruleIds });
  const diff = diffPolicy(snapshot.policy, before);
  const restored = buildRestored({ config, vercel }, snapshot.policy);
  const after = currentPolicy({ config: restored.config, vercel: restored.vercel, ruleIds });
  const remaining = diffPolicy(snapshot.policy, after);
  const unrestorable = remaining.filter(c => c.path === 'ruleIds');
  // 사본 범위 밖이라 그대로 두는 현재 헤더(다른 서비스 규칙일 수 있음)
  const preservedHeaders = remaining.filter(c => c.path === 'securityHeaders' && c.kind === 'added').map(c => c.after);
  const stuck = remaining.filter(c => c.path !== 'ruleIds' && !(c.path === 'securityHeaders' && c.kind === 'added'));
  const changes = diff.filter(c => !(c.path === 'ruleIds'))
    .filter(c => !(c.path === 'securityHeaders' && c.kind === 'added' && preservedHeaders.includes(c.after)));
  const confirm = sha({ snapshot: snapshot.sha256, changes }).slice(0, 12);
  return {
    restoreVersion: snapshot.version, sha256: snapshot.sha256, changes, unrestorable, preservedHeaders, stuck, confirm,
    beforeDigest: policyDigest(before), afterDigest: policyDigest(after), restored,
    preserved: ['설정의 다른 항목(step, repoUrl, publicAppUrl, judgeIssuer, restoreRoute …)', 'src/·api/ 코드와 판정기 규칙', 'DB·RLS·권한 SQL', `감사 이력 ${AUDIT_FILE}(덧붙이기만 함)`],
  };
}

export function formatRestorePlan(plan) {
  const mark = { added: '- 지움(사본에 없음)', removed: '+ 되돌림(사본에 있음)', changed: '~ 값 되돌림' };
  const lines = [
    `복원할 정책 사본 버전: ${plan.restoreVersion}`,
    `사본 sha256: ${plan.sha256} (검증 통과)`,
    `바뀔 항목: ${plan.changes.length === 0 ? '없음' : `${plan.changes.length}건 · ${[...new Set(plan.changes.map(c => c.path))].join(', ')}`}`,
  ];
  for (const c of plan.changes) {
    lines.push(c.kind === 'changed'
      ? `  ${mark.changed}  ${c.path}: 현재 ${c.after ?? '(없음)'} → 사본 ${c.before ?? '(없음)'}`
      : c.kind === 'added'
        ? `  ${mark.added}  ${c.path}: ${c.after}`
        : `  ${mark.removed}  ${c.path}: ${c.before}`);
  }
  for (const c of plan.unrestorable) {
    lines.push(`  ! 자동 복원 불가  ruleIds: ${c.kind === 'removed' ? `사본에만 있음 ${c.before}` : `현재에만 있음 ${c.after}`} (코드 src/decider.mjs 변경이 필요해 이 절차는 바꾸지 않음)`);
  }
  for (const header of plan.preservedHeaders) lines.push(`  = 그대로 둠(사본 범위 밖)  securityHeaders: ${header}`);
  lines.push(`보존: ${plan.preserved.join(' / ')}`);
  return lines.join('\n');
}

const readJson = async path => JSON.parse(await readFile(path, 'utf8'));
const writeAtomic = async (path, text) => { const tmp = `${path}.restore-tmp`; await writeFile(tmp, text); await rename(tmp, path); };

// 파일 단위 실행. apply가 아니면 계획만 돌려줍니다. apply이면 confirm이 계획의 확인 코드와 같을 때만 씁니다.
// 결과 status: 'nothing_to_restore' | 'planned' | 'refused' | 'restored'
export async function runRestore({ root, ruleIds, apply = false, confirm = null, now = () => new Date() }) {
  let snapshotText;
  try { snapshotText = await readFile(join(root, SNAPSHOT_FILE), 'utf8'); } catch {
    throw new PolicySnapshotError('snapshot_missing', `정책 사본 파일을 읽을 수 없습니다: ${SNAPSHOT_FILE}`);
  }
  const configPath = join(root, 'aleph.config.json');
  const vercelPath = join(root, 'vercel.json');
  const [configText, vercelText] = [await readFile(configPath, 'utf8'), await readFile(vercelPath, 'utf8')];
  const plan = planRestore({ snapshotText, config: JSON.parse(configText), vercel: JSON.parse(vercelText), ruleIds });
  if (plan.stuck.length > 0) {
    throw new PolicySnapshotError('restore_incomplete', `복원 뒤에도 남는 차이가 있어 쓰지 않습니다: ${plan.stuck.map(c => c.path).join(', ')}`);
  }
  if (plan.changes.length === 0) {
    // 바꿀 것이 없어도 --apply로 실행했다면 "사본을 검증했고 바뀐 것이 없었다"는 사실만 감사 이력에 덧붙입니다(정책은 쓰지 않음).
    if (!apply) return { status: 'nothing_to_restore', plan };
    const checked = { at: now().toISOString(), event: 'policy_restore_checked', restoreVersion: plan.restoreVersion, snapshotSha256: plan.sha256,
      beforePolicySha256: plan.beforeDigest, afterPolicySha256: plan.beforeDigest, changedPaths: [], changeCount: 0, notRestored: [] };
    await appendFile(join(root, AUDIT_FILE), `${JSON.stringify(checked)}\n`);
    return { status: 'nothing_to_restore', plan, audit: checked };
  }
  if (!apply) return { status: 'planned', plan };
  if (confirm !== plan.confirm) return { status: 'refused', plan, reason: 'confirm_mismatch' };

  const nextConfigText = `${JSON.stringify(plan.restored.config, null, 2)}\n`;
  const headersChanged = plan.changes.some(c => c.path === 'securityHeaders');
  const nextVercelText = headersChanged ? `${JSON.stringify(plan.restored.vercel, null, 2)}\n` : vercelText;
  await writeAtomic(configPath, nextConfigText);
  try {
    if (headersChanged) await writeAtomic(vercelPath, nextVercelText);
  } catch (error) {
    await writeAtomic(configPath, configText);
    throw error;
  }
  // 감사 이력은 덧붙이기만 합니다.
  const entry = {
    at: now().toISOString(), event: 'policy_restore', restoreVersion: plan.restoreVersion, snapshotSha256: plan.sha256,
    beforePolicySha256: plan.beforeDigest, afterPolicySha256: plan.afterDigest,
    changedPaths: [...new Set(plan.changes.map(c => c.path))], changeCount: plan.changes.length,
    notRestored: plan.unrestorable.length > 0 ? ['ruleIds'] : [],
  };
  await appendFile(join(root, AUDIT_FILE), `${JSON.stringify(entry)}\n`);
  return { status: 'restored', plan, audit: entry };
}
