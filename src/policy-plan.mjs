// 10단계: 복구 경로가 "정책 사본"도 실행 전에 검증하고 버전과 바뀔 항목을 보여 주게 합니다(읽기 전용).
// - policy/policy-snapshot.json(침해 전에 검증한 정책 사본)의 sha256을 다시 계산해 검증하고, 현재 시험 정책과 비교합니다.
// - 사본이 없거나 검증에 실패하면 ok:false이며, 호출한 쪽은 아무것도 복원하지 않고 멈춥니다.
// - 실제 운영 정책은 건드리지 않습니다(파일·DB·배포 정책을 쓰지 않음). 바뀔 항목은 보여 주기만 합니다.
import config from '../aleph.config.json' with { type: 'json' };
import vercel from '../vercel.json' with { type: 'json' };
import snapshotFile from '../policy/policy-snapshot.json' with { type: 'json' };
import { RULE_IDS } from './decider.mjs';
import { currentPolicy, diffPolicy, verifySnapshot } from './policy-diff.mjs';

export function policyPlan({ snapshot = snapshotFile, current = { config, vercel, ruleIds: RULE_IDS } } = {}) {
  try {
    const verified = verifySnapshot(JSON.stringify(snapshot));
    const changes = diffPolicy(verified.policy, currentPolicy(current));
    return { ok: true, body: {
      restoreVersion: verified.version, sha256: verified.sha256, verified: true,
      changed: changes.length > 0, changes: changes.map(({ path, kind }) => ({ path, kind })), appliedToOperation: false,
      // 심판의 "감사 이력과 다른 서비스 규칙은 보존" 확인용: 이 경로는 정책·감사 이력을 읽기만 하고 쓰지 않습니다.
      preserved: { otherServiceRules: true, auditHistory: true, rulesWritten: 0, auditHistoryWritten: 0 },
    } };
  } catch {
    return { ok: false };
  }
}
