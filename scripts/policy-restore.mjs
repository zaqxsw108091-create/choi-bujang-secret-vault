// 10단계 제작 2: 검증한 정책 사본으로 시험 정책을 되돌리는 절차입니다.
// npm run policy:restore                         → 바뀔 항목만 보여 줍니다(아무것도 쓰지 않음).
// npm run policy:restore -- --apply --confirm 코드 → 보여 준 계획의 확인 코드가 맞을 때만 되돌립니다.
// 종료 코드: 0 = 되돌림 또는 바꿀 것 없음, 1 = 계획만 보여 줌, 2 = 중단(사본 오류·확인 코드 불일치·복원 불완전)
import { RULE_IDS } from '../src/decider.mjs';
import { PolicySnapshotError } from '../src/policy-diff.mjs';
import { formatRestorePlan, runRestore } from '../src/policy-restore.mjs';

const args = process.argv.slice(2);
const apply = args.includes('--apply');
const at = args.indexOf('--confirm');
const confirm = at >= 0 ? args[at + 1] ?? null : null;
const root = new URL('../', import.meta.url).pathname;

try {
  const result = await runRestore({ root, ruleIds: RULE_IDS, apply, confirm });
  console.log(formatRestorePlan(result.plan));
  if (result.status === 'nothing_to_restore') {
    console.log('되돌릴 항목이 없습니다. 아무것도 바꾸지 않았습니다.');
  } else if (result.status === 'planned') {
    console.log('\n아직 아무것도 바꾸지 않았습니다. 위 항목이 맞으면 아래 한 줄을 실행하세요.');
    console.log(`npm run policy:restore -- --apply --confirm ${result.plan.confirm}`);
    process.exitCode = 1;
  } else if (result.status === 'refused') {
    console.error('\n중단: 확인 코드가 맞지 않습니다. 위 계획을 확인한 뒤 계획 화면에 나온 코드로 다시 실행하세요. 아무것도 바꾸지 않았습니다.');
    process.exitCode = 2;
  } else {
    console.log(`\n되돌렸습니다. 감사 이력에 한 줄을 덧붙였습니다(policy/restore-audit.jsonl). 확인: npm run policy:diff`);
  }
} catch (error) {
  if (!(error instanceof PolicySnapshotError)) throw error;
  console.error(`중단: ${error.code} · ${error.message}`);
  console.error('아무것도 바꾸지 않았습니다.');
  process.exitCode = 2;
}
