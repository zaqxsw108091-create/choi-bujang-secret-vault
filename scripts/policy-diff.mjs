// 10단계 제작 1: 정책 사본과 현재 시험 정책의 차이만 보여 줍니다. 아무것도 쓰지 않습니다.
// 종료 코드: 0 = 차이 없음, 1 = 차이를 보여 줌, 2 = 사본이 없거나 검증 실패로 중단
import { readFile } from 'node:fs/promises';
import { RULE_IDS } from '../src/decider.mjs';
import { PolicySnapshotError, currentPolicy, formatPlan, planPolicyDiff } from '../src/policy-diff.mjs';

const root = new URL('../', import.meta.url);
const read = async path => readFile(new URL(path, root), 'utf8');
const snapshotPath = process.argv[2] ?? 'policy/policy-snapshot.json';

try {
  let snapshotText;
  try { snapshotText = await (process.argv[2] ? readFile(snapshotPath, 'utf8') : read(snapshotPath)); } catch {
    throw new PolicySnapshotError('snapshot_missing', `정책 사본 파일을 읽을 수 없습니다: ${snapshotPath}`);
  }
  const current = currentPolicy({
    config: JSON.parse(await read('aleph.config.json')),
    vercel: JSON.parse(await read('vercel.json')),
    ruleIds: RULE_IDS,
  });
  const plan = planPolicyDiff(snapshotText, current);
  console.log(formatPlan(plan));
  process.exitCode = plan.changes.length === 0 ? 0 : 1;
} catch (error) {
  if (!(error instanceof PolicySnapshotError)) throw error;
  console.error(`중단: ${error.code} · ${error.message}`);
  console.error('차이를 계산하지 않았고 아무것도 바꾸지 않았습니다.');
  process.exitCode = 2;
}
