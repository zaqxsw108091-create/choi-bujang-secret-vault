// 제출 전 확인: 마지막 커밋이 병합 커밋이 아니고 바뀐 파일이 있어야 `npm run bundle`(scripts/bundle.mjs)이 만들어집니다.
// 읽기만 하며 아무것도 바꾸지 않습니다. 비밀값은 다루지 않습니다.
import { execFileSync } from 'node:child_process';

const git = (...args) => execFileSync('git', args, { encoding: 'utf8', timeout: 5000 }).trim();
try {
  const [commit, ...parents] = git('rev-list', '--parents', '-n', '1', 'HEAD').split(' ');
  const files = git('diff-tree', '--root', '--no-commit-id', '--name-only', '--no-renames', '-r', commit).split(/\r?\n/u).filter(Boolean);
  console.log(`마지막 커밋 ${commit.slice(0, 7)} · 부모 ${parents.length}개 · 바뀐 파일 ${files.length}개`);
  if (parents.length > 1) throw new Error('병합 커밋입니다. bundle이 바뀐 파일을 찾지 못합니다. GitHub에서 Squash and merge로 합치거나 일반 커밋을 하나 더 올리세요.');
  if (!files.length) throw new Error('마지막 커밋에 바뀐 파일이 없습니다. 실제 변경이 담긴 일반 커밋이 필요합니다.');
  console.log('통과: 일반 커밋이고 바뀐 파일이 있습니다.');
} catch (error) {
  console.error(`확인 실패: ${error.message}`);
  process.exitCode = 1;
}
