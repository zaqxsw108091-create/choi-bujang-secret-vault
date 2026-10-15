// 12단계 제작 2: npm run matrix — 1~11단계의 정상·금지 요청을 배포 서버에 실제로 보내 표로 남깁니다.
// - 시험 계정 두 개(A, B)와 가상 메모로만 쓰세요. 로그인 요청은 정확히 2번이며 실패해도 다시 시도하지 않습니다.
// - 비밀번호·토큰은 화면에 보이지 않고 저장·출력하지 않습니다. 결과는 artifacts/ 아래(커밋하지 않음)에만 씁니다.
// - 기기 승인은 자료실 주인이 서버(SQL Editor, sql/11-devices.sql의 [B]·[C])에서 직접 합니다. 이 명령은 승인하지 않습니다.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { loginForTokens } from '../src/live-credentials.mjs';
import { ask } from '../src/prompt.mjs';
import { renderTable, runRegression } from '../src/regression-table.mjs';

const root = new URL('../', import.meta.url);
const config = JSON.parse(readFileSync(new URL('aleph.config.json', root), 'utf8'));
const stop = (message) => { console.error(`중단: ${message}`); process.exitCode = 1; };

try {
  console.log('이 명령은 배포 주소로 정상·금지 요청을 실제로 보냅니다(시험 계정 A·B와 가상 메모만 쓰세요).');
  console.log('로그인 요청은 정확히 2번(A 1번, B 1번)이며, 실패하면 다시 시도하지 않고 멈춥니다. 비밀번호는 보이지 않고 저장하지 않습니다. 취소는 Ctrl+C입니다.\n');
  const aEmail = await ask('시험 계정 A의 이메일: ');
  const aPassword = await ask('A의 비밀번호(보이지 않음): ', { hidden: true });
  const bEmail = await ask('시험 계정 B의 이메일: ');
  const bPassword = await ask('B의 비밀번호(보이지 않음): ', { hidden: true });
  let anonKey = process.env.ATTACK_ANON_KEY ?? '';
  if (!anonKey) anonKey = (await ask('공개 anon 키(publishable, 없으면 그냥 Enter — 그 줄은 미실행으로 남음): ', { hidden: true })).trim();
  const login = await loginForTokens({ app: new URL(config.publicAppUrl),
    accounts: [{ name: 'A', email: aEmail, password: aPassword }, { name: 'B', email: bEmail, password: bPassword }] });
  if (!login.ok) { stop(`${login.message} (보낸 로그인 요청: ${login.requests}번)`); } else {
    const rows = await runRegression({
      app: new URL(config.publicAppUrl), config, tokens: login.tokens, anonKey,
      waitForApproval: async ({ devices }) => {
        console.log('\n기기 승인 요청을 보냈습니다. 자료실 주인이 Supabase SQL Editor에서 sql/11-devices.sql의 [B]로 아래 확인 코드를 대조하고 [C]로 승인하세요.');
        for (const { name, code } of devices) console.log(`  ${name} 기기 확인 코드: ${code}`);
        console.log('승인하지 않을 세 번째 기기(승인 전 기기 거부 시험용)는 일부러 승인하지 마세요.');
        await ask('두 기기를 승인했으면 Enter를 누르세요(승인하지 않고 누르면 그 뒤 요청은 미실행으로 남음): ');
      },
    });
    mkdirSync(new URL('artifacts/', root), { recursive: true });
    const table = renderTable(rows);
    writeFileSync(new URL('artifacts/regression-table.md', root), table);
    writeFileSync(new URL('artifacts/regression-table.json', root), `${JSON.stringify({ schema: 'aleph.regression-table.v1', rows }, null, 2)}\n`);
    console.log(`\n${table}\n표를 artifacts/regression-table.md(.json)에 저장했습니다. 커밋하지 않는 폴더입니다.`);
    if (rows.some((row) => row.result === '실패')) process.exitCode = 2;
  }
} catch (error) {
  stop(error?.message ?? '알 수 없는 오류');
}
