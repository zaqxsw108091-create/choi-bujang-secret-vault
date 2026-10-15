// 10단계 점검 보강: 두 시험 계정의 이메일·비밀번호만 입력하면 토큰을 직접 받아 npm run bundle을 실행합니다.
// - 로그인 요청은 정확히 2번(B 1번, A 1번)이며 재시도하지 않습니다. 비밀번호는 화면에 보이지 않고 저장·출력하지 않습니다.
// - 받은 토큰은 이 프로세스 안의 환경변수로만 점검 코드(src/attack-check.mjs)에 넘기고, 화면·파일·제출 묶음에 쓰지 않습니다.
// - 시험 계정과 가상 메모로만 쓰세요. 이 점검은 B의 메모에 다른 계정으로 PUT·DELETE를 실제로 보냅니다(정상이면 403).
import { readFileSync } from 'node:fs';
import { loginForTokens } from '../src/live-credentials.mjs';
import { ask } from '../src/prompt.mjs';
import { prepareLiveDevices } from '../src/regression-table.mjs';

const root = new URL('../', import.meta.url);
const config = JSON.parse(readFileSync(new URL('aleph.config.json', root), 'utf8'));
const stop = (message) => { console.error(`중단: ${message}`); process.exitCode = 1; };

try {
  console.log('이 명령은 로그인 요청을 정확히 2번(메모 주인 B 1번, 다른 계정 A 1번) 보내고, 실패하면 다시 시도하지 않고 멈춥니다.');
  console.log('비밀번호는 입력해도 화면에 보이지 않고, 저장하거나 출력하지 않습니다. 취소는 Ctrl+C입니다.\n');
  const ownerEmail = await ask('메모 주인 B의 이메일: ');
  const ownerPassword = await ask('B의 비밀번호(보이지 않음): ', { hidden: true });
  const otherEmail = await ask('다른 계정 A의 이메일: ');
  const otherPassword = await ask('A의 비밀번호(보이지 않음): ', { hidden: true });
  if (!process.env.ATTACK_ANON_KEY) {
    const key = (await ask('공개 anon 키(publishable, 없으면 그냥 Enter): ', { hidden: true })).trim();
    if (key) process.env.ATTACK_ANON_KEY = key;
  }
  const result = await loginForTokens({
    app: new URL(config.publicAppUrl),
    accounts: [{ name: 'OWNER', email: ownerEmail, password: ownerPassword }, { name: 'OTHER', email: otherEmail, password: otherPassword }],
  });
  if (!result.ok) {
    stop(`${result.message} (보낸 로그인 요청: ${result.requests}번)`);
  } else {
    console.log(`\n로그인 요청 ${result.requests}번 성공. 토큰은 화면에 표시하지 않습니다. 점검을 시작합니다.\n`);
    // 11단계부터는 보호 경로에 승인된 기기의 서명이 필요합니다. 두 계정의 기기를 만들어 승인 요청을 보내고, 학생이 서버에서 승인한 뒤 계속합니다.
    if (config.step >= 11) {
      const prepared = await prepareLiveDevices({
        app: new URL(config.publicAppUrl), tokens: result.tokens,
        waitForApproval: async ({ devices }) => {
          console.log('두 계정의 기기 승인 요청을 보냈습니다. 자료실 주인이 Supabase SQL Editor에서 sql/11-devices.sql의 [B]로 아래 확인 코드를 대조하고 [C]로 승인하세요.');
          for (const { name, code } of devices) console.log(`  ${name === 'OWNER' ? 'B(메모 주인)' : 'A(다른 계정)'} 기기 확인 코드: ${code}`);
          await ask('두 기기를 승인했으면 Enter를 누르세요(승인하지 않고 누르면 두 계정 점검은 확인하지 못함으로 남음): ');
        },
      });
      for (const note of prepared.notes) console.log(`  참고: ${note}`);
      globalThis[Symbol.for('aleph.attack.devices')] = prepared.devices;
    }
    process.env.ATTACK_TOKEN_OWNER = result.tokens.OWNER;
    process.env.ATTACK_TOKEN_OTHER = result.tokens.OTHER;
    await import('./bundle.mjs');
    delete process.env.ATTACK_TOKEN_OWNER;
    delete process.env.ATTACK_TOKEN_OTHER;
    delete globalThis[Symbol.for('aleph.attack.devices')];
    try {
      const bundle = JSON.parse(readFileSync(new URL('artifacts/submission.json', root), 'utf8'));
      console.log('\n두 계정·anon 점검 결과:');
      for (const item of bundle.attackAttempts) {
        if (/^other_owner_|^anon_data_/u.test(item.attackId)) console.log(`  ${item.attackId.padEnd(30)} ${item.observed.slice(0, 80)}`);
      }
    } catch { /* 묶음이 만들어지지 않았으면 위 bundle 오류 메시지를 보면 됩니다. */ }
  }
} catch (error) {
  stop(error?.message ?? '알 수 없는 오류');
}
