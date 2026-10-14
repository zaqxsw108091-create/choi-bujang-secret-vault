// 10단계 점검 보강: 두 계정의 로그인 토큰을 이 앱의 /api/login으로 직접 받습니다(복사·붙여넣기·환경변수 필요 없음).
// - 로그인 요청은 계정마다 정확히 한 번이며 재시도하지 않습니다. 실패하면 거기서 멈추고 다음 계정은 보내지 않습니다.
// - 비밀번호·토큰은 반환값의 message나 오류에 넣지 않습니다. 실패 이유는 상태 번호와 짧은 이유 코드만 적습니다.
// - 두 토큰이 같은 계정(sub가 같음)이면 점검에 쓰지 않습니다.
const TOKEN = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/u;
const EMAIL = /^[^\s@]{1,64}@[^\s@]{1,255}$/u;
const REASON = /^[a-z_]{1,40}$/u;

const subOf = (token) => {
  try {
    const payload = JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
    return typeof payload.sub === 'string' ? payload.sub : null;
  } catch { return null; }
};

export async function loginForTokens({ app, accounts, fetchFn = fetch }) {
  let requests = 0;
  const fail = (message) => ({ ok: false, requests, message });
  if (!Array.isArray(accounts) || accounts.length !== 2) return fail('계정은 정확히 두 개(B, A)가 필요합니다.');
  for (const account of accounts) {
    if (!EMAIL.test(account?.email ?? '') || typeof account.password !== 'string' || !account.password || account.password.length > 256) {
      return fail(`${account?.name ?? '?'} 계정의 이메일 또는 비밀번호 입력이 올바르지 않습니다. 로그인 요청은 보내지 않았습니다.`);
    }
  }
  if (accounts[0].email.trim().toLowerCase() === accounts[1].email.trim().toLowerCase()) {
    return fail('두 계정의 이메일이 같습니다. 서로 다른 계정이어야 합니다. 로그인 요청은 보내지 않았습니다.');
  }
  const tokens = {};
  for (const { name, email, password } of accounts) {
    requests += 1;
    let response;
    try {
      response = await fetchFn(new URL('/api/login', app), {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email.trim(), password }),
      });
    } catch {
      return fail(`${name} 계정 로그인 요청을 보내지 못했습니다(접속 문제). 다시 시도하지 않고 멈춥니다.`);
    }
    let data = null;
    try { data = JSON.parse(await response.text()); } catch { /* JSON이 아니면 앱의 응답으로 보지 않습니다. */ }
    if (response.status === 200 && typeof data?.access_token === 'string' && TOKEN.test(data.access_token)) {
      tokens[name] = data.access_token;
      continue;
    }
    const reason = typeof data?.reason === 'string' && REASON.test(data.reason) ? data.reason : null;
    const hint = response.status === 429 || reason === 'over_request_rate_limit'
      ? ' 로그인 발급 횟수 제한에 걸렸습니다. 몇 분 기다렸다가 다시 하세요.'
      : reason === 'invalid_credentials' ? ' 이메일 또는 비밀번호가 맞지 않습니다.' : '';
    return fail(`${name} 계정 로그인이 거절됐습니다(HTTP ${response.status}${reason ? `, ${reason}` : ''}).${hint} 다시 시도하지 않고 멈춥니다.`);
  }
  const [first, second] = [subOf(tokens[accounts[0].name]), subOf(tokens[accounts[1].name])];
  if (first && first === second) return fail('두 토큰이 같은 계정으로 보여 점검에 쓰지 않습니다.');
  return { ok: true, requests, tokens };
}
