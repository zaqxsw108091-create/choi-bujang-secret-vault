// 경보를 패턴과 맞춰 보고, 애매한 것만 Jev 에게 물어 block / alert / record 를 정합니다.
// 같은 주소(·같은 계정)의 로그인 실패는 짧은 시간(10분) 안에서 모아 기준을 넘는지 봅니다.
//
// 심판의 격리 환경에서 이 파일 하나만 실행되므로, 이 파일은 어떤 모듈도 import 하지 않습니다.
// (node:fs 같은 내장 모듈, npm 패키지, 다른 파일 모두 없음. 패턴 값은 patterns.json 과 같게 아래에 적고,
//  시험이 두 곳이 같은지 확인합니다.)

export const PATTERNS = Object.freeze([
  { name: 'same-ip-failure-burst', mitre: 'T1110', match: { minFailures: 10, minLevel: 10 } },
  { name: 'same-password-many-accounts', mitre: 'T1110', match: { minAccounts: 3, minLevel: 10 } },
]);
const BURST = PATTERNS[0];
const SPRAY = PATTERNS[1];

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const NORMAL_LEVEL = 3;
const JEV_TIMEOUT_MS = 3000;
const WINDOW_MS = 10 * 60 * 1000;

const toAction = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

// 어떤 값이 와도 오류 없이 문자로 바꿉니다(바꿀 수 없으면 빈 문자열).
const text = (value) => {
  try { return String(value ?? ''); } catch { return ''; }
};

// 비밀값처럼 보이는 문자열은 자리만 남깁니다(Jev 에게 보내는 요약에 씁니다).
const SECRET_LIKE = [
  /\b(?:password|passwd|pwd|token|secret|api[_-]?key|비밀번호)\s*[=:]\s*\S+/giu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/gu,
  /\b(?:sb_secret_|sk-)[A-Za-z0-9_-]{12,}/gu,
  /\b[A-Za-z0-9+/_-]{32,}={0,2}/gu,
];
const scrub = (value) => SECRET_LIKE.reduce((out, pattern) => out.replace(pattern, '[가림]'), text(value));

const summarize = (alert) => ({
  id: typeof alert?.id === 'string' ? alert.id : '',
  time: scrub(alert?.timestamp),
  srcip: scrub(alert?.data?.srcip),
  user: scrub(alert?.data?.srcuser),
  level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0,
  description: scrub(alert?.rule?.description),
});

function readSignals(alert) {
  const description = text(alert?.rule?.description);
  const failures = Number(alert?.data?.count);
  const accountList = text(alert?.data?.accounts).split(',').map((a) => a.trim()).filter(Boolean);
  const named = Number(/계정\s*(\d+)\s*개/u.exec(description)?.[1] ?? 0);
  const wordsMany = /여러 계정|서로 다른 계정|계정 이름을 바꿔/u.test(description) ? SPRAY.match.minAccounts : 0;
  return {
    ip: text(alert?.data?.srcip),
    user: text(alert?.data?.srcuser),
    at: Date.parse(alert?.timestamp),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0,
    failures: Number.isFinite(failures) ? failures : 0,
    accountList,
    accounts: Math.max(accountList.length, named, wordsMany),
    hasFailure: /실패|같은 비밀번호/u.test(description),
    succeededAfter: /성공했/u.test(description),
    multiAccounts: /두 계정|세 계정|여러 계정|서로 다른 계정|계정 이름을 바꿔|계정\s*\d+\s*개/u.test(description) || accountList.length > 1,
  };
}

const inWindow = (a, b) => !Number.isFinite(a) || !Number.isFinite(b) || Math.abs(a - b) <= WINDOW_MS;

// 같은 주소의 실패 경보를 10분 안에서 모읍니다: 같은 계정의 실패 건수 합, 건드린 계정 수.
function gather(own, pool) {
  if (!own.ip || !own.hasFailure || own.succeededAfter) return { failures: own.failures, accounts: own.accounts };
  const near = pool.map(readSignals)
    .filter((h) => h.ip === own.ip && h.hasFailure && !h.succeededAfter && inWindow(h.at, own.at));
  const sameUser = near.filter((h) => h.user === own.user).reduce((sum, h) => sum + h.failures, 0);
  const users = new Set(near.flatMap((h) => [h.user, ...h.accountList]).filter(Boolean));
  return {
    failures: Math.max(own.failures, sameUser),
    accounts: Math.max(own.accounts, users.size, ...near.map((h) => h.accounts)),
  };
}

// 패턴 조건을 모두 채운 경보만 명확한 공격으로 봅니다.
function matchPatterns(s, g) {
  const hits = [];
  if (!s.hasFailure || s.succeededAfter) return hits;
  if (g.failures >= BURST.match.minFailures && s.level >= BURST.match.minLevel) hits.push(BURST.name);
  if (g.accounts >= SPRAY.match.minAccounts && s.level >= SPRAY.match.minLevel) hits.push(SPRAY.name);
  return hits;
}

// 애매한 경보가 어느 패턴과 일부 닮았는지 이름만 모읍니다(reason 에 근거 패턴 이름을 적기 위함).
const nearPatterns = (s) => [BURST.name, ...(s.multiAccounts ? [SPRAY.name] : [])];

async function askWithTimeout(askJev, summary) {
  let timer;
  try {
    const waits = [Promise.resolve(askJev(summary))];
    if (typeof setTimeout === 'function') {
      waits.push(new Promise((resolve) => { timer = setTimeout(() => resolve(null), JEV_TIMEOUT_MS); }));
    }
    const answer = await Promise.race(waits);
    const value = typeof answer === 'number' ? answer : answer?.confidence;
    return Number.isFinite(value) && value >= 0 && value <= 1 ? value : null;
  } catch {
    return null;
  } finally {
    if (timer !== undefined && typeof clearTimeout === 'function') clearTimeout(timer);
  }
}

// askJev(summary) 는 0~1 확신도(또는 { confidence })를 돌려주는 함수입니다. 없으면 애매한 건 alert 입니다.
// history 를 주면 그 목록을 함께 모아 보고, 주지 않으면 지금까지 판단한 경보(같은 id·시각은 하나로)를 모아 봅니다.
export function createDecide({ askJev, history } = {}) {
  const seen = new Map();
  return async function decide(alert) {
    let pool = history;
    if (!Array.isArray(pool)) {
      if (typeof alert?.id === 'string') seen.set(`${alert.id}|${alert.timestamp}`, alert);
      pool = [...seen.values()];
    }
    const s = readSignals(alert);
    const g = gather(s, pool);
    const summed = g.failures > s.failures ? ` · 같은 주소·계정 합산 ${g.failures}건` : '';

    if (!s.hasFailure || (s.level <= NORMAL_LEVEL && g.failures < BURST.match.minFailures)) {
      return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 로그인 실패 신호가 없거나 수준이 낮음' };
    }

    const hits = matchPatterns(s, g);
    if (hits.length) {
      const confidence = hits.length > 1 ? 0.98 : 0.95;
      return { action: toAction(confidence), confidence, reason: `패턴 일치: ${hits.join(', ')}${summed}` };
    }

    // 애매한 경보: 실패 뒤 성공했으면 정상 사용자일 수 있어 Jev 가 높게 답해도 차단까지 올리지 않습니다.
    const answered = typeof askJev === 'function' ? await askWithTimeout(askJev, summarize(alert)) : null;
    if (answered === null) {
      return { action: 'alert', confidence: ALERT_AT, reason: `Jev 응답 없음, 일부만 일치: ${nearPatterns(s).join(', ')}${summed}` };
    }
    const confidence = s.succeededAfter ? Math.min(answered, BLOCK_AT - 0.01) : answered;
    return { action: toAction(confidence), confidence, reason: `Jev 확신도 ${answered}, 일부만 일치: ${nearPatterns(s).join(', ')}${summed}` };
  };
}

export const decide = createDecide();
