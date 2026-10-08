// 경보를 패턴과 맞춰 보고, 애매한 것만 Jev 에게 물어 block / alert / record 를 정합니다.
// 근거는 MITRE ATT&CK T1190(외부 공개 앱 악용). 요청 인자의 SQL 구문·스크립트 태그·경로 거슬러 올라가기·명령 구분자가
// 같은 주소에서 반복되고(경보 수준 10 이상) 패턴 조건을 모두 채운 경보만 명확한 공격으로 봅니다.
//
// 심판의 격리 환경에서 이 파일 하나만 실행되므로, 이 파일은 어떤 모듈도 import 하지 않습니다.
// (node:fs 같은 내장 모듈, npm 패키지, 다른 파일 모두 없음. 패턴 값은 patterns.json 과 같게 아래에 적고,
//  시험이 두 곳이 같은지 확인합니다.)

export const PATTERNS = Object.freeze([
  {
    "name": "sql-in-request-args",
    "mitre": "T1190",
    "match": {
      "target": "requestArgs",
      "regex": "\\bunion\\s+(?:all\\s+)?select\\b|\\bor\\s+['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+|\\b(?:drop|delete)\\s+(?:table|from)\\b|\\binsert\\s+into\\b",
      "descriptionRegex": "SQL\\s*(?:구문|표식|표기)|데이터베이스 조회를 이어 붙이는",
      "flags": "i",
      "minRepeats": 2,
      "minLevel": 10
    }
  },
  {
    "name": "script-tag-in-request-args",
    "mitre": "T1190",
    "match": {
      "target": "requestArgs",
      "regex": "<\\s*script\\b|%3c\\s*script\\b",
      "descriptionRegex": "스크립트\\s*(?:삽입|표식|태그)",
      "flags": "i",
      "minRepeats": 2,
      "minLevel": 10
    }
  },
  {
    "name": "path-traversal-repeat",
    "mitre": "T1190",
    "match": {
      "target": "requestArgs",
      "regex": "(?:\\.\\./|\\.\\.\\\\|%2e%2e%2f){2,}",
      "descriptionRegex": "경로를 여러 단계 거슬러|경로 이탈",
      "flags": "i",
      "minRepeats": 2,
      "minLevel": 10
    }
  },
  {
    "name": "command-separator-in-request-args",
    "mitre": "T1190",
    "match": {
      "target": "requestArgs",
      "regex": "(?:;|&&|\\|\\||\\||%3b)\\s*(?:cat|ls|id|whoami|wget|curl|bash|sh|nc|rm|ping)\\b|\\$\\(",
      "descriptionRegex": "명령 구분자",
      "flags": "i",
      "minRepeats": 2,
      "minLevel": 10
    }
  }
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const NORMAL_LEVEL = 3;
const JEV_TIMEOUT_MS = 3000;
const MAX_TEXT = 2000;

const toAction = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

// 어떤 값이 와도 오류 없이 문자로 바꿉니다(바꿀 수 없으면 빈 문자열).
const text = (value) => {
  try { return String(value ?? '').slice(0, MAX_TEXT); } catch { return ''; }
};

// 숫자로 바꿀 수 없는 값(오류를 던지는 값 포함)은 NaN 입니다.
const num = (value) => {
  try { return Number(value); } catch { return NaN; }
};

const compile = (source, flags) => {
  try { return new RegExp(source, flags); } catch { return null; }
};
const COMPILED = PATTERNS.map((p) => ({
  name: p.name,
  minRepeats: p.match.minRepeats,
  minLevel: p.match.minLevel,
  inArgs: compile(p.match.regex, p.match.flags),
  inDescription: compile(p.match.descriptionRegex, p.match.flags),
}));

// 패턴 조건은 못 채웠지만 이름이 닮은 경보에, 가까운 패턴 이름만 reason 에 적기 위한 낱말입니다(판단에는 쓰지 않습니다).
const NEAR_WORDS = Object.freeze({
  'sql-in-request-args': /SQL|select|데이터베이스|따옴표/iu,
  'script-tag-in-request-args': /스크립트|script/iu,
  'path-traversal-repeat': /경로|\.\.|\bup\b/iu,
  'command-separator-in-request-args': /명령|구분\s*문자|구분자/u,
});

// 비밀값처럼 보이는 문자열은 자리만 남깁니다(Jev 에게 보내는 요약에 씁니다).
const SECRET_LIKE = [
  /\b(?:password|passwd|pwd|token|secret|api[_-]?key|비밀번호)\s*[=:]\s*\S+/giu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/gu,
  /\b(?:sb_secret_|sk-)[A-Za-z0-9_-]{12,}/gu,
  /\b[A-Za-z0-9+/_-]{32,}={0,2}/gu,
];
const scrub = (value) => SECRET_LIKE.reduce((out, pattern) => out.replace(pattern, '[가림]'), text(value));

const decoded = (value) => {
  try { return decodeURIComponent(value); } catch { return value; }
};

// 같은 주소의 반복 횟수는 경보의 count 를 씁니다. 없으면 설명의 "N번"을 봅니다.
function readRepeats(alert, description) {
  const count = num(alert?.data?.count);
  if (Number.isFinite(count)) return count;
  const said = num(/(\d+)\s*번/u.exec(description)?.[1]);
  return Number.isFinite(said) ? said : 0;
}

function readSignals(alert) {
  const description = text(alert?.rule?.description);
  const url = text(alert?.data?.url);
  return {
    url,
    description,
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0,
    repeats: readRepeats(alert, description),
  };
}

// 패턴마다 신호(요청 인자 또는 경보 설명)가 있는지 보고, 반복·수준까지 채우면 full, 신호만 있으면 partial 입니다.
function matchPatterns(s) {
  const full = [];
  const partial = [];
  const args = [s.url, decoded(s.url)];
  for (const p of COMPILED) {
    const signal = (p.inArgs && args.some((a) => p.inArgs.test(a))) || (p.inDescription?.test(s.description) ?? false);
    if (!signal) continue;
    (s.repeats >= p.minRepeats && s.level >= p.minLevel ? full : partial).push(p.name);
  }
  return { full, partial };
}

const nearPatterns = (s) => {
  const hay = `${s.description} ${s.url}`;
  return Object.keys(NEAR_WORDS).filter((name) => NEAR_WORDS[name].test(hay));
};

const summarize = (alert, s, partial) => ({
  id: typeof alert?.id === 'string' ? alert.id : '',
  time: scrub(alert?.timestamp),
  srcip: scrub(alert?.data?.srcip),
  url: scrub(s.url),
  count: s.repeats,
  level: s.level,
  description: scrub(s.description),
  nearPatterns: partial,
});

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

// askJev(summary) 는 0~1 확신도(또는 { confidence })를 돌려주는 함수입니다. 없거나 늦거나 이상한 값이면 애매한 건 alert 입니다.
export function createDecide({ askJev } = {}) {
  return async function decide(alert) {
    try {
      return await judge(alert, askJev);
    } catch {
      // 어떤 경보가 와도 오류를 던지지 않습니다. 판단하지 못했으면 사람이 보도록 alert 입니다.
      return { action: 'alert', confidence: ALERT_AT, reason: '판단 중 오류: 경보 형식을 확인해야 함' };
    }
  };
}

async function judge(alert, askJev) {
  const s = readSignals(alert);
  const { full, partial } = matchPatterns(s);

  if (full.length) {
    const confidence = full.length > 1 ? 0.98 : 0.95;
    return { action: toAction(confidence), confidence, reason: `패턴 일치: ${full.join(', ')}` };
  }

  // 주입 신호가 없고 수준이 낮고 반복도 없으면 정상 이벤트입니다.
  if (!partial.length && s.level <= NORMAL_LEVEL && s.repeats < 2) {
    return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 주입 신호가 없고 수준이 낮음' };
  }

  // 애매한 경보: 패턴 조건을 일부만 채웠거나 신호가 약합니다. Jev 에게 묻습니다.
  const near = partial.length ? partial : nearPatterns(s);
  const names = near.length ? near.join(', ') : '일치한 패턴 없음';
  const answered = typeof askJev === 'function' ? await askWithTimeout(askJev, summarize(alert, s, near)) : null;
  if (answered === null) {
    return { action: 'alert', confidence: ALERT_AT, reason: `Jev 응답 없음, 가까운 패턴: ${names}` };
  }
  return { action: toAction(answered), confidence: answered, reason: `Jev 확신도 ${answered}, 가까운 패턴: ${names}` };
}

export const decide = createDecide();
