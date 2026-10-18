// 경보를 패턴과 맞춰 보고 block / alert / record 를 정합니다. 근거는 CVE-2021-44228 형태 요청과 MITRE ATT&CK T1190(외부 공개 앱 악용).
// 완전한 원격 조회 구문(${jndi:프로토콜://…})이 요청 머리글·인자에 실제로 있는 경보만 명확한 공격(block)으로 봅니다.
// 글자를 쪼갠 표기(${lower:j}, ${::-j} 같은 안쪽 조회)는 풀어 본 뒤 완전한 조회 구문이 되면 같은 패턴으로 봅니다. 풀어도 완전한 구문이 아니면 alert 까지만입니다.
// CVE 이름·'jndi' 단어·점검 도구 비슷한 이름처럼 조회 구문이 없는 흔적은 애매한 시도(alert)로만 남기고, 신호가 없으면 정상(record)입니다.
//
// 심판의 격리 환경에서 이 파일 하나만 실행되므로, 이 파일은 어떤 모듈도 import 하지 않습니다.
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 받은 경보만으로 계산합니다. 패턴 값은 patterns.json 과 같게 아래에 적고, 시험이 두 곳이 같은지 확인합니다.

export const PATTERNS = Object.freeze([
  {
    "name": "jndi-lookup-in-header",
    "mitre": "T1190",
    "condition": "요청 머리글(User-Agent 등)에 완전한 원격 조회 구문 ${jndi:프로토콜://주소/…} 이 들어 있다. 'jndi'라는 단어만 있거나 중괄호·조회 조각만 있는 경우는 해당하지 않는다",
    "match": {
      "target": "requestHeaders",
      "regex": "\\$\\{\\s*jndi\\s*:\\s*(?:ldaps?|rmi|dns)://[^}\\s]+\\}",
      "flags": "i"
    },
    "evidence": "근거: CVE-2021-44228(NIST NVD) — 기록되는 머리글의 ${jndi:…} 조회가 외부 코드를 불러오는 공개 취약점. MITRE ATT&CK T1190(외부 공개 앱 악용)."
  },
  {
    "name": "jndi-lookup-in-request-args",
    "mitre": "T1190",
    "condition": "요청 주소·인자(쿼리 값)에 완전한 원격 조회 구문 ${jndi:프로토콜://주소/…} 이 들어 있다. 'CVE-2021-44228' 같은 글자만 검색어에 있거나 'jndi' 단어만 있는 경우는 해당하지 않는다",
    "match": {
      "target": "requestArgs",
      "regex": "\\$\\{\\s*jndi\\s*:\\s*(?:ldaps?|rmi|dns)://[^}\\s]+\\}",
      "flags": "i"
    },
    "evidence": "근거: CVE-2021-44228(NIST NVD) — 요청 인자가 기록될 때 ${jndi:…} 조회가 실행되는 공개 취약점. MITRE ATT&CK T1190(외부 공개 앱 악용)."
  },
  {
    "name": "vuln-scanner-trace-with-lookup",
    "mitre": "T1190",
    "condition": "경보 설명이 알려진 취약점 점검 도구의 흔적을 가리키고, 같은 경보의 머리글·인자에도 완전한 원격 조회 구문이 있다. 점검 도구와 비슷한 이름만 있고 조회 구문이 없으면 해당하지 않는다(점검 흔적은 단독 근거가 아니라 확신도를 더하는 보조 신호)",
    "match": {
      "target": "description+requestArgs+requestHeaders",
      "descriptionRegex": "점검\\s*(?:도구\\s*)?흔적",
      "regex": "\\$\\{\\s*jndi\\s*:\\s*(?:ldaps?|rmi|dns)://[^}\\s]+\\}",
      "flags": "i",
      "requires": "descriptionRegex+regex"
    },
    "evidence": "근거: 과제 안내문이 든 신호(알려진 취약점 점검 도구의 흔적)와 CVE-2021-44228 형태 요청의 동시 출현. MITRE ATT&CK T1190(외부 공개 앱 악용)."
  }
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_TEXT = 8000;
const MAX_VALUES = 60;
const MAX_DEPTH = 4;

const toAction = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

const text = (value) => {
  try { return String(value ?? '').slice(0, MAX_TEXT); } catch { return ''; }
};

const num = (value) => {
  try { return Number(value); } catch { return NaN; }
};

const decoded = (value) => {
  try { return decodeURIComponent(value); } catch { return value; }
};

const compile = (source, flags) => {
  try { return new RegExp(source, flags); } catch { return null; }
};
const byName = (name) => {
  const p = PATTERNS.find((item) => item.name === name);
  return { name, regex: compile(p.match.regex, p.match.flags), description: p.match.descriptionRegex ? compile(p.match.descriptionRegex, p.match.flags) : null };
};
const HEADER = byName('jndi-lookup-in-header');
const ARGS = byName('jndi-lookup-in-request-args');
const SCANNER = byName('vuln-scanner-trace-with-lookup');

// 머리글 쪽 칸(User-Agent·Referer 등)과 주소·인자 쪽 칸을 나눕니다. 모르는 칸은 인자 쪽으로 봅니다.
const HEADER_KEY = /agent|header|referer|referrer|cookie|host|origin|accept|authorization|^x[-_]/iu;

// 완전한 구문은 없지만 닮은 흔적입니다. 판단은 alert 까지만 올리고 block 은 만들지 않습니다.
const HINT_TEXT = /jndi|CVE-\d{4}-\d{4,}|log4(?:j|shell)|log-?library|\$\{|%24%7B/iu;
const NESTED_LOOKUP = /\$\{\s*(?:\$\{|[a-z]+:-)/iu;
const HINT_DESCRIPTION = /원격 조회|조회 (?:구문|형태)|jndi|CVE-\d{4}-\d{4,}|취약점|점검|라이브러리|중괄호/iu;

// 안쪽 조회를 풀어 씁니다: ${lower:x}·${upper:x} 는 글자 하나로, ${…:-x} 는 기본값 x 로 바꿉니다. 더 풀 것이 없을 때까지 최대 5번 반복합니다.
const LOWER_UPPER = /\$\{\s*(lower|upper)\s*:\s*([^${}]*)\}/giu;
const DEFAULT_VALUE = /\$\{[^${}]*:-([^${}]*)\}/gu;
function unwrap(value) {
  let out = value;
  for (let i = 0; i < 5; i += 1) {
    const next = out
      .replace(LOWER_UPPER, (_, kind, inner) => (kind.toLowerCase() === 'lower' ? inner.toLowerCase() : inner.toUpperCase()))
      .replace(DEFAULT_VALUE, '$1');
    if (next === out) break;
    out = next;
  }
  return out;
}

// 경보 data 안의 문자열을 칸 이름과 함께 모읍니다(깊이·개수 제한).
function collect(value, key, out, depth) {
  if (out.length >= MAX_VALUES || depth > MAX_DEPTH || value == null) return;
  if (typeof value === 'string' || typeof value === 'number') {
    out.push({ key, value: text(value) });
  } else if (typeof value === 'object') {
    for (const k of Object.keys(value).slice(0, MAX_VALUES)) collect(value[k], k, out, depth + 1);
  }
}

function readRepeats(alert, description) {
  const count = num(alert?.data?.count);
  if (Number.isFinite(count)) return count;
  const said = num(/(\d+)\s*번/u.exec(description)?.[1]);
  return Number.isFinite(said) ? said : 0;
}

function judge(alert) {
  const description = text(alert?.rule?.description);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const repeats = readRepeats(alert, description);

  const values = [];
  collect(alert?.data, 'data', values, 0);
  collect(alert?.full_log, 'full_log', values, 0);
  const hit = (regex) => values.some((v) => regex && (regex.test(v.value) || regex.test(decoded(v.value))));
  // 원문에서 찾고, 못 찾으면 퍼센트 인코딩과 안쪽 조회를 풀어서 다시 찾습니다.
  const found = (regex, wantHeader) => values.some((v) => {
    if (HEADER_KEY.test(v.key) !== wantHeader || !regex) return false;
    const plain = decoded(v.value);
    return regex.test(v.value) || regex.test(plain) || regex.test(unwrap(v.value)) || regex.test(unwrap(plain));
  });
  const inHeader = found(HEADER.regex, true);
  const inArgs = found(ARGS.regex, false);
  const unwrapped = values.some((v) => !HEADER.regex.test(decoded(v.value)) && (HEADER.regex.test(unwrap(decoded(v.value)))));

  // 명확한 공격: 요청 머리글·인자에 완전한 원격 조회 구문이 실제로 있음.
  if (inHeader || inArgs) {
    const names = [];
    if (inHeader) names.push(HEADER.name);
    if (inArgs) names.push(ARGS.name);
    let confidence = 0.9;
    if (inHeader && inArgs) confidence += 0.04;
    if (repeats >= 2) confidence += 0.03;
    if (SCANNER.description?.test(description)) { confidence += 0.03; names.push(SCANNER.name); }
    if (level >= 12) confidence += 0.02;
    confidence = Math.min(0.99, Math.round(confidence * 100) / 100);
    return { action: toAction(confidence), confidence, reason: `패턴 일치: ${names.join(', ')}${unwrapped ? ' (쪼갠 표기를 풀어서)' : ''}` };
  }

  // 애매한 시도: 조회 구문은 없지만 닮은 흔적(CVE 이름·jndi 단어·잘린 조각·점검 비슷한 설명)이 있음.
  const hintInRequest = hit(HINT_TEXT);
  const hintInDescription = HINT_DESCRIPTION.test(description);
  if (hintInRequest || hintInDescription) {
    let confidence = hintInRequest ? 0.55 : 0.5;
    if (hintInRequest && hintInDescription) confidence += 0.05;
    if (hit(NESTED_LOOKUP)) confidence += 0.1;
    if (repeats >= 2) confidence += 0.05;
    confidence = Math.min(0.75, Math.round(confidence * 100) / 100);
    return { action: toAction(confidence), confidence, reason: `애매함: ${HEADER.name}, ${ARGS.name} 와 닮은 흔적만 있고 완전한 조회 구문은 없음` };
  }

  // 신호가 없고 수준이 낮으면 정상 이벤트입니다. 신호는 없는데 수준이 높으면 사람이 보도록 alert 입니다.
  if (level <= 4) return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 알려진 취약점 악용 신호가 없고 수준이 낮음' };
  return { action: 'alert', confidence: ALERT_AT, reason: '애매함: 패턴 신호는 없지만 경보 수준이 높음' };
}

export function decide(alert) {
  try {
    return judge(alert);
  } catch {
    // 어떤 경보가 와도 오류를 던지지 않습니다. 판단하지 못했으면 사람이 보도록 alert 입니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '판단 중 오류: 경보 형식을 확인해야 함' };
  }
}
