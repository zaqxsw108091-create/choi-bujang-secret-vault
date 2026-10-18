// 경보를 패턴과 맞춰 보고 block / alert / record 를 정합니다. 근거는 MITRE ATT&CK T1068(권한 상승 악용), T1078(정상 계정 도용).
// 경보 설명이 패턴 조건을 모두 채우면 명확한 공격(block)으로 봅니다. 패턴 조건은 못 채웠지만 관리자·권한·그룹 흔적이 있으면 애매한 시도(alert)입니다.
// 흔적이 없거나, 읽기만 한 기록처럼 평소 모습이면 정상(record)입니다.
//
// 내보내는 것은 decide(alert) 하나뿐입니다.
// 심판의 격리 환경에서 이 파일 하나만 실행되므로, 이 파일은 다른 모듈을 불러오지 않습니다.
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 받은 경보만으로 계산합니다. 패턴 값은 patterns.json 과 같게 아래에 적었습니다.

const PATTERNS = Object.freeze([
  {
    "name": "admin-group-added",
    "mitre": "T1078",
    "condition": "경보 설명에 관리자 그룹에 추가됐다·들어갔다·다시 들어왔다는 내용이 있다. 관리자가 아닌 그룹(과제 그룹 등)에 추가된 경우, 그룹 목록·소속을 읽기만 한 경우, 새 로컬 그룹이 만들어진 경우는 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "관리자 그룹(?:에|으로)? ?(?:추가|들어)|관리자로 들어"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1078(정상 계정 도용) — 공격자가 평범한 계정을 관리자 그룹에 넣어 그 계정의 정상 접속 모양으로 높은 권한을 얻는다."
  },
  {
    "name": "unfamiliar-admin-command",
    "mitre": "T1068",
    "condition": "경보 설명에 관리자 명령 실행(또는 세션이 관리자 권한으로 바뀜)이 있고, 처음 보는 주소다·방금 관리자가 됐다·다른 계정의 권한을 썼다 중 하나가 함께 있다. 평소 주소에서 한 번 실행된 경우, 실패 1건으로 끝난 경우, 권한 상승 창이 떴다가 취소된 경우는 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "관리자 명령|관리자 권한으로 바뀌"
        },
        {
          "regex": "처음 보는|처음 봅|방금 관리자가 된|다른 계정의 권한"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1068(권한 상승 악용) — 공격자가 낯선 곳에서 관리자 명령을 실행하거나 다른 계정의 권한을 빌려 평소보다 높은 권한을 쓴다."
  },
  {
    "name": "off-hours-admin-use",
    "mitre": "T1078",
    "condition": "경보 설명에 수업 시간 밖·업무처럼 보이지 않는 시각이 있고, 관리자 그룹 추가 또는 관리자 명령이 함께 있다. 수업 시간 안의 권한 사용이나 수업용 관리 계정의 평소 로그인은 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "수업 시간 밖|업무처럼 보이지 않는 시각"
        },
        {
          "regex": "관리자"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1078(정상 계정 도용) — 훔친 계정은 사용자가 없는 시간대에 쓰이는 경우가 많아, 시간 밖의 권한 사용이 도용의 단서가 된다."
  }
]);

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const MAX_TEXT = 4000;

const toAction = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');
const round = (value) => Math.round(value * 100) / 100;

const text = (value) => {
  try { return String(value ?? '').slice(0, MAX_TEXT); } catch { return ''; }
};

const compile = (source) => {
  try { return new RegExp(source, 'u'); } catch { return null; }
};
const COMPILED = PATTERNS.map((p) => ({ name: p.name, parts: p.match.all.map((part) => compile(part.regex)) }));

// 패턴 조건(all)을 모두 채우면 일치입니다. 정규식이 깨졌으면 일치로 보지 않습니다.
const matches = (compiled, description) => compiled.parts.every((regex) => regex && regex.test(description));

// 패턴 조건은 못 채웠어도 관리자·권한·그룹 흔적이 있는 설명입니다. 판단은 alert 까지만 올리고 block 은 만들지 않습니다.
const TRACE = /관리자|권한|그룹|상승|계정 종류/u;
// 읽기만 한 기록은 평소 모습입니다. 수준이 낮을 때만 확신도를 내립니다.
const READ_ONLY = /읽기만|조회했/u;

function readRepeats(alert) {
  const count = Number(alert?.data?.count);
  return Number.isFinite(count) ? count : 0;
}

function judge(alert) {
  const description = text(alert?.rule?.description);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const repeats = readRepeats(alert);

  // 명확한 공격: 패턴 조건을 모두 채움.
  const hits = COMPILED.filter((compiled) => matches(compiled, description)).map((compiled) => compiled.name);
  if (hits.length) {
    let confidence = 0.88;
    if (hits.length >= 2) confidence += 0.04;
    if (level >= 11) confidence += 0.03;
    if (repeats >= 2) confidence += 0.02;
    confidence = round(Math.min(0.99, confidence));
    return { action: toAction(confidence), confidence, reason: `패턴 일치: ${hits.join(', ')}` };
  }

  // 애매한 시도: 패턴 조건은 못 채웠지만 관리자·권한·그룹 흔적이 있음.
  if (TRACE.test(description)) {
    let confidence = 0.5;
    if (level >= 7) confidence += 0.05;
    if (level <= 3) confidence -= 0.1;
    if (level <= 3 && READ_ONLY.test(description)) confidence -= 0.2;
    confidence = round(Math.max(0.1, Math.min(0.75, confidence)));
    const reason = confidence >= ALERT_AT
      ? '애매함: 관리자·권한·그룹 흔적은 있으나 패턴 조건을 다 채우지 못함'
      : '정상 이벤트: 흔적이 있으나 읽기만 한 평소 모습이라 패턴과 맞지 않음';
    return { action: toAction(confidence), confidence, reason };
  }

  // 흔적이 없고 수준이 낮으면 정상 이벤트입니다. 흔적은 없는데 수준이 높으면 사람이 보도록 alert 입니다.
  if (level >= 8) return { action: 'alert', confidence: ALERT_AT, reason: '애매함: 패턴 신호는 없지만 경보 수준이 높음' };
  return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 권한 상승 패턴 신호가 없음' };
}

export function decide(alert) {
  try {
    return judge(alert);
  } catch {
    // 어떤 경보가 와도 오류를 던지지 않습니다. 판단하지 못했으면 사람이 보도록 alert 입니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '판단 중 오류: 경보 형식을 확인해야 함' };
  }
}
