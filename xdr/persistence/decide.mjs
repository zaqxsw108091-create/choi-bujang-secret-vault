// 경보를 패턴과 맞춰 보고 block / alert / record 를 정합니다. 근거는 MITRE ATT&CK T1543(시스템 프로세스 생성·변경), T1053(예약 작업), T1547.001(시작 폴더).
// 경보 설명이 패턴 조건을 모두 채우면 명확한 공격(block)으로 봅니다. 패턴 조건은 못 채웠지만 서비스·예약 작업·시작 항목·임시 폴더 같은 흔적이 있으면 애매한 시도(alert)입니다.
// 흔적이 없거나, 서명된 서비스·읽기만 한 기록·끝난 작업처럼 평소 모습이면 정상(record)입니다.
//
// 내보내는 것은 decide(alert) 하나뿐입니다.
// 심판의 격리 환경에서 이 파일 하나만 실행되므로, 이 파일은 다른 모듈을 불러오지 않습니다.
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 받은 경보만으로 계산합니다. 패턴 값은 patterns.json 과 같게 아래에 적었습니다.

const PATTERNS = Object.freeze([
    {
      "name": "unsigned-new-service",
      "mitre": "T1543",
      "condition": "경보 설명에 '서비스'가 있고, 서명이 없다·평소 목록에 없다·새로 등록됐다 중 하나가 함께 있다. 서명된 서비스, 서비스 설명만 바뀐 경우, 서비스가 멈췄다 같은 파일로 다시 시작된 경우는 해당하지 않는다",
      "match": {
        "target": "ruleDescription",
        "all": [
          {
            "regex": "서비스"
          },
          {
            "regex": "서명 없|서명이 없|목록에 없|등록됐|등록이 연속"
          }
        ]
      },
      "evidence": "근거: MITRE ATT&CK T1543(시스템 프로세스 생성·변경) — 공격자가 서비스를 새로 등록하거나 바꿔 재부팅 뒤에도 실행을 유지한다."
    },
    {
      "name": "unfamiliar-scheduled-task",
      "mitre": "T1053",
      "condition": "경보 설명에 '예약 작업'이 있고, 처음 본다·이름이 임의 문자열이다·임시 폴더(파일)를 가리킨다 중 하나가 함께 있다. 수업 시간에 만든 작업, 이름이 수업 과제와 비슷한 작업, 평소 시각의 업데이트 예약은 해당하지 않는다",
      "match": {
        "target": "ruleDescription",
        "all": [
          {
            "regex": "예약 작업"
          },
          {
            "regex": "처음 보는|임의 문자열|임시 (?:폴더|파일)"
          }
        ]
      },
      "evidence": "근거: MITRE ATT&CK T1053(예약 작업/작업 실행) — 공격자가 낯선 예약 작업을 만들어 정해진 때마다 프로그램을 다시 실행하며 남는다."
    },
    {
      "name": "startup-folder-change",
      "mitre": "T1547.001",
      "condition": "경보 설명에 '시작 폴더' 또는 '시작 프로그램'이 있고, 평소 목록에 없는 프로그램이 추가됐거나 같은 임시 파일을 가리킨다. 시작 목록을 읽기만 한 경우, 변경 1건뿐이고 이어서 실행된 기록이 없는 경우는 해당하지 않는다",
      "match": {
        "target": "ruleDescription",
        "all": [
          {
            "regex": "시작 (?:폴더|프로그램)"
          },
          {
            "regex": "목록에 없는|추가됐|임시 파일"
          }
        ]
      },
      "evidence": "근거: MITRE ATT&CK T1547.001(시작 폴더) — 시작 폴더에 넣은 프로그램은 로그인할 때마다 자동 실행된다. 이 항목의 번호는 T1543·T1053과 달라 학생 요청 밖에서 더했다."
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

// 패턴 조건은 못 채웠어도 지속성 흔적이 있는 설명입니다. 판단은 alert 까지만 올리고 block 은 만들지 않습니다.
const TRACE = /서비스|예약 작업|시작 (?:폴더|프로그램|항목)|임시 (?:폴더|파일)/u;
const UNSURE = /서명(?:은| 여부)?[^.]*(?:확인되지|모릅니다|알 수)/u;
// 평소 모습을 가리키는 말입니다. 있으면 확신도를 내립니다.
const BENIGN = /서명된|읽기만|평소 (?:시각|저장소)|마쳤|끝났/u;
const TEMP_PATH = /\\temp\\/iu;
const STARTUP_PATH = /\\startup\\/iu;

function readRepeats(alert, description) {
  const count = Number(alert?.data?.count);
  if (Number.isFinite(count)) return count;
  const said = Number(/(\d+)\s*건/u.exec(description)?.[1]);
  return Number.isFinite(said) ? said : 0;
}

function judge(alert) {
  const description = text(alert?.rule?.description);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const path = text(alert?.data?.path);
  const repeats = readRepeats(alert, description);
  const benign = BENIGN.test(description);

  // 명확한 공격: 패턴 조건을 모두 채움.
  const hits = COMPILED.filter((compiled) => matches(compiled, description)).map((compiled) => compiled.name);
  if (hits.length) {
    let confidence = 0.88;
    if (hits.length >= 2) confidence += 0.04;
    if (level >= 11) confidence += 0.03;
    if (repeats >= 2) confidence += 0.02;
    if (TEMP_PATH.test(path) || STARTUP_PATH.test(path)) confidence += 0.02;
    if (benign) confidence -= 0.1;
    confidence = round(Math.min(0.99, confidence));
    return { action: toAction(confidence), confidence, reason: `패턴 일치: ${hits.join(', ')}` };
  }

  // 애매한 시도: 패턴 조건은 못 채웠지만 지속성 흔적이 있음.
  if (TRACE.test(description)) {
    let confidence = 0.5;
    if (UNSURE.test(description)) confidence += 0.05;
    if (level >= 7) confidence += 0.05;
    if (TEMP_PATH.test(path) || STARTUP_PATH.test(path)) confidence += 0.05;
    if (benign) confidence -= 0.2;
    if (level <= 3) confidence -= 0.1;
    confidence = round(Math.max(0.1, Math.min(0.75, confidence)));
    const reason = confidence >= ALERT_AT
      ? '애매함: 서비스·예약 작업·시작 항목 흔적은 있으나 패턴 조건을 다 채우지 못함'
      : '정상 이벤트: 지속성 흔적이 있으나 평소 모습이라 패턴과 맞지 않음';
    return { action: toAction(confidence), confidence, reason };
  }

  // 흔적이 없고 수준이 낮으면 정상 이벤트입니다. 흔적은 없는데 수준이 높으면 사람이 보도록 alert 입니다.
  if (level >= 8) return { action: 'alert', confidence: ALERT_AT, reason: '애매함: 패턴 신호는 없지만 경보 수준이 높음' };
  return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 지속성 패턴 신호가 없음' };
}

export function decide(alert) {
  try {
    return judge(alert);
  } catch {
    // 어떤 경보가 와도 오류를 던지지 않습니다. 판단하지 못했으면 사람이 보도록 alert 입니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '판단 중 오류: 경보 형식을 확인해야 함' };
  }
}
