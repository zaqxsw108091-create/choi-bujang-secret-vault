// 경보를 패턴과 맞춰 보고 block / alert / record 를 정합니다. 근거는 MITRE ATT&CK T1041(명령 통로로 유출), T1048(다른 프로토콜로 유출).
// 경보 설명이 패턴 조건을 모두 채우면 명확한 공격(block)으로 봅니다. 패턴 조건은 못 채웠지만 전송·목적지·압축 파일 흔적이 있으면 애매한 시도(alert)입니다.
// 흔적이 없거나, 경보 수준이 낮은 평소 전송·읽기 기록이면 정상(record)입니다.
//
// 내보내는 것은 decide(alert) 하나뿐입니다.
// 심판의 격리 환경에서 이 파일 하나만 실행되므로, 이 파일은 다른 모듈을 불러오지 않습니다.
// 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 받은 경보만으로 계산합니다. 패턴 값은 patterns.json 과 같게 아래에 적었습니다.

const PATTERNS = Object.freeze([
  {
    "name": "new-destination-bulk-transfer",
    "mitre": "T1048",
    "condition": "경보 설명에 처음 보는·알 수 없는·낯선·평소와 다른 목적지(주소·외부 서버·클라우드 저장소)가 있고, 자료 수십 건 이상·자료 전체·데이터 수십 GB·대용량·큰 파일·압축 파일 여러 개처럼 큰 전송이 함께 있다. 처음 보는 주소로 작은 파일 몇 건만 나간 경우, 실패 1건으로 끝난 경우, 평소 목적지(수업 자료 주소·자료실)로 간 전송, 나가지 않았다·차단됐다처럼 부정하는 문장은 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "(?:처음 보|처음 본|알 수 없는|낯선|평소 쓰지 않는|평소에 쓰지 않던|평소와 다른|등록되지 않은|first-seen|unknown|unfamiliar|new)[^.]{0,12}?(?:목적지|주소|서버|저장소|클라우드|외부|destination|server|address|host)"
        },
        {
          "regex": "자료 \\d{2,}건|(?:자료실|자료|데이터) 전체|전체가|묶음|수십|수백|\\d+ ?(?:GB|TB)|\\d{3,} ?MB|\\d{3,}건|대용량|큰 (?:파일|전송)(?!은 아닙니다)|압축 파일 \\d개|같은 압축 파일|\\b(?:large|huge|bulk|big)\\b"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1048(다른 프로토콜로 유출) — 공격자는 평소 쓰지 않는 외부 목적지로 자료를 한꺼번에 내보내, 평소 통신과 다른 큰 전송이 단서가 된다."
  },
  {
    "name": "off-hours-archive-out",
    "mitre": "T1048",
    "condition": "경보 설명에 수업·업무 시간 밖이나 새벽·야간이 있고, 압축 파일(압축본·archive) 반출 또는 같은 목적지로의 반복 전송이 있으며 전송·반출·올라감 같은 말이 함께 있다. 수업 시간 안에 압축 파일을 만든 것만 있는 경우, 수업 끝 무렵의 백업처럼 보이는 전송 1건, 나가지 않았다·차단됐다처럼 부정하는 문장은 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "(?:수업|업무|근무|영업) 시간 밖|새벽|심야|야간|한밤|off-hours|after hours"
        },
        {
          "regex": "압축 파일|압축본|\\barchive\\b|\\bzip\\b|전송이 \\d{2,}번"
        },
        {
          "regex": "전송|반출|유출|나갔|올라|업로드|복사|\\bsent\\b|upload|exfil"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1048(다른 프로토콜로 유출) — 자료를 묶어 내보내는 일은 사용자가 없는 시간대에 몰래 이루어지는 경우가 많아, 시간 밖의 압축 파일 반출이 단서가 된다."
  },
  {
    "name": "command-channel-repeated-transfer",
    "mitre": "T1041",
    "condition": "경보 설명에 명령 통로(C2)로 큰 파일·대용량이 나갔거나 반복됐다는 내용, 또는 같은 목적지로 대용량 전송이 여러 번 반복됐다는 내용이 있다. 명령 통로에 짧은 자료 이름만 보인 경우(큰 파일이 아님)는 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "(?:명령 통로|C2|command channel)[^.]{0,20}(?:큰 파일(?!은 아닙니다)|대용량|large|반복)|같은 목적지로[^.]{0,10}(?:대용량|큰)[^.]{0,10}\\d*번? ?반복"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1041(명령 통로로 유출) — 공격자는 이미 열어 둔 명령 통로로 자료를 조금씩 반복해 내보내므로, 같은 목적지로의 큰 전송 반복이 단서가 된다."
  },
  {
    "name": "unusual-port-transfer",
    "mitre": "T1048",
    "condition": "경보 설명에 평소에 쓰지 않던(평소와 다른) 포트·프로토콜로 자료가 연속 전송됐다는 내용, 또는 DNS·ICMP 터널로 자료가 빠져나갔다는 내용이 있다. 평소 통로의 일반 전송은 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "(?:평소(?:에)? 쓰지 않(?:던|는)|평소와 다른|낯선|비표준|unusual|non-standard) ?(?:포트|프로토콜|port|protocol)[^.]{0,25}(?:전송|유출|나갔|연속|sent|transfer)|(?:DNS|ICMP) ?터널(?:로|을 통해)[^.]{0,20}(?:자료|데이터|파일)[^.]{0,15}(?:빠져|나갔|유출|전송)"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1048(다른 프로토콜로 유출) — 공격자는 평소 쓰는 통로 대신 다른 포트·프로토콜로 자료를 내보내 기존 감시를 피한다."
  },
  {
    "name": "whole-vault-copied-out",
    "mitre": "T1048",
    "condition": "경보 설명에 자료실 전체(또는 자료 전부)가 짧은 시간에 외부 주소로 복사됐다는 내용이 있다. 내 메모 한 건·공지를 읽거나 저장한 기록, 수업 자료 주소로의 작은 동기화는 해당하지 않는다",
    "match": {
      "target": "ruleDescription",
      "all": [
        {
          "regex": "(?:자료실|자료|데이터) 전체(?:가|를)?[^.]{0,15}(?:외부|밖)[^.]{0,10}(?:복사|전송|유출|나갔|올라)"
        }
      ]
    },
    "evidence": "근거: MITRE ATT&CK T1048(다른 프로토콜로 유출) — 공격자는 자료를 통째로 외부 주소로 복사해 내보내므로, 짧은 시간의 전체 복사가 단서가 된다."
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
  try { return new RegExp(source, 'iu'); } catch { return null; }
};
const COMPILED = PATTERNS.map((p) => ({ name: p.name, parts: p.match.all.map((part) => compile(part.regex)) }));

// 패턴 조건(all)을 모두 채우면 일치입니다. 정규식이 깨졌으면 일치로 보지 않습니다.
const matches = (compiled, description) => compiled.parts.every((regex) => regex && regex.test(description));

// 패턴 조건은 못 채웠어도 전송·목적지·압축 파일 흔적이 있는 설명입니다. 판단은 alert 까지만 올리고 block 은 만들지 않습니다.
const TRACE = /전송|목적지|외부 주소|다른 주소|평소와 다른|압축|나갔|복사|포트|명령 통로|반출|업로드|올라갔|유출|빠져나|터널|destination|upload|archive|exfil|sent/iu;
// 나가지 않았다·없다·실패·취소처럼 부정하는 문장은 패턴 단어가 있어도 공격이 아닙니다. 패턴 일치로 세지 않고 흔적(alert 이하)으로만 봅니다.
const NEGATED = /않았|않습니다|없습니다|없었|못했|아닙니다|차단되|막혔|취소됐|취소되었|실패|not sent|blocked/iu;

const number = (value) => {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
};

function judge(alert) {
  const description = text(alert?.rule?.description);
  const level = Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0;
  const repeats = number(alert?.data?.count);
  const bytes = number(alert?.data?.bytes);

  // 명확한 공격: 패턴 조건을 모두 채움.
  const hits = NEGATED.test(description) ? [] : COMPILED.filter((compiled) => matches(compiled, description)).map((compiled) => compiled.name);
  if (hits.length) {
    let confidence = 0.88;
    if (hits.length >= 2) confidence += 0.04;
    if (level >= 11) confidence += 0.03;
    if (repeats >= 2) confidence += 0.02;
    if (bytes >= 100000000) confidence += 0.02;
    confidence = round(Math.min(0.99, confidence));
    return { action: toAction(confidence), confidence, reason: `패턴 일치: ${hits.join(', ')}` };
  }

  // 애매한 시도: 패턴 조건은 못 채웠지만 전송·목적지·압축 파일 흔적이 있음. 수준이 낮은 평소 전송은 정상으로 내립니다.
  if (TRACE.test(description)) {
    let confidence = 0.5;
    if (level >= 6) confidence += 0.05;
    if (level >= 8) confidence += 0.1;
    if (level <= 4) confidence -= 0.25;
    confidence = round(Math.max(0.1, Math.min(0.75, confidence)));
    const reason = confidence >= ALERT_AT
      ? '애매함: 전송·목적지·압축 파일 흔적은 있으나 패턴 조건을 다 채우지 못함'
      : '정상 이벤트: 흔적이 있으나 수준이 낮은 평소 전송·기록이라 패턴과 맞지 않음';
    return { action: toAction(confidence), confidence, reason };
  }

  // 흔적이 없고 수준이 낮으면 정상 이벤트입니다. 흔적은 없는데 수준이 높으면 사람이 보도록 alert 입니다.
  if (level >= 8) return { action: 'alert', confidence: ALERT_AT, reason: '애매함: 패턴 신호는 없지만 경보 수준이 높음' };
  return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 자료 유출 패턴 신호가 없음' };
}

export function decide(alert) {
  try {
    return judge(alert);
  } catch {
    // 어떤 경보가 와도 오류를 던지지 않습니다. 판단하지 못했으면 사람이 보도록 alert 입니다.
    return { action: 'alert', confidence: ALERT_AT, reason: '판단 중 오류: 경보 형식을 확인해야 함' };
  }
}
