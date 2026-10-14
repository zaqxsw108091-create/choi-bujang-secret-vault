// 9단계에서 학생이 채우는 탐지 함수입니다. 이 기본값은 어떤 접속도 회수하지 않습니다.
// 반 엔진이 검증한 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.

// 계약(docs/DETECT_EVENTS.md)의 사건에서 시각(at)·요청 종류(method)·가명 사용자(identity.sub)
// 세 값만 읽습니다. 메모 내용·토큰·실명 같은 다른 값은 복사하지도 돌려주지도 않습니다.
// 모양이 맞지 않는 사건은 건너뛰고, 건너뛴 개수만 돌려줍니다(사건 내용은 돌려주지 않음).
export function readEvents(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');
  const readable = [];
  let skipped = 0;
  for (const event of events) {
    const at = typeof event?.at === 'string' ? Date.parse(event.at) : Number.NaN;
    const method = typeof event?.method === 'string' ? event.method.toUpperCase() : '';
    const sub = event?.identity?.sub;
    if (!Number.isFinite(at) || !method || typeof sub !== 'string' || sub === '') {
      skipped += 1;
      continue;
    }
    readable.push({ at, method, sub });
  }
  return { events: readable, skipped };
}

export const BURST_WINDOW_MS = 10 * 60 * 1000;
export const BURST_LIMIT = 120;

// 규칙 burst_read: 같은 sub의 GET이 어느 10분 구간(시작 시각 포함, 끝 제외)에서든
// 120건을 넘으면 회수를 제안합니다. 정확히 120건은 대상이 아닙니다.
// 다른 sub의 사건은 합산하지 않고, GET이 아닌 사건은 세지 않습니다.
export function detect(events) {
  const { events: readable } = readEvents(events);
  const bySub = new Map();
  for (const { at, method, sub } of readable) {
    if (method !== 'GET') continue;
    if (!bySub.has(sub)) bySub.set(sub, []);
    bySub.get(sub).push(at);
  }
  for (const [sub, times] of [...bySub].sort(([a], [b]) => (a < b ? -1 : 1))) {
    times.sort((a, b) => a - b);
    let start = 0;
    for (let end = 0; end < times.length; end += 1) {
      while (times[end] - times[start] >= BURST_WINDOW_MS) start += 1;
      if (end - start + 1 > BURST_LIMIT) {
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject: sub };
      }
    }
  }
  return { action: 'observe' };
}
