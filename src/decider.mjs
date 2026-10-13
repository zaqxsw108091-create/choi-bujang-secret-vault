// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 6단계: 등록된 기기의 요청만 허용합니다. 7단계: 복합 이상 접속은 추가 확인(step_up)으로 보냅니다. 사용자·역할·위치는 계약에 없는 값이라 읽지 않습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required']);

// 7단계 입력 검사: request.signals 를 출처별로 읽습니다. 계약에 있는 {source, region, network, hour}만 봅니다.
// 헤더·쿼리·본문에 실린 위치나 네트워크 값은 읽지 않고, 없거나 불명확한 값은 정상값으로 채우지 않고 null 로 둡니다.
// trust: 'none'(출처 없음) | 'fixture'(심판 가상 요청, 실제 접속 증거 아님) | 'unverified'(알 수 없는 출처)
const LABEL = /^[a-z][a-z0-9_-]{0,31}$/u;
const label = value => (typeof value === 'string' && LABEL.test(value) && value !== 'unknown' ? value : null);

export function readSignals(request) {
  const raw = request?.signals;
  const empty = trust => ({ trust, region: null, network: null, hour: null });
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return empty('none');
  if (raw.source === 'none') return empty('none');
  if (raw.source !== 'judge_fixture') return empty('unverified');
  return {
    trust: 'fixture',
    region: label(raw.region),
    network: label(raw.network),
    hour: Number.isInteger(raw.hour) && raw.hour >= 0 && raw.hour <= 23 ? raw.hour : null,
  };
}

// 규칙 step_up_required: 아래 셋이 모두 참일 때만 추가 확인을 요구합니다. 하나라도 빠지면 이 규칙은 아무 일도 하지 않습니다.
// 지역(region)은 조건에 넣지 않으므로 지역 하나만으로는 거부도 추가 확인도 하지 않습니다. 이 규칙은 deny 를 쓰지 않습니다.
//  1) 평소와 다른 시각(밤 0~5시)  2) 처음 보는 네트워크('unusual')  3) 엔진이 준 최근 사건에 위험 신호가 합계 20건 이상.
// 신호는 readSignals 로 출처를 확인한 값(fixture)만 씁니다. 출처가 없거나 불명확하면 아무것도 요구하지 않습니다.
const BURST_MIN = 20;
const burstCount = events => (Array.isArray(events) ? events : []).reduce((sum, e) =>
  (e && e.kind === 'risk_signal' && Number.isInteger(e.count) && e.count > 0 ? sum + e.count : sum), 0);
const stepUpDone = step => step?.verified === true
  && Number.isInteger(step.authAgeSeconds) && step.authAgeSeconds >= 0 && step.authAgeSeconds <= 900;

function needsStepUp(request) {
  const { trust, network, hour } = readSignals(request);
  if (trust !== 'fixture' || network !== 'unusual' || hour === null || hour > 5) return false;
  if (burstCount(request.recentEvents) < BURST_MIN) return false;
  return !stepUpDone(request.stepUp);
}

const respond = (request, decision, reasonCode, ruleId = RULE_IDS[0]) => ({
  schema: 'aleph.decision.v1',
  requestId: request.requestId,
  decision,
  reasonCode,
  ruleIds: [ruleId],
});

export async function decide(request) {
  // 규칙 device_registered: deviceRegistered 가 정확히 true 일 때만 통과합니다.
  // false, 값 없음, 문자열 'true' 같은 다른 값은 모두 미등록으로 봅니다.
  if (request?.deviceRegistered !== true) {
    return respond(request ?? {}, 'deny', 'device_not_registered');
  }
  if (needsStepUp(request)) {
    return respond(request, 'step_up', 'step_up_required', 'step_up_required');
  }
  return respond(request, 'allow', 'approved');
}
