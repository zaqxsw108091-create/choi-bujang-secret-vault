// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 6단계: 등록된 기기의 요청만 허용합니다. 사용자·역할·위치는 계약에 없는 값이라 읽지 않습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

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

const respond =(request, decision, reasonCode) => ({
  schema: 'aleph.decision.v1',
  requestId: request.requestId,
  decision,
  reasonCode,
  ruleIds: [RULE_IDS[0]],
});

export async function decide(request) {
  // 규칙 device_registered: deviceRegistered 가 정확히 true 일 때만 통과합니다.
  // false, 값 없음, 문자열 'true' 같은 다른 값은 모두 미등록으로 봅니다.
  if (request?.deviceRegistered !== true) {
    return respond(request ?? {}, 'deny', 'device_not_registered');
  }
  return respond(request, 'allow', 'approved');
}
