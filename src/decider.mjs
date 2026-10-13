// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 6단계: 등록된 기기의 요청만 허용합니다. 사용자·역할·위치는 계약에 없는 값이라 읽지 않습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
export const RULE_IDS = Object.freeze(['device_registered']);

const respond = (request, decision, reasonCode) => ({
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
