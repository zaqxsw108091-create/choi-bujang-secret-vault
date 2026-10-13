// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기입니다.
// 8단계: 등록 기기라도 알려진 구역 경로만 허용하고, 모르는 경로와 공지 수정은 거부합니다.
// 6단계: 등록된 기기의 요청만 허용합니다. 7단계: 복합 이상 접속은 추가 확인(step_up)으로 보냅니다. 사용자·역할·위치는 계약에 없는 값이라 읽지 않습니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { resourceIdOf } from './resources.mjs';

// 8단계: 구역 규칙 note_zone_self(자기 구역 메모 경로), notice_zone_staff_only(공지 수정), route_unknown(모르는 경로)을 더했습니다.
export const RULE_IDS = Object.freeze(['device_registered', 'step_up_required', 'note_zone_self', 'notice_zone_staff_only', 'route_unknown']);

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

// 8단계 구역 표: 엔진이 확인한 method·route·path만 봅니다. 쿼리(queryLength·querySha256)는 읽지 않고, 기능은 경로가 정하며 자료는 경로의 ID만 고릅니다.
// route 와 path 가 서로 맞고(같은 종류, :id 자리에 모양이 맞는 ID) 표에 있는 조합만 압니다. 표에 없으면 모릅니다.
// 판정기는 자료의 주인을 알 수 없습니다(계약에 자료 소유자·역할 항목이 없음). 남의 메모를 막는 일은 API의 소유자 검사(403)가 합니다.
// 공지 수정은 강사만 해야 하지만 계약에 강사 역할이 없어, 역할 없이 올 수 있는 요청은 모두 거부합니다.
const ZONES = new Map([
  ['GET /notes', { kind: 'note', id: false, decision: 'allow', ruleId: 'note_zone_self' }],
  ['POST /notes', { kind: 'note', id: false, decision: 'allow', ruleId: 'note_zone_self' }],
  ['GET /notes/:id', { kind: 'note', id: true, decision: 'allow', ruleId: 'note_zone_self' }],
  ['PUT /notes/:id', { kind: 'note', id: true, decision: 'allow', ruleId: 'note_zone_self' }],
  ['DELETE /notes/:id', { kind: 'note', id: true, decision: 'allow', ruleId: 'note_zone_self' }],
  ['PUT /notices/:id', { kind: 'notice', id: true, decision: 'deny', ruleId: 'notice_zone_staff_only' }],
]);
const noApi = value => (typeof value === 'string' && value.startsWith('/api/') ? value.slice(4) : value);
const routeKey = route => (typeof route === 'string'
  ? route.replace(/^([A-Z]+) \/api\//u, '$1 /') : null);

export function zoneOf(request) {
  const { method, route, path, subjectId, deviceId } = request ?? {};
  if (typeof subjectId !== 'string' || !subjectId || !/^[0-9a-f]{16}$/u.test(deviceId ?? '')) return null;
  const zone = ZONES.get(routeKey(route));
  if (!zone || typeof method !== 'string' || routeKey(route).split(' ')[0] !== method) return null;
  if (typeof path !== 'string' || /[?#]/u.test(path)) return null;
  const resource = resourceIdOf(`/api${noApi(path).startsWith('/') ? noApi(path) : `/${noApi(path)}`}`);
  if (!resource || resource.split(':')[0] !== zone.kind) return null;
  if ((resource === `${zone.kind}:collection`) === zone.id) return null;
  return { ...zone, resource };
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
  const zone = zoneOf(request);
  if (!zone) return respond(request, 'deny', 'route_not_allowed', 'route_unknown');
  if (zone.decision === 'deny') return respond(request, 'deny', 'zone_denied', zone.ruleId);
  if (needsStepUp(request)) {
    return respond(request, 'step_up', 'step_up_required', 'step_up_required');
  }
  return respond(request, 'allow', 'approved', zone.ruleId);
}
