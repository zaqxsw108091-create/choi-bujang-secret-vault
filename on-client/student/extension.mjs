// 이 파일은 학생이 같은 프로젝트에서 이어서 구현합니다.
// 제공 UI를 받은 것만으로 단계 완료를 인정하지 않습니다.

// 13단계: 로그인 사용자·기기·세션 표시. 모든 값은 createElement와 textContent로만 넣는다.
const DEVICE_LABELS = { compliant: '보안 기준 충족', noncompliant: '보안 기준 미충족', unknown: '확인 불가' };
const SESSION_LABELS = { active: '활성', expired: '만료', revoked: '철회됨', unknown: '확인 불가' };
const MODE_NOTES = { demo: '예제 자료 · 실제 연결 아님', disconnected: '연결 없음', unknown: '연결 상태 확인 불가' };
const UNVERIFIED_CODES = ['CONTRACT_MISMATCH', 'ENGINE_RESULT_UNVERIFIED'];

function make(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}

const isObject = (value) => value !== null && typeof value === 'object';

// 한국어 설명 옆에 전달받은 상태 코드를 그대로 붙인다. 목록에 없는 값은 정상으로 추측하지 않고 확인 불가로 둔다.
function statusText(labels, status) {
  const text = Object.hasOwn(labels, status) ? labels[status] : labels.unknown;
  return `${text}(${String(status ?? '없음')})`;
}

// 기준 충족·활성이 아닌 상태는 글자 앞에 '주의'를 붙이고 오류 모양으로 그린다. 색에만 의존하지 않는다.
function statusLine(title, name, labels, status, normal) {
  const bad = status !== normal;
  return make('p', `${title}: ${name}${name ? ' · ' : ''}${bad ? '주의 · ' : ''}${statusText(labels, status)}`, bad ? 'state state-error' : 'state state-ok');
}

function nameWithId(item) {
  const id = String(item.id ?? '');
  const label = item.label ? String(item.label) : '';
  if (label && id) return `${label} (${id})`;
  return label || id || '이름 없음';
}

// 자료 하나(me·devices·sessions)의 loading / error 표시. ok면 null을 돌려 호출한 쪽이 값을 그린다.
function resourceNotice(resource) {
  if (!isObject(resource)) return make('p', '확인 불가 (전달된 값이 없습니다)', 'state state-error');
  if (resource.status === 'loading') return make('p', '불러오는 중', 'state state-loading');
  if (resource.status === 'error') {
    const code = isObject(resource.error) ? resource.error.code : '';
    const message = isObject(resource.error) && resource.error.message ? String(resource.error.message) : '서버 메시지 없음';
    const head = UNVERIFIED_CODES.includes(code) ? '확인 불가' : '연결 실패';
    return make('p', `${head}: ${message}`, 'state state-error');
  }
  if (resource.status !== 'ok') return make('p', '확인 불가 (알 수 없는 상태)', 'state state-error');
  return null;
}

function modeNote(resource) {
  return isObject(resource) && Object.hasOwn(MODE_NOTES, resource.mode) ? make('p', MODE_NOTES[resource.mode], 'tag tag-demo') : null;
}

function identityBlock(title, resource, drawOk) {
  const block = make('section', null, 'identity-block');
  block.append(make('h3', title));
  const notice = resourceNotice(resource);
  if (notice) block.append(notice);
  else drawOk(block);
  const note = modeNote(resource);
  if (note) block.append(note);
  return block;
}

function drawMe(block, me) {
  const data = me.data;
  if (!isObject(data) || !isObject(data.user) || !isObject(data.device) || !isObject(data.session)) {
    block.append(make('p', '확인 불가: 응답 형식이 계약과 다릅니다', 'state state-error'));
    return;
  }
  block.append(make('p', `사용자: ${nameWithId(data.user)}`));
  block.append(statusLine('현재 기기', nameWithId(data.device), DEVICE_LABELS, data.device.status, 'compliant'));
  block.append(statusLine('현재 세션', String(data.session.id ?? ''), SESSION_LABELS, data.session.status, 'active'));
}

function drawList(block, resource, empty, drawItem) {
  if (!Array.isArray(resource.data)) {
    block.append(make('p', '확인 불가: 응답 형식이 계약과 다릅니다', 'state state-error'));
    return;
  }
  if (resource.data.length === 0) return block.append(make('p', empty, 'state state-empty'));
  const list = make('ul', null, 'plain-list');
  for (const item of resource.data) {
    const row = make('li');
    row.append(isObject(item) ? drawItem(item) : make('span', '확인 불가'));
    list.append(row);
  }
  block.append(list);
}

// 14단계: 업무 앱 접속 판정 표시. 한국어 뜻 옆에 전달받은 원래 코드값을 함께 적는다.
const DECISION_LABELS = { allow: '허용', deny: '거부', challenge: '추가 확인 필요', unknown: '확인 불가' };
const DECISION_NOTES = {
  allow: '정책상 접근이 허용되었습니다. 실제 앱 접속 성공을 보장하지 않습니다.',
  deny: '정책상 접근이 거부되었습니다.',
  challenge: '추가 인증 또는 확인이 필요합니다. 이 앱이 확인 절차를 대신 수행하지 않습니다.',
  unknown: '판정을 확인할 수 없습니다. 접근이 허용되지 않은 것으로 취급하세요.',
};

// 허용·거부·추가 확인·확인 불가 중 하나로만 정규화한다. 목록에 없는 값(문자열이 아닌 값 포함)은 unknown으로 둔다.
function decisionCode(value) {
  return typeof value === 'string' && Object.hasOwn(DECISION_LABELS, value) && value !== 'unknown' ? value : 'unknown';
}

function decisionDetail(name, value) {
  const row = make('p', null, 'decision-detail');
  row.append(make('strong', `${name}: `), make('span', value));
  return row;
}

function decisionBox(code, appId, reason, checkedAt) {
  const box = make('section', null, 'decision-result');
  box.dataset.decision = code;
  const bad = code === 'unknown' || code === 'deny';
  box.append(make('p', `접속 판정: ${DECISION_LABELS[code]}(${code})`, `decision decision-${code}`));
  box.append(make('p', DECISION_NOTES[code], bad || code === 'challenge' ? 'state state-error' : 'state state-ok'));
  box.append(decisionDetail('앱', appId ? String(appId) : '확인 불가'));
  box.append(decisionDetail('판정 이유', reason ? String(reason) : '이유 없음'));
  box.append(decisionDetail('판정 시각', checkedAt ? String(checkedAt) : '확인 불가'));
  return box;
}

function renderDecisionView({ status, mode, data, error, appId } = {}) {
  const root = make('div', null, 'decision-view');
  root.dataset.state = typeof status === 'string' ? status : 'unknown';
  if (status === 'idle') {
    root.append(make('p', '앱을 골라 접속을 요청하세요.', 'state state-empty'));
  } else if (status === 'loading') {
    root.append(make('p', `판정 확인 중${appId ? ` · 앱 ${String(appId)}` : ''}`, 'state state-loading'));
  } else if (status === 'error') {
    const message = isObject(error) && error.message ? String(error.message) : '서버 메시지 없음';
    root.append(make('p', `요청 실패: ${message}`, 'state state-error decision-failed'));
    root.append(make('p', '요청이 실패했을 뿐 접근 거부 판정이 아닙니다. 허용 여부도 확인되지 않았으므로 허용으로 보지 마세요.', 'state state-error'));
    if (appId) root.append(decisionDetail('앱', String(appId)));
  } else if (status === 'ok') {
    // 응답이 요청한 앱의 것이 아니거나 형식이 다르면 판정을 신뢰하지 않고 확인 불가로 보인다.
    if (!isObject(data) || (appId != null && data.appId !== appId)) {
      root.append(make('p', '확인 불가(unknown): 응답 형식이 계약과 다르거나 선택한 앱의 판정이 아닙니다. 허용으로 보지 마세요.', 'state state-error'));
    } else {
      root.append(decisionBox(decisionCode(data.decision), data.appId, data.reason, data.checkedAt));
    }
  } else {
    root.append(make('p', '확인 불가(unknown): 알 수 없는 요청 상태입니다. 허용으로 보지 마세요.', 'state state-error'));
  }
  const note = modeNote({ mode });
  if (note) root.append(note);
  return root;
}

export function createStudentView() {
  return {
    renderIdentity({ me, devices, sessions } = {}) {
      const root = make('div', null, 'identity-view');
      root.append(identityBlock('로그인 사용자·현재 기기·세션', me, (block) => drawMe(block, me)));
      root.append(identityBlock('등록된 기기', devices, (block) => drawList(block, devices, '표시할 기기가 없습니다.',
        (d) => make('span', `${nameWithId(d)} · ${d.status === 'compliant' ? '' : '주의 · '}${statusText(DEVICE_LABELS, d.status)}`))));
      root.append(identityBlock('로그인 세션', sessions, (block) => drawList(block, sessions, '표시할 세션이 없습니다.',
        (s) => make('span', `${String(s.id ?? '')} · ${s.status === 'active' ? '' : '주의 · '}${statusText(SESSION_LABELS, s.status)}`))));
      return root;
    },
    renderDecision(input) { return renderDecisionView(input); },
    renderEvents() { return '학생 구현 대기: 본인 접속·XDR 기록을 연결하세요.'; },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
