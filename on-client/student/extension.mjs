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

// 15단계: 접속 기록·XDR 경보 목록, 필터, 상세. 모든 값은 createElement와 textContent로만 넣는다.
const KIND_LABELS = { access: '접속 기록', xdr: 'XDR 경보' };
const ACCESS_LABELS = { allowed: '접속 허용됨', denied: '접속 거부됨', unknown: '확인 불가' };

const kstFormat = new Intl.DateTimeFormat('ko-KR', {
  timeZone: 'Asia/Seoul', year: 'numeric', month: '2-digit', day: '2-digit',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false,
});

// at 원래 값을 먼저 적고, 해석할 수 있으면 한국 시각을 덧붙인다. 해석할 수 없으면 원래 값만 둔다.
function timeText(at) {
  const raw = String(at ?? '');
  const ms = Date.parse(raw);
  return Number.isFinite(ms) ? `${raw} (한국 시각 ${kstFormat.format(new Date(ms))})` : raw || '시각 없음';
}

function kindText(kind) {
  return Object.hasOwn(KIND_LABELS, kind) ? `${KIND_LABELS[kind]}(${kind})` : `확인 불가(${String(kind ?? '없음')})`;
}

function appText(appId) {
  return appId ? String(appId) : '앱을 확인할 수 없음(appId 없음)';
}

function eventLine(label, value) {
  const row = make('p', null, 'event-field');
  row.append(make('strong', `${label}: `), make('span', value));
  return row;
}

function textEntries(title, entries) {
  const block = make('section', null, 'event-block');
  block.append(make('h4', title));
  if (!Array.isArray(entries) || entries.length === 0) {
    block.append(make('p', '없음', 'state state-empty'));
    return block;
  }
  const list = make('ul', null, 'plain-list');
  for (const entry of entries) {
    const row = make('li');
    row.append(make('strong', `${String(isObject(entry) ? entry.id ?? '' : '')}: `), make('span', String(isObject(entry) ? entry.text ?? '' : '')));
    list.append(row);
  }
  block.append(list);
  return block;
}

// 세 상태를 따로 적는다. 목록에 없는 값은 정상으로 추측하지 않고 확인 불가로 둔다.
function stateLine(title, labels, value, normal) {
  const known = Object.hasOwn(labels, value) ? labels[value] : labels.unknown ?? '확인 불가';
  const bad = value !== normal;
  const code = String(value ?? '없음');
  const shown = value === 'unknown' || !Object.hasOwn(labels, value) ? `확인 불가(${code})` : `${known}(${code})`;
  return make('p', `${title}: ${bad ? '주의 · ' : ''}${shown}`, bad ? 'state state-error' : 'state state-ok');
}

function eventDetail(event) {
  const box = make('section', null, 'event-detail');
  box.dataset.studentEventDetail = String(event.id);
  box.append(make('h3', `${String(event.id)} 상세`));
  box.append(eventLine('사건 ID', String(event.id)));
  box.append(eventLine('앱', appText(event.appId)));
  box.append(textEntries('근거(evidence)', event.evidence));
  box.append(textEntries('규칙(rules)', event.rules));
  const st = isObject(event.state) ? event.state : {};
  const states = make('section', null, 'event-block');
  states.append(make('h4', '상태(state)'));
  states.append(stateLine('접속(access)', ACCESS_LABELS, st.access, 'allowed'));
  states.append(stateLine('세션(session)', SESSION_LABELS, st.session, 'active'));
  states.append(stateLine('기기(device)', DEVICE_LABELS, st.device, 'compliant'));
  box.append(states);
  return box;
}

function byLatest(list) {
  return list
    .map((event, index) => ({ event, index, ms: isObject(event) ? Date.parse(event.at) : NaN }))
    .sort((a, b) => (Number.isFinite(b.ms) ? b.ms : -Infinity) - (Number.isFinite(a.ms) ? a.ms : -Infinity) || a.index - b.index)
    .map((item) => item.event);
}

function filterSelect(id, name, entries) {
  const wrap = make('div', null, 'filter-field');
  const label = make('label', name);
  label.htmlFor = id;
  const select = make('select');
  select.id = id;
  select.append(Object.assign(make('option', '전체'), { value: 'all' }));
  for (const [value, text] of entries) select.append(Object.assign(make('option', text), { value }));
  wrap.append(label, select);
  return { wrap, select };
}

function uniqueValues(list, pick) {
  const seen = new Set();
  for (const event of list) {
    const value = pick(event);
    if (typeof value === 'string' && value !== '') seen.add(value);
  }
  return [...seen];
}

let eventViewSeq = 0;

function renderEventsView({ status, mode, data, error } = {}) {
  const root = make('div', null, 'events-view');
  root.dataset.state = typeof status === 'string' ? status : 'unknown';
  const seq = ++eventViewSeq;
  const note = modeNote({ mode });

  if (status === 'loading') {
    root.append(make('p', '기록을 불러오는 중', 'state state-loading'));
  } else if (status === 'error') {
    const message = isObject(error) && error.message ? String(error.message) : '서버 메시지 없음';
    root.append(make('p', `기록을 불러오지 못했습니다: ${message}`, 'state state-error events-failed'));
    root.append(make('p', '기록 상태를 확인하지 못했습니다. 이전 목록은 현재 결과로 표시하지 않습니다.', 'state state-error'));
    if (isObject(error) && UNVERIFIED_CODES.includes(error.code)) {
      root.append(make('p', '확인 불가: 응답이 계약과 달라 기록을 확인할 수 없습니다.', 'state state-error'));
    }
  } else if (status !== 'ok') {
    root.append(make('p', '확인 불가(unknown): 알 수 없는 조회 상태입니다. 기록을 표시하지 않습니다.', 'state state-error'));
  } else if (!Array.isArray(data) || !data.every(isObject)) {
    root.append(make('p', '확인 불가: 응답 형식이 계약과 다릅니다. 기록을 표시하지 않습니다.', 'state state-error'));
  } else if (data.length === 0) {
    root.append(make('p', '표시할 기록이 없습니다', 'state state-empty events-empty'));
    root.append(make('p', '조회는 정상 완료됐고 본인의 최근 기록이 0건입니다.', 'state state-empty'));
  } else {
    const sorted = byLatest(data); // 복사본만 정렬한다. 받은 배열은 바꾸지 않는다.
    const kinds = filterSelect(`events-kind-${seq}`, '기록 종류', uniqueValues(sorted, (e) => e.kind).map((v) => [v, kindText(v)]));
    const apps = filterSelect(`events-app-${seq}`, '업무 앱', uniqueValues(sorted, (e) => e.appId).map((v) => [v, v]));
    const accesses = filterSelect(`events-access-${seq}`, '접속 상태', uniqueValues(sorted, (e) => (isObject(e.state) ? e.state.access : undefined))
      .map((v) => [v, Object.hasOwn(ACCESS_LABELS, v) ? `${ACCESS_LABELS[v]}(${v})` : `확인 불가(${v})`]));
    const filters = make('div', null, 'events-filters');
    filters.append(kinds.wrap, apps.wrap, accesses.wrap);

    const count = make('p', null, 'events-count');
    count.setAttribute('aria-live', 'polite');
    const list = make('ul', null, 'plain-list events-list');
    const detailSlot = make('div', null, 'events-detail');
    detailSlot.setAttribute('aria-live', 'polite');
    let selectedId = null;

    function draw() {
      const kind = kinds.select.value, app = apps.select.value, access = accesses.select.value;
      const shown = sorted.filter((e) => (kind === 'all' || e.kind === kind)
        && (app === 'all' || e.appId === app)
        && (access === 'all' || (isObject(e.state) && e.state.access === access)));
      count.textContent = `표시 ${shown.length}건 / 받은 기록 ${sorted.length}건 (본인의 최근 기록만, 최대 40건)`;
      list.replaceChildren();
      if (shown.length === 0) {
        list.append(make('li', '선택한 필터에 맞는 기록이 없습니다.', 'state state-empty'));
      }
      for (const event of shown) {
        const row = make('li', null, 'event-row');
        row.dataset.studentEventId = String(event.id);
        row.append(make('p', `${String(event.id)} · ${timeText(event.at)}`, 'event-head'));
        row.append(eventLine('종류', kindText(event.kind)));
        row.append(eventLine('앱', appText(event.appId)));
        row.append(eventLine('요약', String(event.summary ?? '')));
        const button = make('button', `${String(event.id)} 상세`);
        button.type = 'button';
        button.setAttribute('aria-expanded', String(event.id === selectedId));
        button.addEventListener('click', () => {
          selectedId = event.id;
          detailSlot.replaceChildren(eventDetail(event));
          // 목록을 다시 그리지 않고 표시만 바꿔 키보드 포커스를 유지한다.
          for (const other of list.querySelectorAll('button')) other.setAttribute('aria-expanded', String(other === button));
        });
        row.append(button);
        list.append(row);
      }
      // 필터로 선택한 기록이 사라지면 상세도 함께 지운다.
      if (selectedId !== null && !shown.some((e) => e.id === selectedId)) {
        selectedId = null;
        detailSlot.replaceChildren();
      }
    }
    for (const select of [kinds.select, apps.select, accesses.select]) select.addEventListener('change', draw);
    draw();
    root.append(filters, count, list, detailSlot);
    root.append(make('p', '현재 조회 범위는 본인의 최근 기록입니다. 모든 직원의 전체 이력이나 실시간 전체 위협 탐지가 아닙니다. 저장된 XDR 경보만 보이며 이 화면이 새로 탐지하지 않습니다.', 'tag'));
  }
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
    renderEvents(input) { return renderEventsView(input); },
    renderStatus() { return '학생 구현 대기: 기기·세션·알림과 연결 점검 상태를 구분하세요.'; },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
