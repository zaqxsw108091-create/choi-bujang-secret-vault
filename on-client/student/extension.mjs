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
  box.append(unsupportedActions(event));
  return box;
}

// 16단계: 아직 실행 연결이 없는 조치는 요청을 보내지 않는 비활성 버튼으로만 알린다. supportedActions가 비어 있으면 아무것도 만들지 않는다.
const SAFE_ACTION = /^[A-Za-z0-9._:-]{1,64}$/;
let unsupportedSeq = 0;

function unsupportedActions(event) {
  const actions = Array.isArray(event.supportedActions) ? event.supportedActions : [];
  const block = make('section', null, 'event-block unsupported-actions');
  if (actions.length === 0) return block; // 빈 껍데기만 남기지 않는다.
  const valid = [...new Set(actions.filter((a) => typeof a === 'string' && SAFE_ACTION.test(a)))];
  const noteId = `unsupported-note-${++unsupportedSeq}`;
  block.append(make('h4', '조치(action)'));
  const note = make('p', '아직 지원하지 않는 조치입니다. 조치 실행 연결은 준비 중이며, 이 화면은 조치 요청을 보내지 않습니다.', 'state state-empty');
  note.id = noteId;
  block.append(note);
  const row = make('div', null, 'unsupported-buttons');
  for (const action of valid) {
    const button = make('button', `${action} 미지원`);
    button.type = 'button';
    button.disabled = true;
    button.setAttribute('aria-describedby', noteId);
    row.append(button);
  }
  block.append(row);
  if (valid.length !== actions.length) block.append(make('p', `형식이 맞지 않는 조치 ${actions.length - valid.length}개는 표시하지 않았습니다.`, 'state state-error'));
  return block;
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

// 16단계: 기기·세션·알림·도움정보 상태. 모든 값은 createElement와 textContent로만 넣는다.
// 입력으로 매번 전체를 새로 그리므로 다시 불러와 성공하면 이전 실패 안내는 남지 않는다. 이 코드는 어떤 요청도 보내지 않는다.
const RESOURCE_LABELS = {
  me: '로그인 사용자(me)', devices: '기기(devices)', sessions: '세션(sessions)', apps: '업무 앱(apps)',
  events: '기록(events)', access: '접속 판정(access)', diagnostics: '도움정보(diagnostics)',
  vulnerabilities: '취약점(vulnerabilities)', aiConnection: 'AI 연결(aiConnection)',
};
const TIMEOUT_CODES = ['TIMEOUT', 'REQUEST_TIMEOUT', 'ENGINE_TIMEOUT'];
// 자료 불러오기 실패가 아니라 기기·세션·기록의 상태값인 code.
const STATE_CODES = ['noncompliant', 'unknown', 'expired', 'revoked', 'compliant', 'active', 'access', 'xdr'];
const RETRY_GUIDE = '다시 시도는 위쪽 다시 불러오기 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.';

function shortText(value, max = 200) {
  const text = String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim();
  return text.length > max ? `${text.slice(0, max)}…` : text;
}

function resourceName(resource) {
  return typeof resource === 'string' && Object.hasOwn(RESOURCE_LABELS, resource) ? RESOURCE_LABELS[resource] : `확인 불가 자료(${shortText(resource, 60) || '없음'})`;
}

// 불러오기 실패는 빈 목록과 다른 문장·표시로 보여 준다. 시간 초과는 시간 초과라고 적는다.
function failureNotice(subject, resource, guide) {
  const err = isObject(resource.error) ? resource.error : {};
  const code = typeof err.code === 'string' ? err.code : '';
  const message = err.message ? shortText(err.message) : '서버 메시지 없음';
  const box = make('div', null, 'status-failure');
  let head;
  if (TIMEOUT_CODES.includes(code)) head = `${subject} 불러오기 실패: 시간 초과(${code})`;
  else if (UNVERIFIED_CODES.includes(code)) head = `${subject} 확인 불가: 응답을 검증하지 못했습니다(${code})`;
  else head = `${subject} 불러오기 실패: 연결 문제${code ? `(${shortText(code, 60)})` : ''}`;
  box.append(make('p', head, 'state state-error status-failed'));
  box.append(make('p', `서버 메시지: ${message}`, 'state state-error'));
  box.append(make('p', guide, 'state state-error'));
  return box;
}

function statusSection(title, subject, resource, empty, drawItem, scopeNote) {
  const block = make('section', null, 'status-block');
  block.append(make('h3', title));
  block.dataset.state = isObject(resource) && typeof resource.status === 'string' ? resource.status : 'unknown';
  if (!isObject(resource)) {
    block.append(make('p', `${subject} 확인 불가: 전달된 값이 없습니다.`, 'state state-error'));
  } else if (resource.status === 'loading') {
    block.append(make('p', `${subject} 불러오는 중`, 'state state-loading'));
  } else if (resource.status === 'error') {
    block.append(failureNotice(subject, resource, RETRY_GUIDE));
  } else if (resource.status !== 'ok') {
    block.append(make('p', `${subject} 확인 불가: 알 수 없는 상태(${shortText(resource.status, 40) || '없음'})입니다.`, 'state state-error'));
  } else if (!Array.isArray(resource.data) || !resource.data.every(isObject)) {
    block.append(make('p', `${subject} 확인 불가: 응답 형식이 계약과 다릅니다. 목록을 표시하지 않습니다.`, 'state state-error'));
  } else if (resource.data.length === 0) {
    block.append(make('p', empty, 'state state-empty status-empty'));
    block.append(make('p', '조회는 정상 완료됐고 0건입니다. 실패가 아닙니다.', 'state state-empty'));
  } else {
    const list = make('ul', null, 'plain-list');
    for (const item of resource.data) list.append(make('li', drawItem(item)));
    block.append(list);
  }
  if (scopeNote) block.append(make('p', scopeNote, 'tag'));
  const note = modeNote(resource);
  if (note) block.append(note);
  return block;
}

function notificationsSection(notifications) {
  const block = make('section', null, 'status-block');
  block.append(make('h3', '알림'));
  if (!Array.isArray(notifications)) {
    block.append(make('p', '알림 확인 불가: 전달된 값이 없습니다.', 'state state-error'));
    return block;
  }
  if (notifications.length === 0) {
    block.append(make('p', '알림 없음: 주의할 알림이 없습니다.', 'state state-ok status-no-notifications'));
    return block;
  }
  block.append(make('p', `주의할 알림 ${notifications.length}건`, 'state state-error'));
  const list = make('ul', null, 'plain-list notification-list');
  for (const item of notifications) {
    const n = isObject(item) ? item : {};
    const row = make('li', null, 'notification');
    const code = shortText(n.code, 60);
    row.append(eventLine('알림 자료(resource)', resourceName(n.resource)));
    row.append(eventLine('코드(code)', code || '없음'));
    row.append(eventLine('메시지(message)', shortText(n.message) || '메시지 없음'));
    const failure = code !== '' && !STATE_CODES.includes(code);
    row.append(make('p', failure
      ? '할 일: 연결 상태를 확인한 뒤 위쪽 다시 불러오기 버튼을 직접 누르세요. 자동으로 다시 요청하지 않습니다.'
      : '할 일: 해당 항목의 상태를 확인하세요. 이 화면은 조치를 실행하지 않습니다.', 'state state-error'));
    list.append(row);
  }
  block.append(list);
  return block;
}

// 도움정보로 복사할 값은 이 여섯 개뿐이다. 문자열이 아니거나 비밀처럼 보이는 값은 복사하지 않고 가린다.
const SECRET_LIKE = /(token|secret|password|passwd|api[-_ ]?key|authorization|bearer|private[-_ ]?key|eyJ[A-Za-z0-9_-]{10,}|sk-[A-Za-z0-9_-]{8,})/i;

function safeValue(value) {
  if (typeof value !== 'string' || value === '') return '확인 불가';
  const text = shortText(value);
  return SECRET_LIKE.test(text) ? '[비밀처럼 보여 가림]' : text;
}

function diagnosticsFields(data) {
  if (!isObject(data) || !isObject(data.engine)) return null;
  return [
    ['requestId', safeValue(data.requestId)],
    ['component', safeValue(data.component)],
    ['version', safeValue(data.version)],
    ['checkedAt', safeValue(data.checkedAt)],
    ['engine.mode', safeValue(data.engine.mode)],
    ['engine.code', safeValue(data.engine.code)],
  ];
}

function diagnosticsSection(diagnostics) {
  const block = make('section', null, 'status-block diagnostics-block');
  block.append(make('h3', '도움정보(진단)'));
  const state = isObject(diagnostics) ? diagnostics.status : undefined;
  block.dataset.state = typeof state === 'string' ? state : 'unknown';
  let fields = null;
  if (!isObject(diagnostics)) {
    block.append(make('p', '도움정보 확인 불가: 전달된 값이 없습니다.', 'state state-error'));
  } else if (state === 'idle' || state === undefined) {
    block.append(make('p', '도움정보를 아직 불러오지 않았습니다. 제공 화면의 「도움정보 불러오기」를 직접 누르면 여기에 표시됩니다.', 'state state-empty'));
  } else if (state === 'loading') {
    block.append(make('p', '도움정보 불러오는 중', 'state state-loading'));
  } else if (state === 'error') {
    block.append(failureNotice('도움정보', diagnostics, '다시 시도는 제공 화면의 「도움정보 불러오기」를 직접 누르세요. 자동으로 다시 요청하지 않습니다.'));
  } else if (state !== 'ok') {
    block.append(make('p', '도움정보 확인 불가: 알 수 없는 상태입니다.', 'state state-error'));
  } else {
    fields = diagnosticsFields(diagnostics.data);
    if (!fields) block.append(make('p', '도움정보 확인 불가: 응답 형식이 계약과 다릅니다. 복사할 값이 없습니다.', 'state state-error'));
  }

  const text = fields ? fields.map(([name, value]) => `${name}: ${value}`).join('\n') : '';
  if (fields) {
    const pre = make('pre', text, 'diag-output');
    pre.tabIndex = 0; // 키보드로 읽고 선택할 수 있게 한다.
    pre.setAttribute('aria-label', '복사될 도움정보 값');
    block.append(pre);
    block.append(make('p', '이 값은 도움 요청에 쓰도록 복사하는 정보입니다. 비밀번호·토큰·API 키는 들어 있지 않습니다. 복사 전에 직접 읽어 확인하고, 「도움정보 복사」를 누를 때만 복사합니다. 자동으로 전송하지 않습니다.', 'tag'));
  }
  const button = make('button', '도움정보 복사');
  button.type = 'button';
  button.disabled = fields === null;
  const result = make('p', fields ? '' : '복사할 도움정보가 없어 버튼을 사용할 수 없습니다.', 'state');
  result.setAttribute('role', 'status');
  result.setAttribute('aria-live', 'polite');
  button.addEventListener('click', async () => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      result.className = 'state state-ok';
      result.textContent = '도움정보 값 6개를 복사했습니다. 붙여 넣기 전에 비밀 값이 없는지 직접 읽어 확인하세요.';
    } catch {
      const range = document.createRange();
      const pre = block.querySelector('pre');
      if (pre) { range.selectNodeContents(pre); const sel = window.getSelection(); sel.removeAllRanges(); sel.addRange(range); pre.focus(); }
      result.className = 'state state-error';
      result.textContent = '자동 복사를 사용할 수 없습니다. 선택된 값을 Ctrl+C로 직접 복사하세요.';
    }
  });
  block.append(button, result);
  return block;
}

function renderStatusView({ devices, sessions, notifications, diagnostics, mode } = {}, pc) {
  const root = make('div', null, 'status-view');
  // 마지막 총공세: 내 PC 기록·추이·위험 알림(학생 구현)을 이 칸의 맨 위에 둔다. 아래 기존 표시는 그대로다.
  if (pc) root.append(pc.render());
  root.append(statusSection('등록된 기기', '기기 목록', devices, '등록된 기기가 없음',
    (d) => `${nameWithId(d)} · ${d.status === 'compliant' ? '' : '주의 · '}${statusText(DEVICE_LABELS, d.status)}`,
    '내 이름으로 등록되고 회수되지 않은 기기를 최대 100개까지 보며, 운영체제처럼 서버가 모르는 값은 확인 불가입니다.'));
  root.append(statusSection('현재 세션', '세션', sessions, '현재 연결 없음',
    (s) => `${String(s.id ?? '')} · ${s.status === 'active' ? '' : '주의 · '}${statusText(SESSION_LABELS, s.status)}`,
    '세션은 현재 검증된 연결 한 개만 표시합니다. 과거 세션 전체 목록이 아닙니다.'));
  root.append(notificationsSection(notifications));
  root.append(diagnosticsSection(diagnostics));
  const note = modeNote({ mode });
  if (note) root.append(note);
  return root;
}

// 17단계: AI 연결 점검 결과와 사건 설명 기초 표시. 모든 값은 createElement와 textContent로만 넣는다.
// 입력으로 매번 전체를 새로 그리므로 모듈 안에 이전 점검 결과를 보관하지 않는다.
// 다시 점검해 성공하거나 idle로 돌아오면 이전 오류·모델 수는 화면에 남지 않는다. 이 코드는 어떤 요청도 보내지 않는다.
const AI_CAUSES = {
  pending: { title: '권한 준비 중·확인 불가', guide: '앱 권한이 아직 준비 중이거나 확인할 수 없는 상태입니다. 운영 측 준비 전에는 학생 잘못이 아니어도 나옵니다. 담당자에게 계정 연결과 앱 권한 확인을 요청하세요. 연결 성공이 아닙니다.' },
  auth: { title: '인증 실패', guide: '보호 현황에서 계정 연결을 다시 확인하세요. 계속되면 담당자에게 확인을 요청하세요. 열쇠를 복사해 붙이지 마세요.' },
  blocked: { title: '접근 제한', guide: '이 계정의 AI 이용이 제한됐습니다. 계정 연결을 다시 확인하고 담당자에게 이용 권한을 확인하세요.' },
  limit: { title: '반 사용량·이용 한도', guide: '반 사용량 또는 이용 한도에 도달했습니다. 담당자에게 확인을 요청하세요.' },
  hours: { title: '이용 시간 아님', guide: '지금은 AI 이용 시간이 아닙니다. 이용 시간을 확인한 뒤 직접 다시 점검하세요.' },
  rate: { title: '요청 제한', guide: '요청이 잠시 제한됐습니다. 잠시 뒤 직접 다시 점검하세요.' },
  timeout: { title: '시간 초과', guide: '응답 시간이 초과됐습니다. 잠시 뒤 직접 다시 점검하세요.' },
  network: { title: '네트워크', guide: '서버에 연결하지 못했습니다. 잠시 뒤 직접 다시 점검하세요.' },
  cancelled: { title: '취소', guide: '취소됐습니다. 이전 결과는 현재 결과가 아닙니다.' },
  nomodel: { title: '쓸 수 있는 모델 없음', guide: '현재 앱 권한으로 쓸 수 있는 모델이 없습니다. 담당자에게 모델 허용 설정 확인을 요청하세요.' },
  invalid: { title: '확인 불가(설명 입력·응답 형식)', guide: '설명에 쓸 근거나 응답 형식을 확인할 수 없습니다. 이 응답은 사건 설명 결과로 쓰지 않습니다.' },
};
// 앱이 안전한 문구로 바꿔 넘기는 code만 그대로 보여 준다. 목록에 없는 값은 원인을 단정하지 않고 확인 불가로 둔다.
const AI_CODE_CAUSE = {
  ON_AI_PROVISIONING_PENDING: 'pending', AI_REQUEST_UNVERIFIED: 'pending', SUBJECT_SCOPE_UNVERIFIED: 'pending',
  MODEL_NOT_CONFIGURED: 'pending', ON_AI_AUTHORIZATION_CHANGED: 'pending',
  WB_CLCO_AUTH_REQUIRED: 'auth', WB_CLCO_ACCESS_BLOCKED: 'blocked',
  WB_CLCO_COHORT_BUDGET_EXHAUSTED: 'limit', WB_CLCO_LIMIT_REACHED: 'limit',
  WB_CLCO_SESSION_CLOSED: 'hours', WB_CLCO_RATE_LIMITED: 'rate',
  WB_CLCO_TIMEOUT: 'timeout', REQUEST_TIMEOUT: 'timeout', ENGINE_TIMEOUT: 'timeout', TIMEOUT: 'timeout',
  NETWORK_ERROR: 'network', WB_CLCO_NETWORK_ERROR: 'network',
  WB_CLCO_CANCELLED: 'cancelled', CANCELLED: 'cancelled', REQUEST_CANCELLED: 'cancelled',
  ON_AI_MODEL_LIST_EMPTY: 'nomodel', ON_AI_INVALID_INPUT: 'invalid', ON_AI_INVALID_OUTPUT: 'invalid',
};
const AI_AUTH_LABELS = { test: '시험 연결 점검(test)', verified: '앱 권한 확인 후 점검(verified)' };
const AI_AUTH_NOTES = {
  test: '시험 연결입니다. 앱 권한이 확인됐다는 뜻이 아닙니다.',
  verified: '그 시각 기준의 앱 권한 확인과 모델 응답입니다. 이후에도 계속 유효하다는 뜻은 아닙니다.',
};
const AI_MANUAL = '다시 점검은 「AI 연결 점검」 버튼을 직접 눌러야 합니다. 자동으로 다시 점검하지 않습니다.';

function aiCause(error) {
  const code = isObject(error) && typeof error.code === 'string' ? error.code : '';
  const known = Object.hasOwn(AI_CODE_CAUSE, code);
  return { code: known ? code : '', cause: AI_CAUSES[known ? AI_CODE_CAUSE[code] : 'pending'], known };
}

// 오류 code·message·원인·안내를 글자로 보여 준다. 알 수 없는 code와 그 message는 그대로 옮기지 않는다.
function aiErrorLines(error) {
  const { code, cause, known } = aiCause(error);
  const message = known && isObject(error) && typeof error.message === 'string' && error.message ? shortText(error.message) : '';
  const lines = [
    make('p', `오류 코드: ${known ? code : '확인 불가(알 수 없는 코드)'}`, 'state state-error'),
    make('p', `메시지: ${message && !SECRET_LIKE.test(message) ? message : '표시할 수 있는 서버 메시지 없음'}`, 'state state-error'),
    make('p', `원인 구분: ${cause.title}`, 'state state-error'),
    make('p', `안내: ${cause.guide}`),
  ];
  return lines;
}

function aiTimeLine(label, at) {
  return make('p', `${label}: ${typeof at === 'string' && at ? timeText(shortText(at, 64)) : '시각 정보 없음'}`);
}

function renderAiConnectionView({ status, mode, data, error, checkedAt } = {}) {
  const root = make('div', null, 'ai-connection-view');
  root.append(make('h3', 'AI 연결 점검 결과'));
  if (status === 'idle') {
    root.append(make('p', 'AI 연결 점검 전', 'state state-empty'));
    root.append(make('p', '아직 점검하지 않았습니다. 이전 점검 결과는 표시하지 않습니다.'));
    root.append(make('p', '사건 설명은 아직 실행하지 않았습니다.'));
    root.append(make('p', AI_MANUAL, 'muted'));
  } else if (status === 'loading') {
    root.append(make('p', 'AI 연결 점검 중', 'state state-loading'));
    root.append(make('p', '응답을 기다리는 중입니다. 이전 점검 결과는 현재 결과가 아니므로 표시하지 않습니다.'));
    root.append(make('p', '점검을 중단하려면 「AI 연결 점검 취소」 버튼을 직접 누르세요.', 'muted'));
  } else if (status === 'error') {
    root.append(make('p', '주의 · AI 연결 점검 실패(error)', 'state state-error'));
    for (const line of aiErrorLines(error)) root.append(line);
    root.append(make('p', '이전 점검 결과는 현재 결과가 아니므로 표시하지 않습니다. 사건 설명은 실행하지 않았습니다.'));
    root.append(make('p', AI_MANUAL, 'muted'));
  } else if (status === 'ok') {
    const valid = isObject(data) && data.transportChecked === true && Object.hasOwn(AI_AUTH_LABELS, data.audienceAuthorization)
      && Number.isInteger(data.modelCount) && data.modelCount >= 0;
    if (!valid) {
      root.append(make('p', '주의 · 확인 불가: 점검 결과의 형식을 확인할 수 없습니다.', 'state state-error'));
      root.append(make('p', '연결 점검이 끝났다고 표시하지 않습니다. 담당자에게 확인을 요청하세요.'));
    } else {
      root.append(make('p', `연결 점검 결과: ${AI_AUTH_LABELS[data.audienceAuthorization]}`, 'state state-ok'));
      root.append(make('p', AI_AUTH_NOTES[data.audienceAuthorization]));
      root.append(make('p', `응답 모델 수(modelCount): ${data.modelCount}개`));
      root.append(aiTimeLine('점검 시각(checkedAt)', checkedAt));
      if (data.modelCount === 0) {
        root.append(make('p', `주의 · ${AI_CAUSES.nomodel.title}: ${AI_CAUSES.nomodel.guide}`, 'state state-error'));
      }
      root.append(make('p', '연결만 점검했습니다. 사건 설명은 아직 실행하지 않았습니다.', 'state state-empty'));
      root.append(make('p', '모델 목록 응답은 사건 설명이 아닙니다. 사건 설명은 보안 기록에서 따로 요청하고 확인합니다.', 'muted'));
      root.append(make('p', AI_MANUAL, 'muted'));
    }
  } else {
    root.append(make('p', '주의 · 확인 불가: 알 수 없는 점검 상태입니다.', 'state state-error'));
    root.append(make('p', '연결 성공으로 표시하지 않습니다.'));
  }
  const note = modeNote({ mode });
  if (note) root.append(note);
  return root;
}

// 18단계 renderExplanation: 설명을 선택한 기록의 근거·규칙·현재 상태와 함께 보여 준다.
// 성공으로 검증된 설명에만 data-student-explanation-event를 붙인다. 입력으로 매번 새로 그리며 이전 설명을 보관하지 않는다.
// 이 함수는 어떤 요청도 보내지 않고 조치 실행 버튼도 만들지 않는다.
const EXPLANATION_EVENT_ID = /^[A-Za-z0-9._:-]{1,64}$/;
const STATE_NAMES = { access: '접속', session: '세션', device: '기기' };

// 설명을 쓸 수 없는 까닭. 근거를 지어내 맞추지 않고 거부한다.
const REJECT_REASONS = {
  event: '보안 기록(사건 ID)을 확인할 수 없습니다.',
  insufficient: '근거 부족: 이 기록에 설명에 쓸 근거 문장이나 규칙이 없습니다.',
  format: '설명의 요약·근거 ID·제안 형식을 확인할 수 없습니다.',
  mismatch: '근거가 맞지 않습니다: 설명이 인용한 근거 ID가 선택한 기록의 근거와 일치하지 않습니다.',
  proposal: '제안한 조치나 그 근거가 이 기록과 맞지 않습니다(이 기록이 지원하지 않는 조치이거나 없는 근거 ID).',
  executed: 'AI가 이미 실행했다고 답한 설명입니다. 사람 확인 없이 실행된 것으로 읽히는 설명은 쓸 수 없습니다.',
  confirmation: '사람 확인이 필요하다는 표시가 없는 설명입니다. 쓸 수 없습니다.',
};

function validIdList(list) {
  return Array.isArray(list) && list.length > 0 && list.every((id) => typeof id === 'string' && id !== '') && new Set(list).size === list.length;
}

// 설명(data)을 선택한 기록(event)에 대조한다. 맞으면 { ok:true, ... }, 아니면 { ok:false, reason }.
function checkExplanation(event, data) {
  if (!isObject(event) || typeof event.id !== 'string' || !EXPLANATION_EVENT_ID.test(event.id)) return { ok: false, reason: 'event' };
  const evidence = Array.isArray(event.evidence) ? event.evidence.filter((row) => isObject(row) && typeof row.id === 'string' && typeof row.text === 'string') : [];
  const rules = Array.isArray(event.rules) ? event.rules.filter((row) => isObject(row) && typeof row.id === 'string' && typeof row.text === 'string') : [];
  if (evidence.length === 0 || rules.length === 0) return { ok: false, reason: 'insufficient' };
  if (!isObject(data)) return { ok: false, reason: 'format' };
  if (data.executed !== false) return { ok: false, reason: 'executed' };
  if (data.requiresHumanConfirmation !== true) return { ok: false, reason: 'confirmation' };
  const summary = typeof data.summary === 'string' ? shortText(data.summary, 1500) : '';
  if (!summary || !Array.isArray(data.proposals) || data.proposals.length > 3 || !validIdList(data.evidenceIds)) return { ok: false, reason: 'format' };
  const evidenceText = new Map(evidence.map((row) => [row.id, row.text]));
  // 없는 ID가 있거나, 기록의 근거를 빠뜨렸으면 이 기록의 설명으로 인정하지 않는다.
  if (!data.evidenceIds.every((id) => evidenceText.has(id)) || data.evidenceIds.length !== evidenceText.size) return { ok: false, reason: 'mismatch' };
  const supported = Array.isArray(event.supportedActions) ? event.supportedActions : [];
  const proposals = [];
  for (const proposal of data.proposals) {
    const valid = isObject(proposal) && typeof proposal.action === 'string' && SAFE_ACTION.test(proposal.action) && supported.includes(proposal.action)
      && validIdList(proposal.evidenceIds) && proposal.evidenceIds.every((id) => evidenceText.has(id))
      && typeof proposal.reason === 'string' && proposal.reason.trim() !== '';
    if (!valid) return { ok: false, reason: 'proposal' };
    proposals.push({ action: proposal.action, reason: shortText(proposal.reason, 500), evidenceIds: [...proposal.evidenceIds] });
  }
  return { ok: true, id: event.id, summary, evidenceIds: data.evidenceIds, evidenceText, rules, proposals, supportedCount: supported.length };
}

function explanationRows(title, rows) {
  const block = make('section', null, 'event-block');
  block.append(make('h4', title));
  const list = make('ul', null, 'plain-list');
  for (const row of rows) list.append(make('li', row));
  block.append(list);
  return block;
}

function explanationStates(event) {
  const block = make('section', null, 'event-block');
  block.append(make('h4', '확인 불가 상태'));
  const st = isObject(event.state) ? event.state : {};
  const lines = Object.keys(STATE_NAMES).filter((key) => st[key] === 'unknown').map((key) => `${STATE_NAMES[key]}: 확인 불가(unknown)`);
  if (lines.length === 0) {
    block.append(make('p', '없음', 'state state-empty'));
    block.append(make('p', '이 목록은 unknown인 값만 나열합니다. 나머지 값의 사실 판단은 기록의 상태 표시를 따르며, 확인 불가를 정상·안전으로 바꾸지 않습니다.', 'muted'));
  } else {
    const list = make('ul', null, 'plain-list');
    for (const line of lines) list.append(make('li', line, 'state state-error'));
    block.append(list);
    block.append(make('p', '확인 불가는 정상이나 안전이 아닙니다. 연동 시스템이 알려 주지 않은 상태입니다.', 'muted'));
  }
  return block;
}

function explanationProposals(result) {
  const block = make('section', null, 'event-block');
  block.append(make('h4', '조치 제안'));
  if (result.proposals.length === 0) {
    block.append(make('p', result.supportedCount === 0
      ? '연동 시스템이 지원하는 조치가 없어 제안이 없습니다(정상).'
      : 'AI가 이 기록에 대해 제안한 조치가 없습니다. 필요하면 근거를 보고 담당자와 판단하세요.', 'state state-empty'));
    block.append(make('p', 'AI는 아무것도 실행하지 않았습니다(미실행).'));
    return block;
  }
  const list = make('ul', null, 'plain-list');
  for (const proposal of result.proposals) {
    const row = make('li');
    row.append(make('strong', `${proposal.action}: `), make('span', `${proposal.reason} (근거 ${proposal.evidenceIds.join(', ')})`));
    list.append(row);
  }
  block.append(list);
  block.append(make('p', '사람 확인이 필요하며 실행되지 않았습니다(미실행). 이 화면에는 조치를 실행하는 버튼이 없습니다.', 'state state-empty'));
  return block;
}

function renderExplanationView({ event, explanation, checkedAt } = {}) {
  const root = make('div', null, 'explanation-view');
  const status = isObject(explanation) ? explanation.status : undefined;
  // 1) 실패가 먼저다. event가 null이어도 안전한 오류 코드·메시지와 실패 이유를 보여 준다.
  if (status === 'error') {
    root.append(make('p', '주의 · AI 설명 실패(error)', 'state state-error'));
    for (const line of aiErrorLines(explanation.error)) root.append(line);
    const noEvidence = isObject(event) && (!Array.isArray(event.evidence) || event.evidence.length === 0);
    if (!isObject(event)) root.append(make('p', '실패 이유: 선택한 기록을 확인할 수 없어 근거를 대조하지 못했습니다.', 'state state-error'));
    else if (noEvidence) root.append(make('p', `실패 이유: ${REJECT_REASONS.insufficient}`, 'state state-error'));
    root.append(make('p', '기록은 그대로입니다. AI 연결이나 응답 문제는 기록 내용과 업무 앱 판정을 바꾸지 않으며, 과제 실패가 아닙니다.'));
    root.append(make('p', '이전 설명은 현재 결과가 아니므로 표시하지 않습니다. 다시 설명은 기록의 설명 버튼을 직접 눌러야 하며 자동으로 다시 요청하지 않습니다.', 'muted'));
    return root;
  }
  if (status === 'loading') {
    root.append(make('p', 'AI 설명 요청 중', 'state state-loading'));
    root.append(make('p', '응답을 기다리는 중입니다. 이전 설명은 현재 결과가 아니므로 표시하지 않습니다.'));
    return root;
  }
  // 2) 오류 없이 event만 없으면 기록 선택부터 안내한다. 성공 표식은 붙이지 않는다.
  if (!isObject(event)) {
    root.append(make('p', '보안 기록에서 기록을 먼저 고르세요', 'state state-empty'));
    root.append(make('p', '설명은 고른 기록의 근거를 기준으로만 만듭니다. 기록이 없으면 설명을 표시하지 않습니다.'));
    return root;
  }
  if (status === 'idle') {
    root.append(make('p', 'AI 설명 전', 'state state-empty'));
    root.append(make('p', '보안 기록에서 사건을 골라 설명을 직접 요청해야 합니다. 연결 점검만으로는 사건 설명이 실행되지 않습니다.'));
    return root;
  }
  if (status !== 'ok') {
    root.append(make('p', '주의 · 확인 불가: 알 수 없는 설명 상태입니다.', 'state state-error'));
    root.append(make('p', '설명 성공으로 표시하지 않습니다.'));
    return root;
  }
  // 3) ok라도 선택한 기록의 근거와 맞는 설명만 쓴다. 맞지 않으면 내용을 지어내지 않고 이유만 보여 준다.
  const result = checkExplanation(event, explanation.data);
  if (!result.ok) {
    root.append(make('p', '주의 · AI 설명을 쓸 수 없습니다(확인 불가)', 'state state-error'));
    root.append(make('p', `까닭: ${REJECT_REASONS[result.reason]}`, 'state state-error'));
    if (isObject(explanation.error) && typeof explanation.error.code === 'string') {
      const { code, known } = { code: aiCause(explanation.error).code, known: aiCause(explanation.error).known };
      if (known) root.append(make('p', `오류 코드: ${code}`));
    }
    root.append(make('p', '기록은 그대로입니다. 근거에 맞지 않는 AI 요약은 표시하지 않습니다.'));
    return root;
  }
  root.setAttribute('data-student-explanation-event', result.id);
  root.append(make('p', 'AI 설명 도착(ok) · 근거 대조 통과', 'state state-ok'));
  root.append(make('p', `사건 ID: ${result.id}`));
  root.append(make('h3', 'AI 설명(참고용)'));
  root.append(make('p', result.summary));
  root.append(make('p', 'AI 설명은 해석입니다. 사실 판단은 아래 근거 글과 연동 시스템이 알려 준 상태로 하세요.', 'muted'));
  root.append(explanationRows('인용한 근거', result.evidenceIds.map((id) => `${id} — ${result.evidenceText.get(id)}`)));
  root.append(explanationRows('현재 규칙', result.rules.map((rule) => `${rule.id} — ${rule.text}`)));
  root.append(explanationStates(event));
  root.append(explanationProposals(result));
  root.append(aiTimeLine('설명 시각(checkedAt)', checkedAt));
  root.append(make('p', 'AI 설명은 참고 정보입니다. 설명·제안만으로 보안 조치가 실행되지는 않습니다.', 'muted'));
  return root;
}

// 19단계 renderAction: 조치 제안·사람 확인·서버 접수(ACK)·실제 효과 관측을 구분해 보여 준다.
// 버튼·POST 요청·확인 번호는 만들지 않는다(제공 화면의 버튼을 쓴다). 입력으로 매번 새로 그리며 이전 표시를 보관하지 않는다.
// data-student-action-event / data-student-action-request는 현재 사건·요청과 맞게 그린 경우에만 붙인다.
const ACTION_STATUSES = ['idle', 'loading', 'prepared', 'executing', 'pending', 'succeeded', 'denied', 'failed', 'unknown', 'error', 'expired'];
const ACTION_LINES = {
  idle: ['아직 미실행(idle)', '조치를 준비하거나 실행하지 않았습니다.'],
  loading: ['조치 준비 또는 결과 조회 중(loading)', '서버 응답을 기다리는 중이며 결과가 아직 확인되지 않았습니다.'],
  prepared: ['준비됨·미실행(prepared)', '조치는 준비만 되었고 실행되지 않았습니다. 확인 기한 안에 제공 화면에서 대상과 조치를 확인해야 서버로 전달됩니다.'],
  executing: ['서버에 전달 중(executing)', '결과가 아직 확인되지 않았습니다. 서버 응답과 효과 확인을 기다리세요.'],
  pending: ['서버 접수·처리 중(pending)', '서버가 요청을 받았다는 접수 응답(ACK)은 효과 확인이 아닙니다. 결과가 아직 확인되지 않았습니다. 제공 화면의 「원천 결과만 재조회」로 서버 결과를 다시 조회하세요.'],
  succeeded: ['효과 확인(succeeded)', '연동 시스템이 조치 효과를 관측했습니다.'],
  denied: ['거절(denied)', '연동 시스템이 조치를 거절했습니다. 효과가 적용되었다고 읽지 마세요.'],
  failed: ['실패(failed)', '연동 시스템에서 조치가 실패했습니다. 효과가 적용되었다고 읽지 마세요.'],
  unknown: ['결과 불명(unknown)', '효과가 적용되었는지 알 수 없습니다. 성공으로도 효과 없음으로도 판단하지 말고 제공 화면의 「원천 결과만 재조회」로 결과만 다시 조회하세요.'],
  expired: ['확인 기한 지남(expired)', '사람 확인 기한이 지나 조치는 실행되지 않았습니다. 조치를 다시 준비해야 합니다.'],
  error: ['요청 처리 안 됨(error)', '요청이 처리되지 않았습니다. 효과 적용 여부를 이 표시로 판단하지 마세요.'],
};

function actionId(value) {
  return typeof value === 'string' && SAFE_ACTION.test(value) ? value : '';
}

function actionRows(title, rows) {
  const block = make('section', null, 'event-block');
  block.append(make('h4', title));
  const list = make('ul', null, 'plain-list');
  for (const row of rows) list.append(make('li', row));
  block.append(list);
  return block;
}

// 입력이 서로 맞는지 대조한다. 어긋나면 { ok:false, reason }.
function checkAction(input) {
  const { status, event, actionId: id, target, receipt, observation } = input;
  const eventId = isObject(event) && typeof event.id === 'string' && EXPLANATION_EVENT_ID.test(event.id) ? event.id : '';
  const hasReceipt = isObject(receipt);
  const requestId = hasReceipt && typeof receipt.requestId === 'string' && receipt.requestId ? shortText(receipt.requestId, 128) : '';
  const bound = { eventId, requestId };
  if (status === 'idle') return { ok: true, ...bound };
  if (!eventId) return { ok: false, reason: '현재 사건(event.id)을 확인할 수 없습니다.' };
  if (id !== undefined && id !== null && !actionId(id)) return { ok: false, reason: '조치 ID(actionId) 형식을 확인할 수 없습니다.' };
  if (hasReceipt) {
    if (receipt.eventId !== undefined && receipt.eventId !== eventId) return { ok: false, reason: '영수증의 사건이 현재 사건과 다릅니다.' };
    if (receipt.actionId !== undefined && receipt.actionId !== id) return { ok: false, reason: '영수증의 조치가 현재 조치와 다릅니다.' };
    if (receipt.status !== undefined && receipt.status !== status && ['succeeded', 'denied', 'failed'].includes(status)) return { ok: false, reason: '영수증 상태가 표시 상태와 다릅니다.' };
  }
  if (isObject(target) && (typeof target.id !== 'string' || !target.id)) return { ok: false, reason: '실제 대상(target.id)을 확인할 수 없습니다.' };
  if (status === 'succeeded') {
    const confirmed = isObject(observation) && observation.effectApplied === true && typeof observation.observedAt === 'string' && observation.observedAt !== ''
      && hasReceipt && typeof receipt.receiptId === 'string' && receipt.receiptId !== '' && requestId !== '';
    if (!confirmed) return { ok: true, ...bound, downgrade: true };
  }
  return { ok: true, ...bound };
}

function actionIdentityRows(input, check) {
  const { event, actionId: id, target, receipt, confirmationExpiresAt } = input;
  const rows = [];
  if (isObject(event) && check.eventId) {
    rows.push(`사건 ID: ${check.eventId}`);
    const ids = Array.isArray(event.evidence) ? event.evidence.filter((row) => isObject(row) && typeof row.id === 'string' && row.id).map((row) => row.id) : [];
    rows.push(`근거 ID: ${ids.length ? ids.join(', ') : '없음'}`);
  }
  if (actionId(id)) rows.push(`조치(actionId): ${id}`);
  if (isObject(target) && typeof target.id === 'string' && target.id) {
    rows.push(`실제 대상: ${shortText(target.id, 128)}`);
    rows.push(`대상 세대(generation): ${target.generation == null ? '확인 불가' : shortText(target.generation, 32)}`);
  }
  if (isObject(receipt)) {
    if (check.requestId) rows.push(`요청 ID(requestId): ${check.requestId}`);
    if (typeof receipt.receiptId === 'string' && receipt.receiptId) rows.push(`영수증 ID(receiptId): ${shortText(receipt.receiptId, 128)}`);
    if (receipt.version != null && receipt.version !== '') rows.push(`버전(version): ${shortText(receipt.version, 32)}`);
  }
  if (typeof confirmationExpiresAt === 'string' && confirmationExpiresAt) rows.push(`사람 확인 기한: ${timeText(shortText(confirmationExpiresAt, 64))}`);
  return rows;
}

function renderActionView(input) {
  const root = make('div', null, 'action-view');
  const data = isObject(input) ? input : {};
  const status = typeof data.status === 'string' && ACTION_STATUSES.includes(data.status) ? data.status : '';
  // 알 수 없는 status는 성공으로 추측하지 않는다.
  if (!status) {
    root.append(make('p', `주의 · 결과 불명(unknown): 알 수 없는 조치 상태(${shortText(data.status, 40) || '없음'})입니다.`, 'state state-error'));
    root.append(make('p', '성공이나 효과 없음으로 판단하지 말고 제공 화면의 「원천 결과만 재조회」로 결과만 다시 조회하세요.'));
    return root;
  }
  const check = checkAction(data);
  if (!check.ok) {
    root.append(make('p', '주의 · 결과 불명(unknown): 현재 사건·조치·요청과 맞지 않는 표시입니다.', 'state state-error'));
    root.append(make('p', `까닭: ${check.reason}`, 'state state-error'));
    root.append(make('p', '성공이나 효과 없음으로 판단하지 마세요. 제공 화면의 「원천 결과만 재조회」로 결과만 다시 조회하세요.'));
    return root;
  }
  const shown = check.downgrade ? 'unknown' : status;
  const [title, guide] = ACTION_LINES[shown];
  const bad = ['denied', 'failed', 'unknown', 'expired', 'error'].includes(shown);
  const pendingLike = ['loading', 'executing', 'pending', 'prepared'].includes(shown);
  root.append(make('p', `${bad ? '주의 · ' : ''}${title}`, shown === 'succeeded' ? 'state state-ok' : bad ? 'state state-error' : pendingLike ? 'state state-loading' : 'state state-empty'));
  if (check.downgrade) {
    root.append(make('p', '서버가 succeeded라고 했지만 효과 관측(effectApplied: true)·관측 시각·receiptId·requestId가 모두 확인되지 않아 효과 확인으로 쓰지 않습니다.', 'state state-error'));
  }
  root.append(make('p', guide));
  if (isObject(data.receipt) && data.receipt.replayed === true) {
    root.append(make('p', '이 응답은 이미 접수된 같은 요청의 재전달(replayed)입니다. 새 조치가 실행된 것이 아닙니다.', 'muted'));
  }
  if (status === 'idle') {
    root.append(make('p', '지원하는 조치가 없으면 「조치 준비」 버튼이 나오지 않으며, 그것이 정상입니다(supportedActions 빈 배열). 학생 화면에는 조치 버튼이 없습니다.', 'muted'));
  }
  const rows = actionIdentityRows(data, check);
  if (rows.length) root.append(actionRows('현재 사건·조치·요청', rows));
  if (shown === 'succeeded') {
    root.append(actionRows('실제 효과 관측', [`관측 시각(observedAt): ${timeText(shortText(data.observation.observedAt, 64))}`, 'effectApplied: true', `영수증 ID(receiptId): ${shortText(data.receipt.receiptId, 128)}`]));
  } else if (isObject(data.observation) && typeof data.observation.observedAt === 'string' && data.observation.observedAt) {
    root.append(actionRows('관측 기록(효과 확인 아님)', [`관측 시각(observedAt): ${timeText(shortText(data.observation.observedAt, 64))}`, `effectApplied: ${data.observation.effectApplied === true ? 'true' : data.observation.effectApplied === false ? 'false' : '확인 불가'}`]));
  }
  if ((shown === 'denied' || shown === 'failed') && typeof data.message === 'string' && data.message && !SECRET_LIKE.test(data.message)) {
    root.append(make('p', `메시지: ${shortText(data.message, 300)}`, 'state state-error'));
  }
  if (status === 'error') {
    const err = isObject(data.error) ? data.error : {};
    const code = typeof err.code === 'string' && SAFE_ACTION.test(err.code) ? err.code : '확인 불가';
    const message = typeof err.message === 'string' && err.message && !SECRET_LIKE.test(err.message) ? shortText(err.message, 300) : '표시할 수 있는 서버 메시지 없음';
    root.append(make('p', `오류 코드: ${code}`, 'state state-error'));
    root.append(make('p', `error.message: ${message}`, 'state state-error'));
  }
  root.append(make('p', '「조치 화면 취소」는 이 화면의 표시만 지웁니다. 이미 서버에 전달된 조치 효과를 되돌리지 않습니다.', 'muted'));
  if (check.eventId) {
    root.setAttribute('data-student-action-event', check.eventId);
    if (check.requestId) root.setAttribute('data-student-action-request', check.requestId);
  }
  return root;
}

// 20단계 renderVulnerabilities: 설치 패키지의 정확한 버전과 OSV 조회 결과를 구분해 보여 준다.
// 입력으로만 매번 새로 그리며 모듈 안에 이전 표·이전 lockfileHash를 보관하지 않는다.
// idle·loading·error에서는 data를 아예 읽지 않으므로 이전 표가 현재 결과처럼 남지 않는다.
// 늦게 도착한 응답을 막는 일은 제공 코드(public/app.js의 조회 세대 번호)가 맡고, 이 함수는 받은 입력만 그린다.
const SCAN_LABELS = {
  complete: '모두 조회', partial: '일부 조회 실패', not_checked: '아직 조회 안 함',
  not_configured: '조회 준비 미완료', unverifiable: 'lock 파일 확인 불가',
  unknown: '확인 불가',
};
const SCAN_GUIDES = {
  complete: '허용된 패키지를 모두 조회했습니다. 조회 시점에 OSV에 알려진 항목만 반영한 결과입니다.',
  partial: '일부 패키지의 조회가 실패했습니다. 실패한 패키지는 취약점 없음이 아니라 확인 불가입니다. 이미 받은 취약점 ID는 그대로 보여 줍니다.',
  not_checked: '승인된 공개 조회 대상 패키지가 없어 조회하지 않았습니다. 허용 목록이 비어 있으면 이렇게 나오는 것이 정상이며, 취약점이 없다는 뜻이 아닙니다.',
  not_configured: '조회 대상 프로젝트 설정이 필요한 상태입니다. 설정이 비어 있으면 이렇게 나오는 것이 정상이며, 취약점이 없다는 뜻이 아닙니다. 대상 경로와 허용 패키지는 운영자가 준비하며 학생이 바꾸지 않습니다.',
  unverifiable: 'package-lock.json을 확인할 수 없어 설치 버전을 대조하지 못했습니다. 취약점이 없다는 뜻이 아닙니다.',
  unknown: '알 수 없는 조회 상태입니다. 정상이나 취약점 없음으로 읽지 마세요.',
};
const PACKAGE_LABELS = {
  known_vulnerabilities: '알려진 항목 있음', none_found: '알려진 항목 없음', unverifiable: '조회 확인 불가', unknown: '확인 불가',
};
const NONE_FOUND_NOTE = 'none_found는 조회 범위에서 알려진 항목이 없다는 뜻입니다. 이 패키지나 앱이 안전하다는 보증이 아닙니다.';
const OSV_NOTE = 'OSV는 알려진 취약점 데이터베이스입니다. 조회 결과가 없다는 사실만으로 해당 패키지나 앱 전체가 안전하다고 보장할 수 없습니다.';
const NO_INFO = '정보 없음';
// 설치된 정확한 버전(예: 1.2.3, 1.2.3-rc.1). ^1.2.0 같은 범위는 설치 버전으로 인정하지 않는다.
const EXACT_VERSION = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const FINDING_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,159}$/;

function textOrNone(value, max = 128) {
  return typeof value === 'string' && value.trim() !== '' ? shortText(value, max) : NO_INFO;
}

function vulnFindings(list) {
  if (!Array.isArray(list)) return [];
  return list.filter((f) => isObject(f) && typeof f.id === 'string' && FINDING_ID.test(f.id));
}

function vulnCell(findings, hidden) {
  const cell = make('td');
  if (findings.length === 0) {
    cell.append(make('span', hidden ? '받은 취약점 ID 없음' : '취약점 ID 없음'));
    return cell;
  }
  const list = make('ul');
  for (const f of findings) list.append(make('li', `${f.id} · 수정 시각(modified): ${textOrNone(f.modified, 64)}`));
  cell.append(list);
  return cell;
}

function packageRow(pkg) {
  const row = make('tr');
  if (!isObject(pkg)) {
    row.append(make('td', '주의 · 확인 불가: 패키지 행의 형식을 확인할 수 없습니다.'));
    row.firstChild.colSpan = 5;
    return row;
  }
  const nameOk = typeof pkg.name === 'string' && pkg.name !== '';
  const versionOk = typeof pkg.version === 'string' && EXACT_VERSION.test(pkg.version);
  if (nameOk) row.setAttribute('data-student-package-name', shortText(pkg.name, 214));
  if (versionOk) row.setAttribute('data-student-package-version', pkg.version);
  const known = Object.hasOwn(PACKAGE_LABELS, pkg.status) && pkg.status !== 'unknown';
  const findings = vulnFindings(pkg.vulnerabilities);
  let status = known ? pkg.status : 'unknown';
  // 상태와 항목이 서로 맞지 않으면 안전 쪽으로 읽지 않고 확인 불가로 둔다. 받은 ID는 지우지 않는다.
  const mismatch = (status === 'none_found' && findings.length > 0) || (status === 'known_vulnerabilities' && findings.length === 0);
  if (mismatch) status = 'unknown';
  const label = `${status === 'none_found' ? '' : '주의 · '}${PACKAGE_LABELS[status]}(${known ? pkg.status : String(shortText(pkg.status, 40) || '없음')})`;
  const notes = [];
  if (status === 'unverifiable' && findings.length > 0) notes.push('일부 확인 · 전체 조회 확인 불가: 받은 취약점 ID만 표시하며 나머지 조회는 확인할 수 없습니다.');
  else if (status === 'unverifiable') notes.push('조회 확인 불가: 취약점 없음이 아닙니다.');
  if (mismatch) notes.push('상태와 취약점 항목이 맞지 않아 확인 불가로 처리했습니다.');
  if (status === 'none_found') notes.push(NONE_FOUND_NOTE);
  if (!versionOk) notes.push('주의 · 설치된 정확한 버전을 확인할 수 없습니다(버전 범위이거나 형식 오류). 설치 버전으로 표시하지 않습니다.');
  row.append(
    make('td', nameOk ? shortText(pkg.name, 214) : '이름 확인 불가'),
    make('td', versionOk ? pkg.version : `확인 불가(전달된 값: ${shortText(pkg.version, 40) || '없음'})`),
  );
  const statusCell = make('td', label, status === 'none_found' ? 'state state-ok' : 'state state-error');
  for (const note of notes) statusCell.append(make('div', note, 'muted'));
  row.append(statusCell, vulnCell(findings, status === 'unverifiable' || status === 'unknown'));
  row.append(make('td', `출처(source): ${textOrNone(pkg.source, 160)} · 조회 시각(checkedAt): ${textOrNone(pkg.checkedAt, 64)}`));
  return row;
}

function packageTableView(packages) {
  const wrap = make('div', null, 'table-wrap');
  wrap.style.overflowX = 'auto';
  const table = make('table');
  table.append(make('caption', `설치 패키지 ${packages.length}개 (package-lock.json과 node_modules 대조)`));
  const head = make('tr');
  for (const label of ['패키지(name)', '설치 버전(version)', '조회 상태(status)', '취약점 id · modified', '출처 · 조회 시각']) {
    const th = make('th', label);
    th.scope = 'col';
    head.append(th);
  }
  const thead = make('thead');
  thead.append(head);
  const tbody = make('tbody');
  for (const pkg of packages) tbody.append(packageRow(pkg));
  table.append(thead, tbody);
  wrap.append(table);
  return wrap;
}

function scanSummary(data) {
  const box = make('div', null, 'scan-summary');
  const lockVersion = typeof data.lockfileVersion === 'number' || (typeof data.lockfileVersion === 'string' && data.lockfileVersion !== '')
    ? shortText(data.lockfileVersion, 20) : NO_INFO;
  box.append(
    make('p', `lock 파일 버전(lockfileVersion): ${lockVersion}`),
    make('p', `lock 파일 해시(lockfileHash): ${textOrNone(data.lockfileHash)}`),
    make('p', `전체 조회 시각(checkedAt): ${textOrNone(data.checkedAt, 64)}`),
  );
  return box;
}

function renderVulnerabilitiesView({ status, mode, data, error } = {}) {
  const root = make('div', null, 'vulnerabilities-student-view');
  root.append(make('h3', '설치 패키지 · 알려진 취약점 조회'));
  if (status === 'idle') {
    root.append(make('p', '조회 전', 'state state-empty'));
    root.append(make('p', '아직 조회하지 않았습니다. 이전 조회 결과는 표시하지 않으며, 조회 전은 취약점 없음이 아닙니다.'));
  } else if (status === 'loading') {
    root.append(make('p', '조회 중', 'state state-loading'));
    root.append(make('p', '응답을 기다리는 중입니다. 이전 표와 이전 lockfileHash는 현재 결과가 아니므로 표시하지 않습니다.'));
  } else if (status === 'error') {
    const code = isObject(error) && typeof error.code === 'string' && /^[A-Z][A-Z0-9_]{0,39}$/.test(error.code) ? error.code : '';
    const message = isObject(error) && typeof error.message === 'string' && error.message && !SECRET_LIKE.test(error.message)
      ? shortText(error.message) : '표시할 수 있는 서버 메시지 없음';
    root.append(make('p', `주의 · 조회 실패: ${message}`, 'state state-error'));
    root.append(make('p', `오류 코드: ${code || '확인 불가'}`));
    root.append(make('p', '조회 실패는 취약점 없음이 아닙니다. 이전 표와 이전 lockfileHash는 현재 결과가 아니므로 표시하지 않습니다. 다시 조회하려면 위쪽 「설치 패키지 조회」 버튼을 직접 누르세요.'));
  } else if (status === 'ok') {
    const known = isObject(data) && typeof data.status === 'string' && Object.hasOwn(SCAN_LABELS, data.status) && data.status !== 'unknown';
    if (!isObject(data)) {
      root.append(make('p', `주의 · ${SCAN_LABELS.unknown}: 조회 결과가 전달되지 않았습니다.`, 'state state-error'));
      root.append(make('p', SCAN_GUIDES.unknown));
    } else {
      const key = known ? data.status : 'unknown';
      const bad = key !== 'complete';
      root.append(make('p', `전체 조회 상태: ${bad ? '주의 · ' : ''}${SCAN_LABELS[key]}(${known ? data.status : shortText(data.status, 40) || '없음'})`, bad ? 'state state-error' : 'state state-ok'));
      root.append(make('p', SCAN_GUIDES[key]));
      if (known) {
        root.append(scanSummary(data));
        root.append(make('p', '이 결과는 package-lock.json과 설치된 node_modules의 메타데이터를 대조한 값입니다.', 'muted'));
        const packages = Array.isArray(data.packages) ? data.packages : [];
        if (key === 'complete' || key === 'partial') {
          if (packages.length > 0) {
            root.append(packageTableView(packages));
            if (packages.some((p) => isObject(p) && p.status === 'none_found')) root.append(make('p', NONE_FOUND_NOTE, 'muted'));
          } else {
            root.append(make('p', '주의 · 표시할 패키지 행이 없습니다. 이것은 취약점이 없다는 뜻이 아닙니다.', 'state state-error'));
          }
        } else {
          // 미조회·설정 없음·확인 불가에서는 packages가 비어 있어야 정상이다. 비어 있어도 취약점 없음으로 읽히게 하지 않는다.
          root.append(make('p', packages.length === 0
            ? '패키지 행이 없는 것은 조회하지 않았다는 뜻이며, 취약점 없음이 아닙니다.'
            : '주의 · 이 상태에서는 패키지 결과가 오지 않아야 합니다. 전달된 패키지 행은 신뢰하지 않고 표시하지 않습니다.', 'state state-empty'));
        }
      }
    }
    root.append(make('p', OSV_NOTE, 'muted'));
  } else {
    root.append(make('p', '주의 · 확인 불가: 알 수 없는 조회 상태입니다.', 'state state-error'));
    root.append(make('p', '정상이나 취약점 없음으로 표시하지 않습니다.'));
  }
  const note = modeNote({ mode });
  if (note) root.append(note);
  return root;
}

// ============================================================================
// 마지막 총공세 · 학생 구현: 내 PC 기록 · 추이 비교 · 위험 알림
// - 값은 제공 '내 PC 상태'(GET /api/pc/status)가 읽은 결과만 씁니다. 측정 코드를 새로 만들지 않습니다.
// - 이 칸이 하는 일: 조회 기록 남기기, 이전 조회와 비교하기, 기준을 넘으면 알리기.
// - 기록은 이 브라우저(localStorage)에 숫자·상태·시각만 남기며 서버나 외부로 보내지 않습니다.
// - '위험 알림'은 기준값을 넘었다는 알림일 뿐 침해(공격) 판정이 아닙니다.
// - 읽지 못한 값은 예시 값으로 채우지 않고 '확인 불가'와 이유로 보여 줍니다.
// - 값은 createElement와 textContent로만 넣습니다. 새 CSS 파일 없이 제공 클래스와 SVG 속성만 씁니다.
// ============================================================================
const PC_PATH = '/api/pc/status';
const PC_SCHEMA = 'aleph.on.pc-status.v1';
const PC_HISTORY_KEY = 'kesheb.student.pc-history.v1';
const PC_HISTORY_MAX = 200;
// 학습용 처음 기준값이며 공식 보안 기준이 아닙니다.
export const PC_LIMITS = Object.freeze({ cpuWarn: 70, memoryWarn: 80, diskFreeWarn: 15 });
const PC_LABELS = Object.freeze({ cpu: 'CPU', memory: '메모리', disk: '디스크', network: '네트워크 구성', firewall: '방화벽', events: 'Windows 경고·오류' });
const PC_ORDER = Object.freeze(['cpu', 'memory', 'disk', 'network', 'firewall', 'events']);
// 정상·주의·확인 불가로 판정하는 핵심 항목. 네트워크 구성과 경고·오류 건수는 참고 정보입니다.
export const PC_GRADED = Object.freeze(['cpu', 'memory', 'disk', 'firewall']);
const PC_STATUS_LABELS = Object.freeze({ ok: '정상', warn: '주의', unknown: '확인 불가', info: '참고' });
const PC_STATUS_ICONS = Object.freeze({ ok: '●', warn: '▲', unknown: '?', info: '○' });
const PC_STATUS_CLASS = Object.freeze({ ok: 'state state-ok', warn: 'state state-error', unknown: 'state state-empty', info: 'state' });
const PC_REASONS = Object.freeze({
  permission_denied: '권한이 없어 읽지 못했습니다',
  query_failed: '조회에 실패했습니다',
  timeout: '조회 시간이 초과됐습니다',
  unsupported: '이 운영체제에서는 조회하지 않는 항목입니다',
  invalid_response: '응답 형식이 맞지 않습니다',
  invalid_sample: '측정값이 올바르지 않습니다',
  cancelled: '조회가 취소됐습니다',
});

const isFiniteNumber = (n) => typeof n === 'number' && Number.isFinite(n);
const isCount = (n) => Number.isSafeInteger(n) && n >= 0;
const oneDecimal = (n) => Math.round(n * 10) / 10;
const gigabytes = (bytes) => `${(bytes / 1073741824).toFixed(1)}GB`;

function pcUnknown(id, reason) {
  const key = typeof reason === 'string' && Object.hasOwn(PC_REASONS, reason) ? reason : 'invalid_response';
  return { id, label: PC_LABELS[id], status: 'unknown', text: key === 'permission_denied' ? '확인 불가 · 권한 없음' : '확인 불가', value: null, reason: PC_REASONS[key], hint: '' };
}

function pcItem(id, status, text, value, hint = '') {
  return { id, label: PC_LABELS[id], status, text, value, reason: '', hint };
}

// 제공 응답(metrics)을 항목 6개로 판정한다. 모양이 계약과 다르면 정상으로 추측하지 않고 확인 불가로 둔다.
export function judgePcStatus(data) {
  const metrics = isObject(data) && isObject(data.metrics) ? data.metrics : {};
  const read = (id) => (isObject(metrics[id]) ? metrics[id] : null);
  const items = [];

  const cpu = read('cpu');
  if (!cpu || cpu.state !== 'ok') items.push(pcUnknown('cpu', cpu ? cpu.reason : 'invalid_response'));
  else if (!isFiniteNumber(cpu.usagePercent) || cpu.usagePercent < 0 || cpu.usagePercent > 100) items.push(pcUnknown('cpu', 'invalid_response'));
  else {
    const warn = cpu.usagePercent >= PC_LIMITS.cpuWarn;
    items.push(pcItem('cpu', warn ? 'warn' : 'ok', `사용률 ${oneDecimal(cpu.usagePercent)}%`, cpu.usagePercent,
      warn ? 'CPU가 많이 바빠요. 작업 관리자(Ctrl+Shift+Esc)에서 무엇이 쓰는지 볼 수 있어요.' : ''));
  }

  const memory = read('memory');
  if (!memory || memory.state !== 'ok') items.push(pcUnknown('memory', memory ? memory.reason : 'invalid_response'));
  else if (!(isFiniteNumber(memory.totalBytes) && memory.totalBytes > 0 && isFiniteNumber(memory.usedBytes) && memory.usedBytes >= 0 && memory.usedBytes <= memory.totalBytes)) items.push(pcUnknown('memory', 'invalid_response'));
  else {
    const percent = (memory.usedBytes / memory.totalBytes) * 100;
    const warn = percent >= PC_LIMITS.memoryWarn;
    items.push(pcItem('memory', warn ? 'warn' : 'ok', `사용 ${gigabytes(memory.usedBytes)} / ${gigabytes(memory.totalBytes)} (${oneDecimal(percent)}%)`, percent,
      warn ? '작업 공간이 많이 찼어요. 안 쓰는 프로그램을 닫아 보세요.' : ''));
  }

  const disk = read('disk');
  if (!disk || disk.state !== 'ok') items.push(pcUnknown('disk', disk ? disk.reason : 'invalid_response'));
  else if (!(isFiniteNumber(disk.totalBytes) && disk.totalBytes > 0 && isFiniteNumber(disk.freeBytes) && disk.freeBytes >= 0 && disk.freeBytes <= disk.totalBytes)) items.push(pcUnknown('disk', 'invalid_response'));
  else {
    const freePercent = (disk.freeBytes / disk.totalBytes) * 100;
    const warn = freePercent <= PC_LIMITS.diskFreeWarn;
    items.push(pcItem('disk', warn ? 'warn' : 'ok', `남은 공간 ${gigabytes(disk.freeBytes)} / ${gigabytes(disk.totalBytes)} (${oneDecimal(freePercent)}%)`, freePercent,
      warn ? '저장 공간이 부족해요. 설정 > 시스템 > 저장소에서 정리해 보세요.' : ''));
  }

  const network = read('network');
  if (!network || network.state !== 'ok') items.push(pcUnknown('network', network ? network.reason : 'invalid_response'));
  else if (!isCount(network.interfaceCount) || !isCount(network.ipv4Count)) items.push(pcUnknown('network', 'invalid_response'));
  else if (network.interfaceCount === 0) items.push(pcItem('network', 'warn', '연결된 네트워크 구성이 없음', null, '케이블이나 Wi-Fi를 확인해 보세요. 인터넷 접속을 확인한 결과는 아니에요.'));
  else items.push(pcItem('network', 'info', `인터페이스 ${network.interfaceCount}개 · IPv4 ${network.ipv4Count}개`, null, '로컬 구성 요약이며 인터넷 접속이나 ZTNA 허용을 확인한 결과가 아닙니다.'));

  const firewall = read('firewall');
  if (!firewall || firewall.state !== 'ok') items.push(pcUnknown('firewall', firewall ? firewall.reason : 'invalid_response'));
  else if (!Array.isArray(firewall.profiles) || firewall.profiles.length !== 3 || !firewall.profiles.every((p) => isObject(p) && typeof p.name === 'string' && typeof p.enabled === 'boolean')) items.push(pcUnknown('firewall', 'invalid_response'));
  else {
    const off = firewall.profiles.filter((p) => !p.enabled).map((p) => p.name);
    if (off.length === 0) items.push(pcItem('firewall', 'ok', '켜짐 (도메인·개인·공용)', null));
    else items.push(pcItem('firewall', 'warn', off.length === 3 ? '꺼짐' : `일부 꺼짐 (${off.join(', ')})`, null,
      '이 앱은 방화벽을 바꾸지 않습니다. Windows 보안 > 방화벽 및 네트워크 보호에서 직접 확인하세요.'));
  }

  const events = read('events');
  if (!events || events.state !== 'ok') items.push(pcUnknown('events', events ? events.reason : 'invalid_response'));
  else if (!isCount(events.warningCount) || !isCount(events.errorCount)) items.push(pcUnknown('events', 'invalid_response'));
  else {
    const total = events.warningCount + events.errorCount;
    items.push(pcItem('events', 'info', `최근 24시간 경고 ${events.warningCount}건 · 오류 ${events.errorCount}건${events.truncated === true ? ' (일부만 집계)' : ''} · 침해·공격 탐지 결과 아님`, total,
      '건수만 센 참고 정보입니다. 0건이거나 적다고 안전하다는 뜻이 아니고, 많다고 공격이라는 뜻도 아닙니다.'));
  }
  return items;
}

export function summarizePc(items) {
  const graded = items.filter((i) => PC_GRADED.includes(i.id));
  const ok = graded.filter((i) => i.status === 'ok').length;
  return {
    gradedTotal: graded.length,
    ok,
    warn: items.filter((i) => i.status === 'warn').length,
    unknown: items.filter((i) => i.status === 'unknown').length,
    text: `핵심 ${graded.length}개(CPU·메모리·디스크·방화벽) 중 ${ok}개 정상`,
  };
}

// 위험 알림: 조회 기록을 훑어 '주의'가 새로 생기거나 사라진 때를 찾는다. 확인 불가는 상태가 바뀐 것으로 보지 않는다.
export function computeAlerts(entries = [], { maxEvents = 30 } = {}) {
  const previous = new Map();
  const since = new Map();
  const events = [];
  for (const entry of entries) {
    for (const item of entry.items) {
      if (item.status === 'unknown' || item.status === 'info' && item.id !== 'network') continue;
      const wasWarn = previous.get(item.id) === 'warn';
      const isWarn = item.status === 'warn';
      if (isWarn && !wasWarn) { events.push({ at: entry.at, id: item.id, label: item.label, kind: 'start', text: item.text }); since.set(item.id, entry.at); }
      else if (!isWarn && wasWarn) { events.push({ at: entry.at, id: item.id, label: item.label, kind: 'resolved', text: item.text }); since.delete(item.id); }
      previous.set(item.id, item.status);
    }
  }
  const last = entries[entries.length - 1];
  const current = last ? last.items.filter((i) => i.status === 'warn').map((i) => ({ id: i.id, label: i.label, text: i.text, since: since.get(i.id) || last.at })) : [];
  return { current, events: events.slice(-maxEvents).reverse(), checkedAt: last ? last.at : null };
}

// 이전 조회와 이번 조회를 같은 단위로 비교하고 한 줄 설명을 붙인다. 한쪽을 읽지 못했으면 비교하지 않는다.
const TREND_FIELDS = Object.freeze([
  { id: 'cpu', name: 'CPU 사용률', unit: '%', gap: '%p', up: '사용이 늘었어요. CPU는 0.2초 표본이라 조회마다 크게 달라질 수 있어요.', down: '사용이 줄었어요.' },
  { id: 'memory', name: '메모리 사용률', unit: '%', gap: '%p', up: '작업 공간을 더 쓰고 있어요.', down: '여유가 늘었어요.' },
  { id: 'disk', name: '디스크 남은 공간', unit: '%', gap: '%p', up: '남은 공간이 늘었어요.', down: '남은 공간이 줄었어요. 계속 줄면 정리가 필요해요.' },
  { id: 'events', name: 'Windows 경고·오류', unit: '건', gap: '건', count: true, up: '건수가 늘었어요. 건수 변화만 보여 주며 침해를 뜻하지 않아요.', down: '건수가 줄었어요.' },
]);

export function compareReadings(previous, current) {
  const find = (entry, id) => (entry && Array.isArray(entry.items) ? entry.items.find((i) => i.id === id) : undefined);
  return TREND_FIELDS.map((field) => {
    const before = find(previous, field.id);
    const after = find(current, field.id);
    const a = before && isFiniteNumber(before.value) ? before.value : null;
    const b = after && isFiniteNumber(after.value) ? after.value : null;
    if (a === null || b === null) {
      return { id: field.id, name: field.name, comparable: false, text: `${field.name}: 비교할 수 없어요 (${a === null ? '이전' : '이번'} 값을 읽지 못함)`, explain: '' };
    }
    const show = (n) => (field.count ? String(Math.round(n)) : String(oneDecimal(n)));
    const diff = b - a;
    const small = Math.abs(diff) < (field.count ? 1 : 1);
    const direction = small ? 'same' : diff > 0 ? 'up' : 'down';
    const gapText = small ? '변화 없음' : `${diff > 0 ? '+' : '-'}${show(Math.abs(diff))}${field.gap}`;
    return {
      id: field.id, name: field.name, comparable: true, from: a, to: b, direction,
      text: `${field.name} ${show(a)}${field.unit} → ${show(b)}${field.unit} (${gapText})`,
      explain: direction === 'same' ? '거의 그대로예요.' : direction === 'up' ? field.up : field.down,
    };
  });
}

// 저장된 기록을 믿지 않고 모양을 다시 검사한다. 맞지 않는 줄은 버린다.
export function sanitizeHistory(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const entry of raw) {
    if (!isObject(entry) || typeof entry.at !== 'string' || !Number.isFinite(Date.parse(entry.at)) || !Array.isArray(entry.items)) continue;
    const items = [];
    for (const item of entry.items) {
      if (!isObject(item) || !PC_ORDER.includes(item.id) || !Object.hasOwn(PC_STATUS_LABELS, item.status)) continue;
      items.push({
        id: item.id, label: PC_LABELS[item.id], status: item.status,
        text: typeof item.text === 'string' ? item.text.slice(0, 160) : '',
        value: isFiniteNumber(item.value) ? item.value : null,
        reason: typeof item.reason === 'string' ? item.reason.slice(0, 80) : '',
      });
    }
    if (items.length > 0) out.push({ at: entry.at, items });
  }
  return out.slice(-PC_HISTORY_MAX);
}

function pcStorage() {
  try { return globalThis.localStorage ?? null; } catch { return null; }
}
function loadPcHistory() {
  const store = pcStorage();
  if (!store) return { entries: [], persisted: false };
  try {
    const text = store.getItem(PC_HISTORY_KEY);
    return { entries: text ? sanitizeHistory(JSON.parse(text)) : [], persisted: true };
  } catch { return { entries: [], persisted: true }; }
}
function savePcHistory(entries) {
  const store = pcStorage();
  if (!store) return false;
  try { store.setItem(PC_HISTORY_KEY, JSON.stringify(entries)); return true; } catch { return false; }
}
function clearPcHistory() {
  const store = pcStorage();
  if (!store) return;
  try { store.removeItem(PC_HISTORY_KEY); } catch { /* 지울 수 없어도 화면 기록은 비웁니다 */ }
}

function pcTime(iso) {
  const date = new Date(iso);
  if (!Number.isFinite(date.getTime())) return '시각 확인 불가';
  const time = date.toLocaleTimeString('ko-KR', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  return date.toDateString() === new Date().toDateString() ? time : `${date.getMonth() + 1}/${date.getDate()} ${time}`;
}

const SVG_NS = 'http://www.w3.org/2000/svg';
const CHART_METRICS = Object.freeze([
  { id: 'cpu', name: 'CPU 사용률', line: PC_LIMITS.cpuWarn, low: false },
  { id: 'memory', name: '메모리 사용률', line: PC_LIMITS.memoryWarn, low: false },
  { id: 'disk', name: '디스크 남은 공간', line: PC_LIMITS.diskFreeWarn, low: true },
]);

function pcChart(entries, metric) {
  const points = entries
    .map((e) => ({ at: e.at, value: (e.items.find((i) => i.id === metric.id) || {}).value }))
    .filter((p) => isFiniteNumber(p.value))
    .slice(-30);
  if (points.length < 2) return make('p', '그래프는 값을 읽은 조회가 2번 이상 쌓이면 그려져요. "다시 조회"를 눌러 보세요.', 'state state-empty');
  const W = 720, H = 220, L = 38, R = 10, T = 10, B = 26;
  const x = (k) => L + (k * (W - L - R)) / (points.length - 1);
  const y = (v) => T + (1 - Math.min(Math.max(v, 0), 100) / 100) * (H - T - B);
  const node = (name, attrs, css) => {
    const el = document.createElementNS(SVG_NS, name);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, String(v));
    for (const [k, v] of Object.entries(css || {})) el.style.setProperty(k, v);
    return el;
  };
  const svg = node('svg', { viewBox: `0 0 ${W} ${H}`, role: 'img', 'aria-label': `${metric.name} 변화 그래프, 최근 ${points.length}번 조회. 같은 값은 아래 최근 기록에 글자로도 나옵니다.` }, { width: '100%', height: 'auto', display: 'block' });
  for (const g of [0, 25, 50, 75, 100]) {
    svg.append(node('line', { x1: L, x2: W - R, y1: y(g), y2: y(g), 'stroke-width': 1 }, { stroke: 'var(--border)' }));
    const label = node('text', { x: L - 6, y: y(g) + 4, 'text-anchor': 'end', 'font-size': 11 }, { fill: 'var(--muted)' });
    label.textContent = `${g}%`;
    svg.append(label);
  }
  svg.append(node('line', { x1: L, x2: W - R, y1: y(metric.line), y2: y(metric.line), 'stroke-width': 1.5, 'stroke-dasharray': '5 4' }, { stroke: 'var(--challenge)' }));
  const limit = node('text', { x: W - R, y: T + 12, 'text-anchor': 'end', 'font-size': 11 }, { fill: 'var(--muted)' });
  limit.textContent = metric.low ? `${metric.line}% 이하면 주의` : `${metric.line}% 이상이면 주의`;
  svg.append(limit);
  svg.append(node('polyline', { points: points.map((p, k) => `${x(k)},${y(p.value)}`).join(' '), fill: 'none', 'stroke-width': 2.5 }, { stroke: 'var(--accent)' }));
  points.forEach((p, k) => {
    const warn = metric.low ? p.value <= metric.line : p.value >= metric.line;
    const dot = node('circle', { cx: x(k), cy: y(p.value), r: 4 }, { fill: warn ? 'var(--challenge)' : 'var(--accent)' });
    const title = document.createElementNS(SVG_NS, 'title');
    title.textContent = `${pcTime(p.at)} · ${oneDecimal(p.value)}%${warn ? ' (주의)' : ''}`;
    dot.append(title);
    svg.append(dot);
  });
  const first = node('text', { x: L, y: H - 6, 'font-size': 11 }, { fill: 'var(--muted)' });
  first.textContent = pcTime(points[0].at);
  const last = node('text', { x: W - R, y: H - 6, 'text-anchor': 'end', 'font-size': 11 }, { fill: 'var(--muted)' });
  last.textContent = pcTime(points[points.length - 1].at);
  svg.append(first, last);
  // 좁은 화면에서 글자가 깨알처럼 작아지지 않게 그래프에만 가로 스크롤을 준다(키보드로도 스크롤 가능).
  svg.style.setProperty('min-width', '520px');
  const frame = make('div', null, 'pc-chart-frame');
  frame.style.setProperty('overflow-x', 'auto');
  frame.tabIndex = 0;
  frame.setAttribute('role', 'group');
  frame.setAttribute('aria-label', `${metric.name} 그래프 (좁은 화면에서는 좌우로 밀어서 볼 수 있습니다)`);
  frame.append(svg);
  return frame;
}

function pcSection(className, title) {
  const section = make('section', null, className);
  section.style.setProperty('margin-top', '16px');
  section.style.setProperty('padding-top', '12px');
  section.style.setProperty('border-top', '1px solid var(--border)');
  section.append(make('h4', title));
  return section;
}

function pcRow(item, extra) {
  const row = make('p', `${PC_STATUS_ICONS[item.status]} ${PC_STATUS_LABELS[item.status]} · ${item.label}: ${item.text}`, PC_STATUS_CLASS[item.status]);
  row.dataset.pcItem = item.id;
  row.dataset.status = item.status;
  if (extra) row.append(make('span', ` — ${extra}`, 'muted'));
  return row;
}

// 화면 상태(기록·선택·진행 중)를 한곳에 두고, 바뀔 때마다 제공 화면의 onChange로 다시 그린다.
function createPcInsights({ api, onChange } = {}) {
  const loaded = loadPcHistory();
  const state = { entries: loaded.entries, persisted: loaded.persisted, busy: false, latest: null, failure: null, metric: 'cpu', filter: 'all', notice: '', restore: null };
  const changed = () => { if (typeof onChange === 'function') onChange(); };

  async function refresh() {
    if (state.busy) return;
    if (!api || typeof api.get !== 'function') {
      state.failure = { code: 'NO_API', message: '제공 조회 기능을 사용할 수 없습니다.' };
      state.latest = null; state.restore = 'refresh'; changed(); return;
    }
    state.busy = true; state.failure = null; state.notice = ''; state.restore = 'refresh'; changed();
    let result;
    try { result = await api.get(PC_PATH); } catch { result = { ok: false, error: { code: 'REQUEST_FAILED', message: '조회 중 오류가 발생했습니다.' } }; }
    state.busy = false; state.restore = 'refresh';
    const data = result && result.ok === true ? result.data : null;
    if (!isObject(data) || data.schema !== PC_SCHEMA || data.source !== 'local-pc' || !Number.isFinite(Date.parse(data.measuredAt))) {
      const error = result && isObject(result.error) ? result.error : null;
      state.failure = { code: error && error.code ? String(error.code) : 'INVALID_RESPONSE', message: error && error.message ? String(error.message) : '응답 형식이 계약과 다릅니다.' };
      state.latest = null; // 예전 값을 이번 조회처럼 보이지 않게 비운다.
      changed(); return;
    }
    const items = judgePcStatus(data);
    const entry = { at: new Date(data.measuredAt).toISOString(), items: items.map((i) => ({ id: i.id, label: i.label, status: i.status, text: i.text, value: i.value, reason: i.reason })) };
    state.entries = [...state.entries, entry].slice(-PC_HISTORY_MAX);
    state.persisted = savePcHistory(state.entries);
    state.latest = { entry, items, hints: Object.fromEntries(items.map((i) => [i.id, i.hint])) };
    changed();
  }

  function render() {
    const root = make('section', null, 'status-block pc-insights');
    root.dataset.pcInsights = 'true';
    const heading = make('h3', '내 PC 기록·추이·위험 알림 ');
    heading.append(make('span', '학생 구현', 'tag tag-student'));
    root.append(heading);
    root.append(make('p', '값은 제공된 「내 PC 상태」가 이 PC에서 실제로 잰 결과입니다. 이 칸은 그 값으로 기록 남기기·이전 조회와 비교·위험 알림만 만들며, 예시 값은 쓰지 않습니다. 읽지 못한 값은 「확인 불가」와 이유로 보여 줍니다.', 'muted'));

    const bar = make('p', null, 'pc-insights-bar');
    const refresh_ = make('button', state.busy ? '읽는 중…' : '다시 조회', 'btn');
    refresh_.type = 'button';
    refresh_.disabled = state.busy;
    refresh_.dataset.pcFocus = 'refresh';
    refresh_.addEventListener('click', () => { void refresh(); });
    bar.append(refresh_);
    root.append(bar);

    const live = make('p', null, 'state');
    live.setAttribute('role', 'status');
    live.setAttribute('aria-live', 'polite');
    if (state.busy) { live.className = 'state state-loading'; live.textContent = '이 PC에서 읽는 중…'; }
    else if (state.failure) {
      live.className = 'state state-error';
      live.textContent = `이번 조회에 실패했습니다: ${state.failure.message} (${state.failure.code}). 예시 값으로 대신 채우지 않았습니다.`;
    } else if (state.latest) { live.className = 'state state-ok'; live.textContent = `이 PC에서 ${pcTime(state.latest.entry.at)}에 실제로 잰 값입니다. 보안 서버(SDP) 연결 상태와는 별개입니다.`; }
    else { live.className = 'state state-empty'; live.textContent = '아직 이 화면에서 조회하지 않았습니다. 「다시 조회」를 누르면 읽습니다.'; }
    root.append(live);
    if (state.failure && !state.busy) {
      root.append(make('p', '다음에 할 일: 앱이 실행 중인지 확인하고 「다시 조회」를 눌러 주세요. 계속 안 되면 제공 화면의 「도움정보」를 복사해 담당자에게 전달하세요.', 'muted'));
    }

    // 현재 값(이번 조회) + 읽지 못한 항목 안내
    if (state.latest) {
      const summary = summarizePc(state.latest.items);
      const block = pcSection('pc-current', `이번 조회 · ${summary.text}${summary.warn ? ` · 주의 ${summary.warn}개` : ''}${summary.unknown ? ` · 확인 불가 ${summary.unknown}개` : ''}`);
      const list = make('div', null, 'pc-current-list');
      for (const item of state.latest.items) list.append(pcRow(item, item.status === 'unknown' ? item.reason : state.latest.hints[item.id]));
      block.append(list);
      const bad = state.latest.items.filter((i) => i.status === 'unknown');
      if (bad.length) {
        const box = make('div', null, 'state state-empty pc-unknown-box');
        box.append(make('strong', `읽지 못한 항목 ${bad.length}개 — 정상이라는 뜻이 아닙니다.`));
        const ul = make('ul', null, 'plain-list');
        for (const item of bad) ul.append(make('li', `${item.label} 값을 읽지 못했습니다. 이유: ${item.reason}. ${item.text.includes('권한') ? '권한을 확인한 뒤 「다시 조회」를 눌러 주세요(관리자 권한은 쓰지 않습니다).' : item.reason.includes('운영체제') ? 'Windows PC에서 실행하면 읽힐 수 있어요.' : '잠시 뒤 「다시 조회」를 눌러 보세요.'}`));
        box.append(ul);
        block.append(box);
      }
      root.append(block);
    }

    // 위험 알림
    const alerts = computeAlerts(state.entries);
    const alertBlock = pcSection('pc-alerts', `위험 알림 · 지금 주의 ${alerts.current.length}개`);
    alertBlock.dataset.alerts = String(alerts.current.length);
    alertBlock.append(make('p', '기준값을 넘었다는 알림이며 침해(공격) 판정이 아닙니다. 방화벽이 켜져 있거나 경고·오류가 적어도 안전하다는 뜻이 아닙니다.', 'muted'));
    if (state.entries.length === 0) alertBlock.append(make('p', '아직 조회 기록이 없어 알릴 것이 없습니다.', 'state state-empty'));
    else if (alerts.current.length === 0) alertBlock.append(make('p', '지금 기록 기준으로 주의 항목이 없습니다. (읽지 못한 항목은 위 「읽지 못한 항목」에서 따로 보세요.)', 'state state-ok'));
    else {
      for (const a of alerts.current) alertBlock.append(make('p', `▲ 주의 · ${a.label}: ${a.text} · ${pcTime(a.since)}부터`, 'state state-error'));
    }
    if (alerts.events.length) {
      alertBlock.append(make('p', '알림 기록 (최근 10건)', 'muted'));
      const ul = make('ul', null, 'plain-list pc-alert-log');
      for (const e of alerts.events.slice(0, 10)) ul.append(make('li', `${pcTime(e.at)} · ${e.label} · ${e.text} (${e.kind === 'start' ? '주의 시작' : '주의 해소'})`));
      alertBlock.append(ul);
    }
    root.append(alertBlock);

    // 추이 비교 (이전 조회와 이번 조회)
    const trendBlock = pcSection('pc-trend', '이전 조회와 비교');
    if (state.entries.length < 2) trendBlock.append(make('p', '조회가 2번 이상 쌓이면 이전과 비교해 줍니다.', 'state state-empty'));
    else {
      const prev = state.entries[state.entries.length - 2];
      const cur = state.entries[state.entries.length - 1];
      trendBlock.append(make('p', `${pcTime(prev.at)} → ${pcTime(cur.at)}`, 'muted'));
      const ul = make('ul', null, 'plain-list');
      for (const row of compareReadings(prev, cur)) {
        const li = make('li', null);
        li.append(make('span', row.text), make('span', row.explain, 'muted'));
        ul.append(li);
      }
      trendBlock.append(ul);
    }
    root.append(trendBlock);

    // 시간에 따른 변화 그래프
    const chartBlock = pcSection('pc-chart', '시간에 따른 변화');
    const tabs = make('p', null, 'pc-tabs');
    tabs.setAttribute('role', 'group');
    tabs.setAttribute('aria-label', '그래프 항목');
    for (const m of CHART_METRICS) {
      const b = make('button', m.name, 'btn');
      b.type = 'button';
      b.setAttribute('aria-pressed', String(m.id === state.metric));
      b.dataset.pcFocus = `metric-${m.id}`;
      b.addEventListener('click', () => { state.metric = m.id; state.restore = `metric-${m.id}`; changed(); });
      tabs.append(b, document.createTextNode(' '));
    }
    chartBlock.append(tabs, pcChart(state.entries, CHART_METRICS.find((m) => m.id === state.metric)));
    root.append(chartBlock);

    // 기록 보기
    const logBlock = pcSection('pc-log', `기록 보기 · 조회 ${state.entries.length}번`);
    const filters = make('p', null, 'pc-tabs');
    filters.setAttribute('role', 'group');
    filters.setAttribute('aria-label', '기록 거르기');
    for (const [id, name] of [['all', '전체'], ['warn', '주의'], ['unknown', '확인 불가'], ['ok', '정상'], ['info', '참고']]) {
      const b = make('button', name, 'btn');
      b.type = 'button';
      b.setAttribute('aria-pressed', String(id === state.filter));
      b.dataset.pcFocus = `filter-${id}`;
      b.addEventListener('click', () => { state.filter = id; state.restore = `filter-${id}`; changed(); });
      filters.append(b, document.createTextNode(' '));
    }
    logBlock.append(filters);
    const rows = [];
    for (const entry of [...state.entries].reverse()) {
      for (const item of entry.items) if (state.filter === 'all' || item.status === state.filter) rows.push({ at: entry.at, item });
      if (rows.length >= 60) break;
    }
    if (rows.length === 0) logBlock.append(make('p', state.entries.length === 0 ? '아직 기록이 없습니다.' : '이 조건에 맞는 기록이 없습니다.', 'state state-empty'));
    else {
      const ul = make('ul', null, 'plain-list pc-log-list');
      for (const { at, item } of rows.slice(0, 60)) {
        const li = make('li', null);
        li.append(make('span', `${pcTime(at)} · ${PC_STATUS_ICONS[item.status]} ${PC_STATUS_LABELS[item.status]}`), make('span', `${item.label} · ${item.text}${item.status === 'unknown' && item.reason ? ` (${item.reason})` : ''}`));
        ul.append(li);
      }
      logBlock.append(ul);
    }
    const clear = make('button', '기록 지우기', 'btn');
    clear.type = 'button';
    clear.disabled = state.entries.length === 0;
    clear.dataset.pcFocus = 'clear';
    clear.addEventListener('click', () => {
      if (!window.confirm('이 브라우저에 저장된 PC 조회 기록을 모두 지울까요? 되돌릴 수 없습니다.')) return;
      state.entries = []; state.latest = null; clearPcHistory();
      state.notice = '기록을 모두 지웠습니다. 「다시 조회」를 누르면 새로 쌓입니다.'; state.restore = 'refresh'; changed();
    });
    logBlock.append(clear);
    if (state.notice) { const n = make('p', state.notice, 'state state-ok'); n.setAttribute('role', 'status'); logBlock.append(n); }
    logBlock.append(make('p', state.persisted ? '기록은 이 브라우저에 숫자·상태·시각만 저장되며(최근 200번) 서버나 외부로 보내지 않습니다.' : '이 브라우저에서는 기록을 저장할 수 없어, 이 화면을 닫으면 기록이 사라집니다.', 'muted'));
    root.append(logBlock);

    // 다시 그린 뒤에도 키보드 위치를 지키기 위해 방금 누른 단추로 포커스를 되돌린다.
    if (state.restore) {
      const want = state.restore;
      state.restore = null;
      requestAnimationFrame(() => {
        const target = document.querySelector(`[data-pc-focus="${want}"]`);
        if (target && !target.disabled) target.focus();
      });
    }
    return root;
  }

  return { render, refresh, state };
}

export function createStudentView({ api, onChange } = {}) {
  const pc = createPcInsights({ api, onChange });
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
    renderStatus(input) { return renderStatusView(input, pc); },
    renderVulnerabilities(input) { return renderVulnerabilitiesView(input); },
    renderAiConnection(input) { return renderAiConnectionView(input); },
    renderExplanation(input) { return renderExplanationView(input); },
    renderAction(input) { return renderActionView(input); },
  };
}
