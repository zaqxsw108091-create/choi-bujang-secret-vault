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

function renderStatusView({ devices, sessions, notifications, diagnostics, mode } = {}) {
  const root = make('div', null, 'status-view');
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
    renderStatus(input) { return renderStatusView(input); },
    renderVulnerabilities() { return '학생 구현 대기: 정확한 설치 버전·OSV 출처·조회 시각·부분 결과·조회 실패를 구분하세요.'; },
    renderAiConnection(input) { return renderAiConnectionView(input); },
    renderExplanation(input) { return renderExplanationView(input); },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
