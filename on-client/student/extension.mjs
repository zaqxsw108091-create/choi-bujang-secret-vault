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
    renderAiConnection() { return '학생 구현 대기: 모델 응답 점검과 실제 사건 설명을 구분하고 AI 오류·취소·수동 복구를 안내하세요.'; },
    renderExplanation() { return '학생 구현 대기: 선택한 사건의 근거·규칙·현재 상태와 AI 설명을 연결하세요. 제안은 자동 실행하지 않습니다.'; },
    renderAction() { return '학생 구현 대기: 현재 사건·조치·실제 대상·사람 확인·ACK와 원천 효과·unknown을 구분하세요.'; },
  };
}
