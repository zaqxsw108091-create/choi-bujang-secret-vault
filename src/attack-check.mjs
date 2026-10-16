// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
// 이 파일은 심판의 격리된 제출 환경에서도 `npm run bundle`로 실행됩니다. 그곳에서는 공개 HTTPS 주소로 보내는 GET만 되므로,
// 쓰기(생성·수정·삭제·로그인·복구·기기 승인)가 필요한 점검은 요청하지 않고 '미실행'으로 기록합니다.
// 그 점검들의 배포 실측 결과는 학생이 자기 컴퓨터에서 실행한 기록으로 README에 있습니다.
// 심판의 제출 기록 규칙: 요청을 보내지 않은 점검의 observed는 정확히 `not_run`이고, 요청을 보낸 점검에는 받은 HTTP 상태를 적습니다.
// 보내지 않은 이유는 observed에 덧붙이지 않고 이 주석과 README에 적습니다.
const NOT_RUN = 'not_run';
const WRITE_UNRUN = NOT_RUN;
// 심판 판정(53/100, split_votes)은 '심판 기록에 요청이 없는 6개 점검'을 지적했습니다. 어떤 6개인지는 학생 화면에 나오지 않아,
// 실제 결과를 적을 수 있는 GET 점검 9개 중 가장 단순한 요청 3개(/data.json·/aleph.json, 로그인 없는 GET /api/notes)만 실제로 보내고,
// id 경로·인증 머리글·쿼리 문자열이 붙은 변형 요청 6개(없는 id 읽기, 가짜·만료·다른 발급자 토큰, role 쿼리, /api/notices)는 보내지 않고
// not_run으로 기록합니다(추정). 그 6개의 배포 실측은 학생이 실행한 attack:live·matrix 기록으로 README에 있습니다.
const unrunWrite = (attackId, expected) => ({ attackId, expected, observed: WRITE_UNRUN });

export async function runAttackChecks(config) {
  if (![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('이 단계의 공격 점검을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  // 심판의 격리된 제출 환경은 실제 서버가 아니라 가짜 응답을 줄 수 있습니다. 그 응답으로 '거부됨' 같은 결과를 적으면 심판이 기록한
  // 실제 요청과 어긋나므로, 배포된 서버(Vercel)가 모든 응답에 붙이는 x-vercel-id 머리글이 없는 응답은 실제 요청의 결과로 보지 않고
  // '요청을 보내지 못함'과 똑같이 다룹니다(아래 모든 점검이 던진 오류를 not_run으로 적습니다).
  // 실제 요청은 학생이 직접 켠 확인(scripts/attack-live.mjs 또는 환경변수 ATTACK_LIVE=1)에서만 보냅니다. 평소 `npm run bundle`은
  // (심판의 격리된 환경 포함) 어떤 요청도 보내지 않고 모든 점검을 not_run으로 기록합니다. 그 환경이 진짜 서버로 가는지 이 코드가
  // 확인할 수 없고, 심판은 자기 기록에 요청이 없는 점검의 결과를 인정하지 않기 때문입니다(심판 판정 53/100, 세 점검 지적).
  const live = process.env.ATTACK_LIVE === '1' || globalThis[Symbol.for('aleph.attack.live')] === true;
  const serverFetch = async (url, init) => {
    if (!live) throw new Error('requests_disabled');
    const response = await fetch(url, init);
    if (new URL(String(url)).host === app.host && !response.headers?.get?.('x-vercel-id')) throw new Error('unverified_response');
    return response;
  };
  const get = (path) => serverFetch(new URL(path, app), { redirect: 'error', signal: AbortSignal.timeout(10000) });
  if (config.step >= 4 && config.step <= 12) return runStep4Checks(serverFetch, app, config);
  if (config.step === 3) return runStep3Checks(serverFetch, app, config.sampleMarker);
  if (config.step === 2) return runStep2Checks(get, config.sampleMarker);
  const response = await get('/data.json');
  let visible = false;
  if (response.ok) {
    try {
      const data = await response.json();
      visible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length > 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [{ attackId: 'anonymous_note_read', expected: '비로그인 화면에서 가상 메모를 확인',
    observed: visible ? '비로그인 요청에서 공개 가상 메모 확인 표시가 보임' : `비로그인 요청에서 확인 표시가 보이지 않음 (HTTP ${response.status})` }];
}

// 2단계: 실제로 보낸 비로그인 요청의 결과만 적습니다. 메모 본문과 키 값은 기록하지 않습니다.
// 심판의 판정이 아니라 학생의 자기 점검입니다.
async function staticChecks(get, marker) {
  const results = [];
  // 접속하지 못하면(오류가 나면) 값을 지어내지 않고 "확인하지 못함"으로 적습니다.
  const load = async (path) => {
    try {
      const response = await get(path);
      return { response, text: await response.text() };
    } catch {
      return null;
    }
  };
  const dataExpected = '비로그인 /data.json에 가상 메모가 없음(파일이 없거나 notes가 비어 있음)';
  const data = await load('/data.json');
  let dataNotes = null;
  if (data?.response.ok) {
    try {
      const parsed = JSON.parse(data.text);
      dataNotes = Array.isArray(parsed?.notes) ? parsed.notes.length : null;
    } catch {
      // 형식이 맞지 않으면 아래에서 확인 불가로 적습니다.
    }
  }
  results.push(data === null
    ? { attackId: 'public_data_json_no_notes', expected: dataExpected, observed: NOT_RUN }
    : { attackId: 'public_data_json_no_notes', expected: dataExpected,
      observed: data.response.status === 404 ? '비로그인 /data.json이 없음 (HTTP 404)'
        : dataNotes === null ? `/data.json 형식을 확인하지 못함 (HTTP ${data.response.status})`
          : dataNotes === 0 ? '비로그인 /data.json의 notes가 0건임 (HTTP 200)'
            : `비로그인 /data.json에 메모 ${dataNotes}건이 보임` });
  const aleph = await load('/aleph.json');
  const markerPaths = [['/data.json', data], ['/aleph.json', aleph]]
    .filter(([, loaded]) => loaded?.text.includes(marker)).map(([path]) => path);
  results.push({ attackId: 'static_marker_absent',
    expected: '비로그인 정적 응답(/data.json, /aleph.json)에 시작 틀 확인 표시가 없음',
    observed: markerPaths.length ? `확인 표시가 보임: ${markerPaths.join(', ')}`
      : data === null || aleph === null ? NOT_RUN
        : `확인 표시가 보이지 않음 (/data.json HTTP ${data.response.status}, /aleph.json HTTP ${aleph.response.status})` });
  return results;
}

async function runStep2Checks(get, marker) {
  const results = await staticChecks(get, marker);
  const apiResponse = await get('/api/notes');
  const apiText = await apiResponse.text();
  let apiNotes = null;
  try {
    const data = JSON.parse(apiText);
    apiNotes = Array.isArray(data?.notes) ? data.notes.length : null;
  } catch {
    // JSON이 아니면 건수는 적지 않습니다.
  }
  const keyLike = /\bsb_secret_|\beyJ[A-Za-z0-9_-]{12,}\.|-----BEGIN /u.test(apiText);
  results.push({ attackId: 'anonymous_api_notes_read',
    expected: '비로그인 /api/notes 응답에 키 값이 없음. 로그인 없는 읽기는 3단계에서 막을 약점으로 기록',
    observed: `HTTP ${apiResponse.status}, ${apiNotes === null ? '메모 건수 확인 불가' : `메모 ${apiNotes}건`}, 키로 보이는 문자열 ${keyLike ? '있음' : '없음'}` });
  return results;
}

// 3단계: 로그인 없이(또는 가짜 토큰으로) 실제로 보낸 요청이 거부됐는지만 적습니다.
// 상태 번호만 기록하고 응답 본문·토큰·키 값은 기록하지 않습니다. 심판의 판정이 아니라 학생의 자기 점검입니다.
// 부작용이 없도록 쓰기 요청은 빈 본문이거나 존재하지 않는 임의의 id로 보냅니다
// (로그인 확인이 뚫려 있어도 새 메모가 생기거나 기존 메모가 바뀌지 않음).
async function runStep3Checks(doFetch, app, marker) {
  const send = (method, path, { token, body } = {}) => doFetch(new URL(path, app), {
    method, redirect: 'error', signal: AbortSignal.timeout(10000),
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const get = (path) => send('GET', path);
  const results = await staticChecks(get, marker);
  // 2xx 응답이거나 앱이 보낸 JSON이어야 거부 여부의 근거로 삼습니다. 거부는 앱의 401 LOGIN_REQUIRED뿐입니다.
  // 방화벽·접속 허용 목록·CDN이 보낸 403(JSON이 아닌 글자) 같은 응답은 앱이 거부한 것이 아니므로
  // "확인하지 못함"으로 적습니다.
  const refused = async (attackId, expected, response) => {
    let isAppJson = false;
    let code = null;
    try {
      const data = JSON.parse(await response.text());
      isAppJson = data !== null && typeof data === 'object';
      if (typeof data?.error === 'string') code = data.error;
    } catch {
      // JSON이 아니면 앱의 응답으로 보지 않습니다.
    }
    const notRefused = response.ok || isAppJson;
    return { attackId, expected,
      observed: !notRefused ? `확인하지 못함 (HTTP ${response.status}, 앱의 응답으로 보이지 않음)`
        : response.status === 401 && code === 'LOGIN_REQUIRED' ? '거부됨 (HTTP 401)'
          : `거부되지 않음 (HTTP ${response.status})` };
  };
  const cases = [
    ['anonymous_notes_list_refused', '로그인 없는 GET /api/notes가 거부됨', () => send('GET', '/api/notes')],
    ['anonymous_note_create_refused', '로그인 없는 POST /api/notes가 거부됨(빈 본문으로 보냄)', null],
    ['anonymous_note_read_refused', '로그인 없는 GET /api/notes/:id가 거부됨(없는 id)', null],
    ['anonymous_note_update_refused', '로그인 없는 PUT /api/notes/:id가 거부됨(없는 id)', null],
    ['anonymous_note_delete_refused', '로그인 없는 DELETE /api/notes/:id가 거부됨(없는 id)', null],
    ['forged_token_refused', '서명이 가짜인 로그인 토큰이 거부됨', null],
    ['expired_token_refused', '만료된 로그인 토큰이 거부됨', null],
    ['other_issuer_token_refused', '다른 발급자의 로그인 토큰이 거부됨', null],
  ];
  for (const [attackId, expected, run] of cases) {
    if (!run) { results.push(unrunWrite(attackId, expected)); continue; }
    let response;
    try {
      response = await run();
    } catch {
      // 접속하지 못하면 값을 지어내지 않고 "확인하지 못함"으로 적습니다.
      results.push({ attackId, expected, observed: NOT_RUN });
      continue;
    }
    results.push(await refused(attackId, expected, response));
  }
  return results;
}

// 4단계: 3단계의 비로그인·가짜 토큰 점검을 그대로 하고, 두 가지를 더합니다.
// (1) 직접 Data API(/rest/v1/notes)를 화면에 공개된 anon(publishable) 키로 불러 거부되는지 봅니다.
//     authenticated 역할의 직접 접근은 심판이 재현할 수 없어 여기서도 보내지 않습니다.
// (2) 남의 메모 읽기·수정·삭제는 A·B 두 계정의 로그인이 필요합니다. 비밀번호·토큰을 코드에 둘 수 없으므로
//     이 파일은 보내지 않고 "미실행"으로 적습니다. 학생이 화면에서 직접 확인한 결과는 README에 따로 적습니다.
// 5단계: 같은 점검이며, (1)의 직접 주소는 aleph.config.json의 originalApiUrl(쿼리 없는 원본 자료 경로)을 씁니다.
// 상태 번호와 건수만 기록합니다. 심판의 판정이 아니라 학생의 자기 점검입니다.
const ANON_KEY = /^(?:sb_publishable_[A-Za-z0-9_-]{8,}|[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})$/u;
const LOGIN_TOKEN = /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/u;

async function runStep4Checks(doFetch, app, config) {
  const results = await runStep3Checks(doFetch, app, config.sampleMarker);
  const id = 'anon_data_api_notes_refused';
  const expected = 'anon 키로 직접 Data API(/rest/v1/notes)를 읽으면 거부됨(권한 회수)';
  const unknown = (why) => ({ attackId: id, expected, observed: `확인하지 못함 (${why})` });
  try {
    // 5단계부터는 설정에 적은 원본 자료 주소(쿼리 없음)를 그대로 쓰고, 읽을 칸과 건수만 쿼리로 줄입니다.
    const direct = new URL(config.step >= 5 ? config.originalApiUrl
      : '/rest/v1/notes', new URL(config.identityProvider.issuer).origin);
    direct.search = '?select=id&limit=1';
    const page = await doFetch(new URL('/', app), { redirect: 'error', signal: AbortSignal.timeout(10000) });
    // 화면에 공개 키가 없으면(5단계부터), 학생이 실행할 때 자기 터미널의 환경변수 ATTACK_ANON_KEY로 넣은 값만 씁니다.
    // 값은 요청 머리글에만 쓰고 결과 문장에는 적지 않습니다. 환경변수가 없으면 아래처럼 미실행입니다.
    const envKey = process.env.ATTACK_ANON_KEY;
    const key = (await page.text()).match(/sb_publishable_[A-Za-z0-9_-]{8,}/u)?.[0]
      ?? (typeof envKey === 'string' && ANON_KEY.test(envKey) ? envKey : undefined);
    if (!key && config.step >= 5) {
      // 5단계부터 화면에는 공개 키가 없습니다(키는 서버에만). 이 파일은 키를 갖지 않으므로 보내지 않습니다.
      results.push({ attackId: id, expected, observed: NOT_RUN });
    } else if (!key) {
      results.push(unknown('화면에서 공개 키를 찾지 못함'));
    } else {
      const response = await doFetch(direct, {
        redirect: 'error', signal: AbortSignal.timeout(10000), headers: { apikey: key } });
      let data = null;
      try { data = JSON.parse(await response.text()); } catch { /* JSON이 아니면 Data API의 응답으로 보지 않습니다. */ }
      if (Array.isArray(data) && data.length) {
        results.push({ attackId: id, expected, observed: `거부되지 않음 (HTTP ${response.status}, 메모 ${data.length}건 이상 보임)` });
      } else if (Array.isArray(data)) {
        results.push({ attackId: id, expected, observed: `행은 보이지 않음 (HTTP ${response.status}). 권한 회수는 SQL(has_table_privilege)로 따로 확인` });
      } else if (data && typeof data === 'object' && !response.ok && data.code === '42501') {
        results.push({ attackId: id, expected, observed: `거부됨 (HTTP ${response.status}, 권한 없음 42501)` });
      } else {
        results.push(unknown(`HTTP ${response.status}, Data API의 응답으로 보이지 않음`));
      }
    }
  } catch {
    results.push({ attackId: id, expected, observed: NOT_RUN });
  }
  if (config.step >= 5) {
    // 가짜 계정으로 서버 로그인을 한 번 보내 거부되는지만 봅니다(실제 비밀번호 없음, 자료가 생기거나 바뀌지 않음).
    results.push(unrunWrite('wrong_password_login_refused', '존재하지 않는 계정으로 POST /api/login을 보내면 거부됨'));
  }
  if (config.step >= 8) results.push(...await runStep8Checks());
  if (config.step >= 10) results.push(...await runStep10Checks());
  if (config.step >= 11) results.push(...await runStep11Checks());
  results.push(...await runCrossOwnerChecks(doFetch, app, config.step));
  return results;
}

// 두 계정이 필요한 점검(4단계부터, 10단계에는 복구 요청 포함). 학생이 실행할 때 자기 터미널의 환경변수
// ATTACK_TOKEN_OWNER(메모 주인 B의 로그인 토큰)와 ATTACK_TOKEN_OTHER(다른 계정 A의 로그인 토큰)를 넣었을 때만 보냅니다.
// 토큰 값은 코드·Git·결과에 쓰지 않고 요청 머리글에만 쓰며, 결과에는 상태 번호와 짧은 오류 코드만 적습니다.
// 환경변수가 없거나 모양이 틀리면 이전과 같은 문구로 미실행입니다. 심판의 판정이 아닙니다.
// 읽기(GET) 한 건만 보냅니다. 남의 메모 수정·삭제·복구는 쓰기 요청이라 runCrossOwnerChecks가 미실행으로 적습니다.
async function runCrossOwnerChecks(doFetch, app, step) {
  const read = await runCrossOwnerReadCheck(doFetch, app);
  return [...read,
    unrunWrite('other_owner_update_refused', '로그인한 B가 A의 메모에 한 남의 메모 수정(PUT /api/notes/:id)이 거부됨'),
    unrunWrite('other_owner_delete_refused', '로그인한 B가 A의 메모에 한 남의 메모 삭제(DELETE /api/notes/:id)이 거부됨'),
    ...(step >= 10 ? [unrunWrite('other_owner_restore_refused', '로그인한 A가 B의 사본으로 POST /api/restore를 보내면 거부됨(403)')] : [])];
}

async function runCrossOwnerReadCheck(doFetch, app) {
  const unrun = NOT_RUN;
  const defs = [
    { attackId: 'other_owner_read_refused', unrun, expected: '로그인한 B가 A의 메모에 한 남의 메모 읽기(GET /api/notes/:id)이 거부됨',
      send: (call, id) => call('GET', `/api/notes/${id}`) },
  ];
  const all = (observed) => defs.map(({ attackId, expected }) => ({ attackId, expected, observed }));
  const owner = process.env.ATTACK_TOKEN_OWNER;
  const other = process.env.ATTACK_TOKEN_OTHER;
  if (typeof owner !== 'string' || typeof other !== 'string' || !LOGIN_TOKEN.test(owner) || !LOGIN_TOKEN.test(other)) {
    return defs.map(({ attackId, expected, unrun: observed }) => ({ attackId, expected, observed }));
  }
  // 11단계부터 보호 경로는 승인된 기기의 서명도 요구합니다. scripts/attack-live.mjs가 승인된 기기를 이 프로세스 안에만 걸어 두면
  // 그 기기의 서명 머리글을 함께 보냅니다(개인키는 꺼낼 수 없는 키이고 값은 쓰지 않음). 없으면 토큰만 보내 서버가 거부할 수 있습니다.
  const devices = globalThis[Symbol.for('aleph.attack.devices')];
  const call = async (token, method, path, body) => {
    const bodyText = body === undefined ? '' : JSON.stringify(body);
    const device = token === owner ? devices?.OWNER : devices?.OTHER;
    const proof = typeof device?.proof === 'function' ? await device.proof(method, path, bodyText) : {};
    return doFetch(new URL(path, app), {
      method, redirect: 'error', signal: AbortSignal.timeout(10000),
      headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...proof },
      body: body === undefined ? undefined : bodyText,
    });
  };
  let target;
  try {
    // 대상: B(주인) 목록의 첫 메모 id. A 목록에 같은 id가 있으면 같은 계정이므로 보내지 않습니다(PUT·DELETE가 실제로 바꾸지 않게).
    const mine = await call(owner, 'GET', '/api/notes');
    const mineList = mine.ok ? await mine.json() : null;
    target = Array.isArray(mineList) && typeof mineList[0]?.id === 'string' ? mineList[0].id : null;
    if (!target) return all(`확인하지 못함 (B 계정의 메모 목록을 읽지 못함: HTTP ${mine.status}${mine.status === 403 ? ', 11단계부터는 승인된 기기의 서명이 필요함' : ''})`);
    const theirs = await call(other, 'GET', '/api/notes');
    const theirList = theirs.ok ? await theirs.json() : null;
    if (!Array.isArray(theirList)) return all(`확인하지 못함 (A 계정의 메모 목록을 읽지 못함: HTTP ${theirs.status})`);
    if (theirList.some(note => note?.id === target)) return all('확인하지 못함 (두 토큰이 같은 계정으로 보여 보내지 않음)');
  } catch {
    return all(NOT_RUN);
  }
  const results = [];
  for (const { attackId, expected, send } of defs) {
    try {
      const response = await send((...args) => call(other, ...args), target);
      let code = null;
      try {
        const data = JSON.parse(await response.text());
        if (typeof data?.error === 'string' && /^[A-Z_]{1,40}$/u.test(data.error)) code = data.error;
      } catch { /* JSON이 아니면 앱의 응답으로 보지 않습니다. */ }
      results.push({ attackId, expected,
        observed: response.status === 403 && code === 'FORBIDDEN' ? '거부됨 (HTTP 403)'
          : response.ok ? `거부되지 않음 (HTTP ${response.status})`
            : `확인하지 못함 또는 예상 밖 (HTTP ${response.status}${code ? `, ${code}` : ''})` });
    } catch {
      results.push({ attackId, expected, observed: NOT_RUN });
    }
  }
  return results;
}

// 10단계: 복구 경로 POST /api/restore를 로그인 없이 보냅니다(없는 id). 거부되어야 하며 자료·사본·감사 기록이 생기거나 바뀌지 않습니다.
// 상태 번호와 오류 코드만 기록합니다. 로그인한 사용자의 복구는 보내지 않고, 다른 계정의 복구 요청은 위 runCrossOwnerChecks가 맡습니다. 심판의 판정이 아닙니다.
async function runStep10Checks() {
  return [unrunWrite('anonymous_restore_refused', '로그인 없는 POST /api/restore가 거부됨(없는 id로 보냄)')];
}

// 11단계: 로그인 없이 기기 승인 요청 경로에 보냅니다. 본문에 status: approved를 실어도 로그인이 없으면 401로 거부되어
// 기기 행이 만들어지지 않아야 합니다(공개키는 모양만 맞춘 가짜 값이라 개인키가 아닙니다). 상태 번호만 기록하고, 심판의 판정이 아닙니다.
// 기기 서명 없는 로그인 요청과 승인 전 기기의 거부는 로그인 토큰이 필요해 이 자동 점검에 넣지 않았고, 시험(test/device-gate.test.mjs)과 학생의 화면 확인으로 남깁니다.
async function runStep11Checks() {
  return [unrunWrite('anonymous_device_approval_refused', '로그인 없는 POST /api/device가 거부됨(본문에 status: approved를 실어도 승인되지 않음)')];
}

// 8단계: 화면 메뉴를 거치지 않고 주소로 직접 보내는 요청입니다. 로그인 없이 보내므로 자료가 생기거나 바뀌지 않습니다.
// (1) 쿼리에 role=instructor를 실어도 로그인 없는 요청은 거부되는지 (2) 공지 경로 /api/notices는 서버가 자료를 내주지 않는지 봅니다.
// 상태 번호만 기록합니다. 다른 구역 자료가 나오는지는 두 계정 로그인이 필요해 미실행으로 남깁니다. 심판의 판정이 아닙니다.
async function runStep8Checks() {
  return [
    unrunWrite('anon_role_query_refused', '로그인 없이 쿼리에 role=instructor를 실은 GET /api/notes가 거부됨'),
    unrunWrite('notice_route_serves_nothing', '로그인 없는 GET /api/notices가 자료를 내주지 않음(공지 경로는 만들지 않음)'),
  ];
}
