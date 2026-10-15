// 12단계 제작 2: 1~11단계의 정상·금지 요청을 배포 서버에 실제로 보내고, 결과를 한 표로 남깁니다.
// - 표의 열: 단계 · 구분 · 요청 · 기대 · 실제 · 요청 ID · 확인 시각 · 판정.
// - 판정은 실제로 보낸 요청의 응답(HTTP 상태와 짧은 오류 코드)을 기대와 비교한 것뿐입니다. 보내지 못했거나 보내지 않은 요청은
//   '통과'로 적지 않고 '확인하지 못함'·'미실행'으로 남깁니다. 심판의 판정이 아닌 학생의 자기 점검입니다.
// - 요청 ID는 서버가 응답 머리글(x-vercel-id)로 돌려준 값입니다. 학생이 만든 값이 아니라서 Vercel 로그와 대조할 수 있습니다.
// - 표와 JSON에는 상태 번호·오류 코드·요청 ID·시각만 적습니다. 토큰·비밀번호·기기 개인키·메모 제목과 본문·사용자 ID는 담지 않습니다.
// - 판정기(6·7단계)·탐지(9단계)·41종 최종 시험은 이 서버에서 부를 수 있는 API가 없어 항상 '미실행'입니다.
import { codeOf, keyIdOf, readPublicKey, signedText } from './device-gate.mjs';

const ERROR_CODE = /^[A-Z][A-Z0-9_]{1,39}$/u;
const REQUEST_ID = /^[A-Za-z0-9:._-]{1,80}$/u;
const MARKER_VALUE = '회귀표 가상 메모';

const describe = (status, error) => `HTTP ${Array.isArray(status) ? status.join(' 또는 ') : status}${error ? ` ${error}` : ''}`;

export function createMatrix({ app, fetchFn = fetch, now = () => new Date() }) {
  const rows = [];

  // 요청 한 번. 응답에서 상태·오류 코드·요청 ID만 꺼내고, 본문은 verify 함수가 볼 수 있게 이번 호출 안에서만 넘깁니다.
  async function call(method, path, { token, body, device, headers = {} } = {}) {
    const bodyText = body === undefined ? '' : JSON.stringify(body);
    const extra = device ? await device.proof(method, path, bodyText) : {};
    const response = await fetchFn(new URL(path, app), {
      method, redirect: 'manual', signal: AbortSignal.timeout(10000),
      headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...extra, ...headers },
      body: body === undefined ? undefined : bodyText,
    });
    const text = await response.text();
    let json = null;
    try { json = JSON.parse(text); } catch { /* JSON이 아니면 본문 검사는 하지 않습니다. */ }
    const rid = response.headers.get('x-vercel-id');
    return { status: response.status, error: ERROR_CODE.test(json?.error ?? '') ? json.error : null, json, text,
      requestId: rid && REQUEST_ID.test(rid) ? rid : null, header: (name) => response.headers.get(name) };
  }

  // 한 줄 기록. send가 던지면(접속 못 함) '확인하지 못함'. verify는 상태가 맞은 뒤의 추가 조건입니다(예: 목록 모양).
  async function check({ step, kind, request, expect, send, verify }) {
    const checkedAt = now().toISOString();
    const expected = describe(expect.status, expect.error) + (verify?.label ? ` · ${verify.label}` : '');
    let res = null;
    try { res = await send(); } catch { res = null; }
    if (!res) { rows.push({ step, kind, request, expected, actual: '요청을 보내지 못함', requestId: null, checkedAt, result: '확인하지 못함' }); return null; }
    const statusOk = (Array.isArray(expect.status) ? expect.status : [expect.status]).includes(res.status);
    const errorOk = !expect.error || res.error === expect.error;
    let extraOk = true;
    try { extraOk = !verify || verify.test(res) === true; } catch { extraOk = false; }
    const pass = statusOk && errorOk && extraOk;
    rows.push({ step, kind, request, expected, actual: `${describe(res.status, res.error)}${verify && statusOk && errorOk ? (extraOk ? ' · 추가 조건 충족' : ' · 추가 조건 불충족') : ''}`,
      requestId: res.requestId, checkedAt, result: pass ? '통과' : '실패' });
    return res;
  }
  const skip = (step, kind, request, expected, reason) => rows.push({ step, kind, request, expected, actual: `미실행 (${reason})`, requestId: null, checkedAt: null, result: '미실행' });

  return { rows, call, check, skip };
}

// 기기 키: 브라우저와 같은 방식(ECDSA P-256, 개인키는 꺼낼 수 없음). 이 프로세스 메모리에만 있고 파일·출력에 쓰지 않습니다.
export async function newDevice(subtle = globalThis.crypto.subtle) {
  const pair = await subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const publicKey = readPublicKey(await subtle.exportKey('jwk', pair.publicKey));
  const keyId = keyIdOf(publicKey);
  const proof = async (method, path, bodyText) => {
    const url = new URL(path, 'http://local');
    const ts = String(Date.now());
    const text = signedText({ method, target: `${url.pathname}${url.search}`, ts, body: bodyText });
    const sig = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, Buffer.from(text, 'utf8'));
    return { 'X-Device-Key': keyId, 'X-Device-Ts': ts, 'X-Device-Sig': Buffer.from(sig).toString('base64url') };
  };
  return { publicKey, keyId, code: codeOf(keyId), proof };
}

// tokens: { A, B } 두 시험 계정의 로그인 토큰(이 함수 안에서만 요청 머리글에 씀). anonKey가 없으면 직접 Data API 점검은 미실행.
// waitForApproval: 두 기기의 확인 코드를 받아, 학생이 서버(SQL [C])에서 승인할 때까지 기다리는 함수.
export async function runRegression({ app, config, tokens, anonKey, fetchFn = fetch, now, waitForApproval }) {
  const m = createMatrix({ app, fetchFn, now });
  const { call, check, skip } = m;
  const FAKE = 'aaaaaaaa.bbbbbbbb.cccccccc';

  // ---- 로그인이 필요 없는 요청 ----
  await check({ step: '1~2', kind: '정상', request: 'GET /', expect: { status: 200 }, send: () => call('GET', '/') });
  await check({ step: '1~2', kind: '금지', request: 'GET /data.json', expect: { status: 404 }, send: () => call('GET', '/data.json') });
  await check({ step: '2', kind: '정상', request: 'GET /aleph.json', expect: { status: 200 }, send: () => call('GET', '/aleph.json'),
    verify: { label: `확인 표시(${config.sampleMarker}) 없음`, test: (r) => !r.text.includes(config.sampleMarker) } });
  await check({ step: '3', kind: '금지', request: 'GET /api/notes (로그인 없음)', expect: { status: 401, error: 'LOGIN_REQUIRED' }, send: () => call('GET', '/api/notes') });
  await check({ step: '3', kind: '금지', request: 'GET /api/notes (가짜 토큰)', expect: { status: 401, error: 'LOGIN_REQUIRED' }, send: () => call('GET', '/api/notes', { token: FAKE }) });
  await check({ step: '5', kind: '금지', request: 'POST /api/login (없는 계정)', expect: { status: 401, error: 'LOGIN_FAILED' },
    send: () => call('POST', '/api/login', { body: { email: 'no-such-user@example.invalid', password: 'wrong-password-for-matrix' } }) });
  if (anonKey) {
    await check({ step: '4~5', kind: '금지', request: 'GET 원본 자료 주소 (anon 키, 쿼리 없음)', expect: { status: [401, 403] },
      send: () => call('GET', config.originalApiUrl, { headers: { apikey: anonKey, Authorization: `Bearer ${anonKey}` } }) });
  } else skip('4~5', '금지', 'GET 원본 자료 주소 (anon 키)', describe([401, 403]), 'anon 키를 넣지 않음');
  await check({ step: '8', kind: '금지', request: 'GET /api/notes?role=instructor (로그인 없음)', expect: { status: 401, error: 'LOGIN_REQUIRED' }, send: () => call('GET', '/api/notes?role=instructor') });
  await check({ step: '8', kind: '금지', request: 'GET /api/notices', expect: { status: 404 }, send: () => call('GET', '/api/notices') });
  await check({ step: '10', kind: '금지', request: 'POST /api/restore (로그인 없음)', expect: { status: 401, error: 'LOGIN_REQUIRED' },
    send: () => call('POST', '/api/restore', { body: { id: '00000000-0000-4000-8000-000000000000' } }) });
  await check({ step: '11', kind: '정상', request: 'GET /manifest.webmanifest', expect: { status: 200 }, send: () => call('GET', '/manifest.webmanifest') });
  await check({ step: '11', kind: '금지', request: 'POST /api/device (로그인 없음, status:approved를 실음)', expect: { status: 401, error: 'LOGIN_REQUIRED' },
    send: () => call('POST', '/api/device', { body: { status: 'approved' } }) });
  await check({ step: '11', kind: '금지', request: 'GET /api/notes (A 로그인, 기기 서명 없음)', expect: { status: 403, error: 'DEVICE_REQUIRED' }, send: () => call('GET', '/api/notes', { token: tokens.A }) });

  // ---- 기기 준비: A·B 각자 승인 요청(항상 pending), 학생이 서버에서 승인한 뒤 계속 ----
  const dev = { A: await newDevice(), B: await newDevice(), X: await newDevice() };
  for (const name of ['A', 'B', 'X']) {
    const token = name === 'B' ? tokens.B : tokens.A;
    await check({ step: '11', kind: '정상', request: `POST /api/device (${name === 'X' ? 'A의 승인 안 할 기기' : `${name}의 기기`} 승인 요청)`, expect: { status: [200, 201] },
      send: () => call('POST', '/api/device', { token, body: { publicKey: dev[name].publicKey } }),
      verify: { label: '상태 pending 또는 approved', test: (r) => ['pending', 'approved'].includes(r.json?.status) } });
  }
  await waitForApproval({ devices: [{ name: 'A', code: dev.A.code }, { name: 'B', code: dev.B.code }] });
  const approved = {};
  for (const name of ['A', 'B']) {
    const res = await check({ step: '11', kind: '정상', request: `GET /api/device (${name}의 기기 상태)`, expect: { status: 200 },
      send: () => call('GET', `/api/device?keyId=${dev[name].keyId}`, { token: tokens[name] }),
      verify: { label: '상태 approved', test: (r) => r.json?.status === 'approved' } });
    approved[name] = res?.status === 200 && res.json?.status === 'approved';
  }
  await check({ step: '11', kind: '금지', request: 'GET /api/notes (A 로그인, 승인 안 된 기기의 서명)', expect: { status: 403, error: 'DEVICE_NOT_APPROVED' },
    send: () => call('GET', '/api/notes', { token: tokens.A, device: dev.X }) });

  // ---- 승인된 기기로 보내는 정상·금지 요청 ----
  const A = { token: tokens.A, device: dev.A };
  const B = { token: tokens.B, device: dev.B };
  const why = '기기가 승인되지 않음';
  if (!approved.A || !approved.B) {
    for (const [step, kind, request, expected] of [
      ['3', '정상', 'A: 메모 목록·추가·읽기·수정·삭제', describe(200)], ['4', '금지', 'B가 A의 메모 읽기·수정·삭제', describe(403, 'FORBIDDEN')],
      ['8', '정상', 'A: 메모 한 건 읽기와 X-Resource-Id', describe(200)], ['10', '정상', 'A: POST /api/restore', describe(200)],
      ['10', '금지', 'B가 A의 메모를 POST /api/restore', describe(403, 'FORBIDDEN')]]) skip(step, kind, request, expected, why);
  } else {
    await check({ step: '3', kind: '정상', request: 'GET /api/notes (A, 기기 서명)', expect: { status: 200 }, send: () => call('GET', '/api/notes', A),
      verify: { label: '목록 배열', test: (r) => Array.isArray(r.json) } });
    const made = await check({ step: '3', kind: '정상', request: 'POST /api/notes (A, 가상 메모 추가)', expect: { status: 201 },
      send: () => call('POST', '/api/notes', { ...A, body: { title: MARKER_VALUE, body: '가상' } }), verify: { label: 'id 반환', test: (r) => typeof r.json?.id === 'string' } });
    const id = typeof made?.json?.id === 'string' ? made.json.id : null;
    const one = `/api/notes/${id}`;
    if (!id) {
      for (const [step, kind, request, expected] of [
        ['3', '정상', 'A: 메모 한 건 읽기·수정·삭제', describe(200)], ['4', '금지', 'B가 A의 메모 읽기·수정·삭제', describe(403, 'FORBIDDEN')],
        ['8', '정상', 'A: 메모 한 건 읽기와 X-Resource-Id', describe(200)], ['10', '정상', 'A: POST /api/restore', describe(200)],
        ['10', '금지', 'B가 A의 메모를 POST /api/restore', describe(403, 'FORBIDDEN')]]) skip(step, kind, request, expected, '가상 메모를 만들지 못함');
    } else {
      await check({ step: '3', kind: '정상', request: 'GET /api/notes/:id (A, 자기 메모)', expect: { status: 200 }, send: () => call('GET', one, A) });
      await check({ step: '8', kind: '정상', request: 'GET /api/notes/:id (A) 응답 머리글 X-Resource-Id', expect: { status: 200 }, send: () => call('GET', one, A),
        verify: { label: 'X-Resource-Id가 note:로 시작', test: (r) => (r.header('x-resource-id') ?? '').startsWith('note:') } });
      await check({ step: '3', kind: '정상', request: 'PUT /api/notes/:id (A, 자기 메모 수정)', expect: { status: 200 }, send: () => call('PUT', one, { ...A, body: { title: MARKER_VALUE, body: '가상 수정' } }) });
      await check({ step: '10', kind: '정상', request: 'POST /api/restore (A, 자기 메모 한 건)', expect: { status: 200 }, send: () => call('POST', '/api/restore', { ...A, body: { id } }),
        verify: { label: 'verified: true', test: (r) => r.json?.verified === true } });
      await check({ step: '4', kind: '금지', request: 'GET /api/notes/:id (B가 A의 메모)', expect: { status: 403, error: 'FORBIDDEN' }, send: () => call('GET', one, B) });
      await check({ step: '4', kind: '금지', request: 'PUT /api/notes/:id (B가 A의 메모)', expect: { status: 403, error: 'FORBIDDEN' }, send: () => call('PUT', one, { ...B, body: { title: 'x', body: 'y' } }) });
      await check({ step: '4', kind: '금지', request: 'DELETE /api/notes/:id (B가 A의 메모)', expect: { status: 403, error: 'FORBIDDEN' }, send: () => call('DELETE', one, B) });
      await check({ step: '10', kind: '금지', request: 'POST /api/restore (B가 A의 메모)', expect: { status: 403, error: 'FORBIDDEN' }, send: () => call('POST', '/api/restore', { ...B, body: { id } }) });
      await check({ step: '4', kind: '정상', request: 'GET /api/notes (B 목록에 A의 메모 없음)', expect: { status: 200 }, send: () => call('GET', '/api/notes', B),
        verify: { label: 'A의 메모 id가 없음', test: (r) => Array.isArray(r.json) && !r.json.some((n) => n?.id === id) } });
      await check({ step: '3', kind: '정상', request: 'DELETE /api/notes/:id (A, 자기 메모 정리)', expect: { status: 200 }, send: () => call('DELETE', one, A) });
      await check({ step: '3', kind: '금지', request: 'GET /api/notes/:id (A, 지운 메모)', expect: { status: 404, error: 'NOT_FOUND' }, send: () => call('GET', one, A) });
    }
  }

  // ---- 이 서버에서 부를 API가 없는 것: 임의로 통과 처리하지 않습니다 ----
  skip('6', '정상·금지', '판정기: 등록 기기 허용 / 미등록 기기 거부', 'allow / deny', '배포 서버에 판정기 API가 없음(운영 반 엔진 판정). 로컬 연습은 npm run decider:test이며 실제 API 결과가 아님');
  skip('7', '정상·금지', '판정기: 평소 접속 허용 / 복합 이상 접속 step_up', 'allow / step_up', '배포 서버에 판정기 API가 없음. 로컬 연습은 npm run fixture:7이며 실제 API 결과가 아님');
  skip('9', '정상·금지', '탐지: 정상 사건 / 10분 안 GET 120건 초과 회수 제안', 'observe / propose_revocation', '운영 반 엔진의 사건 전달·접속 회수가 연결되지 않음. 로컬 연습은 npm run detect:test');
  skip('12', '시험', '41종 공격 방어 시험(최종 총공세)', '41종 모두 방어', '41종 목록과 실행 수단이 이 저장소에 없고 아직 실행하지 않음. 통과로 적지 않음');
  return m.rows;
}

const cell = (text) => String(text ?? '—').replaceAll('|', '\\|').replaceAll('\n', ' ');
export function renderTable(rows) {
  const count = (result) => rows.filter((row) => row.result === result).length;
  const lines = [
    `# 1~11단계 정상·금지 요청 회귀표`, '',
    `통과 ${count('통과')} · 실패 ${count('실패')} · 확인하지 못함 ${count('확인하지 못함')} · 미실행 ${count('미실행')} (전체 ${rows.length}줄)`, '',
    '실제로 보낸 요청의 응답만 판정했습니다. 미실행·확인하지 못함은 통과가 아닙니다. 학생의 자기 점검이며 심판의 판정이 아닙니다.', '',
    '| 단계 | 구분 | 요청 | 기대 | 실제 | 요청 ID | 확인 시각 | 판정 |', '| --- | --- | --- | --- | --- | --- | --- | --- |',
    ...rows.map((r) => `| ${[r.step, r.kind, r.request, r.expected, r.actual, r.requestId, r.checkedAt, r.result].map(cell).join(' | ')} |`),
  ];
  return `${lines.join('\n')}\n`;
}
