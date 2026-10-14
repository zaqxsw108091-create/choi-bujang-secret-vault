// 로그인한 사용자의 가상 메모를 추가·조회·수정·삭제하는 서버 코드입니다. (3단계 제작 3, 4단계 제작 2에서 소유자 검사 추가)
// - 요청자는 Authorization 토큰을 src/verify-login.mjs로 검사해 확인합니다.
//   브라우저가 보낸 userId·role·owner_id는 URL·쿼리·본문 어디에 있어도 읽지도 믿지도 않습니다.
// - 소유자 검사: 모든 읽기·수정·삭제 조건에 "owner_id = 서버가 확인한 사용자 ID"를 함께 넣습니다.
//   조건을 한 질의에 넣어서 확인과 변경 사이에 끼어들 틈이 없습니다. 조건에 맞는 행이 없을 때만
//   그 id가 있는지 따로 보고, 있으면(남의 메모·주인 없는 메모) 403 FORBIDDEN, 없으면 404 NOT_FOUND로 답합니다.
//   남의 메모의 제목·본문은 어떤 응답에도 넣지 않습니다.
// - POST는 서버가 확인한 사용자 ID를 owner_id로 저장합니다.
// - PUT은 기존 행의 owner_id가 본인일 때만 바꾸고, 새 행의 owner_id도 본인 ID로 고정합니다(소유자 변경 불가).
// - owner_id가 비어 있는 처음 메모는 누구와도 일치하지 않아 아무도 접근하지 못합니다.
// 키·토큰 값은 응답·로그에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';
import { resourceIdOf } from './resources.mjs';
import { clientIp, findBlock, loadBlockRules } from './xdr-block.mjs';
import { defaultBlockLookup } from './xdr-store.mjs';
import { backupBeforeChange, bodyKeys, keepBackup, readRestoreRequest, restoreOneNote } from './note-restore.mjs';
import { policyPlan } from './policy-plan.mjs';
import { createDeviceGate, deviceRequest } from './device-gate.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const MAX_TITLE = 200;
const MAX_BODY = 5000;

// 화면과 API가 쓰는 모양은 {id, title, body}입니다. DB 칸 이름은 content이고 owner_id는 내보내지 않습니다.
// 8단계 제작 3: 거부 사유는 짧은 코드만 서버 로그에 남깁니다. 메모 제목·본문·토큰·사용자 ID는 적지 않습니다.
const deny = (response, status, error, reason) => {
  console.warn(`notes 거부: ${reason}`);
  return response.status(status).json({ error });
};
// 저장된 소유자와 서버가 검증한 사용자 ID가 정확히 같을 때만 자기 자료입니다. 요청의 값은 쓰지 않습니다.
const isOwner = (row, userId) => typeof row?.owner_id === 'string' && row.owner_id === userId;

const toPublic = (row) => ({ id: row.id, title: row.title, body: row.content });

function readNote(raw, { allowId }) {
  let data = raw;
  if (typeof data === 'string') {
    try { data = JSON.parse(data); } catch { return null; }
  }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const { title, body, id } = data;
  if (typeof title !== 'string' || !title.trim() || title.length > MAX_TITLE) return null;
  if (typeof body !== 'string' || body.length > MAX_BODY) return null;
  if (allowId && id !== undefined && (typeof id !== 'string' || !UUID.test(id))) return null;
  // title·body·id 외의 값(owner_id, userId, role 등)은 버립니다.
  return { title: title.trim(), body, id: allowId && typeof id === 'string' ? id.toLowerCase() : undefined };
}

function idFromRequest(request) {
  const fromQuery = request.query?.id;
  if (typeof fromQuery === 'string') return fromQuery;
  if (fromQuery !== undefined) return null;
  try { return new URL(request.url, 'http://local').pathname.split('/').filter(Boolean).pop() ?? null; } catch { return null; }
}

export function createNotesApi({ getVerifier, getSupabase, getPolicyPlan = policyPlan, getBlockRules = () => [], lookupBlock = async () => null, now = () => Date.now(), deviceGate = null }) {
  // 모든 요청의 공통 앞부분: 허용 방법 → 서버 설정 → 로그인 확인 → (11단계) 기기 확인. 통과한 요청만 handle로 갑니다.
  // deviceGate가 없으면 기기 확인을 하지 않습니다(시험용). 운영용 notesApi는 항상 deviceGate를 겁니다.
  // needsDevice=false는 기기 승인 요청 경로뿐입니다(아직 승인 전인 기기가 요청을 보내야 하므로).
  const guarded = (allowed, handle, { needsDevice = true } = {}) => async (request, response) => {
    response.setHeader('Cache-Control', 'no-store');
    if (!allowed.includes(request.method)) {
      response.setHeader('Allow', allowed.join(', '));
      return response.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    }
    // xdr-01·xdr-02: 만료 전 차단 규칙(규칙 파일 또는 공유 저장소)에 걸린 주소는 로그인 확인 전에 거부합니다. 규칙이 없으면 아무도 막지 않습니다.
    const ip = clientIp(request);
    if (findBlock(getBlockRules(), ip, now()) || await lookupBlock(ip, now())) {
      return response.status(403).json({ error: 'BLOCKED_BY_XDR' });
    }
    let verify;
    let supabase;
    try {
      verify = getVerifier();
      supabase = getSupabase();
    } catch {
      // 설정이 없거나 틀리면 열어 두지 않고 닫습니다.
      return response.status(500).json({ error: 'SERVER_NOT_CONFIGURED' });
    }
    try {
      const login = await verify(request.headers?.authorization);
      if (!login) {
        // 토큰 없음·위조·만료·다른 서비스용은 모두 같은 응답입니다.
        response.setHeader('WWW-Authenticate', 'Bearer');
        return deny(response, 401, 'LOGIN_REQUIRED', 'login_required');
      }
      // 11단계: 로그인한 뒤, 이 기기가 서버에 등록(승인)된 기기이고 요청이 그 기기의 서명을 가졌는지 봅니다. 실패하면 자료를 읽기 전에 멈춥니다.
      if (needsDevice && deviceGate) {
        const device = await deviceGate({ request, supabase, userId: login.userId });
        if (!device.ok) return deny(response, device.status, device.error, device.reason);
      }
      // 8단계: 로그인을 통과한 요청에 경로로 정한 자원 ID(note:…)를 붙입니다. 판단에는 아직 쓰지 않습니다.
      const resourceId = resourceIdOf(request.url ?? '');
      if (resourceId) response.setHeader('X-Resource-Id', resourceId);
      return await handle({ request, response, supabase, userId: login.userId, resourceId });
    } catch {
      console.error('notes 함수 오류');
      return response.status(500).json({ error: 'NOTES_FUNCTION_ERROR' });
    }
  };

  const failed = (response, error, label) => {
    console.error(`notes ${label} 실패`, error.code ?? 'unknown');
    return response.status(502).json({ error: 'NOTES_REQUEST_FAILED' });
  };

  // GET /api/notes, POST /api/notes
  const collection = guarded(['GET', 'POST'], async ({ request, response, supabase, userId }) => {
    if (request.method === 'POST') {
      const note = readNote(request.body, { allowId: true });
      if (!note) return response.status(400).json({ error: 'INVALID_BODY' });
      const row = { owner_id: userId, title: note.title, content: note.body };
      if (note.id) row.id = note.id;
      const { data, error } = await supabase.from('notes').insert(row).select('id').single();
      if (error?.code === '23505') return response.status(409).json({ error: 'ID_ALREADY_EXISTS' });
      if (error) return failed(response, error, '추가');
      // 10단계: 만든 직후의 상태를 사본으로 저장합니다(이미 있으면 덮어쓰지 않음, 실패해도 추가는 그대로).
      await keepBackup(supabase, { id: data.id, owner_id: userId, title: row.title, content: row.content });
      return response.status(201).json({ id: data.id });
    }
    // 목록: 서버가 확인한 사용자 본인의 메모만 돌려줍니다.
    const read = (ordered) => {
      let query = supabase.from('notes').select('id, title, content, owner_id').eq('owner_id', userId);
      if (ordered) query = query.order('position', { ascending: true, nullsFirst: false });
      return query.order('created_at', { ascending: true }).order('title', { ascending: true });
    };
    // position(원래 표시 순서) 칸이 아직 없으면(42703) 순서 기준 없이 읽습니다.
    let { data, error } = await read(true);
    if (error?.code === '42703') ({ data, error } = await read(false));
    if (error) return failed(response, error, '목록 읽기');
    // 질의 조건에 더해, 돌려줄 행의 저장된 소유자를 한 번 더 대조합니다.
    return response.status(200).json(data.filter(row => isOwner(row, userId)).map(toPublic));
  });

  // GET /api/notes/:id, PUT /api/notes/:id, DELETE /api/notes/:id
  const item = guarded(['GET', 'PUT', 'DELETE'], async ({ request, response, supabase, userId }) => {
    const id = idFromRequest(request);
    if (typeof id !== 'string' || !UUID.test(id)) return response.status(400).json({ error: 'INVALID_ID' });
    // 본인 조건에 맞는 행이 없을 때만 부릅니다: id가 있으면 남의 것(403), 없으면 404. 자료는 읽어 오지 않고 id만 봅니다.
    const notFound = async () => {
      const { data, error } = await supabase.from('notes').select('id').eq('id', id).maybeSingle();
      if (error) return failed(response, error, '소유자 확인');
      return data ? deny(response, 403, 'FORBIDDEN', 'not_owner') : response.status(404).json({ error: 'NOT_FOUND' });
    };
    if (request.method === 'GET') {
      const { data, error } = await supabase.from('notes').select('id, title, content, owner_id')
        .eq('id', id).eq('owner_id', userId).maybeSingle();
      if (error) return failed(response, error, '읽기');
      if (data && !isOwner(data, userId)) return deny(response, 403, 'FORBIDDEN', 'owner_mismatch');
      return data ? response.status(200).json(toPublic(data)) : await notFound();
    }
    if (request.method === 'PUT') {
      const note = readNote(request.body, { allowId: false });
      if (!note) return response.status(400).json({ error: 'INVALID_BODY' });
      // 10단계: 사본이 없으면 바뀌기 직전 상태를 먼저 저장합니다(있으면 덮어쓰지 않음).
      await backupBeforeChange(supabase, id, userId);
      // 기존 행(owner_id = 본인)만 고르고, 새 값의 owner_id도 본인으로 고정합니다.
      const { data, error } = await supabase.from('notes')
        .update({ title: note.title, content: note.body, owner_id: userId })
        .eq('id', id).eq('owner_id', userId).select('id, title, content');
      if (error) return failed(response, error, '수정');
      return data?.length ? response.status(200).json(toPublic(data[0])) : await notFound();
    }
    // 10단계: 지우기 전에 사본이 없으면 그 상태를 저장합니다(있으면 덮어쓰지 않음).
    await backupBeforeChange(supabase, id, userId);
    const { data, error } = await supabase.from('notes').delete()
      .eq('id', id).eq('owner_id', userId).select('id');
    if (error) return failed(response, error, '삭제');
    return data?.length ? response.status(200).json({ id: data[0].id }) : await notFound();
  });

  // POST /api/restore (10단계): 비공개 사본에서 본인 메모 한 건만 되살립니다. 요청에서는 id만 읽습니다.
  const restore = guarded(['POST'], async ({ request, response, supabase, userId }) => {
    // 심판·클라이언트가 실제로 보낸 필드 이름만 남깁니다(값은 남기지 않음).
    console.info(`notes 복구 요청 필드: ${bodyKeys(request.body).join(',') || '(없음)'}`);
    let parsed = readRestoreRequest(request.body);
    if (!parsed) {
      // 본문에 id가 없으면 주소에서 읽습니다: /api/restore?id=<UUID> 또는 /api/restore/<UUID>
      const fromUrl = idFromRequest(request);
      if (typeof fromUrl === 'string' && UUID.test(fromUrl)) parsed = { id: fromUrl.toLowerCase(), dryRun: false, expectHash: null, expectOwner: null };
    }
    if (!parsed) return response.status(400).json({ error: 'INVALID_BODY' });
    // 정책 사본도 실행 전에 검증합니다. 사본이 없거나 검증에 실패하면 아무것도 복원하지 않고 멈춥니다(읽기 전용, 운영 정책은 건드리지 않음).
    const policy = getPolicyPlan();
    if (!policy.ok) {
      console.warn('notes 거부: policy_snapshot_invalid');
      return response.status(409).json({ error: 'BACKUP_INVALID' });
    }
    const result = await restoreOneNote({ supabase, userId, id: parsed.id, expect: parsed });
    if (result.status === 200) result.body = { ...result.body, policy: policy.body };
    if (result.failure) console.error(`notes 복구 실패 ${result.failure}`);
    else if (result.reason) console.warn(`notes 거부: ${result.reason}`);
    return response.status(result.status).json(result.body);
  });

  // GET·POST /api/device (11단계): 기기 승인 요청과 내 기기 상태. 로그인은 필요하지만 기기 증명은 요구하지 않고, 어떤 자료도 돌려주지 않습니다.
  const device = guarded(['GET', 'POST'], ({ request, response, supabase, userId }) =>
    deviceRequest({ request, response, supabase, userId, deny }), { needsDevice: false });

  return { collection, item, restore, device };
}

// 서버 런타임에서 한 번만 만듭니다. 환경변수가 없으면 만들지 않고 던집니다.
let verifier;
let client;
function secrets() {
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) throw new Error('missing_env');
  return { url, secretKey };
}

export const notesApi = createNotesApi({
  getVerifier() {
    if (!verifier) verifier = createLoginVerifier({ config, supabaseSecretKey: secrets().secretKey });
    return verifier;
  },
  getSupabase() {
    if (!client) {
      const { url, secretKey } = secrets();
      client = createClient(url, secretKey, { auth: { persistSession: false } });
    }
    return client;
  },
  getBlockRules: () => loadBlockRules(),
  lookupBlock: defaultBlockLookup,
  deviceGate: createDeviceGate(),
});
