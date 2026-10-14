// 11단계 제작 2: 기기 승인. 서버가 "이 기기는 등록된 기기이고, 이 요청은 그 기기가 보냈다"를 확인한 요청만 보호 자료로 보냅니다.
// - 기기는 브라우저 메모리에서 만든 서명 키쌍(ECDSA P-256)을 씁니다. 공개키만 서버에 보내고 개인키는 밖으로 나가지 않으며
//   localStorage·sessionStorage·IndexedDB에도 저장하지 않습니다(화면을 닫거나 새로고침하면 사라져 다시 승인받아야 합니다).
// - 승인 요청(POST /api/device)은 상태가 항상 'pending'인 행만 만듭니다. 'approved'로 바꾸는 일은 화면·API에 없고,
//   자료실 주인이 서버 쪽(SQL Editor, sql/11-devices.sql)에서 화면에 나온 확인 코드를 대조한 뒤에만 합니다.
// - 보호 요청은 로그인 토큰에 더해 기기 증명 헤더 세 개를 보냅니다: X-Device-Key(공개키 지문), X-Device-Ts(밀리초), X-Device-Sig(서명).
//   서명 대상은 "v1\n방법\n경로+쿼리\n시각\n본문 sha256"이라서, 서명 뒤에 경로나 본문을 바꾸면 검사에서 떨어집니다.
// - 기기 행의 owner_id가 서버가 확인한 로그인 사용자와 다르면 승인된 기기여도 쓸 수 없습니다.
// 개인키·토큰·메모 본문은 응답·로그에 넣지 않습니다.
import { createHash } from 'node:crypto';

const B64URL_43 = /^[A-Za-z0-9_-]{43}$/u;
const KEY_ID = /^[0-9a-f]{64}$/u;
const SIG = /^[A-Za-z0-9_-]{86}$/u;
const WINDOW_MS = 60_000;
const MAX_PENDING = 5;

export const sha256Hex = (text) => createHash('sha256').update(text, 'utf8').digest('hex');

// 공개키(JWK) 검사: P-256 공개 좌표 두 개만 받습니다. 개인키 성분(d)이나 다른 칸이 있으면 거부합니다.
export function readPublicKey(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const { kty, crv, x, y, ...rest } = raw;
  const extras = Object.keys(rest).filter(k => !['ext', 'key_ops'].includes(k));
  if (kty !== 'EC' || crv !== 'P-256' || !B64URL_43.test(x ?? '') || !B64URL_43.test(y ?? '') || extras.length) return null;
  return { kty, crv, x, y };
}
export const keyIdOf = (jwk) => sha256Hex(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }));
// 화면에 보여 줄 확인 코드(지문 앞 8자). 자료실 주인이 SQL 결과와 눈으로 대조합니다.
export const codeOf = (keyId) => `${keyId.slice(0, 4).toUpperCase()}-${keyId.slice(4, 8).toUpperCase()}`;

export const readDeviceRequest = (raw) => {
  let data = raw;
  if (typeof data === 'string') { try { data = JSON.parse(data); } catch { return null; } }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  const publicKey = readPublicKey(data.publicKey);
  return publicKey ? { publicKey } : null; // status·owner_id 같은 다른 칸은 읽지 않습니다.
};

// 서명 대상의 본문 문자열: 브라우저가 보낸 JSON 글자 그대로(파싱된 객체는 다시 JSON.stringify 해도 같은 글자입니다).
const bodyText = (body) => typeof body === 'string' ? body
  : body && typeof body === 'object' && Object.keys(body).length ? JSON.stringify(body) : '';
export const signedText = ({ method, target, ts, body }) => `v1\n${method}\n${target}\n${ts}\n${sha256Hex(body)}`;
const targetOf = (url) => { const u = new URL(url ?? '/', 'http://local'); return `${u.pathname}${u.search}`; };
// Vercel은 [id] 파일로 요청을 넘길 때 주소에 경로의 id를 쿼리(?id=…)로 덧붙이거나 경로에 [id] 글자를 쓸 수 있습니다.
// 브라우저가 서명한 주소에는 그 덧붙임이 없으므로, 서버가 자기 쪽에서 덧붙은 부분만 걷어낸 주소도 후보로 둡니다.
// 걷어내는 것은 "경로의 마지막 조각과 똑같은 id 쿼리"뿐입니다(그 id는 서명된 경로에 이미 들어 있어 잃는 정보가 없습니다).
// 요청이 후보 중 하나와 서명이 맞아야 하며, 경로·쿼리의 다른 부분이 서명과 다르면 어느 후보도 맞지 않아 거부됩니다.
export function targetsOf(request) {
  const raw = targetOf(request.url);
  const id = typeof request.query?.id === 'string' ? request.query.id : null;
  if (!id) return [raw];
  const u = new URL(request.url ?? '/', 'http://local');
  const path = u.pathname.includes('/[id]') ? u.pathname.replace('/[id]', `/${id}`) : u.pathname;
  const params = new URLSearchParams(u.search);
  if (path.split('/').filter(Boolean).pop() === id && params.get('id') === id) params.delete('id');
  const rest = params.toString();
  const stripped = rest ? `${path}?${rest}` : path;
  return stripped === raw ? [raw] : [raw, stripped];
}

export function createDeviceGate({ now = () => Date.now(), subtle = globalThis.crypto.subtle } = {}) {
  // 결과: { ok: true } 또는 { ok: false, status, error, reason }. 모르는 상태·DB 오류는 열지 않고 닫습니다.
  return async function check({ request, supabase, userId }) {
    const header = (name) => { const v = request.headers?.[name]; return typeof v === 'string' ? v : ''; };
    const keyId = header('x-device-key');
    const ts = header('x-device-ts');
    const sig = header('x-device-sig');
    if (!keyId && !ts && !sig) return { ok: false, status: 403, error: 'DEVICE_REQUIRED', reason: 'device_proof_missing' };
    if (!KEY_ID.test(keyId) || !/^\d{13}$/u.test(ts) || !SIG.test(sig)) {
      return { ok: false, status: 403, error: 'DEVICE_PROOF_INVALID', reason: 'device_proof_malformed' };
    }
    const { data, error } = await supabase.from('devices').select('key_id, owner_id, status, public_key').eq('key_id', keyId).maybeSingle();
    if (error) return { ok: false, status: 503, error: 'DEVICE_CHECK_FAILED', reason: 'device_lookup_failed' };
    // 행이 없거나, 다른 사용자의 기기이거나, 승인 전·회수된 기기는 모두 같은 응답입니다.
    if (!data || data.owner_id !== userId || data.status !== 'approved') {
      return { ok: false, status: 403, error: 'DEVICE_NOT_APPROVED', reason: 'device_not_approved' };
    }
    if (Math.abs(now() - Number(ts)) > WINDOW_MS) {
      return { ok: false, status: 403, error: 'DEVICE_PROOF_INVALID', reason: 'device_proof_stale' };
    }
    const jwk = readPublicKey(data.public_key);
    let valid = false;
    try {
      if (jwk && keyIdOf(jwk) === keyId) {
        const key = await subtle.importKey('jwk', jwk, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
        for (const target of targetsOf(request)) {
          const text = signedText({ method: request.method, target, ts, body: bodyText(request.body) });
          valid = await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, Buffer.from(sig, 'base64url'), Buffer.from(text, 'utf8'));
          if (valid) break;
        }
      }
    } catch { valid = false; }
    return valid ? { ok: true } : { ok: false, status: 403, error: 'DEVICE_PROOF_INVALID', reason: 'device_signature_invalid' };
  };
}

// POST /api/device: 승인 요청(항상 pending). GET /api/device?keyId=…: 내 기기의 상태만 돌려줍니다.
export async function deviceRequest({ request, response, supabase, userId, deny }) {
  const failed = (label, error) => {
    console.error(`device ${label} 실패`, error?.code ?? 'unknown');
    return response.status(502).json({ error: 'DEVICE_REQUEST_FAILED' });
  };
  const read = (keyId) => supabase.from('devices').select('key_id, owner_id, status').eq('key_id', keyId).maybeSingle();
  const view = (row) => ({ status: row.status, code: codeOf(row.key_id), keyId: row.key_id });
  if (request.method === 'GET') {
    const keyId = new URL(request.url ?? '/', 'http://local').searchParams.get('keyId') ?? '';
    if (!KEY_ID.test(keyId)) return response.status(400).json({ error: 'INVALID_KEY_ID' });
    const { data, error } = await read(keyId);
    if (error) return failed('상태 읽기', error);
    if (!data || data.owner_id !== userId) return response.status(404).json({ error: 'NOT_FOUND' });
    return response.status(200).json(view(data));
  }
  const parsed = readDeviceRequest(request.body);
  if (!parsed) return response.status(400).json({ error: 'INVALID_BODY' });
  const keyId = keyIdOf(parsed.publicKey);
  const existing = await read(keyId);
  if (existing.error) return failed('조회', existing.error);
  if (existing.data) {
    if (existing.data.owner_id !== userId) return deny(response, 409, 'DEVICE_CONFLICT', 'device_owner_mismatch');
    return response.status(200).json(view(existing.data));
  }
  const mine = await supabase.from('devices').select('key_id, status').eq('owner_id', userId);
  if (mine.error) return failed('목록', mine.error);
  if ((mine.data ?? []).filter(r => r.status === 'pending').length >= MAX_PENDING) {
    return deny(response, 429, 'TOO_MANY_PENDING', 'device_pending_limit');
  }
  const row = { key_id: keyId, owner_id: userId, public_key: parsed.publicKey, status: 'pending' };
  const { error } = await supabase.from('devices').insert(row);
  if (error?.code === '23505') return deny(response, 409, 'DEVICE_CONFLICT', 'device_race');
  if (error) return failed('추가', error);
  return response.status(201).json(view(row));
}
