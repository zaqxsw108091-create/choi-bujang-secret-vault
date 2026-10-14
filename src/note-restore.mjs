// 10단계 제작 3: 비공개 가상 메모 사본(notes_backup)에서 지정한 한 건만 되살립니다.
// - 요청에서 읽는 값은 id 하나뿐입니다. owner_id·title·content 등은 본문에 있어도 읽지 않습니다.
// - 사본은 "서버가 확인한 사용자 본인 것"만 찾습니다. 사본의 ID·소유자·내용 해시를 다시 대조하고, 맞지 않으면 아무것도 바꾸지 않습니다.
// - 바꾸는 행은 id 한 건뿐이며(다른 메모는 읽지도 쓰지도 않음), 소유자는 바꾸지 않습니다. 다른 사람 소유로 바뀐 행은 덮어쓰지 않습니다.
// - 감사 기록(notes_restore_audit)은 덧붙이기만 합니다. 앞 기록을 쓰지 못하면 메모를 바꾸지 않습니다.
// - 응답과 로그에는 메모 제목·본문·토큰·사용자 ID를 넣지 않습니다(id와 해시, 짧은 사유 코드만).
import { createHash } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[a-f0-9]{64}$/u;

// 내용 해시: 제목·본문을 각각 "UTF-8 바이트 수:글자들"로 이어 붙인 것의 SHA-256(소문자 16진수).
// 길이를 앞에 붙여 제목/본문 경계가 달라도 같은 해시가 나오지 않게 합니다. sql/10-notes-backup.sql의 식과 같습니다.
export const noteContentHash = (title, content) => createHash('sha256')
  .update(`${Buffer.byteLength(title, 'utf8')}:${title}${Buffer.byteLength(content, 'utf8')}:${content}`, 'utf8').digest('hex');

export function readRestoreId(raw) {
  let data = raw;
  if (typeof data === 'string') { try { data = JSON.parse(data); } catch { return null; } }
  if (!data || typeof data !== 'object' || Array.isArray(data)) return null;
  return typeof data.id === 'string' && UUID.test(data.id) ? data.id.toLowerCase() : null;
}

const fail = (status, error, reason) => ({ status, body: { error }, reason });
const dbFailure = (label, error) => ({ status: 502, body: { error: 'NOTES_REQUEST_FAILED' }, failure: `${label}:${error?.code ?? 'unknown'}` });
const textOf = row => typeof row?.title === 'string' && typeof row?.content === 'string';

export async function restoreOneNote({ supabase, userId, id }) {
  const audit = async (event, contentSha256 = null) => supabase.from('notes_restore_audit')
    .insert({ note_id: id, actor_id: userId, event, content_sha256: contentSha256 });

  // 1) 사본: 서버가 확인한 사용자 본인 것만 한 질의로 찾습니다.
  const mine = await supabase.from('notes_backup').select('note_id, owner_id, position, title, content, content_sha256')
    .eq('note_id', id).eq('owner_id', userId).maybeSingle();
  if (mine.error) return dbFailure('사본 읽기', mine.error);
  const backup = mine.data;
  if (!backup) {
    const any = await supabase.from('notes_backup').select('note_id').eq('note_id', id).maybeSingle();
    if (any.error) return dbFailure('사본 확인', any.error);
    return any.data ? fail(403, 'FORBIDDEN', 'not_owner') : fail(404, 'BACKUP_NOT_FOUND', 'backup_not_found');
  }
  // 2) 사본 검증: ID·소유자·내용 해시가 서로 맞아야 합니다(사본이 바뀌었으면 중단).
  if (backup.note_id !== id || backup.owner_id !== userId || !textOf(backup) || !SHA256.test(backup.content_sha256 ?? '')
      || noteContentHash(backup.title, backup.content) !== backup.content_sha256) {
    return fail(409, 'BACKUP_INVALID', 'backup_integrity');
  }
  const wanted = backup.content_sha256;

  // 3) 앞 감사 기록. 쓰지 못하면 메모를 바꾸지 않습니다.
  const first = await audit('requested', wanted);
  if (first.error) return { status: 503, body: { error: 'AUDIT_UNAVAILABLE' }, failure: `감사 기록:${first.error.code ?? 'unknown'}` };

  // 4) 지금 행: id 한 건만 봅니다.
  const live = await supabase.from('notes').select('id, owner_id, title, content').eq('id', id).maybeSingle();
  if (live.error) return dbFailure('현재 행 읽기', live.error);
  let action;
  if (!live.data) {
    const row = { id, owner_id: userId, title: backup.title, content: backup.content };
    if (Number.isInteger(backup.position)) row.position = backup.position;
    const { error } = await supabase.from('notes').insert(row);
    if (error?.code === '23505') return fail(409, 'ID_ALREADY_EXISTS', 'insert_race');
    if (error) return dbFailure('되살리기(추가)', error);
    action = 'inserted';
  } else if (live.data.owner_id !== userId) {
    await audit('refused_owner_conflict', wanted);
    return fail(409, 'OWNER_CONFLICT', 'owner_conflict');
  } else if (textOf(live.data) && noteContentHash(live.data.title, live.data.content) === wanted) {
    action = 'unchanged';
  } else {
    const { error } = await supabase.from('notes').update({ title: backup.title, content: backup.content })
      .eq('id', id).eq('owner_id', userId);
    if (error) return dbFailure('되살리기(수정)', error);
    action = 'updated';
  }

  // 5) 되살린 뒤 다시 읽어, ID·소유자·내용 해시가 사본과 같은지 확인합니다.
  const after = await supabase.from('notes').select('id, owner_id, title, content').eq('id', id).maybeSingle();
  if (after.error) return dbFailure('확인 읽기', after.error);
  const row = after.data;
  if (!row || row.id !== backup.note_id || row.owner_id !== backup.owner_id || !textOf(row)
      || noteContentHash(row.title, row.content) !== backup.content_sha256) {
    await audit('verify_failed', wanted);
    return fail(500, 'RESTORE_VERIFY_FAILED', 'verify_failed');
  }
  const last = await audit(action, wanted);
  if (last.error) return { status: 500, body: { error: 'RESTORE_AUDIT_FAILED' }, failure: `감사 기록:${last.error.code ?? 'unknown'}` };
  return { status: 200, body: { id, restored: action !== 'unchanged', action, contentSha256: wanted, verified: true } };
}

// 자동 사본: 메모를 만들 때, 그리고 사본이 없는 메모를 처음 고치거나 지울 때 "바뀌기 직전의 원래 상태"를 notes_backup에 저장합니다.
// - 이미 사본이 있으면 덮어쓰지 않습니다(ON CONFLICT DO NOTHING). 그래서 나중에 변조돼도 사본은 침해 전 상태 그대로입니다.
// - 사본 저장이 실패해도 정상 메모 작업은 막지 않습니다(사유 코드만 로그에 남기고, 제목·본문·사용자 ID는 적지 않음).
// - 서버가 확인한 소유자의 행만 저장합니다. 요청 본문의 값은 쓰지 않습니다.
export async function keepBackup(supabase, row) {
  try {
    if (!row || !UUID.test(row.id ?? '') || !UUID.test(row.owner_id ?? '') || !textOf(row)) return;
    const { error } = await supabase.from('notes_backup').upsert({
      note_id: row.id.toLowerCase(), owner_id: row.owner_id, position: Number.isInteger(row.position) ? row.position : null,
      title: row.title, content: row.content, content_sha256: noteContentHash(row.title, row.content),
    }, { onConflict: 'note_id', ignoreDuplicates: true });
    if (error) console.warn(`notes 사본 저장 실패 ${error.code ?? 'unknown'}`);
  } catch {
    console.warn('notes 사본 저장 실패');
  }
}

// 고치거나 지우기 전에 본인 소유 행을 한 번 읽어, 사본이 없으면 그 상태를 저장합니다.
export async function backupBeforeChange(supabase, id, userId) {
  try {
    const { data, error } = await supabase.from('notes').select('id, owner_id, title, content, position')
      .eq('id', id).eq('owner_id', userId).maybeSingle();
    if (error || !data || data.owner_id !== userId) return;
    await keepBackup(supabase, data);
  } catch {
    console.warn('notes 사본 저장 실패');
  }
}
