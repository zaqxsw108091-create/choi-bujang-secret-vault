// 8단계 제작 1: 자료마다 서버가 구별할 수 있는 자원 ID를 붙입니다. (구역 규칙은 이후 요청에서 더합니다.)
// 자원 ID 모양: "<종류>:<대상>"
//   메모   note:<메모 UUID>   (목록·추가는 note:collection)
//   공지   notice:<공지 ID>   (목록·추가는 notice:collection)  ← 강사 공지는 메모와 다른 종류입니다.
// 종류는 요청 경로에서만 정합니다. 본문·쿼리·헤더에 실린 종류나 자원 ID는 읽지 않습니다.
// 이 파일은 이름 붙이기만 합니다. 허용·거부 판단과 새 API 경로는 만들지 않습니다.
export const RESOURCE_KINDS = Object.freeze({ note: 'note', notice: 'notice' });

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const NOTICE_ID = /^[A-Za-z0-9_-]{1,64}$/u;
// :id 자리에 올 수 없는 이름: 같은 깊이에 기능 경로(export 등)를 두지 않기 위해, 이런 이름은 자료 ID로 읽지 않습니다.
const RESERVED = new Set(['export', 'import', 'search', 'list', 'all', 'new', 'me', 'admin', 'bulk', 'collection']);
const BASES = { '/api/notes': { kind: 'note', valid: UUID }, '/api/notices': { kind: 'notice', valid: NOTICE_ID } };

// 경로(쿼리 제외)에서 자원 ID를 만듭니다. 모르는 경로나 모양이 틀린 ID는 null입니다.
export function resourceIdOf(path) {
  if (typeof path !== 'string') return null;
  const parts = path.split('?')[0].split('/').filter(Boolean);
  const base = BASES[`/${parts.slice(0, 2).join('/')}`];
  if (!base || parts.length > 3) return null;
  if (parts.length === 2) return `${base.kind}:collection`;
  return base.valid.test(parts[2]) && !RESERVED.has(parts[2].toLowerCase()) ? `${base.kind}:${parts[2].toLowerCase()}` : null;
}

export const resourceKindOf = (resourceId) =>
  (typeof resourceId === 'string' && resourceId.includes(':') ? resourceId.split(':')[0] : null);
