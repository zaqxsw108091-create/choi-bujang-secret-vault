// 10단계 제작 3: POST /api/restore — 비공개 사본에서 본인 메모 한 건을 되살립니다.
// 로그인 검사와 처리는 src/notes-api.mjs, 복원 규칙은 src/note-restore.mjs에 있습니다.
import { notesApi } from '../src/notes-api.mjs';

export default notesApi.restore;
