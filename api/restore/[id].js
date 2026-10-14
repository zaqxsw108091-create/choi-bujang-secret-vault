// 10단계: POST /api/restore/<메모 UUID> — api/restore.js와 같은 처리입니다(id를 주소로 받는 방식).
import { notesApi } from '../../src/notes-api.mjs';

export default notesApi.restore;
