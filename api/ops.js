// 12단계 제작 1: GET /api/ops — 탈환 작전실 요약(숫자·이름만, 메모 본문 없음).
// 로그인·기기 서명 검사는 src/notes-api.mjs, 요약 계산은 src/ops-summary.mjs에 있습니다.
import { notesApi } from '../src/notes-api.mjs';

export default notesApi.ops;
