// 11단계 제작 2: POST /api/device(기기 승인 요청, 항상 대기 상태로 만듦), GET /api/device?keyId=…(내 기기 상태).
// 로그인 검사와 처리는 src/notes-api.mjs, 기기 규칙은 src/device-gate.mjs에 있습니다. 승인은 이 경로로 할 수 없습니다.
import { notesApi } from '../src/notes-api.mjs';

export default notesApi.device;
