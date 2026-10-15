// 12단계 제작 1: 탈환 작전실 요약. 판정기 규칙·탐지 사건·회수 상태·복구 버전을 "숫자와 이름"으로만 모아 돌려줍니다.
// - 각 항목의 state: 'verified'(이번 응답을 만들 때 서버가 실제로 읽거나 확인함) | 'not_run'(이 서버에서 실행·연결되지 않음) | 'unread'(읽으려 했으나 읽지 못함).
//   미실행을 확인된 것처럼 채우지 않습니다. 운영 반 엔진의 판정·사건 전달·접속 회수 집행은 이 저장소에서 확인할 수 없어 항상 not_run입니다.
// - 서버가 확인한 로그인 사용자 본인의 기록만 셉니다. 메모 제목·본문·토큰·사용자 ID·기기 키·접속 주소는 응답과 로그에 넣지 않습니다.
// - 응답의 logLine은 서버 로그(console.info)에 남기는 가린 한 줄과 같은 글자입니다. 화면의 수치와 이 줄이 같아야 합니다.
import { RULE_IDS } from './decider.mjs';
import { BURST_LIMIT, BURST_WINDOW_MS } from './detect.mjs';
import { BLOCK_TABLE } from './xdr-store.mjs';

const DEVICE_STATUS = ['approved', 'pending', 'revoked'];
const AUDIT_EVENTS = ['requested', 'inserted', 'updated', 'unchanged', 'refused_owner_conflict', 'verify_failed'];
const MAX_VERSIONS = 10;
const MAX_ROWS = 1000;

// 읽기 한 번. 오류·예외는 던지지 않고 null로 바꿉니다(그 항목만 unread).
const rowsOf = async (query) => {
  try {
    const { data, error } = await query;
    return error || !Array.isArray(data) ? null : data;
  } catch { return null; }
};

export async function buildOpsSummary({ supabase, userId, now = () => Date.now() }) {
  const at = new Date(now()).toISOString();

  // 판정기 규칙: 코드에 있는 규칙 이름 목록입니다. 운영 엔진이 실제 요청을 판정한 결과가 아니므로 판정 호출은 not_run입니다.
  const decider = { state: 'verified', source: 'code', ruleCount: RULE_IDS.length, ruleIds: [...RULE_IDS],
    engineDecisions: { state: 'not_run', note: '운영 반 엔진의 실제 판정 결과는 이 서버에서 받지 못했습니다.' } };

  // 탐지 사건: 탐지 기준(코드 상수)과, 공유 저장소에 올라와 아직 만료되지 않은 XDR 거부 규칙의 개수(주소는 보여 주지 않음).
  const activeRules = await rowsOf(supabase.from(BLOCK_TABLE).select('rule_id').gt('expires_at', at).limit(MAX_ROWS));
  const detection = {
    burstRule: { reasonCode: 'burst_read', limit: BURST_LIMIT, windowMinutes: BURST_WINDOW_MS / 60000 },
    activeBlockRules: activeRules ? { state: 'verified', count: activeRules.length } : { state: 'unread' },
    engineEvents: { state: 'not_run', note: '운영 반 엔진이 검증한 사건 전달은 연결되지 않았습니다.' },
  };

  // 회수 상태: 내 기기의 승인·대기·회수 개수.
  const devices = await rowsOf(supabase.from('devices').select('status').eq('owner_id', userId).limit(MAX_ROWS));
  const revocation = {
    devices: devices
      ? { state: 'verified', ...Object.fromEntries(DEVICE_STATUS.map(status => [status, devices.filter(row => row.status === status).length])) }
      : { state: 'unread' },
    engineRevocation: { state: 'not_run', note: '운영 반 엔진의 접속 회수 집행은 연결되지 않았습니다.' },
  };

  // 복구 버전: 내 비공개 사본 개수와 각 사본의 버전 표시(내용 해시 앞 12자), 내 복구 감사 기록의 사건별 개수.
  const backups = await rowsOf(supabase.from('notes_backup').select('note_id, content_sha256').eq('owner_id', userId).limit(MAX_ROWS));
  const audit = await rowsOf(supabase.from('notes_restore_audit').select('event').eq('actor_id', userId).limit(MAX_ROWS));
  const versionOf = (row) => (typeof row.content_sha256 === 'string' && /^[a-f0-9]{64}$/u.test(row.content_sha256) ? row.content_sha256.slice(0, 12) : null);
  const restore = {
    backups: backups
      ? { state: 'verified', count: backups.length,
        versions: backups.slice(0, MAX_VERSIONS).map(row => ({ note: String(row.note_id ?? '').slice(0, 8), version: versionOf(row) })) }
      : { state: 'unread' },
    audit: audit
      ? { state: 'verified', count: audit.length, byEvent: Object.fromEntries(AUDIT_EVENTS.map(event => [event, audit.filter(row => row.event === event).length])) }
      : { state: 'unread' },
  };

  const n = (item, key) => (item?.state === 'verified' ? item[key] : 'unread');
  const logLine = `ops 요약: rules=${decider.ruleCount} blockRules=${n(detection.activeBlockRules, 'count')}`
    + ` devices=${devices ? DEVICE_STATUS.map(s => `${s}:${revocation.devices[s]}`).join(',') : 'unread'}`
    + ` backups=${n(restore.backups, 'count')} audit=${n(restore.audit, 'count')}`;
  return { body: { schema: 'aleph.ops-summary.v1', generatedAt: at, decider, detection, revocation, restore, logLine }, logLine };
}
