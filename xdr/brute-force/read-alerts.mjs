// Wazuh 모양의 경보에서 시각·출발 주소·계정·규칙 수준·설명만 뽑습니다. 원본은 고치지 않습니다.
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const FIXTURE = join(ROOT, 'xdr', 'fixtures', 'brute-force.json');

const SECRET_LIKE = [
  /\b(?:password|passwd|pwd|token|secret|api[_-]?key|비밀번호)\s*[=:]\s*\S+/giu,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/gu,
  /\b(?:sb_secret_|sk-)[A-Za-z0-9_-]{12,}/gu,
  /\b[A-Za-z0-9+/_-]{32,}={0,2}/gu,
];

// 비밀값처럼 보이는 문자열은 값 없이 자리만 남깁니다.
export function scrub(text) {
  return SECRET_LIKE.reduce((out, pattern) => out.replace(pattern, '[가림]'), String(text ?? ''));
}

export function extractAlert(alert) {
  return {
    id: typeof alert?.id === 'string' ? alert.id : '',
    time: scrub(alert?.timestamp),
    srcip: scrub(alert?.data?.srcip),
    user: scrub(alert?.data?.srcuser),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0,
    description: scrub(alert?.rule?.description),
  };
}

export async function readAlerts(file = FIXTURE) {
  const fixture = JSON.parse(await readFile(file, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || !Array.isArray(fixture.alerts)) {
    throw new Error('경보 묶음 형식이 아닙니다.');
  }
  const rows = fixture.alerts.map(extractAlert);
  return { alertCount: fixture.alerts.length, rows };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { alertCount, rows } = await readAlerts();
  for (const r of rows) {
    console.log(`${r.id}\t${r.time}\t${r.srcip}\t${r.user}\t수준 ${r.level}\t${r.description}`);
  }
  console.log(`경보 ${alertCount}건 · 뽑은 줄 ${rows.length}줄 · ${alertCount === rows.length ? '일치' : '불일치'}`);
  if (alertCount !== rows.length) process.exitCode = 1;
}
