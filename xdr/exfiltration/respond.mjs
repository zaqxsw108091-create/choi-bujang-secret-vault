// 판정 결과를 ZTNA 거부 규칙(block-rules.json)과 알림 로그(xdr/alerts.log)로 잇습니다. decide.mjs 는 판단만 하고, 파일 쓰기와 연결은 이 파일이 합니다.
// 차단 후보는 확신도 0.85 이상의 block 판정뿐이고, 같은 주소가 정상 이벤트(record)에도 나오면 정상 사용자일 수 있어 규칙에서 뺍니다.
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decide } from './decide.mjs';
import { scrub } from './read-alerts.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIR = join(ROOT, 'xdr', 'exfiltration');
export const RULES_FILE = join(DIR, 'block-rules.json');
export const ALERTS_LOG = join(ROOT, 'xdr', 'alerts.log');
const RULE_ID = 'xdr.ex.deny-ip';
const TTL_MS = 60 * 60 * 1000;
const BLOCK_AT = 0.85;

// 경보마다 decide 를 불러 { alertId, action, confidence, reason } 목록을 만듭니다.
export function decideAll(alerts) {
  return alerts.map((alert) => ({ alertId: alert?.id, ...decide(alert) }));
}

export function buildBlockRules({ alerts, decisions, now = Date.now(), ttlMs = TTL_MS }) {
  const byId = new Map(alerts.map((a) => [a?.id, a]));
  const ipOf = (d) => byId.get(d?.alertId)?.data?.srcip;
  const normalIps = new Set(decisions.filter((d) => d?.action === 'record').map(ipOf));
  const rules = [];
  const seen = new Set();
  for (const d of decisions) {
    if (d?.action !== 'block' || !(d.confidence >= BLOCK_AT) || typeof d.alertId !== 'string') continue;
    const srcip = ipOf(d);
    if (!isIP(String(srcip ?? '')) || normalIps.has(srcip) || seen.has(srcip)) continue;
    seen.add(srcip);
    rules.push({
      ruleId: RULE_ID,
      decision: 'deny',
      srcip,
      evidenceAlertId: d.alertId,
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + ttlMs).toISOString(),
    });
  }
  return rules;
}

// 알림 한 줄: 시각 · 행동 · 경보 번호 · 주소 · 계정 · 확신도 · 이유. 줄바꿈은 공백으로 바꿔 한 줄을 지킵니다.
export function alertLine(decision, alert, now = Date.now()) {
  const ip = alert?.data?.srcip ?? '-';
  const user = alert?.data?.srcuser ?? '-';
  const line = `${new Date(now).toISOString()} ${String(decision.action).toUpperCase()} ${decision.alertId} ${ip} ${user} ${decision.confidence} ${decision.reason}`;
  return scrub(line).replace(/[\r\n]+/gu, ' ');
}

export async function respond({ root = ROOT, now = Date.now(), rulesFile = RULES_FILE, logFile = ALERTS_LOG } = {}) {
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'exfiltration.json'), 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'exfiltration' || !Array.isArray(fixture.alerts)) {
    throw new Error('exfiltration 경보 묶음 형식이 아닙니다.');
  }
  const decisions = decideAll(fixture.alerts);
  const rules = buildBlockRules({ alerts: fixture.alerts, decisions, now });
  await writeFile(rulesFile, `${JSON.stringify({ schema: 'aleph.xdr.block-rules.v1', rules }, null, 2)}\n`, 'utf8');
  const byId = new Map(fixture.alerts.map((a) => [a.id, a]));
  // 알림은 block·alert 만 한 줄씩 쌓습니다. 정상(record)은 남기지 않습니다.
  const lines = decisions.filter((d) => d.action === 'block' || d.action === 'alert').map((d) => alertLine(d, byId.get(d.alertId), now));
  if (lines.length) await appendFile(logFile, `${lines.join('\n')}\n`, 'utf8');
  return { rules, logged: lines.length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { rules, logged } = await respond();
    console.log(`차단 규칙 ${rules.length}개(1시간 뒤 만료) · 알림 ${logged}줄`);
    if (process.argv.includes('--db')) {
      // 공유 저장소(Supabase 표)에도 올립니다. 키는 터미널 환경변수에서만 읽고 출력하지 않습니다.
      const { pushRulesFromEnv, BLOCK_TABLE } = await import('../../src/xdr-store.mjs');
      const { pushed } = await pushRulesFromEnv(rules);
      console.log(`공유 저장소(${BLOCK_TABLE})에 규칙 ${pushed}개를 올렸습니다.`);
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : '연결 오류');
    process.exitCode = 1;
  }
}
