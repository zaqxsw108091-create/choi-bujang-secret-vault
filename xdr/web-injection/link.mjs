// 판정 결과를 ZTNA 거부 규칙(block-rules.json)과 알림 로그(xdr/alerts.log)로 잇습니다.
// 차단 후보는 확신도 0.85 이상의 block 판정뿐이고, 같은 주소가 정상 이벤트에도 나오면 정상 사용자일 수 있어 규칙에서 뺍니다.
import { appendFile, readFile, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { scrub } from './read-alerts.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIR = join(ROOT, 'xdr', 'web-injection');
export const RULES_FILE = join(DIR, 'block-rules.json');
export const ALERTS_LOG = join(ROOT, 'xdr', 'alerts.log');
const RULE_ID = 'xdr.wi.deny-ip';
const TTL_MS = 60 * 60 * 1000;
const BLOCK_AT = 0.85;

export function buildBlockRules({ alerts, decisions, now = Date.now(), ttlMs = TTL_MS }) {
  const byId = new Map(alerts.map((a) => [a?.id, a]));
  const ipOf = (d) => byId.get(d?.alertId)?.data?.srcip;
  // 정상 이벤트(record)에 나온 주소는 차단 대상에서 제외합니다.
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

export async function linkResults({ root = ROOT, now = Date.now(), rulesFile = RULES_FILE, logFile = ALERTS_LOG } = {}) {
  const fixture = JSON.parse(await readFile(join(root, 'xdr', 'fixtures', 'web-injection.json'), 'utf8'));
  let result;
  try {
    result = JSON.parse(await readFile(join(root, 'xdr', 'web-injection', 'result.json'), 'utf8'));
  } catch {
    throw new Error('판정 결과(result.json)가 없습니다. 먼저 npm run xdr:run -- web-injection 을 실행하세요.');
  }
  if (result?.schema !== 'aleph.xdr.result.v1' || result.moduleKey !== 'web-injection' || !Array.isArray(result.decisions)) {
    throw new Error('web-injection 판정 결과 형식이 아닙니다.');
  }
  const rules = buildBlockRules({ alerts: fixture.alerts, decisions: result.decisions, now });
  await writeFile(rulesFile, `${JSON.stringify({ schema: 'aleph.xdr.block-rules.v1', rules }, null, 2)}\n`, 'utf8');
  const byId = new Map(fixture.alerts.map((a) => [a.id, a]));
  // 알림은 block·alert 만 한 줄씩 쌓습니다. 정상(record)은 남기지 않습니다.
  const lines = result.decisions.filter((d) => d?.action === 'block' || d?.action === 'alert').map((d) => alertLine(d, byId.get(d.alertId), now));
  if (lines.length) await appendFile(logFile, `${lines.join('\n')}\n`, 'utf8');
  return { rules, logged: lines.length };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const { rules, logged } = await linkResults();
    console.log(`차단 규칙 ${rules.length}개(1시간 뒤 만료) · 알림 ${logged}줄`);
  } catch (error) {
    console.error(error instanceof Error ? error.message : '연결 오류');
    process.exitCode = 1;
  }
}
