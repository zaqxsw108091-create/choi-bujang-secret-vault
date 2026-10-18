// 보너스 xdr-01~06: XDR 이 만든 주소 차단 규칙(무차별 로그인·웹 주입·알려진 취약점·몰래 심은 프로그램·권한 가로채기·자료 빼돌리기)을 읽고, 요청의 출발 주소가 걸리는지 봅니다.
// 규칙 파일이 없거나 깨져 있으면 아무도 막지 않습니다(기존 5단계 동작 그대로).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const BLOCK_RULES_FILE = join(import.meta.dirname, '..', 'xdr', 'brute-force', 'block-rules.json');
export const WEB_INJECTION_RULES_FILE = join(import.meta.dirname, '..', 'xdr', 'web-injection', 'block-rules.json');
export const KNOWN_CVE_RULES_FILE = join(import.meta.dirname, '..', 'xdr', 'known-cve', 'block-rules.json');
export const PERSISTENCE_RULES_FILE = join(import.meta.dirname, '..', 'xdr', 'persistence', 'block-rules.json');
export const PRIVILEGE_RULES_FILE = join(import.meta.dirname, '..', 'xdr', 'privilege', 'block-rules.json');
export const EXFILTRATION_RULES_FILE = join(import.meta.dirname, '..', 'xdr', 'exfiltration', 'block-rules.json');

function readRules(file) {
  try {
    const data = JSON.parse(readFileSync(file, 'utf8'));
    return Array.isArray(data?.rules) ? data.rules : [];
  } catch {
    return [];
  }
}

// 파일을 하나 주면 그 파일만, 주지 않으면 XDR 보너스가 만든 규칙 파일을 모두 읽습니다.
export function loadBlockRules(file) {
  if (file !== undefined) return readRules(file);
  return [...readRules(BLOCK_RULES_FILE), ...readRules(WEB_INJECTION_RULES_FILE), ...readRules(KNOWN_CVE_RULES_FILE), ...readRules(PERSISTENCE_RULES_FILE), ...readRules(PRIVILEGE_RULES_FILE), ...readRules(EXFILTRATION_RULES_FILE)];
}

// Vercel 은 x-forwarded-for 의 첫 칸에 접속자 주소를 넣습니다.
export function clientIp(request) {
  const forwarded = request?.headers?.['x-forwarded-for'];
  const first = String(Array.isArray(forwarded) ? forwarded[0] : forwarded ?? '').split(',')[0].trim();
  return first || String(request?.socket?.remoteAddress ?? '');
}

export function findBlock(rules, srcip, now = Date.now()) {
  if (!srcip) return null;
  return rules.find((rule) => rule?.decision === 'deny' && rule.srcip === srcip
    && Date.parse(rule.expiresAt) > now) ?? null;
}
