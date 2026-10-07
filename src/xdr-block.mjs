// 보너스 xdr-01: XDR 이 만든 주소 차단 규칙을 읽고, 로그인 요청의 출발 주소가 걸리는지 봅니다.
// 규칙 파일이 없거나 깨져 있으면 아무도 막지 않습니다(기존 5단계 동작 그대로).
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

export const BLOCK_RULES_FILE = join(import.meta.dirname, '..', 'xdr', 'brute-force', 'block-rules.json');

export function loadBlockRules(file = BLOCK_RULES_FILE) {
  try {
    const data = JSON.parse(readFileSync(file, 'utf8'));
    return Array.isArray(data?.rules) ? data.rules : [];
  } catch {
    return [];
  }
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
