// 보너스 xdr-01·xdr-02: XDR 거부 규칙을 Supabase 표(public.xdr_block_rules)에 올리고, 서버가 요청 주소로 찾아봅니다.
// 규칙 파일은 서버 함수끼리 나눠 쓸 수 없어서, 배포 서버에서 막으려면 이 공유 저장소가 필요합니다.
// 켜는 방법: Vercel 환경변수 XDR_BLOCK_STORE 에 supabase 를 학생이 직접 넣습니다(새 비밀값은 없음). 켜지 않으면 아무 일도 하지 않습니다.
// 저장소가 느리거나 오류면 막지 않고 통과시킵니다(규칙이 없으면 아무도 막지 않는 기존 동작과 같음).
// 키 값은 응답·로그·오류 문구에 넣지 않습니다.
import { createClient } from '@supabase/supabase-js';

export const BLOCK_TABLE = 'xdr_block_rules';
const LOOKUP_TIMEOUT_MS = 2000;
const CACHE_MS = 30 * 1000;
const CACHE_MAX = 500;
const IP_LIKE = /^[0-9A-Fa-f:.]{2,45}$/u;

const toRow = (rule) => ({
  rule_id: rule.ruleId,
  srcip: rule.srcip,
  decision: rule.decision,
  evidence_alert_id: rule.evidenceAlertId,
  created_at: rule.createdAt,
  expires_at: rule.expiresAt,
});

// 같은 (규칙 종류, 주소)는 한 줄이라 다시 올리면 만료 시각만 새로 고쳐집니다.
export async function pushRules(supabase, rules) {
  if (!rules.length) return { pushed: 0 };
  const { error } = await supabase.from(BLOCK_TABLE).upsert(rules.map(toRow), { onConflict: 'rule_id,srcip' });
  if (error) throw new Error(`공유 저장소에 올리지 못했습니다(${error.code ?? 'error'}). sql/xdr-1-block-rules.sql 을 실행했는지 확인하세요.`);
  return { pushed: rules.length };
}

let client;
export function defaultSupabase() {
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) throw new Error('SUPABASE_URL·SUPABASE_SECRET_KEY 환경변수가 없습니다. 값은 터미널 환경에 직접 넣으세요(코드·채팅에 적지 않음).');
  client ??= createClient(url, secretKey, { auth: { persistSession: false } });
  return client;
}

// 환경변수가 없으면 호출 방식과 상관없이 항상 거부(reject)로 알립니다.
export const pushRulesFromEnv = async (rules) => pushRules(defaultSupabase(), rules);

export function createRemoteBlockLookup({
  getSupabase,
  enabled = () => process.env.XDR_BLOCK_STORE === 'supabase',
  timeoutMs = LOOKUP_TIMEOUT_MS,
  cacheMs = CACHE_MS,
}) {
  const cache = new Map();
  // 주소 하나의 만료 전 거부 규칙을 돌려주고, 없거나 알 수 없으면 null 입니다. 어떤 경우에도 오류를 던지지 않습니다.
  return async function lookup(srcip, at = Date.now()) {
    try {
      if (!enabled() || typeof srcip !== 'string' || !IP_LIKE.test(srcip)) return null;
      const hit = cache.get(srcip);
      if (hit && hit.until > at) return hit.rule;
      const { data, error } = await getSupabase().from(BLOCK_TABLE)
        .select('rule_id,srcip,decision,evidence_alert_id,expires_at')
        .eq('srcip', srcip)
        .eq('decision', 'deny')
        .gt('expires_at', new Date(at).toISOString())
        .limit(1)
        .abortSignal(AbortSignal.timeout(timeoutMs));
      if (error) return null;
      const row = Array.isArray(data) ? data[0] : null;
      const rule = row && row.decision === 'deny' && row.srcip === srcip
        ? { ruleId: row.rule_id, decision: 'deny', srcip: row.srcip, evidenceAlertId: row.evidence_alert_id, expiresAt: row.expires_at }
        : null;
      // 새로 올라온 규칙이 늦어도 30초 안에 적용되고, 만료 시각이 지난 규칙은 기억하지 않습니다.
      const until = rule ? Math.min(at + cacheMs, Date.parse(rule.expiresAt) || at) : at + cacheMs;
      cache.delete(srcip);
      cache.set(srcip, { rule, until });
      if (cache.size > CACHE_MAX) cache.delete(cache.keys().next().value);
      return rule;
    } catch {
      return null;
    }
  };
}

export const defaultBlockLookup = createRemoteBlockLookup({ getSupabase: defaultSupabase });
