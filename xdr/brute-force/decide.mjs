// 경보를 패턴과 맞춰 보고, 애매한 것만 Jev 에게 물어 block / alert / record 를 정합니다.
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractAlert } from './read-alerts.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const { patterns } = JSON.parse(await readFile(join(HERE, 'patterns.json'), 'utf8'));
const BURST = patterns.find((p) => p.name === 'same-ip-failure-burst');
const SPRAY = patterns.find((p) => p.name === 'same-password-many-accounts');

const BLOCK_AT = 0.85;
const ALERT_AT = 0.5;
const NORMAL_LEVEL = 3;
const JEV_TIMEOUT_MS = 3000;

const toAction = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

function readSignals(alert) {
  const description = String(alert?.rule?.description ?? '');
  const failures = Number(alert?.data?.count);
  const listed = String(alert?.data?.accounts ?? '').split(',').filter(Boolean).length;
  const named = Number(/계정\s*(\d+)\s*개/u.exec(description)?.[1] ?? 0);
  return {
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0,
    failures: Number.isFinite(failures) ? failures : 0,
    accounts: Math.max(listed, named),
    hasFailure: /실패|같은 비밀번호/u.test(description),
    succeededAfter: /성공했/u.test(description),
    mentionsAccounts: /계정/u.test(description),
  };
}

// 애매한 경보가 어느 패턴과 일부 닮았는지 이름만 모읍니다(reason 에 근거 패턴 이름을 적기 위함).
const nearPatterns = (s) => [BURST.name, ...(s.mentionsAccounts ? [SPRAY.name] : [])];

// 패턴 조건을 모두 채운 경보만 명확한 공격으로 봅니다.
function matchPatterns(s) {
  const hits = [];
  if (!s.hasFailure || s.succeededAfter) return hits;
  if (s.failures >= BURST.match.minFailures && s.level >= BURST.match.minLevel) hits.push(BURST.name);
  if (s.accounts >= SPRAY.match.minAccounts && s.level >= SPRAY.match.minLevel) hits.push(SPRAY.name);
  return hits;
}

async function askWithTimeout(askJev, summary) {
  let timer;
  try {
    const answer = await Promise.race([
      Promise.resolve(askJev(summary)),
      new Promise((resolve) => { timer = setTimeout(() => resolve(null), JEV_TIMEOUT_MS); }),
    ]);
    const value = typeof answer === 'number' ? answer : answer?.confidence;
    return Number.isFinite(value) && value >= 0 && value <= 1 ? value : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// askJev(summary) 는 0~1 확신도(또는 { confidence })를 돌려주는 함수입니다. 없으면 애매한 건 alert 입니다.
export function createDecide({ askJev } = {}) {
  return async function decide(alert) {
    const s = readSignals(alert);

    if (!s.hasFailure || s.level <= NORMAL_LEVEL) {
      return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 로그인 실패 신호가 없거나 수준이 낮음' };
    }

    const hits = matchPatterns(s);
    if (hits.length) {
      const confidence = hits.length > 1 ? 0.98 : 0.95;
      return { action: toAction(confidence), confidence, reason: `패턴 일치: ${hits.join(', ')}` };
    }

    // 애매한 경보: 실패 뒤 성공했으면 정상 사용자일 수 있어 Jev 가 높게 답해도 차단까지 올리지 않습니다.
    const answered = typeof askJev === 'function' ? await askWithTimeout(askJev, extractAlert(alert)) : null;
    if (answered === null) {
      return { action: 'alert', confidence: ALERT_AT, reason: `Jev 응답 없음, 일부만 일치: ${nearPatterns(s).join(', ')}` };
    }
    const confidence = s.succeededAfter ? Math.min(answered, BLOCK_AT - 0.01) : answered;
    return { action: toAction(confidence), confidence, reason: `Jev 확신도 ${answered}, 일부만 일치: ${nearPatterns(s).join(', ')}` };
  };
}

export const decide = createDecide();
