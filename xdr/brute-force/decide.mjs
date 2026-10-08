// 경보를 패턴과 맞춰 보고, 애매한 것만 Jev 에게 물어 block / alert / record 를 정합니다.
// 같은 주소(·같은 계정)의 로그인 실패는 짧은 시간(10분) 안에서 모아 기준을 넘는지 봅니다.
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
const WINDOW_MS = 10 * 60 * 1000;

const toAction = (confidence) => (confidence >= BLOCK_AT ? 'block' : confidence >= ALERT_AT ? 'alert' : 'record');

// 경보 묶음(읽기 전용). 순서에 상관없이 같은 결과가 나오도록 판단 때마다 묶음 전체를 봅니다.
async function loadHistory() {
  try {
    const fixture = JSON.parse(await readFile(join(HERE, '..', 'fixtures', 'brute-force.json'), 'utf8'));
    return Array.isArray(fixture?.alerts) ? fixture.alerts : [];
  } catch {
    return [];
  }
}
const DEFAULT_HISTORY = await loadHistory();

function readSignals(alert) {
  const description = String(alert?.rule?.description ?? '');
  const failures = Number(alert?.data?.count);
  const accountList = String(alert?.data?.accounts ?? '').split(',').map((a) => a.trim()).filter(Boolean);
  const named = Number(/계정\s*(\d+)\s*개/u.exec(description)?.[1] ?? 0);
  const wordsMany = /여러 계정|서로 다른 계정|계정 이름을 바꿔/u.test(description) ? SPRAY.match.minAccounts : 0;
  return {
    ip: String(alert?.data?.srcip ?? ''),
    user: String(alert?.data?.srcuser ?? ''),
    at: Date.parse(alert?.timestamp),
    level: Number.isFinite(alert?.rule?.level) ? alert.rule.level : 0,
    failures: Number.isFinite(failures) ? failures : 0,
    accountList,
    accounts: Math.max(accountList.length, named, wordsMany),
    hasFailure: /실패|같은 비밀번호/u.test(description),
    succeededAfter: /성공했/u.test(description),
    multiAccounts: /두 계정|세 계정|여러 계정|서로 다른 계정|계정 이름을 바꿔|계정\s*\d+\s*개/u.test(description) || accountList.length > 1,
  };
}

const inWindow = (a, b) => !Number.isFinite(a) || !Number.isFinite(b) || Math.abs(a - b) <= WINDOW_MS;

// 같은 주소의 실패 경보를 10분 안에서 모읍니다: 같은 계정의 실패 건수 합, 건드린 계정 수.
function gather(own, history) {
  if (!own.ip || !own.hasFailure || own.succeededAfter) return { failures: own.failures, accounts: own.accounts };
  const near = history.map(readSignals)
    .filter((h) => h.ip === own.ip && h.hasFailure && !h.succeededAfter && inWindow(h.at, own.at));
  const sameUser = near.filter((h) => h.user === own.user).reduce((sum, h) => sum + h.failures, 0);
  const users = new Set(near.flatMap((h) => [h.user, ...h.accountList]).filter(Boolean));
  return {
    failures: Math.max(own.failures, sameUser),
    accounts: Math.max(own.accounts, users.size, ...near.map((h) => h.accounts)),
  };
}

// 패턴 조건을 모두 채운 경보만 명확한 공격으로 봅니다.
function matchPatterns(s, g) {
  const hits = [];
  if (!s.hasFailure || s.succeededAfter) return hits;
  if (g.failures >= BURST.match.minFailures && s.level >= BURST.match.minLevel) hits.push(BURST.name);
  if (g.accounts >= SPRAY.match.minAccounts && s.level >= SPRAY.match.minLevel) hits.push(SPRAY.name);
  return hits;
}

// 애매한 경보가 어느 패턴과 일부 닮았는지 이름만 모읍니다(reason 에 근거 패턴 이름을 적기 위함).
const nearPatterns = (s) => [BURST.name, ...(s.multiAccounts ? [SPRAY.name] : [])];

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
// history 는 함께 모아 볼 경보 목록입니다(기본: xdr/fixtures/brute-force.json).
export function createDecide({ askJev, history = DEFAULT_HISTORY } = {}) {
  return async function decide(alert) {
    const s = readSignals(alert);
    const g = gather(s, history);
    const summed = g.failures > s.failures ? ` · 같은 주소·계정 합산 ${g.failures}건` : '';

    if (!s.hasFailure || (s.level <= NORMAL_LEVEL && g.failures < BURST.match.minFailures)) {
      return { action: 'record', confidence: 0.05, reason: '정상 이벤트: 로그인 실패 신호가 없거나 수준이 낮음' };
    }

    const hits = matchPatterns(s, g);
    if (hits.length) {
      const confidence = hits.length > 1 ? 0.98 : 0.95;
      return { action: toAction(confidence), confidence, reason: `패턴 일치: ${hits.join(', ')}${summed}` };
    }

    // 애매한 경보: 실패 뒤 성공했으면 정상 사용자일 수 있어 Jev 가 높게 답해도 차단까지 올리지 않습니다.
    const answered = typeof askJev === 'function' ? await askWithTimeout(askJev, extractAlert(alert)) : null;
    if (answered === null) {
      return { action: 'alert', confidence: ALERT_AT, reason: `Jev 응답 없음, 일부만 일치: ${nearPatterns(s).join(', ')}${summed}` };
    }
    const confidence = s.succeededAfter ? Math.min(answered, BLOCK_AT - 0.01) : answered;
    return { action: toAction(confidence), confidence, reason: `Jev 확신도 ${answered}, 일부만 일치: ${nearPatterns(s).join(', ')}${summed}` };
  };
}

export const decide = createDecide();
