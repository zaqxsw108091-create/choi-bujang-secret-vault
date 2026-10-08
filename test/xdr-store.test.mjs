import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createClient } from '@supabase/supabase-js';
import { createAuthApi } from '../src/auth-api.mjs';
import { createNotesApi } from '../src/notes-api.mjs';
import { BLOCK_TABLE, createRemoteBlockLookup, defaultBlockLookup, pushRules, pushRulesFromEnv } from '../src/xdr-store.mjs';

const NOW = Date.parse('2026-10-08T00:00:00Z');
const iso = (ms) => new Date(ms).toISOString();
const row = (srcip, expiresMs, extra = {}) => ({
  rule_id: 'xdr.wi.deny-ip', srcip, decision: 'deny', evidence_alert_id: 'wi-01', created_at: iso(NOW - 1000), expires_at: iso(expiresMs), ...extra,
});

// Supabase 클라이언트의 질의 모양(from/select/eq/gt/limit/abortSignal/upsert)만 흉내 내는 가짜 저장소입니다.
function fakeSupabase(rows, { mode = 'ok' } = {}) {
  const calls = [];
  const from = (table) => {
    const q = { table, filters: [], signal: null };
    const run = () => new Promise((resolve, reject) => {
      if (mode === 'throw') return reject(new Error('boom'));
      if (mode === 'error') return resolve({ data: null, error: { code: '42P01', message: 'secret-looking-text' } });
      if (mode === 'hang') {
        // 진행 중인 네트워크 요청처럼 이벤트 루프를 붙잡고 있다가, 시간 제한 신호가 오면 중단 오류로 끝냅니다.
        const hold = setTimeout(() => resolve({ data: [], error: null }), 10000);
        q.signal?.addEventListener('abort', () => { clearTimeout(hold); resolve({ data: null, error: { code: 'ABORT' } }); });
        return undefined;
      }
      let data = rows.filter((r) => q.filters.every(([op, key, value]) => (op === 'eq' ? r[key] === value : Date.parse(r[key]) > Date.parse(value))));
      if (q.limit) data = data.slice(0, q.limit);
      return resolve({ data, error: null });
    });
    const b = {
      select(cols) { q.cols = cols; return b; },
      eq(key, value) { q.filters.push(['eq', key, value]); return b; },
      gt(key, value) { q.filters.push(['gt', key, value]); return b; },
      limit(n) { q.limit = n; return b; },
      abortSignal(signal) { q.signal = signal; return b; },
      upsert(list, opts) { q.upsert = list; q.opts = opts; calls.push(q); return Promise.resolve(mode === 'error' ? { error: { code: '42P01' } } : { error: null }); },
      then(resolve, reject) { calls.push(q); return run().then(resolve, reject); },
    };
    return b;
  };
  return { from, calls };
}

const lookupWith = (rows, opts = {}, fakeOpts = {}) => {
  const fake = fakeSupabase(rows, fakeOpts);
  return { fake, lookup: createRemoteBlockLookup({ getSupabase: () => fake, enabled: () => true, ...opts }) };
};

test('공유 저장소: 만료 전 거부 규칙이 있는 주소만 찾고, 만료됐거나 다른 주소는 못 찾는다', async () => {
  const rows = [row('203.0.113.10', NOW + 3600000), row('203.0.113.11', NOW - 1000), row('203.0.113.12', NOW + 3600000, { decision: 'allow' })];
  const { lookup, fake } = lookupWith(rows);
  const found = await lookup('203.0.113.10', NOW);
  assert.deepEqual(found, { ruleId: 'xdr.wi.deny-ip', decision: 'deny', srcip: '203.0.113.10', evidenceAlertId: 'wi-01', expiresAt: iso(NOW + 3600000) });
  assert.equal(await lookup('203.0.113.11', NOW), null); // 만료
  assert.equal(await lookup('203.0.113.12', NOW), null); // deny 가 아님
  assert.equal(await lookup('198.51.100.1', NOW), null); // 규칙 없음
  const q = fake.calls[0];
  assert.equal(q.table, BLOCK_TABLE);
  assert.deepEqual(q.filters, [['eq', 'srcip', '203.0.113.10'], ['eq', 'decision', 'deny'], ['gt', 'expires_at', iso(NOW)]]);
  assert.equal(q.limit, 1);
});

test('공유 저장소: 꺼져 있으면 저장소를 부르지 않는다(기본은 꺼짐)', async () => {
  const fake = fakeSupabase([row('203.0.113.10', NOW + 3600000)]);
  const off = createRemoteBlockLookup({ getSupabase: () => fake, enabled: () => false });
  assert.equal(await off('203.0.113.10', NOW), null);
  assert.equal(fake.calls.length, 0);
  const saved = process.env.XDR_BLOCK_STORE;
  delete process.env.XDR_BLOCK_STORE;
  try {
    assert.equal(await defaultBlockLookup('203.0.113.10', NOW), null); // 환경변수·네트워크 없이 바로 null
  } finally {
    if (saved !== undefined) process.env.XDR_BLOCK_STORE = saved;
  }
});

test('공유 저장소: 주소 모양이 아닌 값은 저장소에 보내지 않는다', async () => {
  const { lookup, fake } = lookupWith([row('203.0.113.10', NOW + 3600000)]);
  for (const bad of [undefined, null, 0, '', ' ', "1.2.3.4' or 1=1", '203.0.113.10,1.1.1.1', 'a'.repeat(100), '1.2.3.4\n', { toString() { return '203.0.113.10'; } }]) {
    assert.equal(await lookup(bad, NOW), null);
  }
  assert.equal(fake.calls.length, 0);
});

test('공유 저장소: 저장소가 오류·예외·응답 없음이면 막지 않고 통과시킨다(오류를 던지지 않음)', async () => {
  const rows = [row('203.0.113.10', NOW + 3600000)];
  for (const mode of ['error', 'throw']) {
    const { lookup } = lookupWith(rows, {}, { mode });
    assert.equal(await lookup('203.0.113.10', NOW), null, mode);
  }
  const { lookup: hang } = lookupWith(rows, { timeoutMs: 30 }, { mode: 'hang' });
  const started = Date.now();
  assert.equal(await hang('203.0.113.10', NOW), null);
  assert.ok(Date.now() - started < 1500);
  const thrower = createRemoteBlockLookup({ getSupabase: () => { throw new Error('missing_env'); }, enabled: () => true });
  assert.equal(await thrower('203.0.113.10', NOW), null);
  const enabledThrows = createRemoteBlockLookup({ getSupabase: () => null, enabled: () => { throw new Error('x'); } });
  assert.equal(await enabledThrows('203.0.113.10', NOW), null);
  // 오류 응답은 기억하지 않아서, 저장소가 살아나면 바로 막기 시작한다.
  const flaky = { fail: true };
  const supabase = { from: (...a) => (flaky.fail ? fakeSupabase(rows, { mode: 'error' }) : fakeSupabase(rows)).from(...a) };
  const lookup = createRemoteBlockLookup({ getSupabase: () => supabase, enabled: () => true });
  assert.equal(await lookup('203.0.113.10', NOW), null);
  flaky.fail = false;
  assert.equal((await lookup('203.0.113.10', NOW + 1))?.srcip, '203.0.113.10');
});

test('공유 저장소: 주소별로 30초만 기억하고, 만료 시각이 지난 규칙은 기억하지 않는다', async () => {
  const rows = [row('203.0.113.10', NOW + 3600000)];
  const { lookup, fake } = lookupWith(rows);
  await lookup('203.0.113.10', NOW);
  await lookup('203.0.113.10', NOW + 29000);
  assert.equal(fake.calls.length, 1); // 30초 안에는 저장소를 다시 부르지 않음
  await lookup('203.0.113.10', NOW + 31000);
  assert.equal(fake.calls.length, 2); // 30초가 지나면 다시 물음
  // 없다는 답도 30초 기억 → 그 사이에 새로 올라온 규칙은 늦어도 30초 안에 적용
  assert.equal(await lookup('198.51.100.9', NOW), null);
  rows.push(row('198.51.100.9', NOW + 3600000));
  assert.equal(await lookup('198.51.100.9', NOW + 10000), null);
  assert.equal((await lookup('198.51.100.9', NOW + 31000))?.srcip, '198.51.100.9');
  // 곧 만료될 규칙은 만료 시각까지만 기억
  const soon = lookupWith([row('192.0.2.5', NOW + 5000)]);
  assert.ok(await soon.lookup('192.0.2.5', NOW));
  assert.equal(await soon.lookup('192.0.2.5', NOW + 6000), null);
});

test('공유 저장소: 기억 칸은 500개를 넘지 않는다', async () => {
  const { lookup, fake } = lookupWith([]);
  for (let i = 0; i < 520; i += 1) await lookup(`10.0.${Math.floor(i / 250)}.${i % 250}`, NOW);
  const before = fake.calls.length;
  await lookup('10.0.0.0', NOW); // 가장 오래된 칸은 밀려나서 다시 묻는다
  assert.equal(fake.calls.length, before + 1);
  await lookup('10.0.2.19', NOW); // 가장 최근 칸은 남아 있어 다시 묻지 않는다
  assert.equal(fake.calls.length, before + 1);
});

test('규칙 올리기: 칸 이름이 표와 같고, 같은 규칙·주소는 덮어쓰며, 오류에는 코드만 있다', async () => {
  const rules = [{ ruleId: 'xdr.wi.deny-ip', decision: 'deny', srcip: '203.0.113.10', evidenceAlertId: 'wi-01', createdAt: iso(NOW), expiresAt: iso(NOW + 3600000) }];
  const fake = fakeSupabase([]);
  assert.deepEqual(await pushRules(fake, rules), { pushed: 1 });
  assert.equal(fake.calls[0].table, BLOCK_TABLE);
  assert.deepEqual(fake.calls[0].opts, { onConflict: 'rule_id,srcip' });
  assert.deepEqual(fake.calls[0].upsert, [row('203.0.113.10', NOW + 3600000, { created_at: iso(NOW) })]);
  const none = fakeSupabase([]);
  assert.deepEqual(await pushRules(none, []), { pushed: 0 });
  assert.equal(none.calls.length, 0);
  await assert.rejects(pushRules(fakeSupabase([], { mode: 'error' }), rules), (error) => /42P01/u.test(error.message) && !/secret/u.test(error.message));
});

test('규칙 올리기: 환경변수가 없으면 값 없이 안내만 하고 멈춘다', async () => {
  const saved = { url: process.env.SUPABASE_URL, key: process.env.SUPABASE_SECRET_KEY };
  delete process.env.SUPABASE_URL;
  delete process.env.SUPABASE_SECRET_KEY;
  try {
    await assert.rejects(pushRulesFromEnv([{ ruleId: 'x' }]), /환경변수가 없습니다/u);
  } finally {
    if (saved.url !== undefined) process.env.SUPABASE_URL = saved.url;
    if (saved.key !== undefined) process.env.SUPABASE_SECRET_KEY = saved.key;
  }
});

test('표 SQL: 코드가 쓰는 표·칸 이름과 같고, anon·authenticated 권한을 닫고 RLS 를 켠다', async () => {
  const sql = await readFile(new URL('../sql/xdr-1-block-rules.sql', import.meta.url), 'utf8');
  const code = sql.split('\n').filter((l) => !l.trim().startsWith('--')).join('\n');
  assert.match(code, new RegExp(`create table if not exists public\\.${BLOCK_TABLE}\\b`, 'u'));
  for (const column of ['rule_id', 'srcip', 'decision', 'evidence_alert_id', 'created_at', 'expires_at']) {
    assert.match(code, new RegExp(`\\b${column}\\s+(?:text|timestamptz)`, 'u'), column);
  }
  assert.match(code, /primary key \(rule_id, srcip\)/u); // onConflict 'rule_id,srcip' 와 같다
  assert.match(code, /alter table public\.xdr_block_rules enable row level security/u);
  assert.match(code, /revoke all on table public\.xdr_block_rules from public, anon, authenticated/u);
  assert.match(code, /grant select, insert, update, delete on table public\.xdr_block_rules to service_role/u);
  assert.doesNotMatch(code, /create policy|grant [^;]*\b(?:anon|authenticated)\b/u);
  assert.doesNotMatch(code, /drop table|delete from/u); // 지우는 문장은 주석(실행 안 됨)으로만 있다
  assert.doesNotMatch(sql, /eyJ[A-Za-z0-9_-]{10,}|sb_secret_|password\s*=/iu);
  assert.doesNotMatch(code, /\bnotes\b/u); // notes 표는 건드리지 않는다
});

const callAuth = (api, ip) => api.login({ method: 'POST', headers: { 'x-forwarded-for': ip }, body: { email: 'a@b.co', password: 'pw' } }, {
  setHeader() {},
  status(code) { return { json: (body) => ({ code, body }) }; },
});
const callNotes = async (api, ip) => {
  let out;
  await api.collection({ method: 'GET', headers: { 'x-forwarded-for': ip } }, {
    setHeader() {},
    status(code) { return { json: (body) => { out = { code, body }; } }; },
  });
  return out;
};

test('배포 서버 흉내: 규칙 파일이 없어도 공유 저장소에 규칙이 있는 주소는 로그인·자료 API 에서 403, 나머지는 기존대로', async () => {
  const { lookup } = lookupWith([row('203.0.113.10', NOW + 3600000)]);
  const upstream = { n: 0 };
  const auth = createAuthApi({
    getSettings: () => ({ url: 'https://example.invalid', secretKey: 'x' }),
    fetchImpl: async () => { upstream.n += 1; return { ok: false, status: 400, json: async () => ({ error_code: 'invalid_credentials' }) }; },
    getBlockRules: () => [], // 배포 서버처럼 규칙 파일 없음
    lookupBlock: lookup,
    now: () => NOW,
  });
  const notes = createNotesApi({ getVerifier: () => async () => null, getSupabase: () => ({}), getBlockRules: () => [], lookupBlock: lookup, now: () => NOW });
  const blockedLogin = await callAuth(auth, '203.0.113.10');
  assert.deepEqual([blockedLogin.code, blockedLogin.body], [403, { error: 'BLOCKED_BY_XDR' }]);
  assert.equal(upstream.n, 0); // 막힌 주소의 요청은 Supabase 로 보내지 않는다
  assert.equal((await callNotes(notes, '203.0.113.10')).code, 403);
  assert.equal((await callAuth(auth, '192.0.2.70')).code, 401); // 막히지 않고 기존 로그인 검사까지 간다
  assert.equal(upstream.n, 1);
  assert.equal((await callNotes(notes, '192.0.2.70')).code, 401); // 막히지 않고 기존 로그인 요구까지 간다
});

test('공유 저장소가 고장 나도 로그인·자료 API 는 기존대로 동작한다(정상 사용자를 막지 않음)', async () => {
  const { lookup } = lookupWith([row('203.0.113.10', NOW + 3600000)], {}, { mode: 'throw' });
  const auth = createAuthApi({
    getSettings: () => ({ url: 'https://example.invalid', secretKey: 'x' }),
    fetchImpl: async () => ({ ok: false, status: 400, json: async () => ({ error_code: 'invalid_credentials' }) }),
    getBlockRules: () => [], lookupBlock: lookup, now: () => NOW,
  });
  assert.equal((await callAuth(auth, '203.0.113.10')).code, 401);
  const notes = createNotesApi({ getVerifier: () => async () => null, getSupabase: () => ({}), getBlockRules: () => [], lookupBlock: lookup, now: () => NOW });
  assert.equal((await callNotes(notes, '203.0.113.10')).code, 401);
});

test('규칙 파일과 공유 저장소 중 한쪽에만 있어도 막고, 기본값(조회 함수 없음)은 아무도 막지 않는다', async () => {
  const fileRule = { ruleId: 'xdr.bf.deny-ip', decision: 'deny', srcip: '198.51.100.7', evidenceAlertId: 'bf-01', createdAt: iso(NOW), expiresAt: iso(NOW + 3600000) };
  const { lookup } = lookupWith([row('203.0.113.10', NOW + 3600000)]);
  const both = createNotesApi({ getVerifier: () => async () => null, getSupabase: () => ({}), getBlockRules: () => [fileRule], lookupBlock: lookup, now: () => NOW });
  assert.equal((await callNotes(both, '198.51.100.7')).code, 403); // 파일 규칙
  assert.equal((await callNotes(both, '203.0.113.10')).code, 403); // 공유 저장소 규칙
  const plain = createNotesApi({ getVerifier: () => async () => null, getSupabase: () => ({}), now: () => NOW });
  assert.equal((await callNotes(plain, '203.0.113.10')).code, 401);
});

test('실제 supabase-js 가 보내는 요청 모양: 조회 조건·인증 헤더·시간 제한, 올리기의 충돌 기준(가짜 fetch, 실제 접속 없음)', async () => {
  const seen = [];
  const fetchImpl = async (url, init = {}) => {
    seen.push({ url: new URL(String(url)), method: init.method ?? 'GET', headers: new Headers(init.headers), body: init.body ?? null, signal: Boolean(init.signal) });
    const body = seen.length === 1 ? [row('203.0.113.10', NOW + 3600000)] : [];
    return new Response(JSON.stringify(body), { status: 200, headers: { 'content-type': 'application/json' } });
  };
  const supabase = createClient('https://example.invalid', 'test-key-not-real', { auth: { persistSession: false }, global: { fetch: fetchImpl } });
  const lookup = createRemoteBlockLookup({ getSupabase: () => supabase, enabled: () => true });
  assert.equal((await lookup('203.0.113.10', NOW))?.evidenceAlertId, 'wi-01');
  const [read] = seen;
  assert.equal(read.method, 'GET');
  assert.equal(read.url.pathname, `/rest/v1/${BLOCK_TABLE}`);
  assert.equal(read.url.searchParams.get('srcip'), 'eq.203.0.113.10');
  assert.equal(read.url.searchParams.get('decision'), 'eq.deny');
  assert.equal(read.url.searchParams.get('expires_at'), `gt.${iso(NOW)}`);
  assert.equal(read.url.searchParams.get('limit'), '1');
  assert.ok(read.headers.has('apikey') && read.headers.has('authorization'));
  assert.equal(read.signal, true); // 시간 제한 신호가 실제 요청까지 간다
  const rules = [{ ruleId: 'xdr.wi.deny-ip', decision: 'deny', srcip: '203.0.113.10', evidenceAlertId: 'wi-01', createdAt: iso(NOW), expiresAt: iso(NOW + 3600000) }];
  await pushRules(supabase, rules);
  const write = seen[1];
  assert.equal(write.method, 'POST');
  assert.equal(write.url.searchParams.get('on_conflict'), 'rule_id,srcip');
  assert.match(write.headers.get('prefer'), /resolution=merge-duplicates/u);
  assert.deepEqual(JSON.parse(write.body), [row('203.0.113.10', NOW + 3600000, { created_at: iso(NOW) })]);
});
