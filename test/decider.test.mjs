import assert from 'node:assert/strict';
import test from 'node:test';
import { decide, RULE_IDS } from '../src/decider.mjs';
import { fixtureRequests } from '../scripts/fixture-7.mjs';

const KEYS = 'decision,reasonCode,requestId,ruleIds,schema';
const shape = (request, out) => {
  assert.equal(Object.keys(out).sort().join(','), KEYS);
  assert.equal(out.schema, 'aleph.decision.v1');
  assert.equal(out.requestId, request.requestId);
  assert.ok(out.ruleIds.length > 0 && out.ruleIds.every(id => RULE_IDS.includes(id)));
};

test('RULE_IDS names exactly the implemented rules', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required', 'note_zone_self', 'notice_zone_staff_only', 'route_unknown']);
});

test('a registered device is allowed', async () => {
  const { normal } = fixtureRequests();
  const out = await decide(normal);
  shape(normal, out);
  assert.equal(out.decision, 'allow');
});

test('an unregistered device or a missing value is denied with device_not_registered', async () => {
  const { normal } = fixtureRequests();
  for (const deviceRegistered of [false, undefined, null, 1, 'true']) {
    const request = { ...normal, deviceRegistered };
    const out = await decide(request);
    shape(request, out);
    assert.equal(out.decision, 'deny');
    assert.equal(out.reasonCode, 'device_not_registered');
  }
});

test('the rule reads only deviceRegistered, not role, identity or device fields', async () => {
  const { normal } = fixtureRequests();
  const request = { ...normal, deviceRegistered: false, role: 'teacher', identity: 'x', device: { approved: true } };
  assert.equal((await decide(request)).decision, 'deny');
});

test('readSignals keeps the source and never fills a missing value with a normal one', async () => {
  const { readSignals } = await import('../src/decider.mjs');
  const { normal } = fixtureRequests();
  assert.deepEqual(readSignals(normal), { trust: 'fixture', region: 'local', network: 'usual', hour: 14 });
  const none = { trust: 'none', region: null, network: null, hour: null };
  assert.deepEqual(readSignals({ signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 0 } }), none);
  for (const bad of [undefined, null, 'x', []]) assert.deepEqual(readSignals({ signals: bad }), none);
  assert.equal(readSignals({ signals: {} }).trust, 'unverified');
  assert.deepEqual(readSignals(undefined), none);
  const partial = readSignals({ signals: { source: 'judge_fixture', region: 'unknown', hour: 24 } });
  assert.deepEqual(partial, { trust: 'fixture', region: null, network: null, hour: null });
});

test('forged client headers or unknown sources are not promoted to trusted signals', async () => {
  const { readSignals } = await import('../src/decider.mjs');
  const { normal } = fixtureRequests();
  const forged = { ...normal, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 14 },
    headers: { 'x-forwarded-for': '1.2.3.4', 'x-region': 'local' }, region: 'local', network: 'usual' };
  assert.equal(readSignals(forged).trust, 'none');
  assert.equal(readSignals(forged).region, null);
  for (const source of ['client', 'header', 'browser', 'JUDGE_FIXTURE', undefined, 1]) {
    const out = readSignals({ signals: { source, region: 'local', network: 'usual', hour: 14 } });
    assert.deepEqual(out, { trust: 'unverified', region: null, network: null, hour: null });
  }
});

test('step_up_required: the fixed compound event gets step_up, the normal one allow', async () => {
  const { normal, suspicious } = fixtureRequests();
  assert.ok(RULE_IDS.includes('device_registered') && RULE_IDS.includes('step_up_required'));
  const out = await decide(suspicious);
  shape(suspicious, out);
  assert.equal(out.decision, 'step_up');
  assert.equal(out.reasonCode, 'step_up_required');
  assert.deepEqual(out.ruleIds, ['step_up_required']);
  const ok = await decide(normal);
  assert.equal(ok.decision, 'allow');
});

test('step_up_required: after a fresh step-up the same event is allowed, a stale or bad one is not', async () => {
  const { suspicious } = fixtureRequests();
  for (const [stepUp, want] of [[{ verified: true, authAgeSeconds: 60 }, 'allow'],
    [{ verified: true, authAgeSeconds: 900 }, 'allow'], [{ verified: true, authAgeSeconds: 901 }, 'step_up'],
    [{ verified: true, authAgeSeconds: null }, 'step_up'], [{ verified: 'true', authAgeSeconds: 1 }, 'step_up'],
    [undefined, 'step_up']]) {
    assert.equal((await decide({ ...suspicious, stepUp })).decision, want);
  }
});

test('step_up_required: one signal alone never triggers it, and it never denies', async () => {
  const { suspicious } = fixtureRequests();
  const s = suspicious.signals;
  const cases = [
    { ...suspicious, signals: { ...s, hour: 14 } },                    // 낮 시각
    { ...suspicious, signals: { ...s, network: 'usual' } },            // 익숙한 네트워크
    { ...suspicious, signals: { ...s, region: 'local' } },             // 지역만 바꿔도 결과 같음(아래 별도)
    { ...suspicious, recentEvents: [] },                               // 읽기 급증 없음
    { ...suspicious, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 19 }] },
    { ...suspicious, recentEvents: [{ kind: 'other', ageSeconds: 60, count: 50 }] },
    { ...suspicious, signals: { source: 'none', region: 'unknown', network: 'unknown', hour: 3 } },
    { ...suspicious, signals: { ...s, source: 'client' } },
    { ...suspicious, signals: { ...s, hour: 3.5 } },
  ];
  for (const request of cases.slice(0, 2).concat(cases.slice(3))) {
    const out = await decide(request);
    shape(request, out);
    assert.equal(out.decision, 'allow');
  }
  const onlyRegion = await decide({ ...suspicious, signals: { ...s, region: 'local' } });
  assert.equal(onlyRegion.decision, 'step_up');                          // 지역은 조건이 아니라서 같은 결과
  const foreignOnly = await decide({ ...fixtureRequests().normal, signals: { ...fixtureRequests().normal.signals, region: 'foreign' } });
  assert.equal(foreignOnly.decision, 'allow');                           // 지역만 낯설다고 막지 않음
});

test('step_up_required: the device rule still comes first', async () => {
  const { suspicious } = fixtureRequests();
  const out = await decide({ ...suspicious, deviceRegistered: false });
  assert.equal(out.decision, 'deny');
  assert.equal(out.reasonCode, 'device_not_registered');
});

test('re-login sequence (virtual events only): blocked before, new request allowed after, nothing echoed', async () => {
  const { suspicious } = fixtureRequests();
  const before = await decide(suspicious);
  assert.equal(before.decision, 'step_up');
  // 새 로그인 뒤의 요청은 새 requestId·새 stepUp 값으로 도착하고, 이전 판정에 기대지 않고 다시 판정됩니다.
  const after = { ...suspicious, requestId: '11111111-1111-4111-8111-111111111111',
    stepUp: { verified: true, authAgeSeconds: 5 }, token: 'TOKEN_SHOULD_NOT_APPEAR' };
  const out = await decide(after);
  shape(after, out);
  assert.equal(out.decision, 'allow');
  assert.equal(JSON.stringify(out).includes('TOKEN_SHOULD_NOT_APPEAR'), false);
  // 같은 새 로그인 값이어도 이전 요청은 그대로 추가 확인입니다(판정은 요청마다 따로).
  assert.equal((await decide(suspicious)).decision, 'step_up');
});

// ---- 8단계 제작 2: 구역 규칙 ----
const ID = '55555555-5555-4555-8555-555555555555';
const zoneRequest = (method, route, path, extra = {}) => ({ ...fixtureRequests().normal, requestId: crypto.randomUUID(), method, route, path, ...extra });

test('step 8: own-note read, edit, list, add and delete stay allowed (also with the /api prefix)', async () => {
  for (const [m, r, p] of [['GET', 'GET /notes/:id', `/notes/${ID}`], ['PUT', 'PUT /notes/:id', `/notes/${ID}`],
    ['DELETE', 'DELETE /notes/:id', `/notes/${ID}`], ['GET', 'GET /notes', '/notes'], ['POST', 'POST /notes', '/notes'],
    ['PUT', 'PUT /api/notes/:id', `/api/notes/${ID}`]]) {
    const req = zoneRequest(m, r, p);
    const out = await decide(req);
    shape(req, out);
    assert.equal(out.decision, 'allow', `${m} ${p}`);
    assert.deepEqual(out.ruleIds, ['note_zone_self']);
  }
});

test('step 8: a notice edit by an ordinary student is denied, and a request-borne role cannot change it', async () => {
  const req = zoneRequest('PUT', 'PUT /notices/:id', '/notices/week-1', { role: 'instructor', identity: 'teacher' });
  const out = await decide(req);
  shape(req, out);
  assert.equal(out.decision, 'deny');
  assert.deepEqual(out.ruleIds, ['notice_zone_staff_only']);
});

test('step 8: unknown routes, mismatched route/path/method, feature paths beside :id and bad ids are denied', async () => {
  const cases = [
    ['GET', 'GET /notes/:id', '/notes/export'], ['GET', 'GET /notes/:id', '/notes/not-a-uuid'],
    ['GET', 'GET /notes/:id', `/notes/${ID}/export`], ['GET', 'GET /notes/:id', `/notes/${ID}?x=1`],
    ['GET', 'GET /notes/:id', '/notes'], ['GET', 'GET /notes', `/notes/${ID}`],
    ['POST', 'GET /notes/:id', `/notes/${ID}`], ['GET', 'GET /notices/:id', '/notices/week-1'],
    ['GET', 'GET /notices', '/notices'], ['PUT', 'PUT /notes/:id', '/notices/week-1'],
    ['GET', 'GET /other', '/other'], ['GET', undefined, `/notes/${ID}`], [undefined, 'GET /notes', '/notes'],
  ];
  for (const [m, r, p] of cases) {
    const req = zoneRequest(m, r, p);
    const out = await decide(req);
    shape(req, out);
    assert.equal(out.decision, 'deny', `${m} ${r} ${p}`);
  }
});

test('step 8: the query never picks the feature or the resource, and a missing user or bad device is denied', async () => {
  const base = zoneRequest('GET', 'GET /notes/:id', `/notes/${ID}`);
  const withQuery = { ...base, queryLength: 40, querySha256: 'b'.repeat(64) };
  assert.equal((await decide(withQuery)).decision, (await decide(base)).decision);
  for (const bad of [{ subjectId: '' }, { subjectId: undefined }, { deviceId: 'xyz' }, { deviceId: undefined }]) {
    assert.equal((await decide({ ...base, ...bad })).decision, 'deny');
  }
  assert.equal((await decide({ ...base, deviceRegistered: false })).reasonCode, 'device_not_registered');
});

test('step 8: the step-up rule still applies to a known route', async () => {
  const { suspicious } = fixtureRequests();
  assert.equal((await decide(suspicious)).decision, 'step_up');
});
