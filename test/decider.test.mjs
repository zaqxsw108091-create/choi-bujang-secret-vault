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

test('RULE_IDS names exactly the two implemented rules', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered', 'step_up_required']);
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
