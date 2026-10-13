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

test('device_registered is the only rule and is named in RULE_IDS', () => {
  assert.deepEqual([...RULE_IDS], ['device_registered']);
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
