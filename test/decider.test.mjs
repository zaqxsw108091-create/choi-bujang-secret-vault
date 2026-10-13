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
