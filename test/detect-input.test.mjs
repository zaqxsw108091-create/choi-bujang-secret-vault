import test from 'node:test';
import assert from 'node:assert/strict';
import { readEvents, detect } from '../src/detect.mjs';

const at = '2026-10-01T00:00:00.000Z';

test('정상 사건과 의심 사건에서 시각·요청 종류·가명 사용자만 읽는다', () => {
  const { events, skipped } = readEvents([
    { at, method: 'get', identity: { sub: 'learner_fixture' } },
    { at, method: 'GET', identity: { sub: 'suspect_fixture' }, token: 'x', content: 'y', name: 'z' },
  ]);
  assert.equal(skipped, 0);
  assert.deepEqual(events.map(e => Object.keys(e).sort()), [['at', 'method', 'sub'], ['at', 'method', 'sub']]);
  assert.deepEqual(events.map(e => [e.method, e.sub]), [['GET', 'learner_fixture'], ['GET', 'suspect_fixture']]);
  assert.ok(!JSON.stringify(events).match(/token|content|"name"/));
});

test('모양이 맞지 않는 사건은 건너뛰고 개수만 센다', () => {
  const { events, skipped } = readEvents([
    null, 'text', {}, { at: 'not-a-date', method: 'GET', identity: { sub: 'a' } },
    { at, method: 'GET' }, { at, method: 'GET', identity: { sub: '' } },
    { at, method: 'GET', identity: { sub: 'ok_fixture' } },
  ]);
  assert.equal(events.length, 1);
  assert.equal(skipped, 6);
});

test('배열이 아니면 invalid_detection_events 오류', () => {
  assert.throws(() => detect('x'), { message: 'invalid_detection_events' });
  assert.throws(() => readEvents(undefined), { message: 'invalid_detection_events' });
});

test('이번 단계에서는 판정이 그대로 observe', () => {
  assert.deepEqual(detect([{ at, method: 'GET', identity: { sub: 'a' } }]), { action: 'observe' });
});
