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

const reads = (n, { sub = 'a', gap = 2000, method = 'GET' } = {}) =>
  Array.from({ length: n }, (_, i) => ({
    at: new Date(Date.parse(at) + i * gap).toISOString(), method, identity: { sub } }));

test('burst_read: 120건은 관찰, 121건은 회수 제안', () => {
  assert.deepEqual(detect(reads(120)), { action: 'observe' });
  assert.deepEqual(detect(reads(121)), { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'a' });
});

test('burst_read: 다른 사용자 합산·10분 밖·GET 아닌 사건은 세지 않는다', () => {
  assert.deepEqual(detect([...reads(100), ...reads(100, { sub: 'b' })]), { action: 'observe' });
  assert.deepEqual(detect(reads(200, { gap: 7000 })), { action: 'observe' });
  assert.deepEqual(detect(reads(200, { method: 'POST' })), { action: 'observe' });
});

test('burst_read: 뒤섞인 순서도 구간으로 센다', () => {
  assert.equal(detect(reads(130).reverse()).action, 'propose_revocation');
});

test('회수 제안: 대상 하나와 이유 코드만 담고 입력은 바꾸지 않는다', () => {
  const input = [...reads(130, { sub: 'z_fixture' }), ...reads(130, { sub: 'b_fixture' })];
  const before = JSON.stringify(input);
  const result = detect(input);
  assert.deepEqual(result, { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'b_fixture' });
  assert.deepEqual(Object.keys(result).sort(), ['action', 'reasonCode', 'subject']);
  assert.equal(JSON.stringify(input), before);
});

test('정상 사건은 회수 제안 없이 observe만 돌려준다', () => {
  assert.deepEqual(detect(reads(30)), { action: 'observe' });
  assert.deepEqual(detect([]), { action: 'observe' });
});
