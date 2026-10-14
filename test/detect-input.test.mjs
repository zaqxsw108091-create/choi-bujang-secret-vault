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
  assert.deepEqual(events.map(e => Object.keys(e).sort()), [['at', 'method', 'network', 'sub'], ['at', 'method', 'network', 'sub']]);
  assert.deepEqual(events.map(e => [e.method, e.sub]), [['GET', 'learner_fixture'], ['GET', 'suspect_fixture']]);
  assert.ok(!JSON.stringify(events).match(/token|content|"name"/));
  assert.deepEqual(events.map(e => e.network), [null, null]);
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

const withNet = (list, network) => list.map(event => ({ ...event, network }));
const history = (n, network) => withNet(reads(n, { gap: 1000 }).map(event => ({
  ...event, at: new Date(Date.parse(event.at) - 3600000).toISOString() })), network);

test('복합: 평소와 다른 네트워크에서 폭주할 때만 회수 제안', () => {
  const burstB = withNet(reads(130), 'net_b');
  assert.deepEqual(detect([...history(5, 'net_a'), ...burstB]),
    { action: 'propose_revocation', reasonCode: 'burst_read', subject: 'a' });
});

test('복합: 평소 네트워크의 폭주, 다른 네트워크의 소량 조회는 제안하지 않는다', () => {
  assert.deepEqual(detect([...history(5, 'net_a'), ...withNet(reads(200), 'net_a')]), { action: 'observe' });
  assert.deepEqual(detect([...history(5, 'net_a'), ...withNet(reads(30), 'net_b')]), { action: 'observe' });
  assert.deepEqual(detect([...history(5, 'net_a'), ...withNet(reads(120), 'net_b')]), { action: 'observe' });
});

test('network가 없거나 unknown이면 계약대로 폭주만으로 판단하고, 결과에 network를 담지 않는다', () => {
  assert.equal(detect(reads(130)).action, 'propose_revocation');
  assert.equal(detect(withNet(reads(130), 'unknown')).action, 'propose_revocation');
  const result = detect([...history(5, 'net_a'), ...withNet(reads(130), 'net_b')]);
  assert.deepEqual(Object.keys(result).sort(), ['action', 'reasonCode', 'subject']);
});
