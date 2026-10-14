import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { ask } from '../src/prompt.mjs';

function terminal() {
  const input = new EventEmitter();
  Object.assign(input, { isTTY: true, raw: false, setRawMode(on) { this.raw = on; }, resume() {}, pause() {}, setEncoding() {} });
  const written = [];
  const output = { write: (text) => { written.push(text); return true; } };
  return { input, output, written };
}

test('hidden 입력은 화면에 글자를 다시 찍지 않고, Enter로 값을 돌려준다', async () => {
  const { input, output, written } = terminal();
  const promise = ask('비밀번호: ', { hidden: true, input, output });
  assert.equal(input.raw, true);
  input.emit('data', 'pw');
  input.emit('data', 'Secret1\r');
  assert.equal(await promise, 'pwSecret1');
  assert.equal(input.raw, false);
  assert.ok(!written.join('').includes('pw'), '입력한 글자가 출력에 없음');
  assert.equal(written[0], '비밀번호: ');
});

test('보이는 입력은 글자를 보여 주고, 백스페이스가 동작한다', async () => {
  const { input, output, written } = terminal();
  const promise = ask('이메일: ', { input, output });
  input.emit('data', 'abc');
  input.emit('data', '\u007f');
  input.emit('data', 'd\n');
  assert.equal(await promise, 'abd');
  assert.ok(written.join('').includes('abc'));
});

test('붙여넣기처럼 여러 글자와 Enter가 한 번에 와도 값만 받는다', async () => {
  const { input, output } = terminal();
  const promise = ask('키: ', { hidden: true, input, output });
  input.emit('data', 'sb_publishable_ABCDEFGH\r');
  assert.equal(await promise, 'sb_publishable_ABCDEFGH');
});

test('Ctrl+C는 취소로 끝나고 터미널 모드를 되돌린다', async () => {
  const { input, output } = terminal();
  const promise = ask('x: ', { hidden: true, input, output });
  input.emit('data', 'ab\u0003');
  await assert.rejects(promise, /취소/u);
  assert.equal(input.raw, false);
});

test('터미널이 아니면(파이프 등) 비밀번호를 받지 않고 거부한다', async () => {
  const input = new EventEmitter();
  await assert.rejects(ask('x: ', { hidden: true, input, output: { write() {} } }), /터미널/u);
});
