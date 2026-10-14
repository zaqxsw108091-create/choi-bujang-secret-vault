// 터미널 입력: 비밀번호·키는 hidden으로 받아 화면에 글자를 다시 찍지 않습니다. 붙여넣기도 한 번에 받습니다.
// 입력이 터미널이 아니면(파이프 등) 비밀번호를 받지 않고 거부합니다(값이 기록에 남지 않게).
export function ask(question, { hidden = false, input = process.stdin, output = process.stdout } = {}) {
  return new Promise((resolve, reject) => {
    if (!input.isTTY || typeof input.setRawMode !== 'function') {
      reject(new Error('이 명령은 터미널(PowerShell 창)에서 직접 실행해야 합니다.'));
      return;
    }
    output.write(question);
    let value = '';
    input.setRawMode(true);
    input.resume();
    input.setEncoding('utf8');
    const finish = (settle, arg) => {
      input.removeListener('data', onData);
      input.setRawMode(false);
      input.pause();
      output.write('\n');
      settle(arg);
    };
    const onData = (chunk) => {
      for (const ch of String(chunk)) {
        if (ch === '\r' || ch === '\n') { finish(resolve, value); return; }
        if (ch === '\u0003') { finish(reject, new Error('입력이 취소됐습니다.')); return; }
        if (ch === '\u007f' || ch === '\b') {
          if (value.length > 0) { value = value.slice(0, -1); if (!hidden) output.write('\b \b'); }
        } else if (ch >= ' ') {
          value += ch;
          if (!hidden) output.write(ch);
        }
      }
    };
    input.on('data', onData);
  });
}
