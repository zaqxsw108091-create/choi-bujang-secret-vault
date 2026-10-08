import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { test } from 'node:test';

const baseline = JSON.parse(await readFile(new URL('../package/baseline-functions.json', import.meta.url)));

// 학생이 2~5단계에서 만든 서버 함수입니다(시작 틀 기준표에는 없음). 함수가 늘거나 줄면 이 목록도 뜻을 갖고 함께 바꿉니다.
// 시험은 api/ 바로 아래 파일만 읽으므로 하위 폴더(api/notes/[id].js)는 세지 않습니다.
const STUDENT_FUNCTIONS = ['api/login.js', 'api/notes.js', 'api/refresh.js'];

test('패키징 함수 기준표는 시작 틀의 실제 API와 일치하고, 학생이 만든 함수 말고는 늘지 않았다', async () => {
  const actual = (await readdir(new URL('../api/', import.meta.url)))
    .filter(name => /\.(?:m?js|ts)$/u.test(name))
    .map(name => join('api', name).replaceAll('\\', '/')).sort();
  assert.equal(baseline.version, 1);
  assert.equal(baseline.starter, 'ChoiTimo/aleph-defense-starter');
  assert.deepEqual(baseline.functions, []);
  assert.deepEqual(baseline.allowedNew, ['api/ai.js', 'api/threat-intel.js']);
  assert.deepEqual(actual, [...baseline.functions, ...baseline.allowedNew, ...STUDENT_FUNCTIONS].sort());
});

test('미구현 서버 뼈대는 성공이나 로그인 통과로 가장하지 않는다', async () => {
  for (const name of ['ai', 'threat-intel']) {
    const { default: handler } = await import(`../api/${name}.js`);
    const headers = new Map();
    let status;
    let body;
    handler({}, {
      setHeader: (key, value) => headers.set(key.toLowerCase(), value),
      status: value => { status = value; return { json: value => { body = value; } }; },
    });
    assert.equal(status, 501);
    assert.equal(headers.get('cache-control'), 'no-store');
    assert.match(body.error, /NOT_IMPLEMENTED$/u);
  }
});

test('P7 시작 틀 안내는 실제 빌드 조건과 새 배포 시험에 맞는다', async () => {
  const readme = await readFile(new URL('../package/README.md', import.meta.url), 'utf8');
  const selfCheck = await readFile(new URL('../package/SELF-CHECK.md', import.meta.url), 'utf8');
  assert.match(readme, /새 Vercel 프로젝트/u);
  assert.match(readme, /Vercel이 제공하는 저장소·커밋·배포 URL 정보/u);
  assert.doesNotMatch(readme, /npm start/u);
  assert.match(selfCheck, /P7-3\.png/u);
});
