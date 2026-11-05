// 마지막 총공세: on-client/student/extension.mjs 의 학생 구현(내 PC 기록·추이·위험 알림) 시험.
// 제공 "내 PC 상태"가 읽은 값을 판정·비교·알림으로 바꾸는 계산 부분과 꾸밈 파일을 시험한다.
// 화면(DOM)은 이 시험에 없다. 브라우저에서 직접 열어 확인한 방법은 docs/FINAL_ASSAULT.md 에 적었다.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import {
  PC_GRADED, PC_LIMITS, compareReadings, computeAlerts, createStudentView, judgePcStatus, sanitizeHistory, summarizePc,
} from '../on-client/student/extension.mjs';
import { parseStudentAppearance, appearanceView } from '../on-client/src/student-appearance.mjs';

const GB = 1073741824;
const metrics = (over = {}) => ({
  cpu: { state: 'ok', usagePercent: 20, sampleMs: 200 },
  memory: { state: 'ok', usedBytes: 8 * GB, totalBytes: 16 * GB },
  network: { state: 'ok', interfaceCount: 2, ipv4Count: 2 },
  disk: { state: 'ok', totalBytes: 500 * GB, freeBytes: 200 * GB },
  firewall: { state: 'ok', profiles: [{ name: 'Domain', enabled: true }, { name: 'Private', enabled: true }, { name: 'Public', enabled: true }] },
  events: { state: 'ok', warningCount: 5, errorCount: 2, truncated: false, sampleLimit: 5000, since: '2026-11-05T00:00:00.000Z' },
  ...over,
});
const judge = (over) => Object.fromEntries(judgePcStatus({ metrics: metrics(over) }).map((i) => [i.id, i]));

test('판정: 모두 정상이면 핵심 4개는 정상, 네트워크·이벤트는 참고', () => {
  const j = judge();
  for (const id of PC_GRADED) assert.equal(j[id].status, 'ok', id);
  assert.equal(j.network.status, 'info');
  assert.equal(j.events.status, 'info');
  assert.match(j.events.text, /침해·공격 탐지 결과 아님/);
  assert.equal(Object.keys(j).length, 6);
});

test('판정: 경계값에서 정상과 주의가 갈린다', () => {
  assert.equal(judge({ cpu: { state: 'ok', usagePercent: PC_LIMITS.cpuWarn - 0.1 } }).cpu.status, 'ok');
  assert.equal(judge({ cpu: { state: 'ok', usagePercent: PC_LIMITS.cpuWarn } }).cpu.status, 'warn');
  assert.equal(judge({ memory: { state: 'ok', usedBytes: 79 * GB, totalBytes: 100 * GB } }).memory.status, 'ok');
  assert.equal(judge({ memory: { state: 'ok', usedBytes: 80 * GB, totalBytes: 100 * GB } }).memory.status, 'warn');
  assert.equal(judge({ disk: { state: 'ok', totalBytes: 100 * GB, freeBytes: 15.1 * GB } }).disk.status, 'ok');
  assert.equal(judge({ disk: { state: 'ok', totalBytes: 100 * GB, freeBytes: 15 * GB } }).disk.status, 'warn');
});

test('판정: 방화벽은 하나라도 꺼지면 주의, 네트워크 구성 0개도 주의', () => {
  const profiles = (a, b, c) => ({ state: 'ok', profiles: [{ name: 'Domain', enabled: a }, { name: 'Private', enabled: b }, { name: 'Public', enabled: c }] });
  assert.equal(judge({ firewall: profiles(true, true, true) }).firewall.status, 'ok');
  const some = judge({ firewall: profiles(true, true, false) }).firewall;
  assert.equal(some.status, 'warn');
  assert.match(some.text, /일부 꺼짐 \(Public\)/);
  assert.equal(judge({ firewall: profiles(false, false, false) }).firewall.text, '꺼짐');
  assert.equal(judge({ network: { state: 'ok', interfaceCount: 0, ipv4Count: 0 } }).network.status, 'warn');
});

test('판정: 읽지 못하면 정상이나 0으로 바꾸지 않고 확인 불가와 이유를 쓴다', () => {
  const j = judge({
    cpu: { state: 'unavailable', reason: 'timeout' },
    firewall: { state: 'unavailable', reason: 'permission_denied' },
    events: { state: 'unavailable', reason: 'unsupported' },
    disk: { state: 'unavailable', reason: 'something_new' },
  });
  assert.equal(j.cpu.status, 'unknown');
  assert.equal(j.cpu.value, null);
  assert.equal(j.cpu.text, '확인 불가');
  assert.match(j.cpu.reason, /시간이 초과/);
  assert.equal(j.firewall.text, '확인 불가 · 권한 없음');
  assert.match(j.events.reason, /운영체제/);
  assert.match(j.disk.reason, /응답 형식/, '모르는 이유 코드는 응답 형식 문제로 처리');
});

test('판정: 이상한 응답 모양은 모두 확인 불가', () => {
  for (const data of [undefined, null, 'x', {}, { metrics: null }, { metrics: [] }]) {
    const items = judgePcStatus(data);
    assert.equal(items.length, 6);
    assert.ok(items.every((i) => i.status === 'unknown'), JSON.stringify(data));
  }
  const j = judge({
    cpu: { state: 'ok', usagePercent: -5 },
    memory: { state: 'ok', usedBytes: 20 * GB, totalBytes: 16 * GB },
    disk: { state: 'ok', totalBytes: 0, freeBytes: 0 },
    firewall: { state: 'ok', profiles: [{ name: 'Domain', enabled: 'yes' }] },
    network: { state: 'ok', interfaceCount: 'many', ipv4Count: 1 },
    events: { state: 'ok', warningCount: -1, errorCount: 0 },
  });
  assert.ok(Object.values(j).every((i) => i.status === 'unknown'));
  assert.equal(judge({ cpu: { state: 'ok', usagePercent: Number.NaN } }).cpu.status, 'unknown');
  assert.equal(judge({ cpu: { state: 'ok', usagePercent: Infinity } }).cpu.status, 'unknown');
  assert.equal(judge({ cpu: { state: 'ok', usagePercent: 101 } }).cpu.status, 'unknown');
});

test('요약: 핵심 4개 기준으로만 센다 (참고 항목은 정상으로 세지 않음)', () => {
  const s = summarizePc(judgePcStatus({ metrics: metrics({ cpu: { state: 'ok', usagePercent: 90 } }) }));
  assert.equal(s.gradedTotal, 4);
  assert.equal(s.ok, 3);
  assert.equal(s.warn, 1);
  assert.match(s.text, /핵심 4개\(CPU·메모리·디스크·방화벽\) 중 3개 정상/);
  const u = summarizePc(judgePcStatus({ metrics: {} }));
  assert.equal(u.ok, 0);
  assert.equal(u.unknown, 6);
});

const entry = (at, items) => ({ at, items: Object.entries(items).map(([id, [status, value]]) => ({ id, label: id, status, text: `${id}-${status}`, value: value ?? null, reason: '' })) });

test('위험 알림: 주의 시작·해소를 찾고, 확인 불가는 상태 변화로 보지 않는다', () => {
  const a = computeAlerts([
    entry('t1', { cpu: ['ok', 10], memory: ['ok', 10] }),
    entry('t2', { cpu: ['warn', 90], memory: ['ok', 10] }),
    entry('t3', { cpu: ['unknown'], memory: ['ok', 10] }),
    entry('t4', { cpu: ['warn', 91], memory: ['warn', 85] }),
    entry('t5', { cpu: ['ok', 10], memory: ['warn', 86] }),
  ]);
  assert.deepEqual(a.current.map((c) => c.id), ['memory']);
  assert.equal(a.current[0].since, 't4');
  assert.deepEqual(a.events.map((e) => `${e.at}:${e.id}:${e.kind}`), ['t5:cpu:resolved', 't4:memory:start', 't2:cpu:start']);
  assert.equal(a.checkedAt, 't5');
});

test('위험 알림: 네트워크 구성이 돌아오면 해소, 이벤트 참고값은 알림이 아님', () => {
  const a = computeAlerts([
    entry('t1', { network: ['warn'], events: ['info', 500] }),
    entry('t2', { network: ['info'], events: ['info', 900] }),
  ]);
  assert.deepEqual(a.current, []);
  assert.deepEqual(a.events.map((e) => `${e.id}:${e.kind}`), ['network:resolved', 'network:start']);
  assert.deepEqual(computeAlerts([]), { current: [], events: [], checkedAt: null });
  assert.equal(computeAlerts([entry('a', { cpu: ['warn', 99] }), entry('b', { cpu: ['ok', 1] }), entry('c', { cpu: ['warn', 99] })], { maxEvents: 2 }).events.length, 2);
});

test('추이 비교: 같은 단위로 비교하고 한 줄 설명을 붙인다', () => {
  const rows = compareReadings(
    entry('t1', { cpu: ['ok', 32], memory: ['ok', 50], disk: ['ok', 40], events: ['info', 10] }),
    entry('t2', { cpu: ['warn', 45], memory: ['ok', 50], disk: ['warn', 12], events: ['info', 12] }),
  );
  const by = Object.fromEntries(rows.map((r) => [r.id, r]));
  assert.equal(by.cpu.text, 'CPU 사용률 32% → 45% (+13%p)');
  assert.equal(by.cpu.direction, 'up');
  assert.equal(by.memory.direction, 'same');
  assert.match(by.memory.text, /변화 없음/);
  assert.equal(by.disk.text, '디스크 남은 공간 40% → 12% (-28%p)');
  assert.match(by.disk.explain, /줄었어요/);
  assert.equal(by.events.text, 'Windows 경고·오류 10건 → 12건 (+2건)');
  assert.match(by.events.explain, /침해를 뜻하지 않아요/);
  assert.ok(rows.every((r) => r.comparable));
});

test('추이 비교: 한쪽을 읽지 못했으면 비교하지 않고 이유를 말한다', () => {
  const rows = compareReadings(entry('t1', { cpu: ['unknown'] }), entry('t2', { cpu: ['ok', 30] }));
  const cpu = rows.find((r) => r.id === 'cpu');
  assert.equal(cpu.comparable, false);
  assert.match(cpu.text, /비교할 수 없어요 \(이전 값을 읽지 못함\)/);
  assert.equal(compareReadings(undefined, undefined).every((r) => !r.comparable), true);
});

test('저장 기록 검사: 모양이 틀린 줄과 이상한 값은 버린다', () => {
  assert.deepEqual(sanitizeHistory('x'), []);
  assert.deepEqual(sanitizeHistory(null), []);
  const good = { at: '2026-11-05T01:02:03.000Z', items: [{ id: 'cpu', status: 'ok', text: 'a'.repeat(500), value: 12.5, reason: 'r'.repeat(500) }] };
  const out = sanitizeHistory([
    good,
    { at: 'x', items: [] },
    { at: good.at, items: [] },
    { at: good.at, items: [{ id: '<script>', status: 'ok' }, { id: 'cpu', status: 'hacked' }] },
    { at: good.at, items: [{ id: 'cpu', label: '<b>가짜</b>', status: 'ok', value: 'NaN' }] },
    42,
  ]);
  assert.equal(out.length, 2);
  assert.equal(out[0].items[0].text.length, 160);
  assert.equal(out[0].items[0].reason.length, 80);
  assert.equal(out[1].items[0].label, 'CPU', '이름은 저장값이 아니라 정해진 표에서만 가져옴');
  assert.equal(out[1].items[0].value, null);
  const many = Array.from({ length: 300 }, (_, i) => ({ at: new Date(Date.UTC(2026, 10, 5, 0, 0, i)).toISOString(), items: [{ id: 'cpu', status: 'ok', text: 't', value: i }] }));
  const kept = sanitizeHistory(many);
  assert.equal(kept.length, 200);
  assert.equal(kept[199].items[0].value, 299, '가장 최근 200번을 남김');
});

test('기존 학생 구현은 그대로: createStudentView는 같은 표시 함수를 모두 가진다', () => {
  const view = createStudentView();
  for (const name of ['renderIdentity', 'renderDecision', 'renderEvents', 'renderStatus', 'renderVulnerabilities', 'renderAiConnection', 'renderExplanation', 'renderAction']) {
    assert.equal(typeof view[name], 'function', name);
  }
});

test('안전: 학생 파일에 위험한 표현이 없다 (HTML 넣기·코드 실행·직접 요청)', () => {
  const source = fs.readFileSync(new URL('../on-client/student/extension.mjs', import.meta.url), 'utf8');
  for (const bad of [/\.innerHTML\b/, /\.outerHTML\b/, /insertAdjacentHTML/, /\beval\s*\(/, /new Function/, /\bfetch\s*\(/, /XMLHttpRequest/, /document\.write/, /sendBeacon/, /WebSocket/]) {
    assert.doesNotMatch(source, bad, String(bad));
  }
  assert.match(source, /const PC_PATH = '\/api\/pc\/status';/);
  // 이번에 추가한 부분만 검사한다(기존 22단계 코드의 비밀값 가리기 규칙 글자는 대상이 아님).
  const added = source.slice(source.indexOf('마지막 총공세 · 학생 구현'), source.indexOf('export function createStudentView'));
  assert.ok(added.length > 5000, '추가한 부분을 찾음');
  assert.doesNotMatch(added, /Authorization|api[-_ ]?key|token|secret|password/i);
  assert.equal([...added.matchAll(/api\.get\(([^)]*)\)/g)].every((m) => m[1] === 'PC_PATH'), true, '제공 조회 길 하나만 부른다');
});

test('꾸밈 파일: 제공 검증기를 보정 없이 통과한다', () => {
  const bytes = fs.readFileSync(new URL('../on-client/student/appearance.json', import.meta.url));
  const parsed = parseStudentAppearance(bytes);
  assert.equal(parsed.ok, true, JSON.stringify(parsed));
  const view = appearanceView({ state: 'valid', value: parsed.value });
  assert.equal(view.state, 'applied');
  assert.equal(view.appName, '내 PC 관제 · 케셰브');
  assert.equal(view.dashboardPreset, 'student-first');
  assert.deepEqual(view.corrected, [], '색이 자동으로 바뀌지 않음');
});
