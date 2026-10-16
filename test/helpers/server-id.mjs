// 시험용: 점검 코드는 배포된 서버가 붙이는 x-vercel-id 머리글이 있는 응답만 실제 응답으로 봅니다.
// 이 파일을 불러오면 가짜 fetch가 돌려주는 응답에 그 머리글을 자동으로 붙입니다(이미 있으면 그대로).
// 머리글이 없는 응답을 시험하려면 가짜 fetch에 __raw = true를 붙여 이 처리를 건너뜁니다.
const original = globalThis.fetch;
let current = original;
const withId = (fn) => {
  if (typeof fn !== 'function' || fn === original || fn.__raw) return fn;
  return async (...args) => {
    const response = await fn(...args);
    if (response.headers.get('x-vercel-id')) return response;
    const headers = new Headers(response.headers);
    headers.set('x-vercel-id', 'test::server-id');
    return new Response(await response.arrayBuffer(), { status: response.status, statusText: response.statusText, headers });
  };
};
Object.defineProperty(globalThis, 'fetch', { configurable: true, get: () => current, set: (fn) => { current = withId(fn); } });
