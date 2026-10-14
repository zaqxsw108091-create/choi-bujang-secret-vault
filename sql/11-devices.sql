-- 11단계 제작 2: 기기 승인 표(devices)입니다. 이 파일에는 이메일·키 값이 없습니다. <<자리표시자>>는 SQL Editor에서 실행할 때 화면에서만 바꾸고 저장·커밋하지 않습니다.
-- 학생이 검토한 뒤 [A] → [B] → [C] 순서로 "구역별로 따로" 실행하세요. 코딩 도구는 DB에 접속하지 않았습니다.
-- 서버 함수(api/device.js 등)만 서버 전용 키(service_role)로 읽고 씁니다. anon·authenticated에는 권한이 없습니다.
-- 저장되는 것은 공개키뿐입니다(개인키는 브라우저 메모리 밖으로 나가지 않습니다).

-- ============ [A] 표 만들기 (한 덩어리로 실행. 오류가 나면 전부 취소됨) ============
begin;

create table if not exists public.devices (
  key_id       text primary key check (key_id ~ '^[a-f0-9]{64}$'),   -- 공개키 지문(sha256)
  owner_id     uuid not null,                                         -- 승인을 요청한 로그인 사용자(서버가 확인한 값)
  public_key   jsonb not null,
  status       text not null default 'pending' check (status in ('pending', 'approved', 'revoked')),
  created_at   timestamptz not null default now(),
  approved_at  timestamptz
);

alter table public.devices enable row level security;
revoke all on public.devices from public, anon, authenticated;

commit;

-- 기대: anon·authenticated 권한이 0행
select grantee, privilege_type from information_schema.role_table_grants
 where table_schema = 'public' and table_name = 'devices' and grantee in ('anon', 'authenticated');

-- ============ [B] 승인 대기 목록 보기 (읽기만 함) ============
-- 화면에 나온 확인 코드(예: AB12-CD34)와 아래 code 열이 같은지, 요청한 시각·사용자가 맞는지 눈으로 대조합니다.
select upper(substr(key_id, 1, 4)) || '-' || upper(substr(key_id, 5, 4)) as code,
       owner_id, created_at, status
  from public.devices
 where status = 'pending'
 order by created_at desc;

-- ============ [C] 승인 또는 회수 (대조가 끝난 기기 한 건만) ============
-- 승인: <<확인코드 앞 4자>>와 <<뒤 4자>>(소문자)를 화면의 코드 AB12-CD34라면 'ab12' 'cd34'로 바꿉니다. 한 줄만 바뀌어야 합니다.
-- update public.devices set status = 'approved', approved_at = now()
--  where status = 'pending' and substr(key_id, 1, 8) = '<<소문자8자>>' returning key_id, owner_id, status;
-- 회수: 승인된 기기를 더 이상 쓰지 못하게 합니다.
-- update public.devices set status = 'revoked'
--  where status = 'approved' and substr(key_id, 1, 8) = '<<소문자8자>>' returning key_id, owner_id, status;
