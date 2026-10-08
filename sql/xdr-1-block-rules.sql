-- 보너스 xdr-01·xdr-02: XDR 거부 규칙을 서버끼리 나눠 쓰는 공유 저장소 표입니다. public.xdr_block_rules 표만 다룹니다.
-- 배포 서버(Vercel)의 서버 함수는 요청마다 따로 떠서 규칙 "파일"을 공유할 수 없으므로, 이 표를 서버 전용 키(service_role)로 읽습니다.
-- 학생이 검토한 뒤 SQL Editor에서 [A] → [B] → [C] 순서로 "구역별로 따로" 선택해 실행하세요. 코딩 도구는 DB에 접속하지 않습니다.
-- 이 표에는 비밀값이 없고(주소·규칙 종류·근거 경보 번호·시각), anon·authenticated 는 읽지도 쓰지도 못합니다.
-- 되돌리려면 [E] 구역을 실행하세요(표만 지웁니다. notes 표와 다른 표는 건드리지 않습니다).

-- ============ [A] 적용 전 확인 (읽기만 함) ============
-- A-1) 기대: 0행(아직 표가 없음). 이미 있으면 1행.
select table_name from information_schema.tables
where table_schema = 'public' and table_name = 'xdr_block_rules';

-- ============ [B] 변경 (한 덩어리로 실행. 오류가 나면 전부 취소됨) ============
begin;

create table if not exists public.xdr_block_rules (
  rule_id           text        not null,
  srcip             text        not null,
  decision          text        not null default 'deny' check (decision = 'deny'),
  evidence_alert_id text        not null,
  created_at        timestamptz not null default now(),
  expires_at        timestamptz not null,
  primary key (rule_id, srcip),
  check (expires_at > created_at)
);

-- 요청 주소로 만료 전 규칙을 빨리 찾기 위한 색인입니다.
create index if not exists xdr_block_rules_srcip_expires_idx on public.xdr_block_rules (srcip, expires_at);

-- RLS 를 켜고 정책을 만들지 않습니다(= service_role 외에는 어떤 행도 못 봄). 권한도 서버 전용 키 역할만 남깁니다.
alter table public.xdr_block_rules enable row level security;
revoke all on table public.xdr_block_rules from public, anon, authenticated;
grant select, insert, update, delete on table public.xdr_block_rules to service_role;

commit;

-- ============ [C] 적용 후 확인 (읽기만 함) ============
-- C-1) 기대: anon·authenticated 는 전부 false, service_role 은 전부 true.
select r.role_name,
       has_table_privilege(r.role_name, 'public.xdr_block_rules', 'SELECT') as can_select,
       has_table_privilege(r.role_name, 'public.xdr_block_rules', 'INSERT') as can_insert,
       has_table_privilege(r.role_name, 'public.xdr_block_rules', 'UPDATE') as can_update,
       has_table_privilege(r.role_name, 'public.xdr_block_rules', 'DELETE') as can_delete
from (values ('anon'), ('authenticated'), ('service_role')) as r(role_name);

-- C-2) 기대: rls_on = true.
select relrowsecurity as rls_on from pg_class where oid = 'public.xdr_block_rules'::regclass;

-- C-3) 기대: "permission denied for table xdr_block_rules" (각 구역을 따로 실행, 끝에 rollback 이라 DB는 안 바뀜)
begin; set local role anon; select * from public.xdr_block_rules; rollback;
begin; set local role authenticated; select * from public.xdr_block_rules; rollback;

-- ============ [D] 운영 중 쓰는 질의 (필요할 때 따로 실행) ============
-- D-1) 지금 걸려 있는 규칙 보기.
select rule_id, srcip, evidence_alert_id, created_at, expires_at
from public.xdr_block_rules
order by expires_at desc;

-- D-2) 내 주소가 잘못 막혔다면 그 줄만 지웁니다. <<MY_IP>> 를 실행할 때 화면에서만 바꾸고 저장하지 마세요.
-- delete from public.xdr_block_rules where srcip = '<<MY_IP>>';

-- D-3) 만료된 줄 청소(막는 데에는 영향 없음. 만료된 규칙은 어차피 적용되지 않습니다).
-- delete from public.xdr_block_rules where expires_at < now();

-- ============ [E] 되돌리기 (이 표만 지움) ============
-- drop table if exists public.xdr_block_rules;
