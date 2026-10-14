-- 10단계 제작 3: 비공개 가상 메모 사본(notes_backup)과 복구 감사 기록(notes_restore_audit)입니다.
-- 이 파일에는 메모 제목·본문·이메일이 없습니다. <<자리표시자>>는 SQL Editor에서 실행할 때 화면에서만 바꾸고 저장·커밋하지 않습니다.
-- 학생이 검토한 뒤 [A] → [B] → [C] → [D] 순서로 "구역별로 따로" 선택해 실행하세요. 코딩 도구는 DB에 접속하지 않았습니다.
-- 서버 함수(api/restore.js)만 서버 전용 키(service_role)로 읽고 씁니다. anon·authenticated에는 권한이 없습니다.

-- ============ [A] 해시 식 확인 (읽기만 함) ============
-- src/note-restore.mjs의 noteContentHash와 같은 식입니다: sha256("<제목 바이트수>:<제목><본문 바이트수>:<본문>")
-- 기대: 아래 한 줄의 결과가 true (제목 'abc', 본문 '한글'의 해시가 코드와 같음)
select encode(sha256(convert_to(
         octet_length(convert_to('abc', 'UTF8'))::text || ':' || 'abc'
         || octet_length(convert_to('한글', 'UTF8'))::text || ':' || '한글', 'UTF8')), 'hex')
       = 'eb3967d31892f473d31f418477c72fd2e94b5ec4d9ca690af329ed77534673cc' as hash_matches_code;

-- ============ [B] 표 만들기 (한 덩어리로 실행. 오류가 나면 전부 취소됨) ============
begin;

create table if not exists public.notes_backup (
  note_id        uuid primary key,          -- 되살릴 메모의 id (notes.id와 같은 값)
  owner_id       uuid not null,             -- 사본을 만들 때의 소유자
  position       int,
  title          text not null,
  content        text not null,
  content_sha256 text not null check (content_sha256 ~ '^[a-f0-9]{64}$'),
  backed_up_at   timestamptz not null default now()
);

create table if not exists public.notes_restore_audit (
  id             bigint generated always as identity primary key,
  at             timestamptz not null default now(),
  note_id        uuid not null,
  actor_id       uuid not null,
  event          text not null check (event in ('requested','inserted','updated','unchanged','refused_owner_conflict','verify_failed')),
  content_sha256 text
);

alter table public.notes_backup enable row level security;
alter table public.notes_restore_audit enable row level security;
revoke all on table public.notes_backup, public.notes_restore_audit from public, anon, authenticated;
-- 감사 기록은 덧붙이기만 합니다: 서버 역할에서도 수정·삭제·비우기 권한을 거두고, 트리거로 한 번 더 막습니다.
revoke update, delete, truncate on table public.notes_restore_audit from service_role;

create or replace function public.notes_restore_audit_append_only() returns trigger
language plpgsql as $$ begin raise exception 'notes_restore_audit is append-only'; end $$;
drop trigger if exists notes_restore_audit_no_change on public.notes_restore_audit;
create trigger notes_restore_audit_no_change before update or delete on public.notes_restore_audit
  for each row execute function public.notes_restore_audit_append_only();

commit;

-- ============ [C] 사본 만들기: 시험 계정 B의 메모 한 건만 (침해 전에 실행) ============
-- <<B_EMAIL>>: 시험 계정 B의 이메일, <<NOTE_ID>>: B가 가진 가상 메모의 id. 실행 화면에서만 바꿉니다.
-- B 소유가 아니면 한 건도 들어가지 않습니다. 이미 사본이 있으면 덮어쓰지 않습니다(검증한 사본 보존).
insert into public.notes_backup (note_id, owner_id, position, title, content, content_sha256)
select n.id, n.owner_id, n.position, n.title, n.content,
       encode(sha256(convert_to(
         octet_length(convert_to(n.title, 'UTF8'))::text || ':' || n.title
         || octet_length(convert_to(n.content, 'UTF8'))::text || ':' || n.content, 'UTF8')), 'hex')
from public.notes n
where n.id = '<<NOTE_ID>>'::uuid
  and n.owner_id = (select u.id from auth.users u where u.email = '<<B_EMAIL>>')
on conflict (note_id) do nothing;

-- ============ [D] 확인 (읽기만 함. 본문은 출력하지 않음) ============
-- D-1) 사본 한 건의 id·소유자·해시. 기대: 1행.
select note_id, owner_id, content_sha256, backed_up_at from public.notes_backup;
-- D-2) 사본의 저장된 해시가 사본 내용으로 다시 계산한 값과 같은지. 기대: hash_ok 전부 true.
select note_id, content_sha256 = encode(sha256(convert_to(
         octet_length(convert_to(title, 'UTF8'))::text || ':' || title
         || octet_length(convert_to(content, 'UTF8'))::text || ':' || content, 'UTF8')), 'hex') as hash_ok
from public.notes_backup;
-- D-3) anon·authenticated 권한. 기대: 두 표 모두 전부 false.
select r.role_name, t.tbl,
       has_table_privilege(r.role_name, t.tbl, 'SELECT') as can_select,
       has_table_privilege(r.role_name, t.tbl, 'INSERT') as can_insert,
       has_table_privilege(r.role_name, t.tbl, 'UPDATE') as can_update,
       has_table_privilege(r.role_name, t.tbl, 'DELETE') as can_delete
from (values ('anon'), ('authenticated')) as r(role_name),
     (values ('public.notes_backup'), ('public.notes_restore_audit')) as t(tbl);
-- D-4) 감사 기록 표에서 service_role의 수정·삭제 권한이 없는지. 기대: can_update, can_delete 모두 false.
select has_table_privilege('service_role', 'public.notes_restore_audit', 'UPDATE') as can_update,
       has_table_privilege('service_role', 'public.notes_restore_audit', 'DELETE') as can_delete;
