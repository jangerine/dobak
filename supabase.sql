-- Supabase 대시보드 > SQL Editor 에 통째로 붙여넣고 Run 하세요.
-- 계정 테이블은 직접 접근이 막혀 있고(RLS, 정책 없음), 아래 두 함수로만 읽고 쓸 수 있어요.

create extension if not exists pgcrypto with schema extensions;

create table if not exists cg_accounts (
  name         text primary key,
  pin_hash     text not null,
  chips        int  not null default 1000,
  fails        int  not null default 0,
  locked_until timestamptz,
  created_at   timestamptz not null default now()
);
alter table cg_accounts enable row level security;

-- 로그인(없는 닉네임이면 가입). PIN 5번 틀리면 5분 잠금. 칩 50 미만이면 500으로 지원.
create or replace function cg_login(n text, p text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare a cg_accounts;
begin
  if n is null or length(n) not between 1 and 8 or p is null or p !~ '^[0-9]{4}$' then
    raise exception 'bad_input';
  end if;
  select * into a from cg_accounts where name = n;
  if not found then
    insert into cg_accounts(name, pin_hash) values (n, crypt(p, gen_salt('bf'))) returning * into a;
    return json_build_object('chips', a.chips, 'new', true);
  end if;
  if a.locked_until is not null and a.locked_until > now() then
    return json_build_object('error', 'locked');
  end if;
  if a.pin_hash <> crypt(p, a.pin_hash) then
    update cg_accounts
       set fails = fails + 1,
           locked_until = case when fails + 1 >= 5 then now() + interval '5 minutes' else null end
     where name = n;
    return json_build_object('error', 'bad_pin');  -- 예외를 던지면 실패 횟수 기록이 롤백되므로 값으로 돌려줘요
  end if;
  update cg_accounts set fails = 0, locked_until = null where name = n;
  if a.chips < 50 then
    update cg_accounts set chips = 500 where name = n;
    a.chips := 500;
  end if;
  return json_build_object('chips', a.chips, 'new', false);
end $$;

-- 칩 저장 (PIN 확인). 0 ~ 1,000,000 으로 제한.
create or replace function cg_set_chips(n text, p text, c int) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  update cg_accounts
     set chips = greatest(0, least(c, 1000000))
   where name = n and pin_hash = crypt(p, pin_hash);
  if not found then raise exception 'bad_pin'; end if;
end $$;

grant execute on function cg_login(text, text), cg_set_chips(text, text, int) to anon;
