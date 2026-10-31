-- Comcord Setup (ohne E-Mail, eigenes Login). In Supabase: SQL Editor -> New query -> alles einfügen -> Run
-- Falls du die alte Version schon ausgeführt hast, werden die alten Tabellen hier gelöscht.
drop table if exists messages cascade;
drop table if exists friendships cascade;
drop table if exists profiles cascade;
drop table if exists sessions cascade;
drop table if exists app_users cascade;

create extension if not exists pgcrypto with schema extensions;

create table app_users (
  id uuid primary key default gen_random_uuid(),
  username text unique not null,
  display_name text not null,
  pass_hash text not null,
  created_at timestamptz default now()
);
create table sessions (
  token uuid primary key default gen_random_uuid(),
  user_id uuid not null references app_users(id) on delete cascade,
  created_at timestamptz default now()
);
create table friendships (
  id bigint generated always as identity primary key,
  requester uuid not null references app_users(id) on delete cascade,
  addressee uuid not null references app_users(id) on delete cascade,
  status text not null default 'pending',
  created_at timestamptz default now(),
  unique (requester, addressee)
);
create table messages (
  id bigint generated always as identity primary key,
  sender uuid not null references app_users(id) on delete cascade,
  receiver uuid not null references app_users(id) on delete cascade,
  content text not null check (char_length(content) between 1 and 2000),
  created_at timestamptz default now()
);
-- Kein direkter Zugriff von außen: nur über die Funktionen unten
alter table app_users enable row level security;
alter table sessions enable row level security;
alter table friendships enable row level security;
alter table messages enable row level security;

create or replace function cc_uid(p_token uuid) returns uuid
language plpgsql security definer set search_path = public, extensions as $$
declare u uuid;
begin
  select user_id into u from sessions where token = p_token;
  if u is null then raise exception 'not_logged_in'; end if;
  return u;
end $$;

create or replace function cc_register(p_username text, p_display text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare u app_users; t uuid; un text := lower(trim(p_username));
begin
  if un !~ '^[a-z0-9_.]{3,20}$' then raise exception 'bad_username'; end if;
  if length(p_password) < 6 then raise exception 'short_password'; end if;
  if exists (select 1 from app_users where username = un) then raise exception 'username_taken'; end if;
  insert into app_users (username, display_name, pass_hash)
    values (un, left(coalesce(nullif(trim(p_display), ''), un), 32), crypt(p_password, gen_salt('bf')))
    returning * into u;
  insert into sessions (user_id) values (u.id) returning token into t;
  return json_build_object('token', t, 'id', u.id, 'username', u.username, 'display_name', u.display_name);
end $$;

create or replace function cc_login(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare u app_users; t uuid;
begin
  select * into u from app_users where username = lower(trim(p_username));
  if u.id is null or u.pass_hash <> crypt(p_password, u.pass_hash) then raise exception 'wrong_login'; end if;
  insert into sessions (user_id) values (u.id) returning token into t;
  return json_build_object('token', t, 'id', u.id, 'username', u.username, 'display_name', u.display_name);
end $$;

create or replace function cc_me(p_token uuid) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare u app_users;
begin
  select * into u from app_users where id = cc_uid(p_token);
  return json_build_object('id', u.id, 'username', u.username, 'display_name', u.display_name);
end $$;

create or replace function cc_logout(p_token uuid) returns json
language plpgsql security definer set search_path = public, extensions as $$
begin
  delete from sessions where token = p_token;
  return json_build_object('ok', true);
end $$;

create or replace function cc_state(p_token uuid) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := cc_uid(p_token); fr json; inc json; outg json; lastin json;
begin
  select coalesce(json_agg(json_build_object('fid', f.id, 'id', o.id, 'username', o.username, 'display_name', o.display_name) order by o.display_name), '[]'::json)
    into fr from friendships f join app_users o on o.id = case when f.requester = me then f.addressee else f.requester end
    where f.status = 'accepted' and me in (f.requester, f.addressee);
  select coalesce(json_agg(json_build_object('fid', f.id, 'id', o.id, 'username', o.username, 'display_name', o.display_name) order by f.id), '[]'::json)
    into inc from friendships f join app_users o on o.id = f.requester where f.status = 'pending' and f.addressee = me;
  select coalesce(json_agg(json_build_object('fid', f.id, 'id', o.id, 'username', o.username, 'display_name', o.display_name) order by f.id), '[]'::json)
    into outg from friendships f join app_users o on o.id = f.addressee where f.status = 'pending' and f.requester = me;
  select json_build_object('id', m.id, 'sender', m.sender, 'name', o.display_name) into lastin
    from messages m join app_users o on o.id = m.sender where m.receiver = me order by m.id desc limit 1;
  return json_build_object('friends', fr, 'incoming', inc, 'outgoing', outg, 'last_in', lastin);
end $$;

create or replace function cc_add_friend(p_token uuid, p_username text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := cc_uid(p_token); o app_users;
begin
  select * into o from app_users where username = lower(trim(p_username));
  if o.id is null then raise exception 'no_such_user'; end if;
  if o.id = me then raise exception 'self'; end if;
  if exists (select 1 from friendships where (requester = me and addressee = o.id) or (requester = o.id and addressee = me)) then
    raise exception 'already';
  end if;
  insert into friendships (requester, addressee) values (me, o.id);
  return json_build_object('display_name', o.display_name);
end $$;

create or replace function cc_answer(p_token uuid, p_fid bigint, p_accept boolean) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := cc_uid(p_token);
begin
  if p_accept then
    update friendships set status = 'accepted' where id = p_fid and addressee = me;
  else
    delete from friendships where id = p_fid and me in (requester, addressee);
  end if;
  return json_build_object('ok', true);
end $$;

create or replace function cc_messages(p_token uuid, p_other uuid) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := cc_uid(p_token); r json;
begin
  select coalesce(json_agg(x order by x.id), '[]'::json) into r from (
    select m.id, m.sender, m.content, m.created_at from messages m
    where (m.sender = me and m.receiver = p_other) or (m.sender = p_other and m.receiver = me)
    order by m.id desc limit 200) x;
  return r;
end $$;

create or replace function cc_send(p_token uuid, p_other uuid, p_content text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := cc_uid(p_token); mid bigint;
begin
  if length(trim(p_content)) = 0 then raise exception 'empty'; end if;
  if not exists (select 1 from friendships f where f.status = 'accepted'
      and ((f.requester = me and f.addressee = p_other) or (f.requester = p_other and f.addressee = me))) then
    raise exception 'not_friends';
  end if;
  insert into messages (sender, receiver, content) values (me, p_other, left(trim(p_content), 2000)) returning id into mid;
  return json_build_object('id', mid);
end $$;

create or replace function cc_delete_msg(p_token uuid, p_id bigint) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare me uuid := cc_uid(p_token);
begin
  delete from messages where id = p_id and sender = me;
  return json_build_object('ok', true);
end $$;

revoke all on function cc_uid(uuid) from public, anon, authenticated;
grant execute on function cc_register(text,text,text), cc_login(text,text), cc_me(uuid), cc_logout(uuid), cc_state(uuid),
  cc_add_friend(uuid,text), cc_answer(uuid,bigint,boolean), cc_messages(uuid,uuid), cc_send(uuid,uuid,text), cc_delete_msg(uuid,bigint)
  to anon, authenticated;
