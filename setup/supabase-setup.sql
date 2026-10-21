-- Chronologie: player records and leaderboard
-- Paste this whole file into the Supabase SQL Editor (Database > SQL Editor > New query) and click Run.
-- It is safe to run more than once.
--
-- What it creates
--   players          one row per nickname: a scrambled (bcrypt) copy of the 4-digit PIN, the game record as JSON,
--                    and summary figures for the leaderboard. The table cannot be read or written directly with
--                    the public key; the game can only use the three functions below.
--   load_player      signs a player in, creating the nickname the first time it is used, and returns their record.
--   save_player      saves a record after checking the PIN.
--   leaderboard      returns nicknames and scores only (never PINs or records), top 20 by points.
--
-- Protection against PIN guessing: after 10 wrong PINs a nickname is locked for 15 minutes.

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.players (
  name_key        text primary key,                 -- lower-case nickname, used for matching
  display_name    text not null,                    -- nickname as the player typed it
  pin_hash        text not null,
  data            jsonb not null default '{}'::jsonb,
  points          integer not null default 0,       -- total points ever earned
  correct         integer not null default 0,
  attempts        integer not null default 0,
  collected       integer not null default 0,
  failed_attempts integer not null default 0,
  locked_until    timestamptz,
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

alter table public.players enable row level security;
revoke all on public.players from anon, authenticated;

-- Internal: checks a PIN and records failed attempts. Returns 'ok', 'unknown', 'locked' or 'pin'.
create or replace function public.chrono_verify(k text, p_pin text)
returns text
language plpgsql
security definer
set search_path = public, extensions
as $$
declare r public.players;
begin
  select * into r from public.players where name_key = k for update;
  if not found then return 'unknown'; end if;
  if r.locked_until is not null and r.locked_until > now() then return 'locked'; end if;
  if r.pin_hash <> crypt(p_pin, r.pin_hash) then
    update public.players
       set failed_attempts = case when r.failed_attempts + 1 >= 10 then 0 else r.failed_attempts + 1 end,
           locked_until    = case when r.failed_attempts + 1 >= 10 then now() + interval '15 minutes' else null end
     where name_key = k;
    return 'pin';
  end if;
  update public.players set failed_attempts = 0, locked_until = null where name_key = k;
  return 'ok';
end;
$$;

create or replace function public.load_player(p_name text, p_pin text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  n text := trim(coalesce(p_name, ''));
  k text := lower(trim(coalesce(p_name, '')));
  v text;
  r public.players;
begin
  if n !~ '^[[:alnum:] _.''-]{2,20}$' or coalesce(p_pin, '') !~ '^[0-9]{4}$' then
    return jsonb_build_object('ok', false, 'error', 'invalid');
  end if;
  v := public.chrono_verify(k, p_pin);
  if v = 'unknown' then
    insert into public.players (name_key, display_name, pin_hash)
    values (k, n, crypt(p_pin, gen_salt('bf')));
    return jsonb_build_object('ok', true, 'created', true, 'name', n, 'data', '{}'::jsonb);
  end if;
  if v <> 'ok' then return jsonb_build_object('ok', false, 'error', v); end if;
  select * into r from public.players where name_key = k;
  return jsonb_build_object('ok', true, 'created', false, 'name', r.display_name, 'data', r.data);
end;
$$;

create or replace function public.save_player(p_name text, p_pin text, p_data jsonb,
  p_points integer, p_correct integer, p_attempts integer, p_collected integer)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare k text := lower(trim(coalesce(p_name, ''))); v text;
begin
  if pg_column_size(p_data) > 500000 then return jsonb_build_object('ok', false, 'error', 'too_large'); end if;
  v := public.chrono_verify(k, coalesce(p_pin, ''));
  if v <> 'ok' then return jsonb_build_object('ok', false, 'error', v); end if;
  update public.players
     set data = p_data, points = greatest(p_points, 0), correct = greatest(p_correct, 0),
         attempts = greatest(p_attempts, 0), collected = greatest(p_collected, 0), updated_at = now()
   where name_key = k;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.leaderboard()
returns table (display_name text, points integer, correct integer, attempts integer, collected integer)
language sql
security definer
set search_path = public
stable
as $$
  select display_name, points, correct, attempts, collected
    from public.players
   where attempts > 0
   order by points desc, collected desc
   limit 20;
$$;

revoke execute on function public.chrono_verify(text, text) from public, anon, authenticated;
grant execute on function public.load_player(text, text) to anon, authenticated;
grant execute on function public.save_player(text, text, jsonb, integer, integer, integer, integer) to anon, authenticated;
grant execute on function public.leaderboard() to anon, authenticated;
