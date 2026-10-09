-- PyDuel initial Supabase schema. Run in Supabase SQL Editor.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  nickname text not null check (char_length(nickname) between 3 and 16),
  character smallint not null default 0 check (character between 0 and 7),
  rating integer not null default 800,
  wins integer not null default 0,
  losses integer not null default 0,
  favorite_topic smallint,
  online boolean not null default false,
  in_duel boolean not null default false,
  last_seen timestamptz not null default now(),
  created_at timestamptz not null default now()
);
alter table public.profiles add column if not exists in_duel boolean not null default false;
create unique index if not exists profiles_nickname_lower_unique on public.profiles (lower(nickname));

create table if not exists public.duel_invites (
  id uuid primary key default gen_random_uuid(),
  from_id uuid not null references public.profiles(id) on delete cascade,
  to_id uuid not null references public.profiles(id) on delete cascade,
  topic_id smallint not null check (topic_id between 0 and 12),
  status text not null default 'pending' check (status in ('pending','accepted','declined','expired','cancelled')),
  expires_at timestamptz not null default (now() + interval '30 seconds'),
  created_at timestamptz not null default now(),
  check (from_id <> to_id)
);
create index if not exists duel_invites_inbox on public.duel_invites (to_id, status, created_at desc);

create table if not exists public.duels (
  id uuid primary key default gen_random_uuid(),
  invite_id uuid not null unique references public.duel_invites(id) on delete cascade,
  player1_id uuid not null references public.profiles(id),
  player2_id uuid not null references public.profiles(id),
  topic_id smallint not null check (topic_id between 0 and 12),
  status text not null default 'active' check (status in ('active','finished','cancelled')),
  round_no integer not null default 1,
  player1_lives smallint not null default 3 check (player1_lives between 0 and 3),
  player2_lives smallint not null default 3 check (player2_lives between 0 and 3),
  winner_id uuid references public.profiles(id),
  updated_at timestamptz not null default now()
);

-- Never send source code or secret tests through this table.
create table if not exists public.duel_events (
  id bigint generated always as identity primary key,
  duel_id uuid not null references public.duels(id) on delete cascade,
  actor_id uuid not null references public.profiles(id) on delete cascade,
  event_type text not null check (event_type in ('typing','submitted','round_hit')),
  payload jsonb not null default '{}'::jsonb check (payload = '{}'::jsonb),
  created_at timestamptz not null default now()
);
create index if not exists duel_events_feed on public.duel_events (duel_id, id);

alter table public.profiles enable row level security;
alter table public.duel_invites enable row level security;
alter table public.duels enable row level security;
alter table public.duel_events enable row level security;

revoke all on public.profiles, public.duel_invites, public.duels, public.duel_events from anon, authenticated;
grant select on public.profiles to authenticated;
grant insert (id,nickname,character,favorite_topic) on public.profiles to authenticated;
grant update (nickname,character,favorite_topic,online,last_seen) on public.profiles to authenticated;
grant select, insert on public.duel_invites to authenticated;
grant update (status) on public.duel_invites to authenticated;
grant select on public.duels to authenticated;
grant select, insert on public.duel_events to authenticated;
grant usage, select on sequence public.duel_events_id_seq to authenticated;

drop policy if exists "profiles readable by signed-in players" on public.profiles;
create policy "profiles readable by signed-in players" on public.profiles for select to authenticated using (true);
drop policy if exists "players create own profile" on public.profiles;
create policy "players create own profile" on public.profiles for insert to authenticated with check (id = auth.uid());
drop policy if exists "players update own profile" on public.profiles;
create policy "players update own profile" on public.profiles for update to authenticated using (id = auth.uid()) with check (id = auth.uid());

drop policy if exists "participants read their invitations" on public.duel_invites;
create policy "participants read their invitations" on public.duel_invites for select to authenticated using (from_id = auth.uid() or to_id = auth.uid());
drop policy if exists "players create invitations as sender" on public.duel_invites;
create policy "players create invitations as sender" on public.duel_invites for insert to authenticated with check (from_id = auth.uid());
drop policy if exists "recipient answers invitation" on public.duel_invites;
create policy "recipient answers invitation" on public.duel_invites for update to authenticated using (to_id = auth.uid() and status = 'pending') with check (to_id = auth.uid() and status in ('accepted','declined','expired'));

drop policy if exists "duel participants read duel" on public.duels;
create policy "duel participants read duel" on public.duels for select to authenticated using (player1_id = auth.uid() or player2_id = auth.uid());
drop policy if exists "duel participants read events" on public.duel_events;
create policy "duel participants read events" on public.duel_events for select to authenticated using (exists (select 1 from public.duels d where d.id = duel_id and (d.player1_id = auth.uid() or d.player2_id = auth.uid())));
drop policy if exists "participants send their own safe events" on public.duel_events;
create policy "participants send their own safe events" on public.duel_events for insert to authenticated with check (
  actor_id = auth.uid() and exists (select 1 from public.duels d where d.id = duel_id and d.status = 'active' and (d.player1_id = auth.uid() or d.player2_id = auth.uid()))
);

create or replace function public.accept_duel_invite(p_invite_id uuid)
returns uuid language plpgsql security definer set search_path = public as $$
declare i public.duel_invites%rowtype; d_id uuid;
begin
  select * into i from public.duel_invites where id = p_invite_id for update;
  if not found or i.to_id <> auth.uid() or i.status <> 'pending' or i.expires_at <= now() then
    raise exception 'Invitation is unavailable';
  end if;
  update public.duel_invites set status = 'accepted' where id = i.id;
  insert into public.duels(invite_id, player1_id, player2_id, topic_id)
    values(i.id, i.from_id, i.to_id, i.topic_id) returning id into d_id;
  update public.profiles set online = true, in_duel = true, last_seen = now() where id in (i.from_id, i.to_id);
  return d_id;
end;
$$;
revoke all on function public.accept_duel_invite(uuid) from public;
grant execute on function public.accept_duel_invite(uuid) to authenticated;

-- First authenticated claim wins the round atomically. The caller should call this
-- only after its local checker reports a correct answer. Server-side code/test
-- verification is required before using this RPC for ranked matches.
drop function if exists public.claim_duel_hit(uuid, integer);
create or replace function public.claim_duel_hit(p_duel_id uuid, p_round_no integer)
returns jsonb language plpgsql security definer set search_path = public as $$
declare d public.duels%rowtype; loser uuid; lives smallint;
begin
  select * into d from public.duels where id = p_duel_id for update;
  if not found or d.status <> 'active' or auth.uid() not in (d.player1_id, d.player2_id) then
    raise exception 'Duel is unavailable';
  end if;
  if p_round_no <> d.round_no then
    return jsonb_build_object('accepted', false, 'round_no', d.round_no);
  end if;
  if auth.uid() = d.player1_id then
    loser := d.player2_id;
    update public.duels set player2_lives = player2_lives - 1, round_no = round_no + 1, updated_at = now()
      where id = d.id returning player2_lives into lives;
  else
    loser := d.player1_id;
    update public.duels set player1_lives = player1_lives - 1, round_no = round_no + 1, updated_at = now()
      where id = d.id returning player1_lives into lives;
  end if;
  if lives <= 0 then
    update public.duels set status = 'finished', winner_id = auth.uid(), updated_at = now() where id = d.id;
    update public.profiles set in_duel = false where id in (d.player1_id, d.player2_id);
  end if;
  return jsonb_build_object('accepted', true, 'round_no', d.round_no, 'loser_id', loser, 'loser_lives', lives, 'finished', lives <= 0);
end;
$$;
revoke all on function public.claim_duel_hit(uuid, integer) from public;
grant execute on function public.claim_duel_hit(uuid, integer) to authenticated;

-- Allow either participant to leave/resign an active duel safely. The opponent wins.
create or replace function public.surrender_duel(p_duel_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare d public.duels%rowtype; winner uuid;
begin
  select * into d from public.duels where id = p_duel_id for update;
  if not found or d.status <> 'active' or (d.player1_id <> auth.uid() and d.player2_id <> auth.uid()) then
    return jsonb_build_object('accepted', false);
  end if;
  winner := case when auth.uid() = d.player1_id then d.player2_id else d.player1_id end;
  update public.duels set status = 'finished', winner_id = winner, updated_at = now() where id = d.id;
  update public.profiles set in_duel = false where id in (d.player1_id, d.player2_id);
  return jsonb_build_object('accepted', true, 'winner_id', winner, 'loser_id', auth.uid());
end;
$$;
revoke all on function public.surrender_duel(uuid) from public;
grant execute on function public.surrender_duel(uuid) to authenticated;
alter table public.duels add column if not exists finished_at timestamptz;
alter table public.duels add column if not exists finish_reason text;
alter table public.duels add column if not exists rating_change_player1 integer not null default 0;
alter table public.duels add column if not exists rating_change_player2 integer not null default 0;

-- Enable table change feeds without failing if they were already added.
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='profiles') then alter publication supabase_realtime add table public.profiles; end if;
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='duel_invites') then alter publication supabase_realtime add table public.duel_invites; end if;
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='duels') then alter publication supabase_realtime add table public.duels; end if;
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='duel_events') then alter publication supabase_realtime add table public.duel_events; end if;
end $$;


-- Ranked match stats and history migration (also available as a standalone upgrade).
-- Persist ranked duel outcomes and make profile counters atomic with duel completion.
alter table public.duels add column if not exists finished_at timestamptz;
alter table public.duels add column if not exists finish_reason text;
alter table public.duels add column if not exists rating_change_player1 integer not null default 0;
alter table public.duels add column if not exists rating_change_player2 integer not null default 0;

create or replace function public.claim_duel_hit(p_duel_id uuid, p_round_no integer)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  d public.duels%rowtype;
  loser uuid;
  lives smallint;
  winner_rating integer;
  loser_rating integer;
  winner_delta integer;
  loser_delta integer;
  p1_delta integer;
  p2_delta integer;
begin
  select * into d from public.duels where id = p_duel_id for update;
  if not found or d.status <> 'active' or auth.uid() not in (d.player1_id, d.player2_id) then
    raise exception 'Duel is unavailable';
  end if;
  if p_round_no <> d.round_no then
    return jsonb_build_object('accepted', false, 'round_no', d.round_no);
  end if;
  if auth.uid() = d.player1_id then
    loser := d.player2_id;
    update public.duels set player2_lives = player2_lives - 1, round_no = round_no + 1, updated_at = now()
      where id = d.id returning player2_lives into lives;
  else
    loser := d.player1_id;
    update public.duels set player1_lives = player1_lives - 1, round_no = round_no + 1, updated_at = now()
      where id = d.id returning player1_lives into lives;
  end if;
  if lives <= 0 then
    -- Lock profile rows in a stable order so simultaneous games cannot deadlock.
    perform id from public.profiles where id in (auth.uid(), loser) order by id for update;
    select rating into winner_rating from public.profiles where id = auth.uid();
    select rating into loser_rating from public.profiles where id = loser;
    winner_delta := greatest(1, round(32.0 / (1.0 + power(10.0, (loser_rating - winner_rating)::numeric / 400.0)))::integer);
    loser_delta := -winner_delta;
    if auth.uid() = d.player1_id then p1_delta := winner_delta; p2_delta := loser_delta;
    else p1_delta := loser_delta; p2_delta := winner_delta; end if;
    update public.duels set status = 'finished', winner_id = auth.uid(), finished_at = now(),
      finish_reason = 'solved', rating_change_player1 = p1_delta, rating_change_player2 = p2_delta, updated_at = now()
      where id = d.id;
    update public.profiles set
      rating = greatest(0, rating + case when id = auth.uid() then winner_delta else loser_delta end),
      wins = wins + case when id = auth.uid() then 1 else 0 end,
      losses = losses + case when id = loser then 1 else 0 end,
      in_duel = false
      where id in (auth.uid(), loser);
  end if;
  return jsonb_build_object('accepted', true, 'round_no', d.round_no, 'loser_id', loser, 'loser_lives', lives, 'finished', lives <= 0);
end;
$$;
revoke all on function public.claim_duel_hit(uuid, integer) from public;
grant execute on function public.claim_duel_hit(uuid, integer) to authenticated;

create or replace function public.surrender_duel(p_duel_id uuid)
returns jsonb language plpgsql security definer set search_path = public as $$
declare
  d public.duels%rowtype;
  winner uuid;
  loser uuid;
  winner_rating integer;
  loser_rating integer;
  winner_delta integer;
  loser_delta integer;
  p1_delta integer;
  p2_delta integer;
begin
  select * into d from public.duels where id = p_duel_id for update;
  if not found or d.status <> 'active' or (d.player1_id <> auth.uid() and d.player2_id <> auth.uid()) then
    return jsonb_build_object('accepted', false);
  end if;
  winner := case when auth.uid() = d.player1_id then d.player2_id else d.player1_id end;
  loser := auth.uid();
  perform id from public.profiles where id in (winner, loser) order by id for update;
  select rating into winner_rating from public.profiles where id = winner;
  select rating into loser_rating from public.profiles where id = loser;
  winner_delta := greatest(1, round(32.0 / (1.0 + power(10.0, (loser_rating - winner_rating)::numeric / 400.0)))::integer);
  loser_delta := -winner_delta;
  if winner = d.player1_id then p1_delta := winner_delta; p2_delta := loser_delta;
  else p1_delta := loser_delta; p2_delta := winner_delta; end if;
  update public.duels set status = 'finished', winner_id = winner, finished_at = now(), finish_reason = 'surrender',
    rating_change_player1 = p1_delta, rating_change_player2 = p2_delta, updated_at = now() where id = d.id;
  update public.profiles set
    rating = greatest(0, rating + case when id = winner then winner_delta else loser_delta end),
    wins = wins + case when id = winner then 1 else 0 end,
    losses = losses + case when id = loser then 1 else 0 end,
    in_duel = false
    where id in (winner, loser);
  return jsonb_build_object('accepted', true, 'winner_id', winner, 'loser_id', loser);
end;
$$;
revoke all on function public.surrender_duel(uuid) from public;
grant execute on function public.surrender_duel(uuid) to authenticated;
notify pgrst, 'reload schema';

