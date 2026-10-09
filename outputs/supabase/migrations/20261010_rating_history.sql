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
