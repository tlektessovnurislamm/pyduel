-- PyDuel: allow a duel participant to surrender or leave the active duel.
-- Run this migration in the Supabase SQL Editor, then refresh the app.
create or replace function public.surrender_duel(p_duel_id uuid)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  d public.duels%rowtype;
  winner uuid;
begin
  select * into d
  from public.duels
  where id = p_duel_id
  for update;

  if not found
     or d.status <> 'active'
     or (d.player1_id <> auth.uid() and d.player2_id <> auth.uid()) then
    return jsonb_build_object('accepted', false);
  end if;

  winner := case
    when auth.uid() = d.player1_id then d.player2_id
    else d.player1_id
  end;

  update public.duels
  set status = 'finished', winner_id = winner, updated_at = now()
  where id = d.id;

  update public.profiles
  set in_duel = false
  where id in (d.player1_id, d.player2_id);

  return jsonb_build_object(
    'accepted', true,
    'winner_id', winner,
    'loser_id', auth.uid()
  );
end;
$$;

revoke all on function public.surrender_duel(uuid) from public;
grant execute on function public.surrender_duel(uuid) to authenticated;

-- Refresh the REST API schema cache so rpc('surrender_duel') is available immediately.
notify pgrst, 'reload schema';
