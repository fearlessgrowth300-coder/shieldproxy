-- Run this ONCE in your Supabase project's SQL editor
-- (project pnhzsteoouhngjdgsfeh — the same one Privacy Shield uses).
-- It adds the backup table used by the BlackBox + ShieldProxy Android apps.
-- Safe to re-run (idempotent).

-- One JSON backup blob per user per app ('shieldproxy' or 'blackbox').
create table if not exists public.app_backups (
  user_id    uuid        not null default auth.uid() references auth.users(id) on delete cascade,
  app        text        not null,
  data       jsonb       not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (user_id, app)
);

alter table public.app_backups enable row level security;

drop policy if exists "own app_backups" on public.app_backups;
create policy "own app_backups" on public.app_backups
  for all
  using (auth.uid() = user_id)
  with check (auth.uid() = user_id);

-- Storage bucket for best-effort per-clone login-session backups (phase 2).
insert into storage.buckets (id, name, public)
values ('clone-sessions', 'clone-sessions', false)
on conflict (id) do nothing;

drop policy if exists "own clone-sessions" on storage.objects;
create policy "own clone-sessions" on storage.objects
  for all
  using (bucket_id = 'clone-sessions' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'clone-sessions' and (storage.foldername(name))[1] = auth.uid()::text);

-- IMPORTANT: also turn OFF email confirmation so sign-up works instantly:
--   Dashboard → Authentication → Providers → Email → uncheck "Confirm email" → Save.
