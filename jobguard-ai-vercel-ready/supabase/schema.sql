-- JobGuard AI — Optional Supabase PostgreSQL Schema with Row Level Security (RLS)
-- Persistence is strictly opt-in. Users can run all local verification features without an account.

create extension if not exists "pgcrypto";

create table if not exists public.verification_reports (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  report_id text not null,
  created_at timestamptz not null default now(),
  is_demo boolean not null default false,
  detected_language text not null default 'en',
  risk_level text not null,
  risk_index integer not null check (risk_index >= 0 and risk_index <= 100),
  evidence_coverage_percent integer not null default 0,
  employer_name text,
  role_title text,
  redacted_preview text,
  report_json jsonb not null
);

alter table public.verification_reports enable row level security;

create policy "Users can view own saved reports"
  on public.verification_reports
  for select
  using (auth.uid() = user_id);

create policy "Users can insert own opt-in reports"
  on public.verification_reports
  for insert
  with check (auth.uid() = user_id);

create policy "Users can delete own saved reports"
  on public.verification_reports
  for delete
  using (auth.uid() = user_id);

create index if not exists idx_verification_reports_user_created
  on public.verification_reports (user_id, created_at desc);
