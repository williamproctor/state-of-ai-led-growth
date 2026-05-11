-- State of AI-Led Growth — survey schema
-- Run once in Supabase SQL Editor (Project → SQL Editor → New query → paste → Run).
-- Idempotent: safe to re-run.

create extension if not exists "citext";
create extension if not exists "pgcrypto";

create table if not exists public.responses (
  id              uuid primary key default gen_random_uuid(),
  created_at      timestamptz not null default now(),

  -- Contact
  email           citext      not null,
  first_name      text,
  last_name       text,
  position        text,

  -- Consent (split per GDPR — one purpose per checkbox)
  optin_report    boolean     not null default false,
  optin_advisor   boolean     not null default false,

  -- Survey body. JSONB so question changes never require a migration.
  -- Keys: q1, q2, ..., q27, plus *-other free-text inputs.
  answers         jsonb       not null,

  -- Provenance
  utm             jsonb,
  referrer        text,
  ip_hash         text,
  user_agent      text,
  honeypot_pass   boolean     not null,

  -- Lifecycle (GDPR soft-delete; never hard-delete to preserve aggregate stats)
  deleted_at      timestamptz
);

create unique index if not exists responses_email_unique
  on public.responses (email)
  where deleted_at is null;

create index if not exists responses_created_at_idx
  on public.responses (created_at desc);

create index if not exists responses_answers_gin
  on public.responses using gin (answers);

-- Lock down public/anon access. The serverless function uses the service_role
-- key (which bypasses RLS), so no anon policies are needed.
alter table public.responses enable row level security;

-- Optional: make life easier for Danni in the table editor.
comment on table  public.responses is 'Survey submissions for State of AI-Led Growth 2026.';
comment on column public.responses.answers is 'JSONB blob of all q1..q27 answers + any "other" free-text values.';
comment on column public.responses.optin_report  is 'Opted in to receive the published report.';
comment on column public.responses.optin_advisor is 'Opted in to be quoted / referenced as a practitioner voice.';
comment on column public.responses.ip_hash is 'sha256(ip + IP_HASH_SALT). Raw IPs are never stored.';
