-- JEMCODES CLOUD STORAGE
-- Run this once in Supabase SQL Editor.
-- IMPORTANT: This schema is intended for a school/prototype deployment.
-- It provides shared storage across browsers, but the table is publicly writable
-- through the anon key. For a production system, replace this with Supabase Auth
-- + per-user Row Level Security policies.

create table if not exists public.jemcodes_cloud (
  collection text not null,
  record_id text not null,
  data jsonb not null,
  updated_at timestamptz not null default now(),
  primary key (collection, record_id)
);

create index if not exists jemcodes_cloud_collection_idx
  on public.jemcodes_cloud (collection);

alter table public.jemcodes_cloud disable row level security;

grant select, insert, update, delete on public.jemcodes_cloud to anon, authenticated;

-- Optional: clear an old prototype table before starting fresh.
-- truncate table public.jemcodes_cloud;
