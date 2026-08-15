
-- JEMCODES NEW SUPABASE SCHEMA
-- Matches the NEW JEMCODES index (6).html architecture.
-- Run this ONCE in Supabase -> SQL Editor.
-- This script does not create or store passwords. Passwords are handled by Supabase Auth.

create extension if not exists pgcrypto;

-- =========================
-- TABLES
-- =========================

create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  full_name text not null default '',
  username text not null default '',
  role text not null default 'student'
    check (role in ('student','worker','teacher','boss')),
  updated_at timestamptz not null default now()
);

create unique index if not exists profiles_username_lower_unique
  on public.profiles (lower(username))
  where username <> '';

create table if not exists public.rooms (
  id text primary key,
  owner_id uuid not null references public.profiles(id) on delete cascade,
  name text not null,
  description text not null default '',
  code text not null unique,
  active boolean not null default true,
  visibility text not null default 'open'
    check (visibility in ('open','private')),
  default_mark text not null default 'present',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create unique index if not exists rooms_code_unique on public.rooms(code);

create table if not exists public.room_members (
  id text primary key,
  room_id text not null references public.rooms(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  joined_at timestamptz not null default now(),
  unique(room_id, user_id)
);

create table if not exists public.attendance (
  id text primary key,
  room_id text not null references public.rooms(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  status text not null default 'present'
    check (status in ('present','absent','exempted')),
  reason text,
  source text not null default 'self',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(room_id, user_id)
);

create table if not exists public.requests (
  id text primary key,
  room_id text not null references public.rooms(id) on delete cascade,
  user_id uuid not null references public.profiles(id) on delete cascade,
  reason text not null default '',
  status text not null default 'pending'
    check (status in ('pending','approved','declined')),
  created_at timestamptz not null default now(),
  decided_at timestamptz
);

create table if not exists public.notifications (
  id text primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  title text not null,
  message text not null default '',
  read boolean not null default false,
  created_at timestamptz not null default now(),
  room_id text references public.rooms(id) on delete cascade
);

create table if not exists public.audit (
  id text primary key,
  user_id uuid not null references public.profiles(id) on delete cascade,
  action text not null,
  detail text not null default '',
  created_at timestamptz not null default now(),
  room_id text references public.rooms(id) on delete cascade
);

create table if not exists public.reports (
  id text primary key,
  owner_id uuid not null references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  rows jsonb not null default '[]'::jsonb
);


-- =========================
-- SAFE BROWSER CONNECTION CHECK
-- =========================
-- This function exposes only a boolean readiness result.
-- It does not expose table rows, passwords, keys, or private data.
create or replace function public.jemcodes_healthcheck()
returns jsonb
language sql
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'ok', true,
    'profiles', to_regclass('public.profiles') is not null,
    'rooms', to_regclass('public.rooms') is not null,
    'room_members', to_regclass('public.room_members') is not null,
    'attendance', to_regclass('public.attendance') is not null,
    'requests', to_regclass('public.requests') is not null,
    'notifications', to_regclass('public.notifications') is not null,
    'audit', to_regclass('public.audit') is not null,
    'reports', to_regclass('public.reports') is not null
  );
$$;

revoke all on function public.jemcodes_healthcheck() from public;
grant execute on function public.jemcodes_healthcheck() to anon, authenticated;

-- =========================
-- INDEXES
-- =========================

create index if not exists rooms_owner_idx on public.rooms(owner_id);
create index if not exists room_members_user_idx on public.room_members(user_id);
create index if not exists room_members_room_idx on public.room_members(room_id);
create index if not exists attendance_user_idx on public.attendance(user_id);
create index if not exists attendance_room_idx on public.attendance(room_id);
create index if not exists requests_user_idx on public.requests(user_id);
create index if not exists requests_room_idx on public.requests(room_id);
create index if not exists notifications_user_idx on public.notifications(user_id);
create index if not exists notifications_room_idx on public.notifications(room_id);
create index if not exists audit_user_idx on public.audit(user_id);
create index if not exists audit_room_idx on public.audit(room_id);
create index if not exists reports_owner_idx on public.reports(owner_id);

-- =========================
-- PROFILE AUTO-CREATION
-- =========================

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (
    id, email, full_name, username, role, updated_at
  )
  values (
    new.id,
    coalesce(new.email, ''),
    coalesce(new.raw_user_meta_data->>'full_name', ''),
    coalesce(new.raw_user_meta_data->>'username', ''),
    case
      when new.raw_user_meta_data->>'role'
        in ('student','worker','teacher','boss')
      then new.raw_user_meta_data->>'role'
      else 'student'
    end,
    now()
  )
  on conflict (id) do update set
    email = excluded.email,
    full_name = case
      when excluded.full_name <> '' then excluded.full_name
      else public.profiles.full_name
    end,
    username = case
      when excluded.username <> '' then excluded.username
      else public.profiles.username
    end,
    role = excluded.role,
    updated_at = now();

  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function public.handle_new_user();

-- =========================
-- SECURITY HELPERS
-- SECURITY DEFINER avoids RLS recursion when checking ownership/membership.
-- =========================

create or replace function public.is_room_owner(p_room_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.rooms
    where id = p_room_id
      and owner_id = auth.uid()
  );
$$;

create or replace function public.is_room_member(p_room_id text)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.room_members
    where room_id = p_room_id
      and user_id = auth.uid()
  );
$$;

create or replace function public.is_manager()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.profiles
    where id = auth.uid()
      and role in ('teacher','boss')
  );
$$;

-- =========================
-- RLS
-- =========================

alter table public.profiles enable row level security;
alter table public.rooms enable row level security;
alter table public.room_members enable row level security;
alter table public.attendance enable row level security;
alter table public.requests enable row level security;
alter table public.notifications enable row level security;
alter table public.audit enable row level security;
alter table public.reports enable row level security;

-- Remove old policies with these names so this script can be safely re-run.
drop policy if exists profiles_select_own_or_related on public.profiles;
drop policy if exists profiles_insert_own on public.profiles;
drop policy if exists profiles_update_own on public.profiles;

drop policy if exists rooms_select_visible_or_related on public.rooms;
drop policy if exists rooms_insert_owner on public.rooms;
drop policy if exists rooms_update_owner on public.rooms;
drop policy if exists rooms_delete_owner on public.rooms;

drop policy if exists room_members_select_related on public.room_members;
drop policy if exists room_members_insert_self on public.room_members;
drop policy if exists room_members_delete_self_or_owner on public.room_members;

drop policy if exists attendance_select_related on public.attendance;
drop policy if exists attendance_insert_self_or_owner on public.attendance;
drop policy if exists attendance_update_self_or_owner on public.attendance;
drop policy if exists attendance_delete_owner on public.attendance;

drop policy if exists requests_select_self_or_owner on public.requests;
drop policy if exists requests_insert_self_member on public.requests;
drop policy if exists requests_update_owner on public.requests;
drop policy if exists requests_delete_self_or_owner on public.requests;

drop policy if exists notifications_select_own on public.notifications;
drop policy if exists notifications_insert_related on public.notifications;
drop policy if exists notifications_update_own on public.notifications;
drop policy if exists notifications_delete_own on public.notifications;

drop policy if exists audit_select_related on public.audit;
drop policy if exists audit_insert_self on public.audit;

drop policy if exists reports_select_owner on public.reports;
drop policy if exists reports_insert_owner on public.reports;
drop policy if exists reports_update_owner on public.reports;
drop policy if exists reports_delete_owner on public.reports;

-- PROFILES
create policy profiles_select_own_or_related
on public.profiles for select
to authenticated
using (
  id = auth.uid()
  or exists (
    select 1 from public.room_members rm
    join public.rooms r on r.id = rm.room_id
    where rm.user_id = profiles.id
      and (rm.user_id = auth.uid() or r.owner_id = auth.uid())
  )
  or exists (
    select 1 from public.rooms r
    where r.owner_id = auth.uid()
      and exists (
        select 1 from public.room_members rm
        where rm.room_id = r.id and rm.user_id = profiles.id
      )
  )
);

create policy profiles_insert_own
on public.profiles for insert
to authenticated
with check (id = auth.uid());

create policy profiles_update_own
on public.profiles for update
to authenticated
using (id = auth.uid())
with check (id = auth.uid());

-- ROOMS
create policy rooms_select_visible_or_related
on public.rooms for select
to authenticated
using (
  owner_id = auth.uid()
  or active = true and visibility = 'open'
  or public.is_room_member(id)
);

create policy rooms_insert_owner
on public.rooms for insert
to authenticated
with check (owner_id = auth.uid());

create policy rooms_update_owner
on public.rooms for update
to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

create policy rooms_delete_owner
on public.rooms for delete
to authenticated
using (owner_id = auth.uid());

-- ROOM MEMBERS
create policy room_members_select_related
on public.room_members for select
to authenticated
using (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
);

create policy room_members_insert_self
on public.room_members for insert
to authenticated
with check (
  user_id = auth.uid()
  and exists (
    select 1 from public.rooms r
    where r.id = room_id and r.active = true
  )
);

create policy room_members_delete_self_or_owner
on public.room_members for delete
to authenticated
using (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
);

-- ATTENDANCE
create policy attendance_select_related
on public.attendance for select
to authenticated
using (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
);

create policy attendance_insert_self_or_owner
on public.attendance for insert
to authenticated
with check (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
);

create policy attendance_update_self_or_owner
on public.attendance for update
to authenticated
using (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
)
with check (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
);

create policy attendance_delete_owner
on public.attendance for delete
to authenticated
using (public.is_room_owner(room_id));

-- REQUESTS
create policy requests_select_self_or_owner
on public.requests for select
to authenticated
using (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
);

create policy requests_insert_self_member
on public.requests for insert
to authenticated
with check (
  user_id = auth.uid()
  and public.is_room_member(room_id)
);

create policy requests_update_owner
on public.requests for update
to authenticated
using (public.is_room_owner(room_id))
with check (public.is_room_owner(room_id));

create policy requests_delete_self_or_owner
on public.requests for delete
to authenticated
using (
  user_id = auth.uid()
  or public.is_room_owner(room_id)
);

-- NOTIFICATIONS
create policy notifications_select_own
on public.notifications for select
to authenticated
using (user_id = auth.uid());

create policy notifications_insert_related
on public.notifications for insert
to authenticated
with check (
  public.is_room_owner(room_id)
  or public.is_room_member(room_id)
  or user_id = auth.uid()
);

create policy notifications_update_own
on public.notifications for update
to authenticated
using (user_id = auth.uid())
with check (user_id = auth.uid());

create policy notifications_delete_own
on public.notifications for delete
to authenticated
using (user_id = auth.uid());

-- AUDIT
create policy audit_select_related
on public.audit for select
to authenticated
using (
  user_id = auth.uid()
  or (room_id is not null and public.is_room_owner(room_id))
);

create policy audit_insert_self
on public.audit for insert
to authenticated
with check (user_id = auth.uid());

-- REPORTS
create policy reports_select_owner
on public.reports for select
to authenticated
using (owner_id = auth.uid());

create policy reports_insert_owner
on public.reports for insert
to authenticated
with check (owner_id = auth.uid());

create policy reports_update_owner
on public.reports for update
to authenticated
using (owner_id = auth.uid())
with check (owner_id = auth.uid());

create policy reports_delete_owner
on public.reports for delete
to authenticated
using (owner_id = auth.uid());

-- =========================
-- REALTIME
-- =========================

do $$
begin
  alter publication supabase_realtime add table public.rooms;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.room_members;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.attendance;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.requests;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.notifications;
exception when duplicate_object then null;
end $$;

do $$
begin
  alter publication supabase_realtime add table public.audit;
exception when duplicate_object then null;
end $$;

-- =========================
-- FINAL CHECK
-- =========================
select
  table_name
from information_schema.tables
where table_schema = 'public'
  and table_name in (
    'profiles',
    'rooms',
    'room_members',
    'attendance',
    'requests',
    'notifications',
    'audit',
    'reports'
  )
order by table_name;
