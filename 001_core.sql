create table if not exists evapro_sessions (
  tenant_id text not null,
  session_id text not null,
  results jsonb not null default '[]'::jsonb,
  closures jsonb not null default '[]'::jsonb,
  exam_package jsonb,
  created_at bigint not null,
  last_activity bigint not null,
  primary key (tenant_id, session_id)
);

create index if not exists evapro_sessions_last_activity_idx
on evapro_sessions (last_activity);

create table if not exists evapro_teacher_registries (
  admin_id text primary key,
  teachers jsonb not null default '[]'::jsonb,
  updated_at text not null
);

-- Defense in depth: these tables are backend-only. The direct Supabase API
-- (anon/authenticated roles) must not expose exam keys, rosters or results.
alter table evapro_sessions enable row level security;
alter table evapro_teacher_registries enable row level security;
revoke all on table evapro_sessions from anon, authenticated;
revoke all on table evapro_sessions from public;

create table if not exists evapro_capabilities (
  token_hash text primary key,
  tenant_id text not null,
  session_id text not null,
  document_hash text not null,
  exam_version text not null,
  expires_at timestamptz not null,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);
alter table evapro_capabilities enable row level security;
revoke all on table evapro_capabilities from public, anon, authenticated;
revoke all on table evapro_teacher_registries from anon, authenticated;

do $$ begin
  alter table evapro_sessions add constraint evapro_sessions_results_array
    check (jsonb_typeof(results) = 'array');
exception when duplicate_object then null; end $$;

do $$ begin
  alter table evapro_sessions add constraint evapro_sessions_closures_array
    check (jsonb_typeof(closures) = 'array');
exception when duplicate_object then null; end $$;
