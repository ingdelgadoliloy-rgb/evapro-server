create table if not exists evapro_attempts (
  tenant_id text not null, session_id text not null, document_hash text not null,
  exam_version text not null, terminal_type text not null check (terminal_type in ('submit', 'closure')),
  receipt_id uuid not null unique, payload jsonb not null, received_at timestamptz not null default now(),
  primary key (tenant_id, session_id, document_hash)
);
create index if not exists evapro_attempts_session_idx on evapro_attempts (tenant_id, session_id, received_at);
