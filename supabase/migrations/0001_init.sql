-- Vaultr server schema (v1) — Supabase / Postgres
-- Apply via Supabase dashboard SQL editor or `supabase db push`.
-- Zero-knowledge: only ciphertext (base64 XChaCha20-Poly1305) ever lands here.

create table public.vaults (
  owner_id uuid primary key references auth.users(id) on delete cascade,
  salt text not null,            -- base64
  kdf_params jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.projects (
  id uuid primary key,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name text not null,
  description text,
  color text,
  icon text,
  deleted boolean not null default false,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (owner_id, name)
);

create table public.environments (
  id uuid primary key,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  project_id uuid not null references public.projects(id) on delete cascade,
  name text not null,
  is_default boolean not null default false,
  sort_order int not null default 0,
  deleted boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (project_id, name)
);

create table public.variables (
  id uuid primary key,
  owner_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  environment_id uuid not null references public.environments(id) on delete cascade,
  key text not null,
  value_encrypted text not null,   -- base64 del ciphertext XChaCha20-Poly1305
  nonce text not null,             -- base64, 24 bytes
  notes text,
  is_readonly boolean not null default false,
  allow_export boolean not null default true,
  deleted boolean not null default false,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (environment_id, key)
);

alter table public.projects enable row level security;
alter table public.environments enable row level security;
alter table public.variables enable row level security;
alter table public.vaults enable row level security;

create policy "own rows" on public.projects    for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own rows" on public.environments for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own rows" on public.variables   for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
create policy "own row"  on public.vaults      for all using (owner_id = auth.uid()) with check (owner_id = auth.uid());
