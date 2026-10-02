-- Remote verifier + key epoch.
--
-- verifier_ct/verifier_nonce hold VAULT_VERIFIER_MESSAGE ("vault-ok") encrypted
-- under the current master key. The server stores ciphertext of a known
-- constant, so this leaks nothing. It lets the client prove possession of the
-- master key without depending on the vault having any variables.
--
-- key_epoch increments on every rekey and every reset. A device whose local
-- epoch is behind the remote must not overwrite the remote meta.
--
-- Additive only: nullable columns and defaults keep pre-existing rows valid.

alter table public.vaults
  add column verifier_ct    text,
  add column verifier_nonce text,
  add column key_epoch      bigint not null default 1,
  add column key_change     text not null default 'init',
  add column key_changed_at timestamptz;

comment on column public.vaults.verifier_ct is
  'ciphertext of VAULT_VERIFIER_MESSAGE under the current master key; nullable for vaults predating this migration';
comment on column public.vaults.key_epoch is
  'incremented on every rekey and reset; guards against stale devices overwriting newer vault meta';
comment on column public.vaults.key_change is
  'init | rekey | reset — why key_epoch last changed';
