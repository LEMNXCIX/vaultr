-- Key epoch on the local vault meta.
--
-- Mirrors the server-side `vaults.key_epoch`. A device whose epoch is behind
-- the remote must not overwrite remote vault meta. Defaults to 1, which is
-- also what pre-existing vaults get: they were all initialized at epoch 1.
--
-- Additive only; no table rebuild, so foreign_keys stays on.

ALTER TABLE vault_meta
    ADD COLUMN key_epoch INTEGER NOT NULL DEFAULT 1;
