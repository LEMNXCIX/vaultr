use super::*;
use chrono::TimeZone;
use crypto::MasterKey;
use models::{Environment, Id, Project, Variable};
use storage::Storage;

use super::account::{
    keyring_calls, supabase_entry, supabase_session_file, sync_session_file_override, StoredSession,
};
use super::rows::{
    b64_decode, parse_id, tombstone_environment, tombstone_project, tombstone_variable,
    variable_from_dto,
};
use super::verify::{verifier_parts, verify_key_against_sample, verify_verifier};

fn ts(mins: u32) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap() + chrono::Duration::minutes(i64::from(mins))
}

fn sample_project(id: Id, updated: DateTime<Utc>, deleted: bool) -> Project {
    Project {
        id,
        name: "P".into(),
        description: None,
        color: None,
        icon: None,
        created_at: updated,
        updated_at: updated,
        owner_id: None,
        version: 1,
        deleted,
    }
}

fn sample_env(id: Id, project_id: Id, updated: DateTime<Utc>) -> Environment {
    Environment {
        id,
        project_id,
        name: "local".into(),
        is_default: true,
        sort_order: 0,
        created_at: updated,
        updated_at: updated,
        deleted: false,
    }
}

fn sample_var(id: Id, env_id: Id, updated: DateTime<Utc>) -> Variable {
    Variable {
        id,
        environment_id: env_id,
        key: "K".into(),
        value_encrypted: vec![1, 2, 3],
        nonce: vec![0; 24],
        notes: None,
        is_readonly: false,
        allow_export: true,
        created_at: updated,
        updated_at: updated,
        version: 1,
        deleted: false,
    }
}

#[test]
fn lww_remote_newer_wins_both_directions() {
    let storage = Storage::open_in_memory().unwrap();
    let id = uuid::Uuid::now_v7();

    // Local older → remote wins, full overwrite including name/version.
    storage
        .create_project(&sample_project(id, ts(10), false))
        .unwrap();
    let newer = ProjectRow {
        owner_id: None,
        id: id.to_string(),
        name: "Renamed".into(),
        description: Some("from remote".into()),
        color: None,
        icon: None,
        deleted: false,
        version: 4,
        updated_at: Some(ts(20)),
    };
    assert_eq!(
        merge_project(&storage, &newer).unwrap(),
        MergeOutcome::Applied(false)
    );
    let merged = storage.find_project_by_id(id).unwrap().unwrap();
    assert_eq!(merged.name, "Renamed");
    assert_eq!(merged.version, 4);

    // Local newer → remote loses, local untouched.
    let older = ProjectRow {
        owner_id: None,
        id: id.to_string(),
        name: "Stale".into(),
        description: None,
        color: None,
        icon: None,
        deleted: true,
        version: 2,
        updated_at: Some(ts(15)),
    };
    assert_eq!(
        merge_project(&storage, &older).unwrap(),
        MergeOutcome::LocalKept
    );
    assert_eq!(
        storage.find_project_by_id(id).unwrap().unwrap().name,
        "Renamed"
    );
}

#[test]
fn lww_missing_local_row_is_inserted_missing_remote_ts_loses() {
    let storage = Storage::open_in_memory().unwrap();
    let id = uuid::Uuid::now_v7();

    // Missing locally → insert.
    let row = ProjectRow {
        owner_id: None,
        id: id.to_string(),
        name: "New".into(),
        description: None,
        color: None,
        icon: None,
        deleted: false,
        version: 1,
        updated_at: Some(ts(5)),
    };
    assert_eq!(
        merge_project(&storage, &row).unwrap(),
        MergeOutcome::Applied(false)
    );

    // Remote without updated_at → conservative keep-local.
    let no_ts = ProjectRow {
        updated_at: None,
        ..row
    };
    assert_eq!(
        merge_project(&storage, &no_ts).unwrap(),
        MergeOutcome::LocalKept
    );
}

#[test]
fn tombstone_pull_cascades_children() {
    let storage = Storage::open_in_memory().unwrap();
    let pid = uuid::Uuid::now_v7();
    let eid = uuid::Uuid::now_v7();
    let vid = uuid::Uuid::now_v7();
    storage
        .create_project(&sample_project(pid, ts(10), false))
        .unwrap();
    storage
        .create_environment(&sample_env(eid, pid, ts(10)))
        .unwrap();
    storage
        .create_variable(&sample_var(vid, eid, ts(10)))
        .unwrap();

    // Pull: parent tombstoned remotely, strictly newer than local.
    let tombstone = ProjectRow {
        owner_id: None,
        id: pid.to_string(),
        name: "P".into(),
        description: None,
        color: None,
        icon: None,
        deleted: true,
        version: 2,
        updated_at: Some(ts(30)),
    };
    assert_eq!(
        merge_project(&storage, &tombstone).unwrap(),
        MergeOutcome::Applied(true)
    );

    // Cascade pass (runs inside sync right after merge).
    let cascaded = storage.cascade_tombstones(ts(31)).unwrap();
    assert_eq!(cascaded, 2, "env + var must be soft-deleted");

    assert!(
        storage
            .find_environment_by_id(eid)
            .unwrap()
            .unwrap()
            .deleted
    );
    assert!(storage.find_variable_by_id(vid).unwrap().unwrap().deleted);

    // Cascaded children are dirty → they propagate as tombstones on push.
    assert_eq!(storage.dirty_environments().unwrap().len(), 1);
    assert_eq!(storage.dirty_variables().unwrap().len(), 1);
}

#[test]
fn tombstoning_preserves_ciphertext_byte_for_byte() {
    let now = ts(0);
    let row = VariableRow {
        owner_id: Some("u".into()),
        id: "018f0000-0000-7000-8000-000000000001".into(),
        environment_id: "018f0000-0000-7000-8000-000000000002".into(),
        key: "SECRET".into(),
        value_encrypted: b64_encode(b"opaque-ciphertext"),
        nonce: b64_encode(b"opaque-nonce-24-bytes-xx"),
        notes: Some("keep me".into()),
        is_readonly: true,
        allow_export: false,
        deleted: false,
        version: 4,
        updated_at: None,
    };

    let dead = tombstone_variable(&row, now);
    assert!(dead.deleted);
    assert_eq!(dead.version, 5);
    assert_eq!(dead.updated_at, Some(now));
    assert_eq!(
        dead.value_encrypted, row.value_encrypted,
        "ciphertext must survive"
    );
    assert_eq!(dead.nonce, row.nonce, "nonce must survive");
    assert_eq!(dead.key, row.key);
    assert_eq!(dead.notes, row.notes);
    assert_eq!(dead.owner_id, row.owner_id);
    assert_eq!(dead.is_readonly, row.is_readonly);
    assert_eq!(dead.allow_export, row.allow_export);
}

#[test]
fn tombstoning_project_and_environment_preserves_fields() {
    let now = ts(0);

    let project = ProjectRow {
        owner_id: Some("u".into()),
        id: "018f0000-0000-7000-8000-000000000003".into(),
        name: "P".into(),
        description: Some("keep me".into()),
        color: Some("red".into()),
        icon: None,
        deleted: false,
        version: 2,
        updated_at: None,
    };
    let dead_project = tombstone_project(&project, now);
    assert!(dead_project.deleted);
    assert_eq!(dead_project.version, 3);
    assert_eq!(dead_project.updated_at, Some(now));
    assert_eq!(dead_project.name, project.name);
    assert_eq!(dead_project.description, project.description);
    assert_eq!(dead_project.color, project.color);
    assert_eq!(dead_project.icon, project.icon);
    assert_eq!(dead_project.owner_id, project.owner_id);

    // EnvironmentRow carries no `version`: only `deleted`/`updated_at`
    // may change, everything else survives.
    let env = EnvironmentRow {
        owner_id: Some("u".into()),
        id: "018f0000-0000-7000-8000-000000000004".into(),
        project_id: project.id.clone(),
        name: "local".into(),
        is_default: true,
        sort_order: 7,
        deleted: false,
        updated_at: None,
    };
    let dead_env = tombstone_environment(&env, now);
    assert!(dead_env.deleted);
    assert_eq!(dead_env.updated_at, Some(now));
    assert_eq!(dead_env.project_id, env.project_id);
    assert_eq!(dead_env.name, env.name);
    assert_eq!(dead_env.is_default, env.is_default);
    assert_eq!(dead_env.sort_order, env.sort_order);
    assert_eq!(dead_env.owner_id, env.owner_id);
}

fn sample_project_row() -> ProjectRow {
    ProjectRow {
        owner_id: Some("u".into()),
        id: "018f0000-0000-7000-8000-000000000010".into(),
        name: "P".into(),
        description: None,
        color: None,
        icon: None,
        deleted: false,
        version: 1,
        updated_at: None,
    }
}

fn sample_environment_row() -> EnvironmentRow {
    EnvironmentRow {
        owner_id: Some("u".into()),
        id: "018f0000-0000-7000-8000-000000000011".into(),
        project_id: "018f0000-0000-7000-8000-000000000010".into(),
        name: "local".into(),
        is_default: true,
        sort_order: 0,
        deleted: false,
        updated_at: None,
    }
}

fn sample_variable_row() -> VariableRow {
    VariableRow {
        owner_id: Some("u".into()),
        id: "018f0000-0000-7000-8000-000000000012".into(),
        environment_id: "018f0000-0000-7000-8000-000000000011".into(),
        key: "K".into(),
        value_encrypted: b64_encode(b"opaque-ciphertext"),
        nonce: b64_encode(b"opaque-nonce-24-bytes-xx"),
        notes: None,
        is_readonly: false,
        allow_export: true,
        deleted: false,
        version: 1,
        updated_at: None,
    }
}

#[test]
fn reset_tombstones_every_table_and_preserves_parent_order() {
    let now = ts(0);
    let (projects, environments, variables) = reset_tombstone_sets(
        &[sample_project_row()],
        &[sample_environment_row()],
        &[sample_variable_row()],
        now,
    );
    assert_eq!(projects.len(), 1);
    assert_eq!(environments.len(), 1);
    assert_eq!(variables.len(), 1);
    assert!(projects[0].deleted && environments[0].deleted && variables[0].deleted);
    assert_eq!(
        variables[0].value_encrypted,
        b64_encode(b"opaque-ciphertext")
    );
    assert_eq!(
        variables[0].nonce,
        b64_encode(b"opaque-nonce-24-bytes-xx"),
        "the nonce must survive the tombstone byte-identical too"
    );
}

fn remote_vault_row() -> VaultRow {
    VaultRow {
        owner_id: Some("u".into()),
        salt: b64_encode(&[9u8; 16]),
        kdf_params: serde_json::json!({"m_cost": 2048, "t_cost": 1, "p_cost": 1, "output_len": 32}),
        verifier_ct: Some(b64_encode(b"ct")),
        verifier_nonce: Some(b64_encode(b"nonce")),
        key_epoch: 2,
        key_change: Some(models::constants::KEY_CHANGE_RESET.into()),
        key_changed_at: None,
    }
}

#[test]
fn pending_reset_wipes_only_when_a_remote_row_exists() {
    // A remote row is live: the wipe must run, and the marker may only be
    // cleared once it has.
    assert_eq!(
        plan_pending_reset(Some(&remote_vault_row())),
        PendingResetPlan::Wipe
    );
    // No `vaults` row: nothing to wipe, so the marker is already
    // satisfied and is cleared without any network write.
    assert_eq!(plan_pending_reset(None), PendingResetPlan::AlreadyWiped);
}

#[test]
fn reset_epoch_is_always_ahead_of_the_remote_and_never_lowers_it() {
    // The reset must advance past whatever the server holds, so another
    // device sees `remote_epoch > local_epoch && key_change == "reset"` and
    // stops instead of adopting and re-pushing its pre-wipe rows.
    assert_eq!(reset_epoch_for(7), 8);
    assert_eq!(reset_epoch_for(0), 1, "a vault predating the epoch reads 0");
    for remote in [1i64, 2, 7, 99, i64::MAX] {
        assert!(
            reset_epoch_for(remote) >= remote,
            "a retry of the wipe can never lower {remote}"
        );
    }
    assert_eq!(
        reset_epoch_for(i64::MAX),
        i64::MAX,
        "saturation beats an overflow panic in a sync path"
    );
}

#[test]
fn a_push_local_that_finishes_a_reset_publishes_the_reset() {
    assert_eq!(
        key_change_for(SaltAction::PushLocal, false),
        models::constants::KEY_CHANGE_INIT
    );
    // The account had no `vaults` row, so this sync creates it out of the
    // post-reset domain: publishing `init` would tell another device that
    // merely the master password changed, which leads it to adopt and push
    // its wiped rows back.
    assert_eq!(
        key_change_for(SaltAction::PushLocal, true),
        models::constants::KEY_CHANGE_RESET
    );
    // A rekey is its own signal and never relabels as a reset, even if a
    // reset marker was also pending.
    assert_eq!(
        key_change_for(SaltAction::PushRekey, false),
        models::constants::KEY_CHANGE_REKEY
    );
    assert_eq!(
        key_change_for(SaltAction::PushRekey, true),
        models::constants::KEY_CHANGE_REKEY
    );
}

#[test]
fn salt_guard_only_proceeds_on_the_post_wipe_vault_meta() {
    let local = [9u8; 16];

    // The snapshot `sync()` fetched BEFORE `push_reset` ran: the local salt
    // has already moved, the remote epoch is not ahead, and the rekey
    // marker is gone (a reset clears it), so the guard aborts. This is the
    // dead end the post-wipe refetch removes.
    assert_eq!(
        salt_action(&SaltInputs {
            local_salt: &local,
            local_epoch: 2,
            remote_salt_b64: Some(&b64_encode(&[4u8; 16])),
            remote_epoch: Some(2),
            remote_key_change: Some(models::constants::KEY_CHANGE_INIT),
            pending_marker: None,
        }),
        SaltAction::RemoteKeyChanged
    );

    // The snapshot taken AFTER the wipe carries the local salt, so the same
    // sync proceeds and reports success. The reset `key_change` never
    // reaches the guard: salt equality short-circuits first.
    assert_eq!(
        salt_action(&SaltInputs {
            local_salt: &local,
            local_epoch: 2,
            remote_salt_b64: Some(&b64_encode(&local)),
            remote_epoch: Some(2),
            remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
            pending_marker: None,
        }),
        SaltAction::Proceed
    );
}

fn salt_inputs<'a>(
    local: &'a [u8],
    remote: Option<&'a str>,
    marker: Option<&'a str>,
) -> SaltInputs<'a> {
    SaltInputs {
        local_salt: local,
        local_epoch: 1,
        remote_salt_b64: remote,
        remote_epoch: None,
        remote_key_change: None,
        pending_marker: marker,
    }
}

#[test]
fn salt_guard_covers_all_four_branches() {
    let local = [9u8; 16];
    let local_b64 = b64_encode(&local);
    let local_hex = hex::encode(local);
    let other_b64 = b64_encode(&[8u8; 16]);

    // Remote has no vault → push local meta (first sync).
    assert_eq!(
        salt_action(&salt_inputs(&local, None, None)),
        SaltAction::PushLocal
    );
    assert_eq!(
        salt_action(&salt_inputs(&local, None, Some(&local_hex))),
        SaltAction::PushLocal
    );

    // Salts equal → normal sync regardless of a (stale) marker.
    assert_eq!(
        salt_action(&salt_inputs(&local, Some(&local_b64), None)),
        SaltAction::Proceed
    );
    assert_eq!(
        salt_action(&salt_inputs(&local, Some(&local_b64), Some(&local_hex))),
        SaltAction::Proceed
    );

    // Salts differ + marker matches THIS device's salt → rekeyed here:
    // push the new meta before the rows.
    assert_eq!(
        salt_action(&salt_inputs(&local, Some(&other_b64), Some(&local_hex))),
        SaltAction::PushRekey
    );

    // Salts differ, no marker → abort, nothing pushed or pulled.
    assert_eq!(
        salt_action(&salt_inputs(&local, Some(&other_b64), None)),
        SaltAction::RemoteKeyChanged
    );
    // A marker for a different salt must not authorize the push.
    assert_eq!(
        salt_action(&salt_inputs(&local, Some(&other_b64), Some("deadbeef"))),
        SaltAction::RemoteKeyChanged
    );
}

#[test]
fn remote_epoch_ahead_blocks_a_stale_local_rekey() {
    // This device rekeyed and has a pending marker, but the remote has
    // since rotated again. Pushing our stale meta would clobber it.
    let local = [1u8; 16];
    let local_hex = hex::encode(local);
    let i = SaltInputs {
        local_salt: &local,
        local_epoch: 2,
        remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
        remote_epoch: Some(3),
        remote_key_change: None,
        pending_marker: Some(&local_hex),
    };
    assert_eq!(salt_action(&i), SaltAction::RemoteKeyChanged);
}

#[test]
fn remote_epoch_ahead_with_matching_salt_still_proceeds() {
    // Salts match, so the key domains agree; a higher remote epoch is
    // bookkeeping, not a reason to abort.
    let local = [1u8; 16];
    let i = SaltInputs {
        local_salt: &local,
        local_epoch: 1,
        remote_salt_b64: Some(&b64_encode(&local)),
        remote_epoch: Some(9),
        remote_key_change: None,
        pending_marker: None,
    };
    assert_eq!(salt_action(&i), SaltAction::Proceed);
}

#[test]
fn remote_epoch_behind_does_not_block_our_newer_rekey() {
    let local = [1u8; 16];
    let i = SaltInputs {
        local_salt: &local,
        local_epoch: 5,
        remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
        remote_epoch: Some(4),
        remote_key_change: None,
        pending_marker: Some(&hex::encode(local)),
    };
    assert_eq!(salt_action(&i), SaltAction::PushRekey);
}

#[test]
fn remote_reset_is_distinguished_from_a_remote_rekey() {
    let local = [1u8; 16];
    let other = b64_encode(&[2u8; 16]);

    let mut i = SaltInputs {
        local_salt: &local,
        local_epoch: 1,
        remote_salt_b64: Some(&other),
        remote_epoch: Some(3),
        remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
        pending_marker: None,
    };
    assert_eq!(salt_action(&i), SaltAction::RemoteReset);

    // Same shape, but the remote rotated the key rather than being reset.
    i.remote_key_change = Some(models::constants::KEY_CHANGE_REKEY);
    assert_eq!(
        salt_action(&i),
        SaltAction::RemoteKeyChanged,
        "a rekey elsewhere keeps the guided adoption flow"
    );

    // A pre-migration remote row has no key_change: stay conservative.
    i.remote_key_change = None;
    assert_eq!(salt_action(&i), SaltAction::RemoteKeyChanged);
}

#[test]
fn remote_reset_never_triggers_on_matching_salt_or_lower_epoch() {
    let local = [1u8; 16];
    let matching = SaltInputs {
        local_salt: &local,
        local_epoch: 1,
        remote_salt_b64: Some(&b64_encode(&local)),
        remote_epoch: Some(99),
        remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
        pending_marker: None,
    };
    assert_eq!(salt_action(&matching), SaltAction::Proceed);

    let mut behind = matching;
    let diverged = b64_encode(&[2u8; 16]);
    behind.remote_salt_b64 = Some(&diverged);
    behind.local_epoch = 5;
    behind.remote_epoch = Some(4);
    assert_eq!(salt_action(&behind), SaltAction::RemoteKeyChanged);
}

#[test]
fn a_pending_reset_marker_beats_the_rekey_marker_check() {
    // This device has a stale rekey marker and the remote was reset after
    // it. The reset must win, or we would push our stale salt over the wipe.
    let local = [1u8; 16];
    let i = SaltInputs {
        local_salt: &local,
        local_epoch: 1,
        remote_salt_b64: Some(&b64_encode(&[2u8; 16])),
        remote_epoch: Some(3),
        remote_key_change: Some(models::constants::KEY_CHANGE_RESET),
        pending_marker: Some(&hex::encode(local)),
    };
    assert_eq!(salt_action(&i), SaltAction::RemoteReset);
}

#[test]
fn cursor_advances_to_max_seen_never_regresses() {
    let prev = Some(ts(50));
    let seen = vec![
        Some(ts(10)),
        Some(ts(90)),
        None, // row without ts must not poison the cursor
        Some(ts(70)),
    ];
    assert_eq!(next_cursor(prev, &seen), Some(ts(90)));
    assert_eq!(next_cursor(None, &seen), Some(ts(90)));
    assert_eq!(next_cursor(prev, &[]), prev);
    assert_eq!(next_cursor(None, &[None]), None);
}

#[test]
fn dto_mapping_roundtrip_preserves_fields_and_blobs() {
    let vid = uuid::Uuid::now_v7();
    let eid = uuid::Uuid::now_v7();
    let mut var = sample_var(vid, eid, ts(42));
    var.value_encrypted = vec![9, 8, 7, 6, 5];
    var.nonce = vec![1; 24];

    let dto = variable_to_dto(&var);
    assert_eq!(dto.value_encrypted, b64_encode(&[9, 8, 7, 6, 5]));
    let back = variable_from_dto(&dto).unwrap();
    assert_eq!(back.id, var.id);
    assert_eq!(back.environment_id, var.environment_id);
    assert_eq!(back.key, var.key);
    assert_eq!(back.value_encrypted, var.value_encrypted);
    assert_eq!(back.nonce, var.nonce);
    assert_eq!(back.version, var.version);
    assert_eq!(back.deleted, var.deleted);
    assert_eq!(back.updated_at, var.updated_at);
}

#[test]
fn report_display_mentions_counts() {
    let report = SyncReport {
        pushed: 3,
        pulled: 5,
        conflicts_won_remote: vec!["a".into(), "b".into()],
        deleted_pulled: 1,
        skipped_orphans: 0,
    };
    assert_eq!(
        report.to_string(),
        "3 subidas, 5 bajadas, 2 actualizados remotamente: a, b, 1 borrados"
    );
    let with_orphans = SyncReport {
        skipped_orphans: 2,
        ..report
    };
    assert_eq!(
        with_orphans.to_string(),
        "3 subidas, 5 bajadas, 2 actualizados remotamente: a, b, 1 borrados, 2 huérfanos omitidos"
    );
}

#[test]
fn orphaned_children_are_skipped_not_hard_failures() {
    let storage = Storage::open_in_memory().unwrap();
    let pid = uuid::Uuid::now_v7();
    storage
        .create_project(&sample_project(pid, ts(10), false))
        .unwrap();
    // No environment row locally.

    let orphan_env = EnvironmentRow {
        owner_id: None,
        id: uuid::Uuid::now_v7().to_string(),
        project_id: uuid::Uuid::now_v7().to_string(), // unknown project
        name: "staging".into(),
        is_default: false,
        sort_order: 0,
        deleted: false,
        updated_at: Some(ts(20)),
    };
    assert_eq!(
        merge_environment(&storage, &orphan_env).unwrap(),
        MergeOutcome::SkippedOrphan
    );
    assert!(storage
        .find_environment_by_id(parse_id(&orphan_env.id).unwrap())
        .unwrap()
        .is_none());

    // Known parent → applies normally.
    let child_env = EnvironmentRow {
        owner_id: None,
        id: uuid::Uuid::now_v7().to_string(),
        project_id: pid.to_string(),
        name: "local".into(),
        is_default: true,
        sort_order: 0,
        deleted: false,
        updated_at: Some(ts(20)),
    };
    assert_eq!(
        merge_environment(&storage, &child_env).unwrap(),
        MergeOutcome::Applied(false)
    );

    // Variable whose environment is unknown → skipped.
    let orphan_var = VariableRow {
        owner_id: None,
        id: uuid::Uuid::now_v7().to_string(),
        environment_id: uuid::Uuid::now_v7().to_string(), // unknown env
        key: "K".into(),
        value_encrypted: b64_encode(&[1, 2, 3]),
        nonce: b64_encode(&[0; 24]),
        notes: None,
        is_readonly: false,
        allow_export: true,
        deleted: false,
        version: 1,
        updated_at: Some(ts(20)),
    };
    assert_eq!(
        merge_variable(&storage, &orphan_var).unwrap(),
        MergeOutcome::SkippedOrphan
    );
}

#[test]
fn remote_sample_verification_accepts_right_key_and_empty_sample() {
    use crypto::{derive_master_key, encrypt};

    let password = SecretString::new("correct-horse".into());
    let salt = [7u8; 16];
    let params = KdfParams {
        m_cost: 2048,
        t_cost: 1,
        p_cost: 1,
        output_len: 32,
    };
    let good_key = derive_master_key(&password, &salt, &params).unwrap();
    let wrong_key = derive_master_key(&SecretString::new("wrong".into()), &salt, &params).unwrap();

    // A remote variable encrypted by the vault owner.
    let (ct, nonce) = encrypt(&good_key, "secret-value").unwrap();
    let row = VariableRow {
        owner_id: None,
        id: "018f0000-0000-7000-8000-000000000001".into(),
        environment_id: "018f0000-0000-7000-8000-000000000002".into(),
        key: "K".into(),
        value_encrypted: b64_encode(&ct),
        nonce: b64_encode(&nonce),
        notes: None,
        is_readonly: false,
        allow_export: true,
        deleted: false,
        version: 1,
        updated_at: None,
    };

    // Right password decrypts the remote sample.
    assert!(verify_key_against_sample(&good_key, std::slice::from_ref(&row)).is_ok());

    // Wrong password derives a different key → typed invalid-password error.
    assert!(matches!(
        verify_key_against_sample(&wrong_key, std::slice::from_ref(&row)),
        Err(CoreError::InvalidPassword(_))
    ));

    // Zero variables remotely → nothing to verify (accepted path).
    assert!(verify_key_against_sample(&good_key, &[]).is_ok());

    // Only tombstones → they still carry ciphertext; verification proceeds.
    let mut tombstone = row;
    tombstone.deleted = true;
    assert!(verify_key_against_sample(&good_key, &[tombstone]).is_ok());
}

fn vault_row_with_verifier(key: &MasterKey) -> VaultRow {
    let (ct, nonce) = encrypt(key, models::constants::VAULT_VERIFIER_MESSAGE).unwrap();
    VaultRow {
        owner_id: None,
        salt: "c2FsdA==".into(),
        kdf_params: serde_json::json!({"m_cost": 2048, "t_cost": 1, "p_cost": 1, "output_len": 32}),
        verifier_ct: Some(b64_encode(&ct)),
        verifier_nonce: Some(b64_encode(&nonce)),
        key_epoch: 1,
        key_change: Some("init".into()),
        key_changed_at: None,
    }
}

fn test_keys() -> (MasterKey, MasterKey, KdfParams, Vec<u8>) {
    let params = KdfParams {
        m_cost: 2048,
        t_cost: 1,
        p_cost: 1,
        output_len: 32,
    };
    let salt = vec![9u8; 16];
    let good =
        derive_master_key(&SecretString::new("correct-horse".into()), &salt, &params).unwrap();
    let bad = derive_master_key(&SecretString::new("wrong".into()), &salt, &params).unwrap();
    (good, bad, params, salt)
}

#[test]
fn verifier_accepts_only_the_right_key() {
    let (good, bad, _, _) = test_keys();
    let row = vault_row_with_verifier(&good);
    let (ct, nonce) = (
        b64_decode(row.verifier_ct.as_ref().unwrap()).unwrap(),
        b64_decode(row.verifier_nonce.as_ref().unwrap()).unwrap(),
    );
    assert!(verify_verifier(&good, &ct, &nonce).is_ok());
    assert!(matches!(
        verify_verifier(&bad, &ct, &nonce),
        Err(CoreError::InvalidPassword(_))
    ));
}

#[test]
fn verifier_rejects_ciphertext_of_the_wrong_constant() {
    // Right key, but the row was encrypted over some other plaintext: the
    // AEAD tag passes yet the message must not match.
    let (good, _, _, _) = test_keys();
    let (ct, nonce) = encrypt(&good, "some-other-value").unwrap();
    assert!(matches!(
        verify_verifier(&good, &ct, &nonce),
        Err(CoreError::InvalidPassword(_))
    ));
}

#[test]
fn verifier_row_without_nonce_is_an_explicit_error() {
    let (good, _, _, _) = test_keys();
    let mut row = vault_row_with_verifier(&good);
    row.verifier_nonce = None;
    assert!(matches!(
        verifier_parts(&row),
        Err(CoreError::RemoteVerifierIncomplete)
    ));
}

#[test]
fn backfill_only_on_matching_domain_without_verifier() {
    let key = test_keys().0;
    let mut old_row = vault_row_with_verifier(&key);
    old_row.verifier_ct = None;
    old_row.verifier_nonce = None;

    assert!(needs_verifier_backfill(SaltAction::Proceed, Some(&old_row)));
    assert!(
        !needs_verifier_backfill(SaltAction::Proceed, None),
        "no remote vault: the first push already carries the verifier"
    );
    assert!(
        !needs_verifier_backfill(SaltAction::RemoteKeyChanged, Some(&old_row)),
        "a salt mismatch must abort, never write"
    );
    assert!(
        !needs_verifier_backfill(SaltAction::PushRekey, Some(&old_row)),
        "a rekey push already carries a verifier"
    );
    assert!(
        !needs_verifier_backfill(SaltAction::Proceed, Some(&vault_row_with_verifier(&key))),
        "already has a verifier"
    );
}

#[test]
fn init_remote_guard_does_not_consult_the_vault_being_created() {
    let dir = tempfile::tempdir().unwrap();
    let fresh = App::open(dir.path().join("vault.db")).unwrap();

    // A database that was just created has no master-key session of its own…
    assert!(fresh.session_store().unwrap().is_none());

    // …yet the guard `vltr init` runs is armed by ACCOUNT-level state only,
    // so it still fires. That is the situation on every `init`.
    assert!(init_remote_guard_needed(true, true));
    assert!(!init_remote_guard_needed(false, true));
    assert!(!init_remote_guard_needed(true, false));

    // Compile-time pin on the probes: they keep taking no database. Making
    // the Supabase session per-vault again breaks this test at compile
    // time, because a new database has no session and the guard would
    // silently skip `remote_has_vault()`.
    let _configured: fn() -> bool = App::sync_available_config;
    let _session: fn() -> bool = App::sync_session_exists;
}

#[test]
fn stored_session_debug_never_leaks_tokens() {
    let stored = StoredSession {
        access_token: "SUPER-SECRET-ACCESS".into(),
        refresh_token: "super-secret-refresh".into(),
        expires_in: 3600,
        user_id: "u".into(),
        saved_at: 12345,
    };
    let text = format!("{stored:?}");
    assert!(!text.contains("SUPER-SECRET-ACCESS"));
    assert!(!text.contains("super-secret-refresh"));
    assert!(text.contains("StoredSession"));
}

/// `VLTR_SYNC_SESSION_FILE` is process-global: the tests that read or write
/// it must not run concurrently with each other.
fn env_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn sample_session() -> Session {
    Session {
        access_token: "access-token".into(),
        refresh_token: "refresh-token".into(),
        expires_in: 3600,
        user_id: "user-1".into(),
    }
}

#[test]
fn sync_session_override_roundtrips_through_the_file_only() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sync-session.json");
    std::env::set_var("VLTR_SYNC_SESSION_FILE", &path);

    // Control: the keyring probe must actually see a request, or the
    // assertion at the end of this test would pass vacuously.
    // `Entry::new` only builds the entry, it never reaches the backend.
    let before = keyring_calls();
    let _ = supabase_entry();
    assert_eq!(
        keyring_calls(),
        before + 1,
        "probe must observe a keyring request"
    );

    save_supabase_session(&sample_session()).unwrap();
    assert!(path.exists(), "override must be the file that gets written");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600, "session file must be 0600");
    }

    let loaded = load_stored_session()
        .unwrap()
        .expect("override file must be read back");
    assert_eq!(loaded.access_token, "access-token");
    assert_eq!(loaded.refresh_token, "refresh-token");
    assert_eq!(loaded.user_id, "user-1");
    assert_eq!(loaded.expires_in, 3600);

    clear_supabase_session().unwrap();
    assert!(!path.exists(), "clear must remove the override file");
    assert!(load_stored_session().unwrap().is_none());

    // The load-bearing assertion: none of the above asked for the keyring.
    assert_eq!(
        keyring_calls(),
        before + 1,
        "the override must bypass the keyring entirely"
    );

    std::env::remove_var("VLTR_SYNC_SESSION_FILE");
}

#[test]
fn sync_session_override_missing_file_is_not_logged_in() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    std::env::set_var("VLTR_SYNC_SESSION_FILE", dir.path().join("absent.json"));

    let before = keyring_calls();
    assert!(load_stored_session().unwrap().is_none());
    // `clear` with no file is a no-op, not an error (matches `vltr logout`
    // being idempotent).
    clear_supabase_session().unwrap();
    assert_eq!(keyring_calls(), before);

    std::env::remove_var("VLTR_SYNC_SESSION_FILE");
}

#[test]
fn sync_session_override_reports_a_file_it_could_not_delete() {
    let _guard = env_lock();
    let dir = tempfile::tempdir().unwrap();
    // The override file holds the account's Supabase tokens, and the delete has
    // to fail for a reason no user privilege can talk the process out of: a
    // directory in its place answers `unlink` with EISDIR.
    let path = dir.path().join("sync-session.json");
    std::fs::create_dir(&path).unwrap();
    std::env::set_var("VLTR_SYNC_SESSION_FILE", &path);

    let error = clear_supabase_session()
        .expect_err("a sync session file that survived the delete must not be reported as closed");
    assert!(
        error.to_string().contains("sync session"),
        "the error must name what could not be removed, got: {error}"
    );
    assert!(path.exists(), "the file is still there, which is the point");

    std::fs::remove_dir(&path).unwrap();
    std::env::remove_var("VLTR_SYNC_SESSION_FILE");
}

#[test]
fn blank_sync_session_override_falls_back_to_the_default_file() {
    let _guard = env_lock();
    std::env::remove_var("VLTR_SYNC_SESSION_FILE");
    assert!(
        sync_session_file_override().is_none(),
        "unset must not be an override"
    );
    let default = supabase_session_file().unwrap();

    std::env::set_var("VLTR_SYNC_SESSION_FILE", "");
    assert!(
        sync_session_file_override().is_none(),
        "empty is not a path"
    );
    assert_eq!(
        supabase_session_file().unwrap(),
        default,
        "empty must fall back"
    );

    std::env::set_var("VLTR_SYNC_SESSION_FILE", "   ");
    assert_eq!(
        supabase_session_file().unwrap(),
        default,
        "whitespace must fall back"
    );

    assert!(
        default.ends_with("sync-session.json"),
        "default path must not change, got {default:?}"
    );

    std::env::remove_var("VLTR_SYNC_SESSION_FILE");
}
