//! Row DTOs mirroring the Supabase tables in supabase/migrations/0001_init.sql.
//! Column names are snake_case exactly as PostgREST exposes them; blob fields
//! are base64 TEXT — encoding is the caller's job (core).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultRow {
    pub owner_id: Option<String>,
    /// base64
    pub salt: String,
    pub kdf_params: serde_json::Value,
    /// base64 ciphertext of `VAULT_VERIFIER_MESSAGE` under the current master key.
    /// `None` for vaults written before 0002_key_epoch_verifier.
    #[serde(default)]
    pub verifier_ct: Option<String>,
    #[serde(default)]
    pub verifier_nonce: Option<String>,
    #[serde(default = "default_key_epoch")]
    pub key_epoch: i64,
    #[serde(default = "default_key_change")]
    pub key_change: Option<String>,
    #[serde(default)]
    pub key_changed_at: Option<DateTime<Utc>>,
}

fn default_key_epoch() -> i64 {
    1
}

fn default_key_change() -> Option<String> {
    Some("init".to_string())
}

// created_at/updated_at are server-side; not sent or needed on pull.

// ---------------------------------------------------------------------------
// Bulk-push key uniformity
// ---------------------------------------------------------------------------
//
// PostgREST requires that every row of a bulk upsert
// (`Prefer: resolution=merge-duplicates`) carry the SAME set of keys, and
// answers `PGRST102` / 400 — rejecting the whole batch, not just the odd row —
// otherwise. So the optional columns below must serialise as an explicit `null`
// when they are absent, and must NOT carry `skip_serializing_if`: omitting the
// key for one row makes the batch heterogeneous and takes the entire sync down.
//
// `default` is the opposite half and stays: it is for *deserialising* a row the
// server may have written without that column (a pre-migration vault, a
// defaulted column), not for serialising.
//
// This bites as soon as a vault is not homogeneous. A seed where every project
// has no description is uniform by accident and hides it; the mixed shape
// arrives the moment a second device pushes a project that has one.
//
// `VaultRow` is deliberately exempt: `push_vault` is a single-row upsert, which
// is trivially uniform, and there is nothing to disagree with.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectRow {
    pub owner_id: Option<String>,
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub color: Option<String>,
    pub icon: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default = "one")]
    pub version: i64,
    /// Server-side `updated_at` (timestamptz). Parsed to `DateTime<Utc>`
    /// before any comparison — never compare raw strings.
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentRow {
    pub owner_id: Option<String>,
    pub id: String,
    pub project_id: String,
    pub name: String,
    #[serde(default)]
    pub is_default: bool,
    #[serde(default)]
    pub sort_order: i32,
    #[serde(default)]
    pub deleted: bool,
    /// Server-side `updated_at` (timestamptz). Parsed to `DateTime<Utc>`
    /// before any comparison — never compare raw strings.
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VariableRow {
    pub owner_id: Option<String>,
    pub id: String,
    pub environment_id: String,
    pub key: String,
    /// base64 ciphertext (XChaCha20-Poly1305)
    pub value_encrypted: String,
    /// base64, 24 bytes
    pub nonce: String,
    pub notes: Option<String>,
    #[serde(default)]
    pub is_readonly: bool,
    #[serde(default = "yes")]
    pub allow_export: bool,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default = "one")]
    pub version: i64,
    /// Server-side `updated_at` (timestamptz). Parsed to `DateTime<Utc>`
    /// before any comparison — never compare raw strings.
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
}

fn one() -> i64 {
    1
}
fn yes() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    #[test]
    fn variable_row_roundtrip_snake_case() {
        let row = VariableRow {
            owner_id: None,
            id: "018f0000-0000-7000-8000-000000000001".into(),
            environment_id: "018f0000-0000-7000-8000-000000000002".into(),
            key: "API_KEY".into(),
            value_encrypted: "Y2lwaGVydGV4dA==".into(),
            nonce: "MjRieXRlc25vbmNl".into(),
            notes: None,
            is_readonly: true,
            allow_export: false,
            deleted: false,
            version: 3,
            updated_at: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"value_encrypted\""));
        assert!(json.contains("\"environment_id\""));
        assert!(json.contains("\"is_readonly\""));
        assert!(json.contains("\"allow_export\""));
        assert!(json.contains("\"updated_at\":\"2026-01-01T00:00:00Z\""));
        assert!(!json.contains("valueEncrypted"));
        let back: VariableRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
    }

    #[test]
    fn project_row_roundtrip_with_defaults() {
        // Server may omit defaulted columns on pull; defaults must fill in.
        let minimal = r#"{"id":"p1","name":"proj","updated_at":"2026-01-01T00:00:00Z"}"#;
        let row: ProjectRow = serde_json::from_str(minimal).unwrap();
        assert!(!row.deleted);
        assert_eq!(row.version, 1);
        assert_eq!(
            row.updated_at,
            Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap())
        );
        let json = serde_json::to_string(&row).unwrap();
        let back: ProjectRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
    }

    #[test]
    fn vault_row_parses_post_migration_shape() {
        let json = r#"{
            "owner_id": "u",
            "salt": "c2FsdA==",
            "kdf_params": {"m_cost": 19456, "t_cost": 2, "p_cost": 1, "output_len": 32},
            "verifier_ct": "Y3Q=",
            "verifier_nonce": "bm9uY2U=",
            "key_epoch": 3,
            "key_change": "reset",
            "key_changed_at": "2026-10-02T00:00:00Z"
        }"#;
        let row: VaultRow = serde_json::from_str(json).unwrap();
        assert_eq!(row.verifier_ct.as_deref(), Some("Y3Q="));
        assert_eq!(row.key_epoch, 3);
        assert_eq!(row.key_change.as_deref(), Some("reset"));
    }

    #[test]
    fn vault_row_parses_pre_migration_shape_with_defaults() {
        // Row written before 0002_key_epoch_verifier: no verifier, no epoch.
        let json = r#"{"salt": "c2FsdA==", "kdf_params": {"m_cost": 19456, "t_cost": 2, "p_cost": 1, "output_len": 32}}"#;
        let row: VaultRow = serde_json::from_str(json).unwrap();
        assert_eq!(row.verifier_ct, None);
        assert_eq!(row.verifier_nonce, None);
        assert_eq!(row.key_epoch, 1, "missing key_epoch defaults to 1");
        assert_eq!(row.key_change, Some("init".into()));
        assert_eq!(row.key_changed_at, None);
    }

    #[test]
    fn vault_row_kdf_params_is_opaque_json() {
        let row = VaultRow {
            owner_id: None,
            salt: "c2FsdA==".into(),
            kdf_params: serde_json::json!({"m": 19456, "t": 2, "p": 1}),
            verifier_ct: None,
            verifier_nonce: None,
            key_epoch: 1,
            key_change: Some("init".into()),
            key_changed_at: None,
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"salt\":\"c2FsdA==\""));
        let back: VaultRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
    }

    // ---------- Bulk-push key uniformity ----------

    /// Sorted set of keys a row puts on the wire. PostgREST compares these
    /// across a whole bulk-upsert batch and rejects the batch if they differ.
    fn wire_keys<T: Serialize>(row: &T) -> Vec<String> {
        let value = serde_json::to_value(row).unwrap();
        let mut keys: Vec<String> = value.as_object().unwrap().keys().cloned().collect();
        keys.sort();
        keys
    }

    fn project_row(description: Option<&str>) -> ProjectRow {
        ProjectRow {
            owner_id: Some("u".into()),
            id: "018f0000-0000-7000-8000-000000000001".into(),
            name: "proj".into(),
            description: description.map(str::to_owned),
            color: None,
            icon: None,
            deleted: false,
            version: 1,
            updated_at: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        }
    }

    fn environment_row() -> EnvironmentRow {
        EnvironmentRow {
            owner_id: Some("u".into()),
            id: "018f0000-0000-7000-8000-000000000002".into(),
            project_id: "018f0000-0000-7000-8000-000000000001".into(),
            name: "local".into(),
            is_default: true,
            sort_order: 0,
            deleted: false,
            updated_at: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        }
    }

    fn variable_row(notes: Option<&str>) -> VariableRow {
        VariableRow {
            owner_id: Some("u".into()),
            id: "018f0000-0000-7000-8000-000000000003".into(),
            environment_id: "018f0000-0000-7000-8000-000000000002".into(),
            key: "TOKEN".into(),
            value_encrypted: "Y2lwaGVydGV4dA==".into(),
            nonce: "MjRieXRlc25vbmNl".into(),
            notes: notes.map(str::to_owned),
            is_readonly: false,
            allow_export: true,
            deleted: false,
            version: 1,
            updated_at: Some(Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()),
        }
    }

    /// Two projects, one with a description and one without, must serialise to
    /// the same set of keys — the difference between a bulk upsert that lands
    /// and one PostgREST answers with `PGRST102` / 400, rejecting **every** row
    /// of the batch.
    ///
    /// This is the whole bug in miniature, with no network and no fake: a
    /// homogeneous seed is uniform by accident, which is why the mixed shape is
    /// the only one worth a test. `null` is fine — a *missing key* is what the
    /// server refuses.
    #[test]
    fn two_projects_one_described_and_one_not_serialise_to_the_same_keys() {
        let described = project_row(Some("has a description"));
        let bare = project_row(None);

        assert_eq!(
            wire_keys(&described),
            wire_keys(&bare),
            "PGRST102: two projects in one push must agree on which columns they \
             carry, or the server rejects the whole batch"
        );

        let keys = wire_keys(&bare);
        for column in ["description", "color", "icon", "updated_at"] {
            assert!(
                keys.iter().any(|k| k == column),
                "{column} must be present on every row — absent is what serialising \
                 an Option as a missing key means"
            );
        }

        // The absent description is an explicit null, not a hole.
        let json = serde_json::to_value(&bare).unwrap();
        assert!(
            json["description"].is_null(),
            "an absent description must go out as null, not be dropped"
        );
    }

    /// Same guarantee for the other two DTOs that go into a bulk push, since a
    /// `skip_serializing_if` reintroduced on any one of them is enough to break
    /// a real sync.
    #[test]
    fn optional_columns_never_disappear_from_a_serialised_row() {
        // `notes` is the only variable column that can be empty in practice,
        // and the one a user triggers by leaving notes off a single variable.
        assert_eq!(
            wire_keys(&variable_row(Some("has notes"))),
            wire_keys(&variable_row(None))
        );

        // `EnvironmentRow` has a single optional column and both `local` and a
        // staged environment arrive in the same batch, so it is the quiet one.
        assert_eq!(
            wire_keys(&environment_row()),
            wire_keys(&EnvironmentRow {
                updated_at: None,
                ..environment_row()
            })
        );

        // An entirely absent optional value still yields the key.
        let keys = wire_keys(&EnvironmentRow {
            updated_at: None,
            ..environment_row()
        });
        assert!(
            keys.iter().any(|k| k == "updated_at"),
            "a None updated_at must still serialise, as null"
        );
    }

    /// The converse of the guarantee above, and the reason the fix was not done
    /// by deleting `#[serde(default)]`: a row the server wrote *without* an
    /// optional column still has to deserialise. Both halves are needed —
    /// `default` for the pull, an unconditional key for the push.
    #[test]
    fn an_absent_column_still_deserialises_from_a_server_row() {
        let minimal = r#"{"id":"e1","project_id":"p1","name":"local"}"#;
        let env: EnvironmentRow = serde_json::from_str(minimal).unwrap();
        assert_eq!(
            env.updated_at, None,
            "a server row without updated_at must still parse"
        );
        // Plain `#[serde(default)]` is bool::default(), i.e. false. Recorded
        // here because it is easy to mistake for a true default.
        assert!(!env.is_default);
        assert_eq!(env.sort_order, 0);
        assert!(!env.deleted);

        let minimal = r#"{"id":"v1","environment_id":"e1","key":"K","value_encrypted":"Y3Q=","nonce":"bm9uY2U="}"#;
        let var: VariableRow = serde_json::from_str(minimal).unwrap();
        assert_eq!(var.notes, None);
        assert!(var.allow_export);
        assert_eq!(var.version, 1);
    }
}
