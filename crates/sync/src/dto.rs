//! Row DTOs mirroring the Supabase tables in supabase/migrations/0001_init.sql.
//! Column names are snake_case exactly as PostgREST exposes them; blob fields
//! are base64 TEXT — encoding is the caller's job (core).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultRow {
    /// base64
    pub salt: String,
    pub kdf_params: serde_json::Value,
}

// owner_id/created_at/updated_at are server-side; not sent or needed on pull.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProjectRow {
    pub id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default = "one")]
    pub version: i64,
    /// Server-side `updated_at` (timestamptz). Parsed to `DateTime<Utc>`
    /// before any comparison — never compare raw strings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EnvironmentRow {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VariableRow {
    pub id: String,
    pub environment_id: String,
    pub key: String,
    /// base64 ciphertext (XChaCha20-Poly1305)
    pub value_encrypted: String,
    /// base64, 24 bytes
    pub nonce: String,
    #[serde(skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    fn vault_row_kdf_params_is_opaque_json() {
        let row = VaultRow {
            salt: "c2FsdA==".into(),
            kdf_params: serde_json::json!({"m": 19456, "t": 2, "p": 1}),
        };
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.contains("\"salt\":\"c2FsdA==\""));
        let back: VaultRow = serde_json::from_str(&json).unwrap();
        assert_eq!(back, row);
    }
}
