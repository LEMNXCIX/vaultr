//! Supabase REST transport: auth (email+password with refresh) and
//! PostgREST upsert push / paginated pull. Transport only — no business
//! logic, no base64 handling (caller in `core` does that).

mod auth;
mod dto;

pub use auth::Session;
pub use dto::{EnvironmentRow, ProjectRow, VariableRow, VaultRow};

use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("config error: {0}")]
    Config(String),
    /// A row body could not be serialised at all. Distinct from `Http`: nothing
    /// left the process.
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
    /// Refused before the network, by [`SyncClient::push_rows`]: a row would
    /// have gone out without a usable `updated_at`, which the server's
    /// `NOT NULL` column refuses. Carries a message naming the table and the
    /// column, because the alternative — the server's own answer — names
    /// neither once it reaches a caller as a bare status code.
    #[error("{0}")]
    NullUpdatedAt(String),
}

pub type Result<T> = std::result::Result<T, SyncError>;

const PAGE_SIZE: u32 = 2000;

pub struct SyncClient {
    http: reqwest::Client,
    base_url: String,
    anon_key: String,
}

/// Body sent to `vaults`. A struct rather than a parameter list: the row has
/// enough fields that positional args stop being readable at the call site.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct VaultMetaPush {
    pub salt: String,
    pub kdf_params: serde_json::Value,
    pub verifier_ct: Option<String>,
    pub verifier_nonce: Option<String>,
    pub key_epoch: i64,
    pub key_change: String,
    pub key_changed_at: Option<String>,
}

impl SyncClient {
    pub fn new(base_url: &str, anon_key: &str) -> Result<Self> {
        if base_url.is_empty() || anon_key.is_empty() {
            return Err(SyncError::Config(
                "base_url and anon_key must be set".into(),
            ));
        }
        let base_url = base_url.trim_end_matches('/').to_string();
        // ponytail: timeout fijo de 30s; configurable si sync por lotes grandes lo necesita
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .map_err(SyncError::Http)?;
        Ok(Self {
            http,
            base_url,
            anon_key: anon_key.to_string(),
        })
    }

    /// Upsert into `vaults` keyed by `owner_id` (its primary key).
    pub async fn push_vault(&self, session: &Session, meta: &VaultMetaPush) -> Result<()> {
        let mut row = VaultRow {
            owner_id: Some(session.user_id.clone()),
            salt: meta.salt.clone(),
            kdf_params: meta.kdf_params.clone(),
            verifier_ct: meta.verifier_ct.clone(),
            verifier_nonce: meta.verifier_nonce.clone(),
            key_epoch: meta.key_epoch,
            key_change: Some(meta.key_change.clone()),
            key_changed_at: None,
        };
        if let Some(ts) = &meta.key_changed_at {
            row.key_changed_at = Some(
                DateTime::parse_from_rfc3339(ts)
                    .map_err(|e| SyncError::Config(format!("invalid key_changed_at: {e}")))?
                    .with_timezone(&Utc),
            );
        }
        self.post_upsert(session, "vaults", "owner_id", &[row])
            .await
    }

    pub async fn get_vault(&self, session: &Session) -> Result<Option<VaultRow>> {
        let url = format!("{}/rest/v1/vaults?select=*&limit=1", self.base_url);
        let resp = self
            .http
            .get(&url)
            .bearer_auth(&session.access_token)
            .header("apikey", &self.anon_key)
            .send()
            .await?;
        let mut rows = self.parse_rest(resp).await?;
        Ok(if rows.is_empty() {
            None
        } else {
            Some(rows.swap_remove(0))
        })
    }

    /// Bulk upsert via PostgREST merge-duplicates; conflicts resolve on the
    /// table's primary key (`id`).
    ///
    /// The body is serialised, checked, then sent — the check is the point.
    /// Every table pushed here declares `updated_at timestamptz not null
    /// default now()`, and the row DTOs type that column as `Option` because
    /// the *pull* needs it (a server row may omit it, `#[serde(default)]`
    /// covers that). Postgres applies a column default to an **absent** key and
    /// to nothing else, so a row carrying `"updated_at": null` is a `23502
    /// not_null_violation`: a 400 that arrives as a bare status code, from
    /// which nothing downstream can tell which column was wrong. See
    /// [`reject_unstamped`].
    ///
    /// `vaults` is deliberately not covered by that check: it is pushed
    /// through [`SyncClient::push_vault`], carries no `updated_at` at all, and
    /// the client never reads the server's stamp on it.
    pub async fn push_rows<T: Serialize>(
        &self,
        session: &Session,
        table: &str,
        rows: &[T],
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let body = serde_json::to_value(rows)?;
        // A slice always serialises to a JSON array.
        let batch = body.as_array().expect("a serialised slice");
        reject_unstamped(table, batch)?;
        let url = format!("{}/rest/v1/{table}", self.base_url);
        // ponytail: single POST assumes caller chunks; PostgREST handles MVP-scale payloads
        let resp = self
            .http
            .post(&url)
            .header("Prefer", "resolution=merge-duplicates,return=minimal")
            .bearer_auth(&session.access_token)
            .header("apikey", &self.anon_key)
            .json(&body)
            .send()
            .await?;
        Self::check(resp).await
    }

    /// Pull rows updated after `since` (all rows when None), oldest first,
    /// paged via Range header until a short page.
    pub async fn pull_rows<T: DeserializeOwned>(
        &self,
        session: &Session,
        table: &str,
        since: Option<&str>,
    ) -> Result<Vec<T>> {
        let mut out = Vec::new();
        let mut offset: u32 = 0;
        loop {
            let page = self
                .pull_page_at::<T>(session, table, since, offset)
                .await?;
            let short = page.len() < PAGE_SIZE as usize;
            out.extend(page);
            if short {
                break;
            }
            offset += PAGE_SIZE;
        }
        Ok(out)
    }

    /// First page only (up to PAGE_SIZE rows, oldest first). Used where the
    /// full table is unnecessary, e.g. sampling a ciphertext to verify a
    /// password during bootstrap.
    pub async fn pull_page<T: DeserializeOwned>(
        &self,
        session: &Session,
        table: &str,
    ) -> Result<Vec<T>> {
        self.pull_page_at(session, table, None, 0).await
    }

    async fn pull_page_at<T: DeserializeOwned>(
        &self,
        session: &Session,
        table: &str,
        since: Option<&str>,
        offset: u32,
    ) -> Result<Vec<T>> {
        let to = offset + PAGE_SIZE - 1;
        let mut url = format!(
            "{}/rest/v1/{table}?select=*&order=updated_at.asc",
            self.base_url
        );
        if let Some(since) = since {
            url.push_str(&format!("&updated_at=gt.{since}"));
        }
        let resp = self
            .http
            .get(&url)
            .header("Range", format!("{offset}-{to}"))
            .bearer_auth(&session.access_token)
            .header("apikey", &self.anon_key)
            .send()
            .await?;
        self.parse_rest(resp).await
    }

    async fn post_upsert<T: Serialize>(
        &self,
        session: &Session,
        table: &str,
        conflict: &str,
        rows: &[T],
    ) -> Result<()> {
        let url = format!("{}/rest/v1/{table}?on_conflict={conflict}", self.base_url);
        let resp = self
            .http
            .post(&url)
            .header("Prefer", "resolution=merge-duplicates,return=minimal")
            .bearer_auth(&session.access_token)
            .header("apikey", &self.anon_key)
            .json(rows)
            .send()
            .await?;
        Self::check(resp).await
    }

    async fn check(resp: reqwest::Response) -> Result<()> {
        resp.error_for_status().map(|_| ()).map_err(SyncError::from)
    }

    async fn parse_rest<T: DeserializeOwned>(&self, resp: reqwest::Response) -> Result<Vec<T>> {
        let resp = resp.error_for_status()?;
        resp.json::<Vec<T>>().await.map_err(Into::into)
    }
}

/// Refuse a batch in which any row would go out without a usable `updated_at`.
/// Pure; the wire body is already serialised when it is called, so this reads
/// what would actually be sent rather than what the caller meant to send.
///
/// Two shapes are refused, and neither is filled in with a substitute value:
///
/// * **`null`** — what `updated_at: None` serialises to. The column is `NOT
///   NULL`, so the server answers `23502 not_null_violation` and the whole
///   batch is lost.
/// * **absent** — reachable only if a `skip_serializing_if` ever reaches this
///   DTO. Legal SQL, and worse: the column's `default now()` would cover it and
///   the row would enter the LWW merge carrying a timestamp the vault invented.
///   The brief of this function is that a push either carries the row's own
///   timestamp or does not go out.
///
/// The error names the table, the column and the offending row's position,
/// because the alternative is a 400 that carries none of them and reaches the
/// CLI as `Sin conexión con Supabase: http error: status code 400`.
fn reject_unstamped(table: &str, rows: &[serde_json::Value]) -> Result<()> {
    for (index, row) in rows.iter().enumerate() {
        let reason = match row.get("updated_at") {
            None => Some("does not carry `updated_at` at all, which the server would stamp"),
            Some(serde_json::Value::Null) => Some("carries `updated_at: null`"),
            Some(_) => None,
        };
        let Some(reason) = reason else { continue };
        return Err(SyncError::NullUpdatedAt(format!(
            "refusing to push to `{table}`: row {} of {} {reason} \
             (the column is NOT NULL on the server)",
            index + 1,
            rows.len()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The guard is where the DTO's `Option` stops being a wire value, and it
    /// is pure — so the refusal is testable with no network and no server.
    #[test]
    fn a_stamped_batch_passes() {
        let rows = vec![
            json!({"id": "a", "updated_at": "2026-01-01T00:00:00Z"}),
            json!({"id": "b", "updated_at": "2026-01-02T00:00:00Z"}),
        ];
        assert!(reject_unstamped("variables", &rows).is_ok());
    }

    /// The reported hole: `None` goes out as an explicit `null`, and the
    /// message has to name the column, the table and the row — the whole point
    /// of refusing here instead of letting the server answer with a bare 400.
    #[test]
    fn a_null_updated_at_is_refused_and_the_message_names_field_and_table() {
        let rows = vec![
            json!({"id": "a", "updated_at": "2026-01-01T00:00:00Z"}),
            json!({"id": "b", "updated_at": null}),
            json!({"id": "c", "updated_at": "2026-01-02T00:00:00Z"}),
        ];
        let err = reject_unstamped("variables", &rows).expect_err("row 2 has no timestamp");
        assert!(matches!(err, SyncError::NullUpdatedAt(_)), "{err}");
        let message = err.to_string();
        assert!(message.contains("updated_at"), "{message}");
        assert!(message.contains("variables"), "{message}");
        assert!(message.contains("row 2 of 3"), "{message}");
    }

    /// The silent-corruption half. Legal SQL, so nothing would fail — the
    /// server would just hand the row a `now()` and the merge would take it as
    /// the row's own. Refusing is the only honest answer, and it is why an
    /// absent key is treated like a null one.
    #[test]
    fn an_absent_updated_at_is_refused_rather_than_left_to_the_column_default() {
        let rows = vec![json!({"id": "a", "name": "no timestamp"})];
        let err = reject_unstamped("projects", &rows).expect_err("the column has a default");
        let message = err.to_string();
        assert!(message.contains("updated_at"), "{message}");
        assert!(message.contains("projects"), "{message}");
    }

    /// An empty batch is not a violation — `push_rows` returns `Ok` early for
    /// it, and the guard agrees rather than inventing a row to complain about.
    #[test]
    fn an_empty_batch_is_not_a_violation() {
        assert!(reject_unstamped("projects", &[]).is_ok());
    }
}
