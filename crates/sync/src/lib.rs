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
    pub async fn push_rows<T: Serialize>(
        &self,
        session: &Session,
        table: &str,
        rows: &[T],
    ) -> Result<()> {
        if rows.is_empty() {
            return Ok(());
        }
        let url = format!("{}/rest/v1/{table}", self.base_url);
        // ponytail: single POST assumes caller chunks; PostgREST handles MVP-scale payloads
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
