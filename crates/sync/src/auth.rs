use super::{Result, SyncError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize)]
pub struct Session {
    pub access_token: String,
    pub refresh_token: String,
    #[serde(default)]
    pub expires_in: u64,
    /// `sub` del JWT; se estampa como `owner_id` en cada fila pusheada.
    #[serde(default)]
    pub user_id: String,
}

#[derive(Deserialize)]
struct GoTrueUser {
    id: String,
}

#[derive(Serialize)]
struct PasswordGrant<'a> {
    email: &'a str,
    password: &'a str,
}

#[derive(Serialize)]
struct RefreshGrant<'a> {
    refresh_token: &'a str,
}

#[derive(Deserialize)]
struct AuthErrorBody {
    #[serde(default)]
    msg: Option<String>,
    #[serde(default)]
    error_description: Option<String>,
    #[serde(default)]
    error: Option<String>,
}

/// Extract a short message from a Supabase auth error body.
/// Result is capped at 200 chars; bodies here never contain secrets.
pub fn parse_auth_error(body: &str) -> String {
    let parsed: Option<AuthErrorBody> = serde_json::from_str(body).ok();
    let msg = parsed
        .and_then(|e| e.msg.or(e.error_description).or(e.error))
        .unwrap_or_else(|| body.chars().take(200).collect());
    msg.chars().take(200).collect()
}

impl super::SyncClient {
    /// Email+password login against `{base}/auth/v1/token?grant_type=password`.
    pub async fn login(&self, email: &str, password: &str) -> Result<Session> {
        self.auth_post(
            &format!("{}/auth/v1/token?grant_type=password", self.base_url),
            &PasswordGrant { email, password },
        )
        .await
    }

    /// Refresh an expired session via grant_type=refresh_token.
    pub async fn refresh(&self, refresh_token: &str) -> Result<Session> {
        self.auth_post(
            &format!("{}/auth/v1/token?grant_type=refresh_token", self.base_url),
            &RefreshGrant { refresh_token },
        )
        .await
    }

    async fn auth_post<B: Serialize>(&self, url: &str, body: &B) -> Result<Session> {
        #[derive(Deserialize)]
        struct GoTrueSession {
            #[serde(flatten)]
            session: Session,
            #[serde(default)]
            user: Option<GoTrueUser>,
        }

        let resp = self
            .http
            .post(url)
            .header("apikey", &self.anon_key)
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().await.unwrap_or_default();
            return Err(SyncError::Auth(parse_auth_error(&text)));
        }
        let mut parsed: GoTrueSession = resp.json().await.map_err(SyncError::Http)?;
        if let Some(user) = parsed.user {
            parsed.session.user_id = user.id;
        }
        Ok(parsed.session)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_deserializes_supabase_response() {
        let body = r#"{
            "access_token":"eyJ...",
            "token_type":"bearer",
            "expires_in":3600,
            "expires_at":1790000000,
            "refresh_token":"rt-token"
        }"#;
        let s: Session = serde_json::from_str(body).unwrap();
        assert_eq!(s.access_token, "eyJ...");
        assert_eq!(s.refresh_token, "rt-token");
        assert_eq!(s.expires_in, 3600);
    }

    #[test]
    fn parse_auth_error_modern_msg_field() {
        assert_eq!(
            parse_auth_error(r#"{"msg":"Invalid login credentials","code":400}"#),
            "Invalid login credentials"
        );
    }

    #[test]
    fn parse_auth_error_legacy_error_description() {
        assert_eq!(
            parse_auth_error(
                r#"{"error":"invalid_grant","error_description":"Invalid refresh token"}"#
            ),
            "Invalid refresh token"
        );
    }

    #[test]
    fn parse_auth_error_truncates_and_never_panics_on_non_json() {
        let long = "x".repeat(500);
        assert_eq!(parse_auth_error(&long).len(), 200);
        assert_eq!(parse_auth_error("not json at all"), "not json at all");
        // JSON with no known fields falls back to truncated raw body
        assert_eq!(parse_auth_error(r#"{"a":1}"#), r#"{"a":1}"#);
    }
}
