//! A stateful stand-in for PostgREST + GoTrue, shared by the sync HTTP tests.
//!
//! Every endpoint `SyncClient` speaks is mounted on one in-process
//! [`MockServer`] backed by an in-memory store with real upsert semantics:
//! `vaults` keyed by `owner_id`, the rest keyed by `id`. A mock answering with
//! a fixed body cannot tell a push from a pull, a live row from a tombstone or
//! one client from two — and telling those apart is the whole point of these
//! tests, so the store has to be real.
//!
//! The store is also *inspectable from the test*: the assertions read the rows
//! the client actually left behind (and the bytes it actually sent), rather
//! than re-deriving them from the client side.
//!
//! # Nothing here can reach the keyring
//!
//! `Remote::start` points [`SUPABASE_URL_ENV`], [`SUPABASE_KEY_ENV`] and
//! `VLTR_SYNC_SESSION_FILE` at this server and a temp file. The last one is what
//! makes the Supabase session path safe: with it set, `sync.rs` never calls
//! `supabase_entry()`, so the account-global `supabase-session` keyring entry
//! cannot be overwritten by a test run. The tests build their vaults with
//! `App::open_in_memory`, which `session::save_master_key(None, ..)` short
//! circuits, so the master-key side never reaches the keyring either.
//!
//! [`SUPABASE_URL_ENV`]: vltr_core::sync::SUPABASE_URL_ENV
//! [`SUPABASE_KEY_ENV`]: vltr_core::sync::SUPABASE_KEY_ENV

#![allow(dead_code)] // each test binary links this module and uses a subset

use serde_json::{json, Value};
use std::sync::{Arc, Mutex, MutexGuard};
use vltr_core::sync::{SUPABASE_KEY_ENV, SUPABASE_URL_ENV};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

/// `user.id` returned by the fake GoTrue token endpoint; also the `owner_id`
/// stamped on every row the client pushes.
pub const TEST_USER_ID: &str = "e2e00000-0000-7000-8000-000000000001";

const SYNC_SESSION_FILE_ENV: &str = "VLTR_SYNC_SESSION_FILE";

/// Drive a future on a single-threaded runtime, exactly like the CLI's
/// `block_on` (`crates/cli/src/main.rs`). Deliberately *not*
/// `#[tokio::test]`: its default multi-threaded runtime would be a second,
/// differently-configured runtime in the same process as the one running
/// `MockServer`.
pub fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(fut)
}

// ---------- Store ----------

/// The remote database, in memory.
#[derive(Default)]
pub struct Store {
    vaults: Vec<Value>,
    projects: Vec<Value>,
    environments: Vec<Value>,
    variables: Vec<Value>,
    /// Number of upcoming `POST /rest/v1/vaults` to answer with 500.
    vault_push_failures: usize,
}

impl Store {
    fn table(&self, table: &str) -> &Vec<Value> {
        match table {
            "vaults" => &self.vaults,
            "projects" => &self.projects,
            "environments" => &self.environments,
            "variables" => &self.variables,
            other => panic!("unknown table {other}"),
        }
    }

    fn table_mut(&mut self, table: &str) -> &mut Vec<Value> {
        match table {
            "vaults" => &mut self.vaults,
            "projects" => &mut self.projects,
            "environments" => &mut self.environments,
            "variables" => &mut self.variables,
            other => panic!("unknown table {other}"),
        }
    }

    /// The remote vault row, if the account has one.
    pub fn vault(&self) -> Option<Value> {
        self.vaults.first().cloned()
    }

    /// base64 salt of the remote vault row — the key-domain identifier the
    /// salt guard compares against.
    pub fn vault_salt(&self) -> Option<String> {
        self.vault()
            .and_then(|v| v.get("salt").and_then(Value::as_str).map(str::to_owned))
    }

    /// Install a remote vault row (the `owner_id` is always `TEST_USER_ID`).
    pub fn set_vault(&mut self, salt_b64: &str, kdf_params: Value) {
        self.vaults = vec![json!({
            "owner_id": TEST_USER_ID,
            "salt": salt_b64,
            "kdf_params": kdf_params,
        })];
    }

    pub fn projects(&self) -> &[Value] {
        &self.projects
    }

    pub fn variables(&self) -> &[Value] {
        &self.variables
    }

    /// Insert variable rows directly, as another device (or a previous run)
    /// would have left them.
    pub fn insert_variables(&mut self, rows: Vec<Value>) {
        for row in rows {
            upsert(&mut self.variables, "id", row);
        }
    }

    /// Answer the next `n` vault-meta pushes with HTTP 500.
    pub fn fail_next_vault_push(&mut self, n: usize) {
        self.vault_push_failures = n;
    }
}

/// PostgREST `on_conflict=<key>`: replace the row with the same primary key,
/// insert when there is none.
fn upsert(rows: &mut Vec<Value>, key: &str, row: Value) {
    let id = row.get(key).and_then(Value::as_str).map(str::to_owned);
    match rows
        .iter()
        .position(|r| r.get(key).and_then(Value::as_str) == id.as_deref())
    {
        Some(i) => rows[i] = row,
        None => rows.push(row),
    }
}

fn row_ts(row: &Value) -> chrono::DateTime<chrono::Utc> {
    row.get("updated_at")
        .and_then(Value::as_str)
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        .map_or(chrono::DateTime::<chrono::Utc>::MIN_UTC, |dt| {
            dt.with_timezone(&chrono::Utc)
        })
}

fn percent_decode(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                let hex = std::str::from_utf8(&bytes[i + 1..i + 3]).unwrap_or("");
                match u8::from_str_radix(hex, 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(bytes[i]);
                        i += 1;
                    }
                }
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `updated_at=gt.<rfc3339>`, the incremental pull filter.
fn pull_since(query: &str) -> Option<chrono::DateTime<chrono::Utc>> {
    query.split('&').find_map(|pair| {
        let ts = pair.strip_prefix("updated_at=gt.")?;
        chrono::DateTime::parse_from_rfc3339(&percent_decode(ts))
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    })
}

/// `Range: 0-1999` — PostgREST's offset/length pagination.
fn page_bounds(request: &Request) -> (usize, usize) {
    let raw = request
        .headers
        .get("range")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0-1999");
    match raw.split_once('-') {
        Some((from, to)) => (
            from.trim().parse().unwrap_or(0),
            to.trim().parse().unwrap_or(usize::MAX),
        ),
        None => (0, raw.trim().parse().unwrap_or(usize::MAX)),
    }
}

// ---------- Responders ----------

/// `POST /auth/v1/token?grant_type=password` — a GoTrue session, with the
/// `user` object `sync::Session` takes `user_id` from.
struct Token;

impl Respond for Token {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "expires_in": 3600,
            "user": { "id": TEST_USER_ID, "email": "e2e@vaultr.test" },
        }))
    }
}

/// `GET /rest/v1/vaults?select=*&limit=1`.
struct GetVaults(Arc<Mutex<Store>>);

impl Respond for GetVaults {
    fn respond(&self, _request: &Request) -> ResponseTemplate {
        let store = lock(&self.0);
        let body = match store.vault() {
            Some(row) => json!([row]),
            None => json!([]),
        };
        ResponseTemplate::new(200).set_body_json(body)
    }
}

/// `POST /rest/v1/vaults?on_conflict=owner_id`.
struct PushVaults(Arc<Mutex<Store>>);

impl Respond for PushVaults {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut store = lock(&self.0);
        if store.vault_push_failures > 0 {
            store.vault_push_failures -= 1;
            return ResponseTemplate::new(500)
                .set_body_json(json!({ "message": "injected push failure" }));
        }
        // `return=minimal`: the client only checks the status code.
        upsert_all(&mut store.vaults, "owner_id", request);
        ResponseTemplate::new(201)
    }
}

/// `POST /rest/v1/{table}` — bulk upsert on `id`.
struct PushRows(Arc<Mutex<Store>>, &'static str);

impl Respond for PushRows {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut store = lock(&self.0);
        upsert_all(store.table_mut(self.1), "id", request);
        ResponseTemplate::new(201)
    }
}

/// `GET /rest/v1/{table}?select=*&order=updated_at.asc[&updated_at=gt.<ts>]`.
struct GetRows(Arc<Mutex<Store>>, &'static str);

impl Respond for GetRows {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let store = lock(&self.0);
        let mut rows = store.table(self.1).clone();
        if let Some(since) = request.url.query().and_then(pull_since) {
            rows.retain(|row| row_ts(row) > since);
        }
        rows.sort_by_key(row_ts);
        let (from, to) = page_bounds(request);
        let page: Vec<Value> = rows
            .into_iter()
            .skip(from)
            .take(to.saturating_sub(from).saturating_add(1))
            .collect();
        ResponseTemplate::new(200).set_body_json(page)
    }
}

fn upsert_all(rows: &mut Vec<Value>, conflict_key: &str, request: &Request) {
    let body: Vec<Value> = serde_json::from_slice(&request.body).unwrap_or_default();
    for row in body {
        upsert(rows, conflict_key, row);
    }
}

fn lock(store: &Arc<Mutex<Store>>) -> MutexGuard<'_, Store> {
    store
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------- Fixture ----------

/// A running fake remote plus the process-global env vars pointing at it.
///
/// Holding one of these **holds a process-global mutex for its whole
/// lifetime** ([`env_lock`]): `VAULTR_SUPABASE_URL`, `VAULTR_SUPABASE_KEY` and
/// `VLTR_SYNC_SESSION_FILE` are process-wide and every test in a binary runs in
/// parallel, so two tests pointing at two different servers would otherwise
/// read each other's state. Serialising is the honest fix — the alternative,
/// one shared server for every test, would make the store assertions of one
/// test depend on the traffic of another.
pub struct Remote {
    server: MockServer,
    store: Arc<Mutex<Store>>,
    session_file: std::path::PathBuf,
    _dir: tempfile::TempDir,
    _env: MutexGuard<'static, ()>,
}

/// Process-global env vars: one test at a time.
fn env_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Remote {
    /// Start the server, point the env vars at it and clear them again on drop.
    pub fn start() -> Self {
        let env = env_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let session_file = dir.path().join("sync-session.json");
        let store = Arc::new(Mutex::new(Store::default()));
        let server = block_on(MockServer::start());

        block_on(
            Mock::given(method("POST"))
                .and(path("/auth/v1/token"))
                .respond_with(Token)
                .mount(&server),
        );
        block_on(
            Mock::given(method("GET"))
                .and(path("/rest/v1/vaults"))
                .respond_with(GetVaults(Arc::clone(&store)))
                .mount(&server),
        );
        block_on(
            Mock::given(method("POST"))
                .and(path("/rest/v1/vaults"))
                .respond_with(PushVaults(Arc::clone(&store)))
                .mount(&server),
        );
        for table in ["projects", "environments", "variables"] {
            block_on(
                Mock::given(method("GET"))
                    .and(path(format!("/rest/v1/{table}")))
                    .respond_with(GetRows(Arc::clone(&store), table))
                    .mount(&server),
            );
            block_on(
                Mock::given(method("POST"))
                    .and(path(format!("/rest/v1/{table}")))
                    .respond_with(PushRows(Arc::clone(&store), table))
                    .mount(&server),
            );
        }

        std::env::set_var(SUPABASE_URL_ENV, server.uri());
        std::env::set_var(SUPABASE_KEY_ENV, "test-anon-key");
        std::env::set_var(SYNC_SESSION_FILE_ENV, &session_file);

        Self {
            server,
            store,
            session_file,
            _dir: dir,
            _env: env,
        }
    }

    pub fn uri(&self) -> String {
        self.server.uri()
    }

    /// The store, for seeding and assertions.
    pub fn store(&self) -> MutexGuard<'_, Store> {
        lock(&self.store)
    }

    /// Path `VLTR_SYNC_SESSION_FILE` points at: where the account session must
    /// land instead of the keyring.
    pub fn session_file(&self) -> &std::path::Path {
        &self.session_file
    }

    /// Log in against the fake GoTrue endpoint, which is what writes the
    /// account session. Goes through the real `App::sync_login`, so the HTTP
    /// request is covered too.
    pub fn login(&self) {
        let app = vltr_core::App::open_in_memory().expect("app");
        block_on(app.sync_login("e2e@vaultr.test", "supabase-password")).expect("sync_login");
    }

    /// A cursor into the request log. Take one before the action under test and
    /// hand it to [`Remote::rest_requests_after`] to see only what that action
    /// did — `MockServer::reset` is not an option, it drops the mounted mocks.
    pub fn request_mark(&self) -> usize {
        self.requests().len()
    }

    /// Every request the server has received, oldest first.
    pub fn requests(&self) -> Vec<RecordedRequest> {
        block_on(self.server.received_requests())
            .unwrap_or_default()
            .iter()
            .map(|r| RecordedRequest {
                method: r.method.as_str().to_owned(),
                path: r.url.path().to_owned(),
                body: String::from_utf8_lossy(&r.body).into_owned(),
            })
            .collect()
    }

    /// Data-plane requests (everything under `/rest/v1`) after `mark`, in order.
    pub fn rest_requests_after(&self, mark: usize) -> Vec<RecordedRequest> {
        self.requests()
            .into_iter()
            .skip(mark)
            .filter(|r| r.path.starts_with("/rest/v1"))
            .collect()
    }

    /// `["POST /rest/v1/variables", ...]` for the requests after `mark`: a
    /// compact log to assert against.
    pub fn rest_log_after(&self, mark: usize) -> Vec<String> {
        self.rest_requests_after(mark)
            .iter()
            .map(|r| format!("{} {}", r.method, r.path))
            .collect()
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        // Runs on panic too, so a failing test cannot leak its env vars into
        // the next one and send it to a dead server.
        std::env::remove_var(SUPABASE_URL_ENV);
        std::env::remove_var(SUPABASE_KEY_ENV);
        std::env::remove_var(SYNC_SESSION_FILE_ENV);
    }
}

/// One request as the server saw it.
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub body: String,
}
