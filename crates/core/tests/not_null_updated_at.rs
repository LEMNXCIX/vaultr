//! `updated_at` is `Option` in the row DTOs and `NOT NULL` on the server.
//!
//! The three row DTOs declare `updated_at: Option<DateTime<Utc>>` with
//! `#[serde(default)]`, which is right for the **pull**: a row the server wrote
//! without the column still has to parse. But the same `Option` travels into the
//! **push**, where the column is `timestamptz not null default now()` on all
//! three tables (see `supabase/migrations/0001_init.sql`). Postgres applies a
//! column default to an **absent** key, never to an explicit `null`, so a row
//! carrying `"updated_at": null` is a `23502 not_null_violation` — a bare 400
//! that the CLI reports as `Sin conexión con Supabase: http error: status code
//! 400`, naming neither the field nor the table.
//!
//! Nothing in production builds such a row today: all six constructors in
//! `crates/core/src/sync/rows.rs` stamp `Some`, and every `None` lives in
//! network-free unit tests. These tests pin the **boundary** that keeps it that
//! way — the refusal has to happen at `push_rows`, where the `Option` stops
//! being a wire value — rather than trusting that observation to hold forever.
//!
//! The failure mode the guard exists to prevent is a *silent* one, so nothing
//! here invents a timestamp to make a push succeed: a missing `updated_at` is
//! refused exactly like a null one. Were the server lenient about `NULL`, a
//! row pushed without a timestamp would come back with none, and the merge
//! would then reject it (`server row without updated_at cannot be merged`) —
//! or worse, a server-stamped `now()` would quietly enter LWW as fabricated
//! data. Failing is the honest outcome in both worlds.
//!
//! Three directions, as in `bulk_push_http.rs`:
//!
//! * `the_fake_refuses_an_explicit_null_updated_at_the_way_postgres_does` —
//!   the fake is not laxer than the server, so the refusal below is provably
//!   load-bearing rather than decorative.
//! * `a_push_carrying_a_null_updated_at_fails_with_its_own_error_naming_the_field`
//!   — the client refuses the whole batch before the wire, naming the field and
//!   the table.
//! * `a_push_carrying_an_updated_at_still_lands_exactly_as_before` — the
//!   ordinary path is untouched, byte for byte.
//!
//! Nothing here contacts Supabase or reaches the keyring; see the module docs
//! of `support`.

mod support;

use chrono::{DateTime, TimeZone, Utc};
use serde_json::{json, Value};
use support::{block_on, Remote, TEST_USER_ID};
use sync::{ProjectRow, Session, SyncClient, VariableRow};

/// A `Session` with only what a row push reads. The fake's GoTrue is not
/// involved: this is a transport test, not an auth one.
fn session() -> Session {
    Session {
        access_token: "test-access-token".into(),
        refresh_token: "test-refresh-token".into(),
        expires_in: 3600,
        user_id: TEST_USER_ID.into(),
    }
}

fn client(remote: &Remote) -> SyncClient {
    SyncClient::new(&remote.uri(), "test-anon-key").expect("client")
}

fn ts() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap()
}

fn project_row(id: &str, updated_at: Option<DateTime<Utc>>) -> ProjectRow {
    ProjectRow {
        owner_id: Some(TEST_USER_ID.into()),
        id: id.into(),
        name: "P".into(),
        description: None,
        color: None,
        icon: None,
        deleted: false,
        version: 1,
        updated_at,
    }
}

fn variable_row(id: &str, updated_at: Option<DateTime<Utc>>) -> VariableRow {
    VariableRow {
        owner_id: Some(TEST_USER_ID.into()),
        id: id.into(),
        environment_id: "018f0000-0000-7000-8000-000000000002".into(),
        key: "TOKEN".into(),
        value_encrypted: "Y2lwaGVydGV4dA==".into(),
        nonce: "MjRieXRlc25vbmNl".into(),
        notes: None,
        is_readonly: false,
        allow_export: true,
        deleted: false,
        version: 1,
        updated_at,
    }
}

/// `POST /rest/v1/<table>` with a hand-written body, bypassing the DTOs — the
/// only way to put a shape on the wire no DTO would produce.
fn post_bulk(remote: &Remote, table: &str, body: &Value) -> (u16, Value) {
    let url = format!("{}/rest/v1/{table}", remote.uri());
    block_on(async {
        let resp = reqwest::Client::new()
            .post(url)
            .header("Prefer", "resolution=merge-duplicates,return=minimal")
            .json(body)
            .send()
            .await
            .expect("the fake answers any POST to a mounted table");
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        (status, serde_json::from_str(&text).unwrap_or(Value::Null))
    })
}

/// Bodies of every `POST /rest/v1/<table>` after `mark`.
fn pushed_bodies(remote: &Remote, mark: usize, table: &str) -> Vec<Vec<Value>> {
    remote
        .rest_requests_after(mark)
        .into_iter()
        .filter(|r| r.method == "POST" && r.path == format!("/rest/v1/{table}"))
        .map(|r| serde_json::from_str::<Vec<Value>>(&r.body).expect("a JSON array of rows"))
        .collect()
}

// ---------------------------------------------------------------------------
// 1. The fake itself: `NOT NULL` is a decision Postgres makes, and the fake
//    has to make the same one or it certifies the bug instead of catching it.
// ---------------------------------------------------------------------------

/// Stated as a test because a fake that accepts what the server refuses is
/// worthless here: with the fake permissive, a null `updated_at` would sail
/// through every other sync test in this directory and the only place it could
/// ever surface is a user's real vault.
///
/// The two halves are what Postgres actually does, and the difference between
/// them is the whole content of the guard:
///
/// * a key **absent** from the payload takes the column default — legal;
/// * a key **present and null** is an attempt to write SQL `NULL` into a
///   `NOT NULL` column, and the server answers `400` with `23502`.
#[test]
fn the_fake_refuses_an_explicit_null_updated_at_the_way_postgres_does() {
    let remote = Remote::start();

    // Absent key → the column default applies. Not a violation.
    let defaulted = json!([
        {"id": "aaaaaaaa-0000-7000-8000-000000000001", "name": "defaulted"},
    ]);
    assert_eq!(
        post_bulk(&remote, "projects", &defaulted).0,
        201,
        "an absent key is not a NOT NULL violation: the column default covers it"
    );

    // Stamped → fine.
    let stamped = json!([
        {"id": "aaaaaaaa-0000-7000-8000-000000000002", "name": "stamped",
         "updated_at": "2026-01-01T00:00:00Z"},
    ]);
    assert_eq!(post_bulk(&remote, "projects", &stamped).0, 201);

    // Explicit null, alongside a row that is fine: the batch goes out as a unit,
    // so the whole thing is refused — including the row that had nothing wrong
    // with it. This is the batch shape a stray `None` would produce.
    let mixed = json!([
        {"id": "aaaaaaaa-0000-7000-8000-000000000003", "name": "ok",
         "updated_at": "2026-01-01T00:00:00Z"},
        {"id": "aaaaaaaa-0000-7000-8000-000000000004", "name": "null", "updated_at": null},
    ]);
    let (status, body) = post_bulk(&remote, "projects", &mixed);
    assert_eq!(
        status, 400,
        "an explicit null in a NOT NULL column is a 400 against Supabase, not a \
         silently defaulted row"
    );
    assert_eq!(body["code"], "23502");
    assert!(
        body["message"]
            .as_str()
            .unwrap_or_default()
            .contains("updated_at"),
        "the server names the column; so must the fake: {body}"
    );

    let store = remote.store();
    for id in [
        "aaaaaaaa-0000-7000-8000-000000000003",
        "aaaaaaaa-0000-7000-8000-000000000004",
    ] {
        assert!(
            store.projects().iter().all(|r| r["id"] != id),
            "the rejection applies nothing at all; the fake must not half-apply a \
             refused batch"
        );
    }
    assert_eq!(
        store.projects().len(),
        2,
        "only the two batches that were accepted are on the remote"
    );
}

// ---------------------------------------------------------------------------
// 2. The guard: `push_rows` refuses the null itself, naming field and table
// ---------------------------------------------------------------------------

/// The one that matters. A row carrying `updated_at: None` must fail with
/// `push_rows`' own error, and the message must name `updated_at` and the table
/// — because the alternative (the server's 400) names neither, and the CLI
/// turns every sync error into `Sin conexión con Supabase`.
///
/// Also pins the three properties that make the refusal worth having: nothing
/// reaches the wire (this is a pre-flight check, not a retry after a 400),
/// nothing is applied, and the refusal names *which* row of the batch was
/// bad, so a thousand-row push is still debuggable.
///
/// Fails against: the guard moved out of `push_rows` into a caller; a message
/// that drops the field or the table; an `unwrap_or_else(Utc::now)` in place of
/// the refusal (the store assertions below would see the fabricated timestamp).
#[test]
fn a_push_carrying_a_null_updated_at_fails_with_its_own_error_naming_the_field() {
    let remote = Remote::start();
    let mark = remote.request_mark();

    let rows = vec![
        variable_row("aaaaaaaa-0000-7000-8000-000000000001", Some(ts())),
        variable_row("aaaaaaaa-0000-7000-8000-000000000002", None),
        variable_row("aaaaaaaa-0000-7000-8000-000000000003", Some(ts())),
    ];

    let err = block_on(client(&remote).push_rows(&session(), "variables", &rows)).expect_err(
        "a row carrying `updated_at: null` is refused by `push_rows` itself: the \
         server would answer 23502, and the CLI would report that as a connection \
         failure naming neither the field nor the table",
    );

    let message = err.to_string();
    assert!(
        message.contains("updated_at"),
        "the error must name the field, or nobody can tell which column is wrong: \
         {message}"
    );
    assert!(
        message.contains("variables"),
        "the error must name the table the row was headed for: {message}"
    );
    assert!(
        message.contains("2"),
        "the error must say which row of the batch was bad: {message}"
    );
    assert!(
        !matches!(err, sync::SyncError::Http(_)),
        "a transport error is the symptom this replaces, not the fix"
    );

    // Refused at the boundary: no request was made at all.
    assert!(
        remote.rest_requests_after(mark).is_empty(),
        "the row never went on the wire; a guard that let the request out and \
         merely inspected the answer would not be a boundary"
    );
    assert!(
        remote.store().variables().is_empty(),
        "no row of a refused batch is applied — including the two that were fine"
    );
}

/// The same refusal for the other two tables, and for the other shape of the
/// hole: a row that omits `updated_at` altogether. That one is legal SQL — the
/// default would cover it — and that is exactly why it must be refused here:
/// the server would stamp `now()`, the merge would take the fabricated
/// timestamp as the row's own, and nothing would ever say the value was made up.
/// A silent default is the worst possible outcome, so it fails here instead.
///
/// Projects, because `push_reset` pushes tombstones of pulled rows and a pulled
/// row is the one shape that can legitimately arrive without the column.
#[test]
fn a_push_missing_its_updated_at_is_refused_rather_than_defaulted() {
    let remote = Remote::start();
    let mark = remote.request_mark();

    let rows = vec![project_row("aaaaaaaa-0000-7000-8000-000000000005", None)];

    let err = block_on(client(&remote).push_rows(&session(), "projects", &rows))
        .expect_err("a row with no `updated_at` must not be pushed");
    let message = err.to_string();
    assert!(message.contains("updated_at"), "{message}");
    assert!(message.contains("projects"), "{message}");
    assert!(
        remote.rest_requests_after(mark).is_empty(),
        "the server would have stamped now() for it, inventing a timestamp the \
         merge would then treat as real"
    );
}

// ---------------------------------------------------------------------------
// 3. The ordinary path, byte for byte
// ---------------------------------------------------------------------------

/// Nothing about a stamped row changed. A guard that rejected `Some`, or that
/// rewrote the timestamp it carries, would be a regression this test exists to
/// catch: `now()` over a real LWW timestamp silently changes which side of a
/// conflict wins.
///
/// The wire bytes are asserted, not just the outcome: `updated_at` must go out
/// as the exact value the row holds, and the batch must still be one bulk POST
/// with the same body shape as before.
#[test]
fn a_push_carrying_an_updated_at_still_lands_exactly_as_before() {
    let remote = Remote::start();
    let mark = remote.request_mark();

    let rows = vec![
        project_row("aaaaaaaa-0000-7000-8000-000000000006", Some(ts())),
        project_row("aaaaaaaa-0000-7000-8000-000000000007", Some(ts())),
    ];

    block_on(client(&remote).push_rows(&session(), "projects", &rows))
        .expect("a stamped row is the ordinary case and must push exactly as before");

    let bodies = pushed_bodies(&remote, mark, "projects");
    assert_eq!(bodies.len(), 1, "one bulk POST, as before");
    assert_eq!(bodies[0].len(), 2);
    for row in &bodies[0] {
        assert_eq!(
            row["updated_at"], "2026-01-01T00:00:00Z",
            "the row's own timestamp must reach the wire unchanged — never null, \
             never now(): {row}"
        );
    }

    let store = remote.store();
    assert_eq!(store.projects().len(), 2, "both rows reached the remote");
    for row in store.projects() {
        assert_eq!(row["updated_at"], "2026-01-01T00:00:00Z");
    }
}
