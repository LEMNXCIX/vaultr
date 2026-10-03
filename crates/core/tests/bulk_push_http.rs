//! PostgREST's bulk-upsert contract: **every row of one `POST` must carry the
//! same set of keys**, or the server rejects the whole batch with
//! `PGRST102` / 400.
//!
//! This is the fourth thing `support::Remote` learned to enforce, and it was
//! learned the hard way: the row DTOs in `crates/sync/src/dto.rs` carried
//! `skip_serializing_if = "Option::is_none"` on every optional column, so a
//! described project and an undescribed one serialised to *different shapes*.
//! Against Supabase that batch is a 400. Against the fake it was a 201, so all
//! nine tests in `sync_http.rs` and `reset_sync_http.rs` stayed green while the
//! real sync of any vault holding one described project and one undescribed
//! project failed outright.
//!
//! The lesson generalises: a fake that is more permissive than the server does
//! not merely fail to help, it actively certifies the bug. Hence these two
//! tests run in both directions.
//!
//! * `the_fake_rejects_a_heterogeneous_bulk_push_the_way_postgrest_does` proves
//!   the fake is no longer permissive. Without it the test below could pass
//!   vacuously against a fake that accepts everything.
//! * `a_bulk_push_that_mixes_present_and_absent_optional_columns_lands` is the
//!   regression itself: an ordinary vault, synced.
//!
//! Nothing here contacts Supabase or reaches the keyring; see the module docs
//! of `support`.

mod support;

use secrecy::SecretString;
use serde_json::{json, Value};
use support::{block_on, Remote, Store};
use vltr_core::App;

fn secret(s: &str) -> SecretString {
    SecretString::new(s.to_owned())
}

// ---------------------------------------------------------------------------
// 1. The fake itself: it must reject what PostgREST rejects
// ---------------------------------------------------------------------------

/// The check the whole directory was missing, stated as a test.
///
/// PostgREST answers a heterogeneous batch with HTTP 400 and
/// `{"code":"PGRST102","message":"All object keys must match"}` — and, crucially,
/// rejects **every** row, not the odd one out: one row missing a column takes
/// the whole sync down with it. A row *present with a null value* is fine; a row
/// with the key *absent* is not. That is the entire difference, and it is
/// invisible unless the fake checks for it.
///
/// The two batches differ in exactly one thing — whether the second row carries
/// the `description` key — so the pair also documents that the fake draws the
/// line in the same place as the server.
///
/// Fails against: a fake whose uniformity check is not mounted on
/// `POST /rest/v1/<table>`; a check that rejects the null-valued batch as well.
#[test]
fn the_fake_rejects_a_heterogeneous_bulk_push_the_way_postgrest_does() {
    let remote = Remote::start();

    // Both rows carry `description` — one with a value, one explicitly null.
    let uniform = json!([
        {"id": "aaaaaaaa-0000-7000-8000-000000000001", "name": "a", "description": "set"},
        {"id": "aaaaaaaa-0000-7000-8000-000000000002", "name": "b", "description": null},
    ]);
    // Identical, except the second row simply does not have the key.
    let heterogeneous = json!([
        {"id": "aaaaaaaa-0000-7000-8000-000000000003", "name": "a", "description": "set"},
        {"id": "aaaaaaaa-0000-7000-8000-000000000004", "name": "b"},
    ]);

    let accepted = post_bulk(&remote, "projects", &uniform);
    assert_eq!(
        accepted.status, 201,
        "rows that agree on their keys are what PostgREST accepts — a null value \
         is fine, a missing key is the thing it rejects"
    );

    let rejected = post_bulk(&remote, "projects", &heterogeneous);
    assert_eq!(
        rejected.status, 400,
        "the fake must not be more permissive than the server: a batch whose \
         rows disagree on their keys is a 400 against Supabase"
    );
    let body: Value = serde_json::from_str(&rejected.body).expect("the PGRST102 body");
    assert_eq!(body["code"], "PGRST102");
    assert_eq!(body["message"], "All object keys must match");

    // And the rejection is total: not one row of a rejected batch is applied.
    let store = remote.store();
    assert!(
        store
            .projects()
            .iter()
            .all(|r| r["id"] != "aaaaaaaa-0000-7000-8000-000000000003"),
        "PGRST102 rejects the whole batch; the fake must not have half-applied it"
    );
}

/// One bulk POST's answer: status plus the raw body (parsed outside the
/// runtime, so the test reads like the wire it is inspecting).
struct BulkResponse {
    status: u16,
    body: String,
}

/// `POST /rest/v1/<table>` with a hand-written body, bypassing the DTOs — the
/// only way to put a shape on the wire the client would never produce.
fn post_bulk(remote: &Remote, table: &str, body: &Value) -> BulkResponse {
    let url = format!("{}/rest/v1/{table}", remote.uri());
    block_on(async {
        let resp = reqwest::Client::new()
            .post(url)
            .header("Prefer", "resolution=merge-duplicates,return=minimal")
            .json(body)
            .send()
            .await
            .expect("the fake answers any POST to a mounted table");
        BulkResponse {
            status: resp.status().as_u16(),
            body: resp.text().await.unwrap_or_default(),
        }
    })
}

// ---------------------------------------------------------------------------
// 2. The regression: an ordinary vault with mixed optional columns
// ---------------------------------------------------------------------------

/// A vault whose every batch mixes "the optional column is set" with "it is
/// not". Nothing exotic about it — one user, one `sync`, two projects and two
/// variables. Before the fix the projects POST carried one row with a
/// `description` key and one without, and the server answered PGRST102.
fn mixed_vault(password: &str) -> App {
    let mut app = App::open_in_memory().unwrap();
    app.init(secret(password)).unwrap();
    app.create_project("Described", Some("has a description".into()), None, None)
        .unwrap();
    app.create_project("Bare", None, None, None).unwrap();
    app.set_variable(
        "Described",
        "local",
        "TOKEN",
        "a-value",
        Some("has notes".into()),
    )
    .unwrap();
    app.set_variable("Bare", "local", "TOKEN", "b-value", None)
        .unwrap();
    app
}

/// The load-bearing assertion is that `sync()` returns `Ok` at all: against the
/// bug the very first row POST is refused and the whole sync dies with a
/// transport error, taking every other row with it.
///
/// The key-set assertions are what pin down *why*, so a future regression that
/// merely reorders the push cannot quietly pass.
///
/// Fails against: any `skip_serializing_if` reintroduced on a column of
/// `ProjectRow`/`EnvironmentRow`/`VariableRow`; a caller that splits the batch
/// to dodge the check (the server-side rejection would still return, so the
/// store assertions would catch it).
#[test]
fn a_bulk_push_that_mixes_present_and_absent_optional_columns_lands() {
    let remote = Remote::start();
    remote.login();
    let app = mixed_vault("mixed-password");

    let mark = remote.request_mark();
    let report = block_on(app.sync()).expect(
        "a vault holding one described project and one undescribed one is not \
         exotic; against the real server this batch answers PGRST102 and the \
         entire sync fails",
    );
    assert_eq!(
        report.pushed, 7,
        "vault meta + 2 projects + 2 environments + 2 variables — a rejected \
         batch would take every table down with it, not just the odd row"
    );

    // The bytes, not the intent: every row of every batch agrees on its keys.
    let mut saw_mixed_description = false;
    let mut saw_mixed_notes = false;
    for (table, optional_columns) in [
        (
            "projects",
            vec!["description", "color", "icon", "updated_at"],
        ),
        ("environments", vec!["updated_at"]),
        ("variables", vec!["notes", "updated_at"]),
    ] {
        let batches = pushed_bodies(&remote, mark, table);
        assert_eq!(batches.len(), 1, "one bulk POST per {table}");
        let keys = uniform_keys(&batches[0], table);
        for column in optional_columns {
            assert!(
                keys.iter().any(|k| k == column),
                "{table}: {column} must be on every row of the batch — an absent \
                 key on one row is the whole of PGRST102"
            );
        }
        if table == "projects" {
            saw_mixed_description = has_value_and_null(&batches[0], "description");
        }
        if table == "variables" {
            saw_mixed_notes = has_value_and_null(&batches[0], "notes");
        }
    }
    assert!(
        saw_mixed_description,
        "the fixture must actually mix a set description with an absent one, or \
         this test is not exercising the bug it exists for"
    );
    assert!(
        saw_mixed_notes,
        "same for `notes` on VariableRow, the other optional column that mixes"
    );

    // And the server kept every row — the point of uniform keys is that the
    // batch lands whole.
    let store = remote.store();
    assert_eq!(
        store.projects().len(),
        2,
        "both projects reached the remote"
    );
    assert_eq!(
        store.environments().len(),
        2,
        "both `local` environments reached the remote"
    );
    assert_eq!(
        store.variables().len(),
        2,
        "both variables reached the remote"
    );
    let described = store
        .projects()
        .iter()
        .find(|p| p["name"] == "Described")
        .expect("the described project");
    assert_eq!(described["description"], "has a description");
    let bare = store
        .projects()
        .iter()
        .find(|p| p["name"] == "Bare")
        .expect("the undescribed project");
    assert!(
        bare["description"].is_null(),
        "an absent description must land as SQL NULL, not be dropped"
    );
}

/// Sorted key set of every row in `batch`, asserted identical — the shape
/// PostgREST requires of a bulk upsert. Returns it so the caller can look for
/// the columns it cares about.
fn uniform_keys(batch: &[Value], what: &str) -> Vec<String> {
    let mut expected: Option<Vec<String>> = None;
    for row in batch {
        let obj = row
            .as_object()
            .unwrap_or_else(|| panic!("{what}: every pushed row is an object, got {row}"));
        let mut keys: Vec<String> = obj.keys().cloned().collect();
        keys.sort();
        match &expected {
            None => expected = Some(keys),
            Some(first) => assert_eq!(
                *first, keys,
                "{what}: PGRST102 — PostgREST rejects the WHOLE batch when two \
                 rows disagree on which columns they carry, not just the odd one out"
            ),
        }
    }
    expected.unwrap_or_else(|| panic!("{what}: the push carried no rows"))
}

/// Whether `column` is set on some rows of `batch` and null on others — the
/// exact mix that `skip_serializing_if` turns into a heterogeneous payload.
fn has_value_and_null(batch: &[Value], column: &str) -> bool {
    let valued = batch
        .iter()
        .any(|row| row.get(column).is_some_and(|v| !v.is_null()));
    let null = batch
        .iter()
        .any(|row| row.get(column).is_some_and(Value::is_null));
    valued && null
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

// ---------- helpers ----------

/// Unused import guard: `Store` is referenced through `remote.store()`'s
/// return type in the test bodies above.
const _: fn(&Store) = |_| {};
