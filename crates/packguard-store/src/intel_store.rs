//! Phase 14.1c — IntelStore scaffolding (~/.packguard/intel/intel.db).
//!
//! Holds the ecosystem-wide vulnerability + malware catalog plus the
//! intel sync_log, all keyed by natural identity rather than the
//! project-specific `packages.id` FK that the legacy Store uses.
//!
//! Strict scaffolding: this module is unused at runtime. The existing
//! Store still owns the full sync/audit code path; nothing here is
//! wired into the server, CLI, or `packguard-intel` crate. The
//! cutover (and the data migration that copies the legacy rows here)
//! lives in 14.1d.

use anyhow::{Context, Result};
use chrono::Utc;
use packguard_core::model::{AffectedSpec, MalwareKind, MalwareReport, Severity, Vulnerability};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

use crate::{StoredJob, StoredMalware, StoredVulnerability, SyncState};

mod intel_embedded {
    refinery::embed_migrations!("migrations_intel");
}

pub struct IntelStore {
    conn: Connection,
}

impl IntelStore {
    /// Open or create `<packguard_home>/intel/intel.db` with WAL mode +
    /// foreign keys enabled. Parent directories are created as needed.
    /// The migration runner is idempotent: re-opening an existing file
    /// is a no-op for the schema.
    pub fn open(packguard_home: &Path) -> Result<Self> {
        let intel_dir = packguard_home.join("intel");
        std::fs::create_dir_all(&intel_dir)
            .with_context(|| format!("creating {}", intel_dir.display()))?;
        let db_path = intel_dir.join("intel.db");
        let mut conn =
            Connection::open(&db_path).with_context(|| format!("opening {}", db_path.display()))?;
        conn.busy_timeout(std::time::Duration::from_secs(5))
            .context("setting busy_timeout on intel store")?;
        crate::enable_wal(&conn).context("enabling WAL on intel store")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign keys on intel store")?;
        intel_embedded::migrations::runner()
            .run(&mut conn)
            .context("running intel migrations")?;
        Ok(Self { conn })
    }

    /// In-memory variant for tests. Same schema, no FS side-effects.
    pub fn open_in_memory() -> Result<Self> {
        let mut conn = Connection::open_in_memory().context("opening in-memory intel store")?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .context("enabling foreign keys")?;
        intel_embedded::migrations::runner()
            .run(&mut conn)
            .context("running intel migrations")?;
        Ok(Self { conn })
    }

    // --- sync_log -------------------------------------------------------

    pub fn get_sync_state(&self, kind: &str) -> Result<Option<SyncState>> {
        self.conn
            .query_row(
                "SELECT etag, last_modified, last_commit, synced_at, record_count \
                 FROM sync_log WHERE kind = ?1",
                params![kind],
                |row| {
                    Ok(SyncState {
                        etag: row.get(0)?,
                        last_modified: row.get(1)?,
                        last_commit: row.get(2)?,
                        synced_at: row.get(3)?,
                        record_count: row.get(4)?,
                    })
                },
            )
            .optional()
            .context("get_sync_state")
    }

    pub fn put_sync_state(&mut self, kind: &str, state: &SyncState) -> Result<()> {
        let now = Utc::now().to_rfc3339();
        let synced_at = state.synced_at.clone().unwrap_or(now);
        self.conn
            .execute(
                "INSERT INTO sync_log (kind, etag, last_modified, last_commit, synced_at, record_count) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6) \
                 ON CONFLICT(kind) DO UPDATE SET \
                    etag = excluded.etag, \
                    last_modified = excluded.last_modified, \
                    last_commit = excluded.last_commit, \
                    synced_at = excluded.synced_at, \
                    record_count = excluded.record_count",
                params![
                    kind,
                    state.etag,
                    state.last_modified,
                    state.last_commit,
                    synced_at,
                    state.record_count,
                ],
            )
            .context("put_sync_state")?;
        Ok(())
    }

    // --- vulnerabilities -----------------------------------------------

    /// Bulk-upsert advisories. Idempotent on
    /// `(source, advisory_id, ecosystem, package_name)`. Returns the
    /// number of rows touched. Mirrors the legacy
    /// `Store::persist_vulnerabilities` semantics minus the
    /// `packages` upsert (intel is natural-key only).
    pub fn persist_vulnerabilities(&mut self, vulns: &[Vulnerability]) -> Result<usize> {
        if vulns.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.transaction().context("begin intel vuln tx")?;
        let mut count = 0usize;
        for v in vulns {
            let aliases_json = serde_json::to_string(&v.aliases).context("serializing aliases")?;
            let affected_json =
                serde_json::to_string(&v.affected).context("serializing affected spec")?;
            let fixed_json =
                serde_json::to_string(&v.fixed_versions).context("serializing fixed_versions")?;
            let severity = if matches!(v.severity, Severity::Unknown) {
                None
            } else {
                Some(v.severity.as_str().to_string())
            };
            tx.execute(
                "INSERT INTO vulnerabilities \
                   (source, advisory_id, ecosystem, package_name, severity, cve_id, \
                    aliases_json, summary, url, affected_json, fixed_versions_json, \
                    published_at, modified_at, fetched_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14) \
                 ON CONFLICT(source, advisory_id, ecosystem, package_name) DO UPDATE SET \
                    severity = excluded.severity, \
                    cve_id = excluded.cve_id, \
                    aliases_json = excluded.aliases_json, \
                    summary = excluded.summary, \
                    url = excluded.url, \
                    affected_json = excluded.affected_json, \
                    fixed_versions_json = excluded.fixed_versions_json, \
                    published_at = excluded.published_at, \
                    modified_at = excluded.modified_at, \
                    fetched_at = excluded.fetched_at",
                params![
                    v.source,
                    v.advisory_id,
                    v.ecosystem,
                    v.package_name,
                    severity,
                    v.cve_id,
                    aliases_json,
                    v.summary,
                    v.url,
                    affected_json,
                    fixed_json,
                    v.published_at,
                    v.modified_at,
                    now,
                ],
            )
            .context("upsert intel vulnerability")?;
            count += 1;
        }
        tx.commit().context("commit intel vuln tx")?;
        Ok(count)
    }

    /// Load every advisory the catalog has for `(ecosystem, package_name)`.
    /// Version filtering is the matcher's job (it walks `affected_json`).
    pub fn load_vulnerabilities_for(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> Result<Vec<StoredVulnerability>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source, advisory_id, ecosystem, package_name, severity, \
                        cve_id, aliases_json, summary, url, affected_json, \
                        fixed_versions_json, published_at, modified_at, fetched_at \
                 FROM vulnerabilities \
                 WHERE ecosystem = ?1 AND package_name = ?2",
            )
            .context("prepare load_vulnerabilities_for")?;
        let rows = stmt
            .query_map(params![ecosystem, package_name], read_intel_vulnerability)
            .context("query intel vulnerabilities")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn count_vulnerabilities(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM vulnerabilities", [], |row| row.get(0))
            .context("count intel vulnerabilities")
    }

    /// Dump every advisory in the catalog ordered by `(ecosystem,
    /// package_name, advisory_id)`. Used by `packguard audit` and the
    /// `/api/audit` endpoint to stream the full vulnerability set
    /// without per-package round-trips.
    pub fn load_all_vulnerabilities(&self) -> Result<Vec<StoredVulnerability>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source, advisory_id, ecosystem, package_name, severity, \
                        cve_id, aliases_json, summary, url, affected_json, \
                        fixed_versions_json, published_at, modified_at, fetched_at \
                 FROM vulnerabilities \
                 ORDER BY ecosystem, package_name, advisory_id",
            )
            .context("prepare load_all_vulnerabilities")?;
        let rows = stmt
            .query_map([], read_intel_vulnerability)
            .context("query all intel vulnerabilities")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // --- malware_reports -----------------------------------------------

    /// Bulk-upsert malware/typosquat findings. Idempotent on
    /// `(source, ref_id, ecosystem, package_name, version)`.
    pub fn persist_malware_reports(&mut self, reports: &[MalwareReport]) -> Result<usize> {
        if reports.is_empty() {
            return Ok(0);
        }
        let now = Utc::now().to_rfc3339();
        let tx = self.conn.transaction().context("begin intel malware tx")?;
        let mut count = 0usize;
        for r in reports {
            let evidence_str =
                serde_json::to_string(&r.evidence).context("serializing malware evidence")?;
            tx.execute(
                "INSERT INTO malware_reports \
                   (source, ref_id, ecosystem, package_name, version, kind, summary, url, \
                    evidence_json, reported_at, fetched_at) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11) \
                 ON CONFLICT(source, ref_id, ecosystem, package_name, version) DO UPDATE SET \
                    kind = excluded.kind, \
                    summary = excluded.summary, \
                    url = excluded.url, \
                    evidence_json = excluded.evidence_json, \
                    reported_at = excluded.reported_at, \
                    fetched_at = excluded.fetched_at",
                params![
                    r.source,
                    r.ref_id,
                    r.ecosystem,
                    r.package_name,
                    r.version,
                    r.kind.as_str(),
                    r.summary,
                    r.url,
                    evidence_str,
                    r.reported_at,
                    now,
                ],
            )
            .context("upsert intel malware_report")?;
            count += 1;
        }
        tx.commit().context("commit intel malware tx")?;
        Ok(count)
    }

    /// Load malware reports for `(ecosystem, package_name)` ordered by
    /// insertion (so callers can prefer earliest-source on ties).
    pub fn load_malware_reports_for(
        &self,
        ecosystem: &str,
        package_name: &str,
    ) -> Result<Vec<StoredMalware>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source, ref_id, ecosystem, package_name, version, kind, \
                        summary, url, evidence_json, reported_at, fetched_at \
                 FROM malware_reports \
                 WHERE ecosystem = ?1 AND package_name = ?2 \
                 ORDER BY id",
            )
            .context("prepare load_malware_reports_for")?;
        let rows = stmt
            .query_map(params![ecosystem, package_name], read_intel_malware)
            .context("query intel malware_reports")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn count_malware_reports(&self) -> Result<i64> {
        self.conn
            .query_row("SELECT COUNT(*) FROM malware_reports", [], |row| row.get(0))
            .context("count intel malware_reports")
    }

    /// Dump every malware report in the catalog ordered by `(ecosystem,
    /// package_name, id)`. Used by `audit --focus malware|typosquat`
    /// and the `/api/audit` malware view.
    pub fn load_all_malware_reports(&self) -> Result<Vec<StoredMalware>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT source, ref_id, ecosystem, package_name, version, kind, \
                        summary, url, evidence_json, reported_at, fetched_at \
                 FROM malware_reports \
                 ORDER BY ecosystem, package_name, id",
            )
            .context("prepare load_all_malware_reports")?;
        let rows = stmt
            .query_map([], read_intel_malware)
            .context("query all intel malware_reports")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    // --- jobs (Phase 14.2d.2) ------------------------------------------
    //
    // The `jobs` table moved here from the per-project store so the
    // legacy `<home>/store.db` could be retired. Schema mirrors the
    // original `migrations/V4__jobs.sql` exactly (same columns, same
    // semantics) so the wire-facing `JobView` payload + the runner
    // state machine in `packguard-server/src/jobs.rs` stay unchanged.

    /// Insert a fresh job row in `pending` state.
    pub fn create_job(&mut self, id: &str, kind: &str) -> Result<StoredJob> {
        let now = Utc::now().to_rfc3339();
        self.conn
            .execute(
                "INSERT INTO jobs (id, kind, status, started_at) VALUES (?1, ?2, 'pending', ?3)",
                params![id, kind, now],
            )
            .context("inserting intel job row")?;
        Ok(StoredJob {
            id: id.into(),
            kind: kind.into(),
            status: "pending".into(),
            started_at: now,
            finished_at: None,
            result_json: None,
            error: None,
        })
    }

    pub fn update_job_status(
        &mut self,
        id: &str,
        status: &str,
        result_json: Option<&str>,
        error: Option<&str>,
    ) -> Result<()> {
        let finished_at = matches!(status, "succeeded" | "failed").then(|| Utc::now().to_rfc3339());
        self.conn
            .execute(
                "UPDATE jobs SET status = ?1, finished_at = ?2, result_json = ?3, error = ?4 WHERE id = ?5",
                params![status, finished_at, result_json, error, id],
            )
            .context("updating intel job row")?;
        Ok(())
    }

    pub fn load_job(&self, id: &str) -> Result<Option<StoredJob>> {
        self.conn
            .query_row(
                "SELECT id, kind, status, started_at, finished_at, result_json, error \
                 FROM jobs WHERE id = ?1",
                params![id],
                read_intel_job,
            )
            .optional()
            .context("loading intel job row")
    }

    pub fn load_recent_jobs(&self, limit: i64) -> Result<Vec<StoredJob>> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, kind, status, started_at, finished_at, result_json, error \
                 FROM jobs ORDER BY started_at DESC LIMIT ?1",
            )
            .context("preparing intel load_recent_jobs")?;
        let rows = stmt
            .query_map(params![limit], read_intel_job)
            .context("querying intel load_recent_jobs")?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}

fn read_intel_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredJob> {
    Ok(StoredJob {
        id: row.get(0)?,
        kind: row.get(1)?,
        status: row.get(2)?,
        started_at: row.get(3)?,
        finished_at: row.get(4)?,
        result_json: row.get(5)?,
        error: row.get(6)?,
    })
}

fn read_intel_vulnerability(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredVulnerability> {
    let severity_raw: Option<String> = row.get(4)?;
    let severity = severity_raw
        .as_deref()
        .map(Severity::parse)
        .unwrap_or(Severity::Unknown);
    let aliases_json: String = row.get(6)?;
    let affected_json: String = row.get(9)?;
    let fixed_json: String = row.get(10)?;
    let aliases: Vec<String> = serde_json::from_str(&aliases_json).unwrap_or_default();
    let affected: AffectedSpec = serde_json::from_str(&affected_json).unwrap_or_default();
    let fixed_versions: Vec<String> = serde_json::from_str(&fixed_json).unwrap_or_default();
    Ok(StoredVulnerability {
        source: row.get(0)?,
        advisory_id: row.get(1)?,
        ecosystem: row.get(2)?,
        package_name: row.get(3)?,
        severity,
        cve_id: row.get(5)?,
        aliases,
        summary: row.get(7)?,
        url: row.get(8)?,
        affected,
        fixed_versions,
        published_at: row.get(11)?,
        modified_at: row.get(12)?,
        fetched_at: row.get(13)?,
    })
}

fn read_intel_malware(row: &rusqlite::Row<'_>) -> rusqlite::Result<StoredMalware> {
    let kind_raw: String = row.get(5)?;
    let kind = MalwareKind::parse(&kind_raw);
    let evidence_str: String = row.get(8)?;
    let evidence: serde_json::Value =
        serde_json::from_str(&evidence_str).unwrap_or_else(|_| serde_json::json!({}));
    Ok(StoredMalware {
        source: row.get(0)?,
        ref_id: row.get(1)?,
        ecosystem: row.get(2)?,
        package_name: row.get(3)?,
        version: row.get(4)?,
        kind,
        summary: row.get(6)?,
        url: row.get(7)?,
        evidence,
        reported_at: row.get(9)?,
        fetched_at: row.get(10)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Store;
    use packguard_core::model::AffectedSpec;
    use serde_json::json;
    use tempfile::tempdir;

    fn sample_vuln(eco: &str, name: &str, advisory: &str) -> Vulnerability {
        Vulnerability {
            source: "osv".into(),
            advisory_id: advisory.into(),
            ecosystem: eco.into(),
            package_name: name.into(),
            severity: Severity::High,
            cve_id: Some("CVE-2026-0001".into()),
            aliases: vec!["GHSA-xxxx-xxxx-xxxx".into()],
            summary: Some("test vuln".into()),
            url: Some("https://example.com/adv".into()),
            affected: AffectedSpec::default(),
            fixed_versions: vec!["1.2.3".into()],
            published_at: Some("2026-01-01T00:00:00Z".into()),
            modified_at: Some("2026-01-02T00:00:00Z".into()),
        }
    }

    fn sample_malware(eco: &str, name: &str, ref_id: &str) -> MalwareReport {
        MalwareReport {
            source: "osv-mal".into(),
            ref_id: ref_id.into(),
            ecosystem: eco.into(),
            package_name: name.into(),
            version: "1.0.0".into(),
            kind: MalwareKind::Malware,
            summary: Some("test malware".into()),
            url: None,
            evidence: json!({"reason": "test"}),
            reported_at: Some("2026-01-01T00:00:00Z".into()),
        }
    }

    #[test]
    fn open_creates_intel_dir_and_db_file() {
        let tmp = tempdir().unwrap();
        let pg_home = tmp.path().join(".packguard");
        assert!(!pg_home.exists(), "guard: home should not exist yet");
        let _intel = IntelStore::open(&pg_home).unwrap();
        assert!(pg_home.is_dir(), "open() must create the home dir");
        assert!(
            pg_home.join("intel").is_dir(),
            "open() must create the intel/ subdir"
        );
        assert!(
            pg_home.join("intel/intel.db").is_file(),
            "open() must create intel.db"
        );
    }

    #[test]
    fn sync_log_roundtrip_in_intel_store() {
        let mut intel = IntelStore::open_in_memory().unwrap();
        assert!(intel.get_sync_state("osv-npm").unwrap().is_none());
        let state = SyncState {
            etag: Some("\"abc\"".into()),
            last_modified: Some("Wed, 01 Apr 2026 12:00:00 GMT".into()),
            last_commit: None,
            synced_at: Some("2026-04-01T12:00:00Z".into()),
            record_count: 12_345,
        };
        intel.put_sync_state("osv-npm", &state).unwrap();
        let got = intel.get_sync_state("osv-npm").unwrap().unwrap();
        assert_eq!(got.etag, state.etag);
        assert_eq!(got.last_modified, state.last_modified);
        assert_eq!(got.synced_at, state.synced_at);
        assert_eq!(got.record_count, state.record_count);
    }

    #[test]
    fn vulnerabilities_persist_and_load_for() {
        let mut intel = IntelStore::open_in_memory().unwrap();
        let vulns = vec![
            sample_vuln("npm", "lodash", "GHSA-aaaa-aaaa-aaaa"),
            sample_vuln("npm", "lodash", "GHSA-bbbb-bbbb-bbbb"),
            sample_vuln("npm", "react", "GHSA-cccc-cccc-cccc"),
        ];
        let n = intel.persist_vulnerabilities(&vulns).unwrap();
        assert_eq!(n, 3);
        assert_eq!(intel.count_vulnerabilities().unwrap(), 3);

        let loaded = intel.load_vulnerabilities_for("npm", "lodash").unwrap();
        assert_eq!(loaded.len(), 2);
        let advisories: Vec<&str> = loaded.iter().map(|v| v.advisory_id.as_str()).collect();
        assert!(advisories.contains(&"GHSA-aaaa-aaaa-aaaa"));
        assert!(advisories.contains(&"GHSA-bbbb-bbbb-bbbb"));
        // Re-persisting is idempotent on the natural key.
        let n2 = intel.persist_vulnerabilities(&vulns).unwrap();
        assert_eq!(n2, 3);
        assert_eq!(intel.count_vulnerabilities().unwrap(), 3);
    }

    #[test]
    fn load_all_vulnerabilities_orders_by_eco_name_advisory() {
        let mut intel = IntelStore::open_in_memory().unwrap();
        intel
            .persist_vulnerabilities(&[
                sample_vuln("pypi", "django", "PYSEC-bbb"),
                sample_vuln("npm", "react", "GHSA-aaa"),
                sample_vuln("npm", "lodash", "GHSA-zzz"),
                sample_vuln("npm", "lodash", "GHSA-aaa"),
            ])
            .unwrap();
        let all = intel.load_all_vulnerabilities().unwrap();
        let keys: Vec<(String, String, String)> = all
            .iter()
            .map(|v| {
                (
                    v.ecosystem.clone(),
                    v.package_name.clone(),
                    v.advisory_id.clone(),
                )
            })
            .collect();
        // Stable ordering: ecosystem then package_name then advisory_id.
        assert_eq!(
            keys,
            vec![
                ("npm".into(), "lodash".into(), "GHSA-aaa".into()),
                ("npm".into(), "lodash".into(), "GHSA-zzz".into()),
                ("npm".into(), "react".into(), "GHSA-aaa".into()),
                ("pypi".into(), "django".into(), "PYSEC-bbb".into()),
            ]
        );
    }

    #[test]
    fn load_all_malware_reports_orders_by_eco_name_id() {
        let mut intel = IntelStore::open_in_memory().unwrap();
        intel
            .persist_malware_reports(&[
                sample_malware("pypi", "evilpkg", "MAL-0001"),
                sample_malware("npm", "another", "MAL-0003"),
                sample_malware("pypi", "evilpkg", "MAL-0002"),
            ])
            .unwrap();
        let all = intel.load_all_malware_reports().unwrap();
        // Sorted by (ecosystem, package_name, id). Insertion order
        // breaks ties because `id` is autoincrement.
        let pairs: Vec<(String, String, String)> = all
            .iter()
            .map(|r| {
                (
                    r.ecosystem.clone(),
                    r.package_name.clone(),
                    r.ref_id.clone(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("npm".into(), "another".into(), "MAL-0003".into()),
                ("pypi".into(), "evilpkg".into(), "MAL-0001".into()),
                ("pypi".into(), "evilpkg".into(), "MAL-0002".into()),
            ]
        );
    }

    #[test]
    fn malware_reports_persist_and_load_for() {
        let mut intel = IntelStore::open_in_memory().unwrap();
        let reports = vec![
            sample_malware("pypi", "evilpkg", "MAL-0001"),
            sample_malware("pypi", "evilpkg", "MAL-0002"),
            sample_malware("npm", "another", "MAL-0003"),
        ];
        let n = intel.persist_malware_reports(&reports).unwrap();
        assert_eq!(n, 3);
        assert_eq!(intel.count_malware_reports().unwrap(), 3);

        let loaded = intel.load_malware_reports_for("pypi", "evilpkg").unwrap();
        assert_eq!(loaded.len(), 2);
        let refs: Vec<&str> = loaded.iter().map(|r| r.ref_id.as_str()).collect();
        assert_eq!(refs, vec!["MAL-0001", "MAL-0002"]);
    }

    #[test]
    fn intel_store_is_isolated_from_project_store() {
        // Both stores live under the same packguard_home, but they
        // hold separate SQLite files. Writes to the intel catalog
        // land in `intel.db`; per-project stores never see them.
        // Post-V8 the project store no longer carries the legacy
        // `vulnerabilities`/`malware_reports` tables at all, so the
        // isolation check is reduced to: the two SQLite files coexist
        // and the intel writes only show up in IntelStore counts.
        let tmp = tempdir().unwrap();
        let pg_home = tmp.path().join(".packguard");
        std::fs::create_dir_all(&pg_home).unwrap();
        let project_db = pg_home.join("projects/sample/store.db");
        let _project = Store::open(&project_db).unwrap();
        let mut intel = IntelStore::open(&pg_home).unwrap();
        intel
            .persist_vulnerabilities(&[sample_vuln("npm", "lodash", "GHSA-zzzz-zzzz-zzzz")])
            .unwrap();
        intel
            .persist_malware_reports(&[sample_malware("npm", "evilpkg", "MAL-9999")])
            .unwrap();
        assert_eq!(intel.count_vulnerabilities().unwrap(), 1);
        assert_eq!(intel.count_malware_reports().unwrap(), 1);
        assert!(pg_home.join("intel/intel.db").is_file());
        assert!(project_db.is_file());
    }

    #[test]
    fn migration_v1_idempotent_on_reopen() {
        let tmp = tempdir().unwrap();
        let pg_home = tmp.path().join(".packguard");
        let mut intel = IntelStore::open(&pg_home).unwrap();
        intel
            .persist_vulnerabilities(&[sample_vuln("npm", "lodash", "GHSA-id")])
            .unwrap();
        drop(intel);
        // Re-open the same file: migrations runner must detect V1 is
        // already applied (no double-create error) and the data must
        // survive the reopen.
        let intel = IntelStore::open(&pg_home).unwrap();
        assert_eq!(intel.count_vulnerabilities().unwrap(), 1);
    }
}
