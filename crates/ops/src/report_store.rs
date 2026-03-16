use rusqlite::{params, Connection, OptionalExtension};
use serde_json::Value;
use std::convert::TryFrom;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS runs(
    run_id TEXT PRIMARY KEY,
    started_at_ms INTEGER NOT NULL,
    ended_at_ms INTEGER,
    selection_json TEXT NOT NULL,
    verdict TEXT,
    attempted INTEGER,
    installed INTEGER,
    failed INTEGER,
    unaccounted INTEGER,
    app_version TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS events(
    run_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    ts_ms INTEGER NOT NULL,
    phase TEXT NOT NULL,
    severity TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    message TEXT NOT NULL,
    PRIMARY KEY(run_id, seq)
);

CREATE TABLE IF NOT EXISTS packages(
    run_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    from_version TEXT,
    to_version TEXT,
    arch TEXT,
    repository TEXT,
    action TEXT,
    result TEXT,
    risk TEXT,
    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_assessments(
    run_id TEXT NOT NULL PRIMARY KEY,
    risk_level TEXT,
    recommendations_json TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_events_run_id_seq ON events(run_id, seq);
CREATE INDEX IF NOT EXISTS idx_runs_started_at_ms ON runs(started_at_ms);
CREATE INDEX IF NOT EXISTS idx_runs_ended_at_ms ON runs(ended_at_ms);
CREATE INDEX IF NOT EXISTS idx_packages_run_id ON packages(run_id);
CREATE INDEX IF NOT EXISTS idx_packages_package_name ON packages(package_name);
CREATE INDEX IF NOT EXISTS idx_packages_action ON packages(action);
CREATE INDEX IF NOT EXISTS idx_ai_assessments_created_at ON ai_assessments(created_at);
";

#[derive(Debug, Clone)]
pub struct RunRow {
    pub run_id: String,
    pub started_at_ms: i64,
    pub ended_at_ms: Option<i64>,
    pub selection_json: String,
    pub verdict: Option<String>,
    pub attempted: Option<i64>,
    pub installed: Option<i64>,
    pub failed: Option<i64>,
    pub unaccounted: Option<i64>,
    pub app_version: String,
}

#[derive(Debug, Clone)]
pub struct EventRow {
    pub run_id: String,
    pub seq: i64,
    pub ts_ms: i64,
    pub phase: String,
    pub severity: String,
    pub event_type: String,
    pub payload_json: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackageEvidenceRow {
    pub run_id: String,
    pub package_name: String,
    pub from_version: Option<String>,
    pub to_version: Option<String>,
    pub arch: Option<String>,
    pub repository: Option<String>,
    pub action: Option<String>,
    pub result: Option<String>,
    pub risk: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAssessmentRow {
    pub run_id: String,
    pub risk_level: Option<String>,
    pub recommendations_json: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiPersistenceEligibility {
    EligibleOpenRun,
    MissingRun,
    ClosedRun,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCohesionDiagnostic {
    pub run_id: String,
    pub run_exists: bool,
    pub event_count: usize,
    pub package_count: usize,
    pub ai_assessment_present: bool,
    pub verdict: Option<String>,
    pub started_at_ms: Option<i64>,
    pub ended_at_ms: Option<i64>,
    pub warnings: Vec<String>,
}

impl RunCohesionDiagnostic {
    pub fn render(&self) -> String {
        let mut lines = vec![
            format!("run_id={}", self.run_id),
            format!("run_exists={}", self.run_exists),
            format!("event_count={}", self.event_count),
            format!("package_count={}", self.package_count),
            format!("ai_assessment_present={}", self.ai_assessment_present),
            format!("verdict={}", self.verdict.as_deref().unwrap_or("None")),
            format!(
                "started_at_ms={}",
                self.started_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "None".to_string())
            ),
            format!(
                "ended_at_ms={}",
                self.ended_at_ms
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "None".to_string())
            ),
        ];
        if self.warnings.is_empty() {
            lines.push("warnings=none".to_string());
        } else {
            lines.push(format!("warnings={}", self.warnings.join(" | ")));
        }
        lines.join("\n")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AiAttachmentDiagnostic {
    pub run_id: String,
    pub risk_level: Option<String>,
    pub event_count: usize,
    pub package_count: usize,
    pub verdict: Option<String>,
    pub started_at_ms: Option<i64>,
    pub ended_at_ms: Option<i64>,
    pub warnings: Vec<String>,
}

impl AiAttachmentDiagnostic {
    fn render(&self) -> String {
        let mut lines = vec![
            format!("run_id={}", self.run_id),
            format!(
                "risk_level={}",
                self.risk_level.as_deref().unwrap_or("None")
            ),
            format!("event_count={}", self.event_count),
            format!("package_count={}", self.package_count),
            format!("verdict={}", self.verdict.as_deref().unwrap_or("None")),
        ];
        if self.warnings.is_empty() {
            lines.push("warnings=none".to_string());
        } else {
            lines.push(format!("warnings={}", self.warnings.join(" | ")));
        }
        lines.join("\n")
    }
}

#[derive(Debug)]
pub struct ReportStore {
    conn: Mutex<Connection>,
}

impl ReportStore {
    pub fn new() -> Result<Self, String> {
        let path = default_db_path()?;
        Self::with_db_path(path)
    }

    pub fn with_db_path<P: AsRef<Path>>(path: P) -> Result<Self, String> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| {
                format!("failed to create db directory {}: {err}", parent.display())
            })?;
        }

        let conn = Connection::open(path)
            .map_err(|err| format!("failed to open sqlite db {}: {err}", path.display()))?;
        conn.pragma_update(None, "foreign_keys", "ON")
            .map_err(|err| format!("failed to enable sqlite foreign keys: {err}"))?;
        conn.execute_batch(SCHEMA_SQL)
            .map_err(|err| format!("failed to initialize report store schema: {err}"))?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn start_run(&self, selection_json: &str, app_version: &str) -> Result<String, String> {
        let run_id = Uuid::new_v4().to_string();
        let started_at_ms = now_ms()?;
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;

        conn.execute(
            "INSERT INTO runs(
                run_id,
                started_at_ms,
                ended_at_ms,
                selection_json,
                verdict,
                attempted,
                installed,
                failed,
                unaccounted,
                app_version
            ) VALUES (?1, ?2, NULL, ?3, NULL, NULL, NULL, NULL, NULL, ?4)",
            params![&run_id, started_at_ms, selection_json, app_version],
        )
        .map_err(|err| format!("failed to insert run: {err}"))?;

        Ok(run_id)
    }

    pub fn update_run_selection(&self, run_id: &str, selection_json: &str) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let updated = conn
            .execute(
                "UPDATE runs
                 SET selection_json = ?2
                 WHERE run_id = ?1",
                params![run_id, selection_json],
            )
            .map_err(|err| format!("failed to update run selection: {err}"))?;
        if updated == 0 {
            return Err(format!("run not found: {run_id}"));
        }
        Ok(())
    }

    pub fn delete_run(&self, run_id: &str) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        conn.execute("DELETE FROM events WHERE run_id = ?1", params![run_id])
            .map_err(|err| format!("failed to delete run events: {err}"))?;
        conn.execute("DELETE FROM packages WHERE run_id = ?1", params![run_id])
            .map_err(|err| format!("failed to delete run packages: {err}"))?;
        conn.execute(
            "DELETE FROM ai_assessments WHERE run_id = ?1",
            params![run_id],
        )
        .map_err(|err| format!("failed to delete run AI assessment: {err}"))?;
        conn.execute("DELETE FROM runs WHERE run_id = ?1", params![run_id])
            .map_err(|err| format!("failed to delete run: {err}"))?;
        Ok(())
    }

    pub fn prune_preview_only_runs(&self) -> Result<usize, String> {
        let runs = self.list_runs(10_000)?;
        let mut removed = 0usize;
        for run in runs {
            let events = self.load_events(&run.run_id)?;
            let packages = self.load_packages(&run.run_id)?;
            let ai = self.load_ai_assessment(&run.run_id)?;

            if !selection_json_is_preview_only(&run.selection_json)
                && !is_preview_only_open_root(&run, &events, &packages, ai.as_ref())
            {
                continue;
            }
            self.delete_run(&run.run_id)?;
            removed += 1;
        }
        Ok(removed)
    }

    pub fn append_event(
        &self,
        run_id: &str,
        phase: &str,
        severity: &str,
        event_type: &str,
        payload_json: &str,
        message: &str,
    ) -> Result<(), String> {
        let ts_ms = now_ms()?;
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let tx = conn
            .transaction()
            .map_err(|err| format!("failed to start append_event transaction: {err}"))?;

        let run_exists = tx
            .query_row(
                "SELECT 1 FROM runs WHERE run_id = ?1 LIMIT 1",
                params![run_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|err| format!("failed to verify run before appending event: {err}"))?
            .is_some();
        if !run_exists {
            return Err(format!("run not found: {run_id}"));
        }

        let next_seq: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(seq), -1) + 1 FROM events WHERE run_id = ?1",
                params![run_id],
                |row| row.get(0),
            )
            .map_err(|err| format!("failed to compute next event sequence: {err}"))?;

        tx.execute(
            "INSERT INTO events(
                run_id,
                seq,
                ts_ms,
                phase,
                severity,
                event_type,
                payload_json,
                message
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                run_id,
                next_seq,
                ts_ms,
                phase,
                severity,
                event_type,
                payload_json,
                message
            ],
        )
        .map_err(|err| format!("failed to insert event: {err}"))?;

        tx.commit()
            .map_err(|err| format!("failed to commit append_event transaction: {err}"))?;
        Ok(())
    }

    pub fn finish_run(
        &self,
        run_id: &str,
        ended_at_ms: i64,
        verdict: &str,
        attempted: i64,
        installed: i64,
        failed: i64,
        unaccounted: i64,
    ) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let updated = conn
            .execute(
                "UPDATE runs
                 SET ended_at_ms = ?2,
                     verdict = ?3,
                     attempted = ?4,
                     installed = ?5,
                     failed = ?6,
                     unaccounted = ?7
                 WHERE run_id = ?1",
                params![
                    run_id,
                    ended_at_ms,
                    verdict,
                    attempted,
                    installed,
                    failed,
                    unaccounted
                ],
            )
            .map_err(|err| format!("failed to finish run: {err}"))?;
        if updated == 0 {
            return Err(format!("run not found: {run_id}"));
        }
        Ok(())
    }

    pub fn replace_packages(
        &self,
        run_id: &str,
        packages: &[PackageEvidenceRow],
    ) -> Result<(), String> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let tx = conn
            .transaction()
            .map_err(|err| format!("failed to start replace_packages transaction: {err}"))?;

        let run_exists = tx
            .query_row(
                "SELECT 1 FROM runs WHERE run_id = ?1 LIMIT 1",
                params![run_id],
                |_| Ok(()),
            )
            .optional()
            .map_err(|err| format!("failed to verify run before replacing packages: {err}"))?
            .is_some();
        if !run_exists {
            return Err(format!("run not found: {run_id}"));
        }

        tx.execute("DELETE FROM packages WHERE run_id = ?1", params![run_id])
            .map_err(|err| format!("failed to clear existing package rows: {err}"))?;

        {
            let mut stmt = tx
                .prepare(
                    "INSERT INTO packages(
                        run_id,
                        package_name,
                        from_version,
                        to_version,
                        arch,
                        repository,
                        action,
                        result,
                        risk
                    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
                )
                .map_err(|err| format!("failed to prepare package insert: {err}"))?;

            for package in packages {
                stmt.execute(params![
                    run_id,
                    &package.package_name,
                    &package.from_version,
                    &package.to_version,
                    &package.arch,
                    &package.repository,
                    &package.action,
                    &package.result,
                    &package.risk,
                ])
                .map_err(|err| format!("failed to insert package row: {err}"))?;
            }
        }

        tx.commit()
            .map_err(|err| format!("failed to commit replace_packages transaction: {err}"))?;
        Ok(())
    }

    pub fn upsert_ai_assessment(
        &self,
        run_id: &str,
        risk_level: Option<&str>,
        recommendations_json: &str,
    ) -> Result<(), String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let updated = conn
            .execute(
                "INSERT INTO ai_assessments(
                    run_id,
                    risk_level,
                    recommendations_json,
                    created_at
                 ) VALUES (?1, ?2, ?3, CURRENT_TIMESTAMP)
                 ON CONFLICT(run_id) DO UPDATE SET
                    risk_level = excluded.risk_level,
                    recommendations_json = excluded.recommendations_json,
                    created_at = CURRENT_TIMESTAMP",
                params![run_id, risk_level, recommendations_json],
            )
            .map_err(|err| format!("failed to upsert ai assessment: {err}"))?;
        if updated == 0 {
            return Err(format!("run not found: {run_id}"));
        }
        Ok(())
    }

    pub fn ensure_run_active_for_ai(&self, run_id: &str) -> Result<(), String> {
        match self.ai_persistence_eligibility(run_id)? {
            AiPersistenceEligibility::EligibleOpenRun => Ok(()),
            AiPersistenceEligibility::ClosedRun => {
                Err(format!("run already closed for ai persistence: {run_id}"))
            }
            AiPersistenceEligibility::MissingRun => {
                Err(format!("run not found for ai persistence: {run_id}"))
            }
        }
    }

    pub fn ai_persistence_eligibility(
        &self,
        run_id: &str,
    ) -> Result<AiPersistenceEligibility, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let row = conn
            .query_row(
                "SELECT ended_at_ms
                 FROM runs
                 WHERE run_id = ?1
                 LIMIT 1",
                params![run_id],
                |row| row.get::<_, Option<i64>>(0),
            )
            .optional()
            .map_err(|err| format!("failed to verify run for ai persistence: {err}"))?;

        match row {
            Some(None) => Ok(AiPersistenceEligibility::EligibleOpenRun),
            Some(Some(_)) => Ok(AiPersistenceEligibility::ClosedRun),
            None => Ok(AiPersistenceEligibility::MissingRun),
        }
    }

    pub fn latest_open_run_id(&self) -> Result<Option<String>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        conn.query_row(
            "SELECT run_id
             FROM runs
             WHERE ended_at_ms IS NULL
             ORDER BY started_at_ms DESC, rowid DESC
             LIMIT 1",
            [],
            |row| row.get(0),
        )
        .optional()
        .map_err(|err| format!("failed to load latest open run id: {err}"))
    }

    pub fn upsert_ai_assessment_for_latest_open_run(
        &self,
        risk_level: Option<&str>,
        recommendations_json: &str,
    ) -> Result<Option<String>, String> {
        let Some(run_id) = self.latest_open_run_id()? else {
            return Ok(None);
        };
        self.upsert_ai_assessment(&run_id, risk_level, recommendations_json)?;
        Ok(Some(run_id))
    }

    pub fn list_runs(&self, limit: usize) -> Result<Vec<RunRow>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT
                    run_id,
                    started_at_ms,
                    ended_at_ms,
                    selection_json,
                    verdict,
                    attempted,
                    installed,
                    failed,
                    unaccounted,
                    app_version
                 FROM runs
                 ORDER BY started_at_ms DESC
                 LIMIT ?1",
            )
            .map_err(|err| format!("failed to prepare list_runs query: {err}"))?;

        let rows = stmt
            .query_map(params![limit as i64], |row| {
                Ok(RunRow {
                    run_id: row.get(0)?,
                    started_at_ms: row.get(1)?,
                    ended_at_ms: row.get(2)?,
                    selection_json: row.get(3)?,
                    verdict: row.get(4)?,
                    attempted: row.get(5)?,
                    installed: row.get(6)?,
                    failed: row.get(7)?,
                    unaccounted: row.get(8)?,
                    app_version: row.get(9)?,
                })
            })
            .map_err(|err| format!("failed to query runs: {err}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("failed to load run rows: {err}"))
    }

    pub fn load_events(&self, run_id: &str) -> Result<Vec<EventRow>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT
                    run_id,
                    seq,
                    ts_ms,
                    phase,
                    severity,
                    event_type,
                    payload_json,
                    message
                 FROM events
                 WHERE run_id = ?1
                 ORDER BY seq ASC",
            )
            .map_err(|err| format!("failed to prepare load_events query: {err}"))?;

        let rows = stmt
            .query_map(params![run_id], |row| {
                Ok(EventRow {
                    run_id: row.get(0)?,
                    seq: row.get(1)?,
                    ts_ms: row.get(2)?,
                    phase: row.get(3)?,
                    severity: row.get(4)?,
                    event_type: row.get(5)?,
                    payload_json: row.get(6)?,
                    message: row.get(7)?,
                })
            })
            .map_err(|err| format!("failed to query events: {err}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("failed to load event rows: {err}"))
    }

    pub fn load_packages(&self, run_id: &str) -> Result<Vec<PackageEvidenceRow>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let mut stmt = conn
            .prepare(
                "SELECT
                    run_id,
                    package_name,
                    from_version,
                    to_version,
                    arch,
                    repository,
                    action,
                    result,
                    risk
                 FROM packages
                 WHERE run_id = ?1
                 ORDER BY
                    CASE LOWER(COALESCE(risk, ''))
                        WHEN 'red' THEN 0
                        WHEN 'amber' THEN 1
                        WHEN 'green' THEN 2
                        ELSE 3
                    END ASC,
                    action ASC,
                    package_name ASC,
                    arch ASC",
            )
            .map_err(|err| format!("failed to prepare load_packages query: {err}"))?;

        let rows = stmt
            .query_map(params![run_id], |row| {
                Ok(PackageEvidenceRow {
                    run_id: row.get(0)?,
                    package_name: row.get(1)?,
                    from_version: row.get(2)?,
                    to_version: row.get(3)?,
                    arch: row.get(4)?,
                    repository: row.get(5)?,
                    action: row.get(6)?,
                    result: row.get(7)?,
                    risk: row.get(8)?,
                })
            })
            .map_err(|err| format!("failed to query packages: {err}"))?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("failed to load package rows: {err}"))
    }

    pub fn load_ai_assessment(&self, run_id: &str) -> Result<Option<AiAssessmentRow>, String> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        conn.query_row(
            "SELECT
                run_id,
                risk_level,
                recommendations_json,
                created_at
             FROM ai_assessments
             WHERE run_id = ?1",
            params![run_id],
            |row| {
                Ok(AiAssessmentRow {
                    run_id: row.get(0)?,
                    risk_level: row.get(1)?,
                    recommendations_json: row.get(2)?,
                    created_at: row.get(3)?,
                })
            },
        )
        .optional()
        .map_err(|err| format!("failed to load ai assessment row: {err}"))
    }

    pub fn inspect_run_cohesion(&self, run_id: &str) -> Result<RunCohesionDiagnostic, String> {
        let run = self
            .list_runs(10_000)?
            .into_iter()
            .find(|row| row.run_id == run_id);
        let events = self.load_events(run_id)?;
        let packages = self.load_packages(run_id)?;
        let ai = self.load_ai_assessment(run_id)?;

        let mut warnings = Vec::new();
        if run.is_none() {
            warnings.push("run row missing".to_string());
        }
        if run.is_some() && !events.is_empty() && packages.is_empty() {
            warnings.push("run has events but no package evidence".to_string());
        }
        if run.is_some() && (!events.is_empty() || !packages.is_empty()) && ai.is_none() {
            warnings.push("run has events/packages but no ai assessment".to_string());
        }
        if ai.is_some() && is_tiny_incidental_run(&events, &packages) {
            warnings.push("ai assessment is attached to a tiny incidental run".to_string());
        }

        Ok(RunCohesionDiagnostic {
            run_id: run_id.to_string(),
            run_exists: run.is_some(),
            event_count: events.len(),
            package_count: packages.len(),
            ai_assessment_present: ai.is_some(),
            verdict: run.as_ref().and_then(|row| row.verdict.clone()),
            started_at_ms: run.as_ref().map(|row| row.started_at_ms),
            ended_at_ms: run.as_ref().and_then(|row| row.ended_at_ms),
            warnings,
        })
    }

    pub fn inspect_ai_attachment_anomalies(&self) -> Result<Vec<AiAttachmentDiagnostic>, String> {
        let runs = self.list_runs(10_000)?;
        let mut diagnostics = Vec::new();

        for run in runs {
            let Some(ai) = self.load_ai_assessment(&run.run_id)? else {
                continue;
            };
            let events = self.load_events(&run.run_id)?;
            let packages = self.load_packages(&run.run_id)?;
            let mut warnings = Vec::new();

            if is_tiny_incidental_run(&events, &packages) {
                warnings.push("ai assessment attached to a tiny incidental run".to_string());
            }
            if run.verdict.as_deref() == Some("FAIL") && packages.is_empty() {
                warnings.push(
                    "ai assessment attached to a failed run with no package evidence".to_string(),
                );
            }

            diagnostics.push(AiAttachmentDiagnostic {
                run_id: run.run_id,
                risk_level: ai.risk_level,
                event_count: events.len(),
                package_count: packages.len(),
                verdict: run.verdict,
                started_at_ms: Some(run.started_at_ms),
                ended_at_ms: run.ended_at_ms,
                warnings,
            });
        }

        Ok(diagnostics)
    }

    pub fn render_run_cohesion_debug(&self, run_id: &str) -> Result<String, String> {
        let mut output = self.inspect_run_cohesion(run_id)?.render();
        let ai_warnings = self
            .inspect_ai_attachment_anomalies()?
            .into_iter()
            .filter(|diagnostic| !diagnostic.warnings.is_empty())
            .map(|diagnostic| diagnostic.render())
            .collect::<Vec<_>>();
        if !ai_warnings.is_empty() {
            output.push_str("\n\nai_attachment_anomalies:\n");
            output.push_str(&ai_warnings.join("\n---\n"));
        }
        Ok(output)
    }

    pub fn prune_older_than(&self, days: i64) -> Result<(), String> {
        if days < 0 {
            return Err("days must be non-negative".to_string());
        }
        let cutoff_ms = now_ms()? - (days * 24 * 60 * 60 * 1000);
        let mut conn = self
            .conn
            .lock()
            .map_err(|_| "report store mutex poisoned".to_string())?;
        let tx = conn
            .transaction()
            .map_err(|err| format!("failed to start prune transaction: {err}"))?;

        tx.execute(
            "DELETE FROM events
             WHERE run_id IN (
                 SELECT run_id
                 FROM runs
                 WHERE COALESCE(ended_at_ms, started_at_ms) < ?1
             )",
            params![cutoff_ms],
        )
        .map_err(|err| format!("failed to prune old events: {err}"))?;

        tx.execute(
            "DELETE FROM runs
             WHERE COALESCE(ended_at_ms, started_at_ms) < ?1",
            params![cutoff_ms],
        )
        .map_err(|err| format!("failed to prune old runs: {err}"))?;

        tx.commit()
            .map_err(|err| format!("failed to commit prune transaction: {err}"))?;
        Ok(())
    }
}

fn default_db_path() -> Result<PathBuf, String> {
    let home = dirs::home_dir().ok_or_else(|| "failed to resolve home directory".to_string())?;
    Ok(home.join(".config").join("chamrisk").join("chamrisk.db"))
}

fn is_tiny_incidental_run(events: &[EventRow], packages: &[PackageEvidenceRow]) -> bool {
    if !packages.is_empty() {
        return false;
    }
    if events.is_empty() {
        return true;
    }
    if events.len() > 2 {
        return false;
    }

    !events.iter().any(|event| {
        matches!(
            event.event_type.as_str(),
            "preview.result"
                | "zypper.apply.result"
                | "reconcile.summary"
                | "ReconcileSummary"
                | "PackageResult"
        )
    })
}

fn selection_json_is_preview_only(selection_json: &str) -> bool {
    let Ok(value) = serde_json::from_str::<Value>(selection_json) else {
        return false;
    };
    value
        .get("mode")
        .and_then(Value::as_str)
        .map(|mode| mode.eq_ignore_ascii_case("preview"))
        .unwrap_or(false)
}

fn is_preview_only_open_root(
    run: &RunRow,
    events: &[EventRow],
    packages: &[PackageEvidenceRow],
    ai: Option<&AiAssessmentRow>,
) -> bool {
    if run.ended_at_ms.is_some() || run.verdict.is_some() || ai.is_some() || events.is_empty() {
        return false;
    }

    let preview_only_events = events.iter().all(|event| {
        matches!(
            event.event_type.as_str(),
            "preview.result" | "zypper.preview.plan"
        )
    });

    if !preview_only_events {
        return false;
    }

    packages.is_empty()
        || packages
            .iter()
            .all(|package| package.result.as_deref().unwrap_or("").is_empty())
}

fn now_ms() -> Result<i64, String> {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock error: {err}"))?;
    i64::try_from(duration.as_millis()).map_err(|_| "timestamp overflow".to_string())
}
