use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use portalis_core::{Config, SCHEMA_VERSION};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Revision {
    pub id: String,
    pub kind: String,
    pub config: Config,
    pub created_at: DateTime<Utc>,
    pub applied_at: Option<DateTime<Utc>>,
    pub apply_error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditEntry {
    pub id: i64,
    pub action: String,
    pub revision_id: Option<String>,
    pub details: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackupRecord {
    pub id: String,
    pub revision_id: String,
    pub object_key: String,
    pub checksum: String,
    pub size_bytes: usize,
    pub created_at: DateTime<Utc>,
    pub status: String,
    pub error: Option<String>,
}

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)
            .with_context(|| format!("open SQLite database {}", path.display()))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        let database = Self { conn };
        database.migrate()?;
        Ok(database)
    }

    fn migrate(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY NOT NULL, value TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS revisions (
                 id TEXT PRIMARY KEY NOT NULL,
                 kind TEXT NOT NULL CHECK(kind IN ('draft', 'active')),
                 schema_version INTEGER NOT NULL,
                 config_json TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 applied_at TEXT,
                 apply_error TEXT
             );
             CREATE INDEX IF NOT EXISTS revisions_kind_created ON revisions(kind, created_at DESC);
             CREATE TABLE IF NOT EXISTS audit_log (
                 id INTEGER PRIMARY KEY AUTOINCREMENT,
                 action TEXT NOT NULL,
                 revision_id TEXT,
                 details TEXT NOT NULL,
                 created_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS s3_profiles (
                 id TEXT PRIMARY KEY NOT NULL,
                 name TEXT NOT NULL,
                 endpoint TEXT NOT NULL,
                 region TEXT NOT NULL,
                 bucket TEXT NOT NULL,
                 prefix TEXT NOT NULL,
                 path_style INTEGER NOT NULL DEFAULT 0,
                 provider TEXT NOT NULL,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS backups (
                 id TEXT PRIMARY KEY NOT NULL,
                 revision_id TEXT NOT NULL,
                 object_key TEXT NOT NULL,
                 checksum TEXT NOT NULL,
                 size_bytes INTEGER NOT NULL,
                 created_at TEXT NOT NULL,
                 status TEXT NOT NULL,
                 error TEXT
             );",
        )?;
        self.conn.execute(
            "INSERT OR IGNORE INTO metadata(key, value) VALUES('schema_version', ?1)",
            [SCHEMA_VERSION.to_string()],
        )?;
        Ok(())
    }

    pub fn draft_config(&self) -> Result<Option<Revision>> {
        self.latest_revision("draft")
    }

    pub fn active_config(&self) -> Result<Option<Config>> {
        Ok(self
            .latest_revision("active")?
            .map(|revision| revision.config))
    }

    pub fn active_revision(&self) -> Result<Option<Revision>> {
        self.latest_revision("active")
    }

    fn latest_revision(&self, kind: &str) -> Result<Option<Revision>> {
        self.conn.query_row(
            "SELECT id, kind, config_json, created_at, applied_at, apply_error FROM revisions WHERE kind = ?1 ORDER BY created_at DESC LIMIT 1",
            [kind],
            |row| {
                let config_json: String = row.get(2)?;
                let created_at: String = row.get(3)?;
                let applied_at: Option<String> = row.get(4)?;
                Ok(Revision {
                    id: row.get(0)?, kind: row.get(1)?, config: serde_json::from_str(&config_json).map_err(|error| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error)))?,
                    created_at: parse_time(&created_at)?, applied_at: applied_at.as_deref().map(parse_time).transpose()?, apply_error: row.get(5)?,
                })
            },
        ).optional().map_err(Into::into)
    }

    pub fn save_draft(&self, config: &Config) -> Result<Revision> {
        let revision = new_revision("draft", config, None, None)?;
        self.conn.execute("INSERT INTO revisions(id, kind, schema_version, config_json, created_at, applied_at, apply_error) VALUES(?1, 'draft', ?2, ?3, ?4, NULL, NULL)", params![revision.id, SCHEMA_VERSION, serde_json::to_string(config)?, revision.created_at.to_rfc3339()])?;
        self.audit("save_draft", Some(&revision.id), "draft saved")?;
        Ok(revision)
    }

    pub fn mark_active(&mut self, config: &Config) -> Result<Revision> {
        let transaction = self.conn.transaction()?;
        let revision = new_revision("active", config, Some(Utc::now()), None)?;
        transaction.execute("INSERT INTO revisions(id, kind, schema_version, config_json, created_at, applied_at, apply_error) VALUES(?1, 'active', ?2, ?3, ?4, ?5, NULL)", params![revision.id, SCHEMA_VERSION, serde_json::to_string(config)?, revision.created_at.to_rfc3339(), revision.applied_at.map(|time| time.to_rfc3339())])?;
        transaction.commit()?;
        self.audit("apply", Some(&revision.id), "revision became active")?;
        Ok(revision)
    }

    pub fn mark_apply_error(&self, revision_id: &str, error: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE revisions SET apply_error = ?1 WHERE id = ?2",
            params![error, revision_id],
        )?;
        self.audit("apply_failed", Some(revision_id), error)
    }

    pub fn revisions(&self, limit: usize) -> Result<Vec<Revision>> {
        let mut statement = self.conn.prepare("SELECT id, kind, config_json, created_at, applied_at, apply_error FROM revisions ORDER BY created_at DESC LIMIT ?1")?;
        let rows = statement.query_map([limit as i64], |row| {
            let config_json: String = row.get(2)?;
            let created_at: String = row.get(3)?;
            let applied_at: Option<String> = row.get(4)?;
            Ok(Revision {
                id: row.get(0)?,
                kind: row.get(1)?,
                config: serde_json::from_str(&config_json).map_err(|error| {
                    rusqlite::Error::FromSqlConversionFailure(
                        2,
                        rusqlite::types::Type::Text,
                        Box::new(error),
                    )
                })?,
                created_at: parse_time(&created_at)?,
                applied_at: applied_at.as_deref().map(parse_time).transpose()?,
                apply_error: row.get(5)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn revision(&self, id: &str) -> Result<Option<Revision>> {
        self.conn.query_row(
            "SELECT id, kind, config_json, created_at, applied_at, apply_error FROM revisions WHERE id = ?1",
            [id],
            |row| {
                let config_json: String = row.get(2)?;
                let created_at: String = row.get(3)?;
                let applied_at: Option<String> = row.get(4)?;
                Ok(Revision {
                    id: row.get(0)?, kind: row.get(1)?,
                    config: serde_json::from_str(&config_json).map_err(|error| rusqlite::Error::FromSqlConversionFailure(2, rusqlite::types::Type::Text, Box::new(error)))?,
                    created_at: parse_time(&created_at)?, applied_at: applied_at.as_deref().map(parse_time).transpose()?, apply_error: row.get(5)?,
                })
            },
        ).optional().map_err(Into::into)
    }

    pub fn audit(&self, action: &str, revision_id: Option<&str>, details: &str) -> Result<()> {
        self.conn.execute("INSERT INTO audit_log(action, revision_id, details, created_at) VALUES(?1, ?2, ?3, ?4)", params![action, revision_id, details, Utc::now().to_rfc3339()])?;
        Ok(())
    }

    pub fn audit_entries(&self, limit: usize) -> Result<Vec<AuditEntry>> {
        let mut statement = self.conn.prepare("SELECT id, action, revision_id, details, created_at FROM audit_log ORDER BY id DESC LIMIT ?1")?;
        let rows = statement.query_map([limit as i64], |row| {
            let created_at: String = row.get(4)?;
            Ok(AuditEntry {
                id: row.get(0)?,
                action: row.get(1)?,
                revision_id: row.get(2)?,
                details: row.get(3)?,
                created_at: parse_time(&created_at)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn backup_record(
        &self,
        revision_id: &str,
        object_key: &str,
        checksum: &str,
        size_bytes: usize,
        status: &str,
        error: Option<&str>,
    ) -> Result<()> {
        self.conn.execute("INSERT INTO backups(id, revision_id, object_key, checksum, size_bytes, created_at, status, error) VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)", params![Uuid::new_v4().to_string(), revision_id, object_key, checksum, size_bytes as i64, Utc::now().to_rfc3339(), status, error])?;
        Ok(())
    }

    pub fn backups(&self, limit: usize) -> Result<Vec<BackupRecord>> {
        let mut statement = self.conn.prepare("SELECT id, revision_id, object_key, checksum, size_bytes, created_at, status, error FROM backups ORDER BY created_at DESC LIMIT ?1")?;
        let rows = statement.query_map([limit as i64], |row| {
            let created_at: String = row.get(5)?;
            Ok(BackupRecord {
                id: row.get(0)?,
                revision_id: row.get(1)?,
                object_key: row.get(2)?,
                checksum: row.get(3)?,
                size_bytes: row.get::<_, i64>(4)? as usize,
                created_at: parse_time(&created_at)?,
                status: row.get(6)?,
                error: row.get(7)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    pub fn has_successful_backup(&self, revision_id: &str) -> Result<bool> {
        Ok(self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM backups WHERE revision_id = ?1 AND status = 'uploaded')",
            [revision_id],
            |row| row.get(0),
        )?)
    }
}

fn parse_time(value: &str) -> rusqlite::Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(value)
        .map(|time| time.with_timezone(&Utc))
        .map_err(|error| {
            rusqlite::Error::FromSqlConversionFailure(
                0,
                rusqlite::types::Type::Text,
                Box::new(error),
            )
        })
}

fn new_revision(
    kind: &str,
    config: &Config,
    applied_at: Option<DateTime<Utc>>,
    apply_error: Option<String>,
) -> Result<Revision> {
    Ok(Revision {
        id: Uuid::new_v4().to_string(),
        kind: kind.into(),
        config: config.clone(),
        created_at: Utc::now(),
        applied_at,
        apply_error,
    })
}
