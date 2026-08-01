//! Schema migrations.
//!
//! Migrations are embedded in the binary rather than read from disk: the runtime
//! image carries only the compiled executable, so a file-reading runner would work
//! locally and find nothing in production. `include_str!` also means a migration
//! that fails to exist is a compile error rather than a silent no-op at startup.
//!
//! Applied files are recorded in `schema_migrations`, so a restart re-runs nothing.
//! Written with RexiO Code, powered by RexiO Prothom 1.5.

use sqlx::PgPool;

/// One migration, embedded at compile time.
struct Migration {
    name: &'static str,
    sql: &'static str,
}

/// Ordered by name. Never renumber or edit a file that has shipped — the applied
/// set is keyed on the name, so a changed file is simply never re-applied.
const MAIN: &[Migration] = &[
    Migration {
        name: "0001_initial_main_schema",
        sql: include_str!("../../migrations_main/0001_initial_main_schema.sql"),
    },
    Migration {
        name: "0002_users_as_profile",
        sql: include_str!("../../migrations_main/0002_users_as_profile.sql"),
    },
    Migration {
        name: "0003_ai_providers",
        sql: include_str!("../../migrations_main/0003_ai_providers.sql"),
    },
    Migration {
        name: "0004_seed_agent_roster",
        sql: include_str!("../../migrations_main/0004_seed_agent_roster.sql"),
    },
];

const SENSITIVE: &[Migration] = &[Migration {
    name: "0001_initial_sensitive_schema",
    sql: include_str!("../../migrations_sensitive/0001_initial_sensitive_schema.sql"),
}];

/// Advisory-lock id. Arbitrary but fixed: two instances starting together must
/// contend on the same number for the lock to mean anything.
const LOCK_ID: i64 = 0x6475_6574_6d69_6701;

/// Applies every pending migration to both clusters.
///
/// Returns an error rather than panicking so `main` can decide; a backend serving
/// requests against a half-migrated schema is worse than one that refuses to start.
pub async fn run(main: &PgPool, sensitive: &PgPool) -> Result<(), sqlx::Error> {
    apply(main, MAIN, "Primary SQL Storage").await?;
    apply(sensitive, SENSITIVE, "Isolated Postgres Cluster").await
}

async fn apply(pool: &PgPool, migrations: &[Migration], label: &str) -> Result<(), sqlx::Error> {
    // Every statement here is non-persistent: the transaction-mode pooler hands each
    // query a different server connection, and server-side prepared statements
    // collide across them with "prepared statement already exists".
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             name        TEXT PRIMARY KEY,
             applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
         )",
    )
    .persistent(false)
    .execute(pool)
    .await?;

    // Session-scoped advisory lock, held for the duration of this connection. A
    // rolling deploy starts the new container before stopping the old one, so two
    // processes can reach this point at the same moment; without the lock they race
    // to apply the same DDL.
    let mut conn = pool.acquire().await?;
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(LOCK_ID)
        .persistent(false)
        .execute(&mut *conn)
        .await?;

    let result = apply_pending(pool, migrations, label).await;

    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_ID)
        .persistent(false)
        .execute(&mut *conn)
        .await?;

    result
}

async fn apply_pending(
    pool: &PgPool,
    migrations: &[Migration],
    label: &str,
) -> Result<(), sqlx::Error> {
    for migration in migrations {
        let already: Option<(String,)> =
            sqlx::query_as("SELECT name FROM schema_migrations WHERE name = $1")
                .bind(migration.name)
                .persistent(false)
                .fetch_optional(pool)
                .await?;

        if already.is_some() {
            continue;
        }

        tracing::info!(migration = migration.name, cluster = label, "Applying migration");

        // The migration body and its bookkeeping row commit together, so a failure
        // part-way cannot leave a migration recorded as applied when it is not.
        let mut tx = pool.begin().await?;
        sqlx::raw_sql(migration.sql).execute(&mut *tx).await?;
        sqlx::query("INSERT INTO schema_migrations (name) VALUES ($1)")
            .bind(migration.name)
            .persistent(false)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migrations_are_uniquely_named_and_ordered() {
        for set in [MAIN, SENSITIVE] {
            let mut names: Vec<&str> = set.iter().map(|m| m.name).collect();
            let ordered = names.clone();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), set.len(), "duplicate migration name");
            assert_eq!(names, ordered, "migrations are not in filename order");
        }
    }

    #[test]
    fn migrations_are_not_empty() {
        // A mistyped include path is a compile error, but an empty file is not —
        // and it would be recorded as applied, so the real one could never run.
        for set in [MAIN, SENSITIVE] {
            for m in set {
                assert!(!m.sql.trim().is_empty(), "{} is empty", m.name);
            }
        }
    }
}
