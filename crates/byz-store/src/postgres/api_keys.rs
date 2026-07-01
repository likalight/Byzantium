use byz_common::{ByzResult, ByzantiumError};
use chrono::{DateTime, Utc};
use rand::Rng;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct ApiKeyRow {
    pub id: Uuid,
    pub label: String,
    pub operator_id: String,
    pub scopes: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Clone)]
pub struct ApiKeyRepository {
    db: Arc<PgPool>,
}

impl ApiKeyRepository {
    pub fn new(db: Arc<PgPool>) -> Self {
        Self { db }
    }

    /// Generate a new API key, store its SHA-256 hash, and return (id, raw_key).
    /// The raw key is of the form `byz_key_<32 random hex chars>`.
    /// The raw key is NEVER stored — only the hash is persisted.
    pub async fn create(
        &self,
        operator_id: &str,
        label: &str,
        scopes: &[&str],
        expires_at: Option<DateTime<Utc>>,
    ) -> ByzResult<(Uuid, String)> {
        // Generate 16 random bytes → 32 hex chars
        let random_bytes: [u8; 16] = rand::thread_rng().gen();
        let random_hex = hex::encode(random_bytes);
        let raw_key = format!("byz_key_{}", random_hex);

        let key_hash = sha256_hex(raw_key.as_bytes());
        let scopes_vec: Vec<String> = scopes.iter().map(|s| s.to_string()).collect();

        let id: Uuid = sqlx::query_scalar(
            r#"
            INSERT INTO api_keys (key_hash, label, operator_id, scopes, expires_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
            "#,
        )
        .bind(&key_hash)
        .bind(label)
        .bind(operator_id)
        .bind(&scopes_vec)
        .bind(expires_at)
        .fetch_one(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok((id, raw_key))
    }

    /// Validate a raw API key: hash it, look up in DB, check not revoked/expired,
    /// update last_used_at, and return the row.
    pub async fn validate(&self, raw_key: &str) -> ByzResult<Option<ApiKeyRow>> {
        let key_hash = sha256_hex(raw_key.as_bytes());

        let row = sqlx::query_as::<_, ApiKeyRowDb>(
            r#"
            SELECT id, label, operator_id, scopes, created_at, expires_at, revoked_at
            FROM api_keys
            WHERE key_hash = $1
            "#,
        )
        .bind(&key_hash)
        .fetch_optional(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        let row = match row {
            None => return Ok(None),
            Some(r) => r,
        };

        // Check revoked
        if row.revoked_at.is_some() {
            return Ok(None);
        }

        // Check expired
        if let Some(exp) = row.expires_at {
            if Utc::now() > exp {
                return Ok(None);
            }
        }

        // Update last_used_at (fire and forget — don't fail auth on this error)
        let db = self.db.clone();
        let hash = key_hash.clone();
        tokio::spawn(async move {
            let _ = sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE key_hash = $1")
                .bind(&hash)
                .execute(&*db)
                .await;
        });

        Ok(Some(ApiKeyRow {
            id: row.id,
            label: row.label,
            operator_id: row.operator_id,
            scopes: row.scopes,
            created_at: row.created_at,
            expires_at: row.expires_at,
            revoked_at: row.revoked_at,
        }))
    }

    /// Revoke a key by id, scoped to operator_id for safety.
    pub async fn revoke(&self, id: Uuid, operator_id: &str) -> ByzResult<()> {
        let result = sqlx::query(
            r#"
            UPDATE api_keys
            SET revoked_at = NOW()
            WHERE id = $1 AND operator_id = $2 AND revoked_at IS NULL
            "#,
        )
        .bind(id)
        .bind(operator_id)
        .execute(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            return Err(ByzantiumError::Internal(format!(
                "api key {} not found or already revoked",
                id
            )));
        }
        Ok(())
    }

    /// List all keys for an operator (never returns the raw key or hash).
    pub async fn list(&self, operator_id: &str) -> ByzResult<Vec<ApiKeyRow>> {
        let rows = sqlx::query_as::<_, ApiKeyRowDb>(
            r#"
            SELECT id, label, operator_id, scopes, created_at, expires_at, revoked_at
            FROM api_keys
            WHERE operator_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(operator_id)
        .fetch_all(&*self.db)
        .await
        .map_err(|e| ByzantiumError::Database(e.to_string()))?;

        Ok(rows
            .into_iter()
            .map(|r| ApiKeyRow {
                id: r.id,
                label: r.label,
                operator_id: r.operator_id,
                scopes: r.scopes,
                created_at: r.created_at,
                expires_at: r.expires_at,
                revoked_at: r.revoked_at,
            })
            .collect())
    }
}

/// Internal sqlx query type — not exported.
#[derive(sqlx::FromRow)]
struct ApiKeyRowDb {
    id: Uuid,
    label: String,
    operator_id: String,
    scopes: Vec<String>,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    hex::encode(h.finalize())
}
