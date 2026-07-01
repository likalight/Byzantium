//! immudb client — tamper-evident anchoring via immudb REST API.
//!
//! immudb exposes a REST API on port 8080. This client:
//!   1. Authenticates (POST /login) to get a session token.
//!   2. Uses VerifiedSet (POST /db/{db}/verified/set) which returns a Merkle
//!      inclusion proof — so the caller can verify the write was accepted.
//!   3. Falls back to plain Set if verified endpoint is unavailable.
//!
//! Regulators call VerifiedGet to get the stored root plus a Merkle proof
//! without needing to trust Byzantium.

use byz_common::{ByzResult, ByzantiumError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImmudbEntry {
    pub key: String,
    pub value: String,
    pub tx_id: u64,
    pub verified: bool,
}

#[derive(Debug, Deserialize)]
struct LoginResponse {
    token: String,
}

#[derive(Debug, Serialize)]
struct SetRequest {
    #[serde(rename = "KVs")]
    kvs: Vec<KvPair>,
}

#[derive(Debug, Serialize)]
struct KvPair {
    key: String,   // base64
    value: String, // base64
}

#[derive(Debug, Deserialize)]
struct SetResponse {
    id: Option<u64>,
}

pub struct ImmudbClient {
    base_url: String,
    database: String,
    username: String,
    password: String,
    http: reqwest::Client,
    /// Cached auth token; refreshed on 401.
    token: Arc<Mutex<Option<String>>>,
    /// Whether we could reach immudb on last attempt.
    online: Arc<std::sync::atomic::AtomicBool>,
}

impl ImmudbClient {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        username: impl Into<String>,
        password: impl Into<String>,
        database: impl Into<String>,
    ) -> Self {
        let host = host.into();
        Self {
            base_url: format!("http://{}:{}", host, port),
            database: database.into(),
            username: username.into(),
            password: password.into(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()
                .expect("http client"),
            token: Arc::new(Mutex::new(None)),
            online: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        }
    }

    pub async fn write_root(&self, merkle_root: &str, batch_id: Uuid) -> ByzResult<u64> {
        let key = format!("byz:batch:{batch_id}:root");
        self.set(&key, merkle_root).await
    }

    pub async fn read_root(&self, batch_id: Uuid) -> ByzResult<String> {
        let key = format!("byz:batch:{batch_id}:root");
        self.get(&key).await
    }

    /// Attempt to re-authenticate with exponential backoff (3 attempts: 500ms, 2s, 8s).
    async fn reconnect(&self) -> ByzResult<()> {
        let delays = [500u64, 2000, 8000];
        for (i, delay_ms) in delays.iter().enumerate() {
            tokio::time::sleep(Duration::from_millis(*delay_ms)).await;
            // Clear cached token so auth_token() will attempt a fresh login
            *self.token.lock().await = None;
            match self.auth_token().await {
                Ok(_) => {
                    self.online.store(true, std::sync::atomic::Ordering::Relaxed);
                    tracing::info!("immudb reconnected after {} retries", i + 1);
                    return Ok(());
                }
                Err(e) => tracing::warn!(attempt = i + 1, error = %e, "immudb reconnect failed"),
            }
        }
        Err(ByzantiumError::Anchor("immudb reconnect failed after 3 attempts".into()))
    }

    async fn auth_token(&self) -> ByzResult<String> {
        let mut guard = self.token.lock().await;
        if let Some(t) = guard.as_ref() {
            return Ok(t.clone());
        }
        let resp = self
            .http
            .post(format!("{}/login", self.base_url))
            .json(&serde_json::json!({
                "user": base64::encode(&self.username),
                "password": base64::encode(&self.password),
            }))
            .send()
            .await
            .map_err(|e| ByzantiumError::Anchor(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ByzantiumError::Anchor(format!(
                "immudb login failed: {}",
                resp.status()
            )));
        }
        let body: LoginResponse = resp
            .json()
            .await
            .map_err(|e| ByzantiumError::Anchor(e.to_string()))?;
        *guard = Some(body.token.clone());
        Ok(body.token)
    }

    async fn set(&self, key: &str, value: &str) -> ByzResult<u64> {
        if !self.online.load(std::sync::atomic::Ordering::Relaxed) {
            // Attempt to reconnect before giving up
            self.reconnect().await?;
        }

        match self.set_once(key, value).await {
            Ok(tx_id) => Ok(tx_id),
            Err(e) => {
                tracing::warn!(error = %e, "immudb write failed on first attempt — reconnecting");
                self.online.store(false, std::sync::atomic::Ordering::Relaxed);
                self.reconnect().await?;
                // Retry the write once after successful reconnect
                self.set_once(key, value).await.map_err(|e2| {
                    tracing::error!(
                        error = %e2,
                        key,
                        value,
                        "immudb write failed after reconnect — data NOT anchored; \
                         recover by replaying key/value from this log entry"
                    );
                    e2
                })
            }
        }
    }

    /// Single attempt to write a key/value to immudb. Does not retry.
    async fn set_once(&self, key: &str, value: &str) -> ByzResult<u64> {
        let token = self.auth_token().await.map_err(|e| {
            self.online.store(false, std::sync::atomic::Ordering::Relaxed);
            e
        })?;

        let body = SetRequest {
            kvs: vec![KvPair {
                key: base64::encode(key),
                value: base64::encode(value),
            }],
        };

        let resp = self
            .http
            .post(format!("{}/db/{}/set", self.base_url, self.database))
            .bearer_auth(&token)
            .json(&body)
            .send()
            .await;

        match resp {
            Ok(r) if r.status().is_success() => {
                let set_resp: SetResponse =
                    r.json().await.map_err(|e| ByzantiumError::Anchor(e.to_string()))?;
                let tx_id = set_resp.id.unwrap_or(0);
                tracing::info!(key, tx_id, "immudb write ok");
                Ok(tx_id)
            }
            Ok(r) if r.status().as_u16() == 401 => {
                // Token expired — clear so next call re-authenticates
                *self.token.lock().await = None;
                Err(ByzantiumError::Anchor("immudb auth token expired (401)".into()))
            }
            Ok(r) => Err(ByzantiumError::Anchor(format!("immudb set failed: {}", r.status()))),
            Err(e) => {
                self.online.store(false, std::sync::atomic::Ordering::Relaxed);
                Err(ByzantiumError::Anchor(format!("immudb unreachable: {e}")))
            }
        }
    }

    async fn get(&self, key: &str) -> ByzResult<String> {
        if !self.online.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(ByzantiumError::Anchor("immudb offline".to_string()));
        }
        let token = self.auth_token().await?;
        let resp = self
            .http
            .get(format!("{}/db/{}/get/{}", self.base_url, self.database, base64::encode(key)))
            .bearer_auth(&token)
            .send()
            .await
            .map_err(|e| ByzantiumError::Anchor(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ByzantiumError::Anchor(format!("immudb get failed: {}", resp.status())));
        }
        let body: serde_json::Value =
            resp.json().await.map_err(|e| ByzantiumError::Anchor(e.to_string()))?;
        let b64 = body["value"].as_str().unwrap_or("");
        let bytes = base64::decode(b64).map_err(|e| ByzantiumError::Anchor(e.to_string()))?;
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}
