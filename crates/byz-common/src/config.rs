use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub gateway: GatewayConfig,
    #[serde(default)]
    pub database: DatabaseConfig,
    #[serde(default)]
    pub redis: RedisConfig,
    #[serde(default)]
    pub neo4j: Neo4jConfig,
    #[serde(default)]
    pub immudb: ImmudbConfig,
    #[serde(default)]
    pub reputation: ReputationConfig,
    #[serde(default)]
    pub zkme: ZkMeConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub host: String,
    pub port: u16,
    pub trust_check_timeout_ms: u64,
    /// Comma-separated list of valid Bearer API keys for rails.
    /// Loaded from BYZ_API_KEYS env var (e.g. "key1,key2").
    pub api_keys: Vec<String>,
    /// Max trust-check requests per minute per IP (0 = unlimited).
    pub rate_limit_per_min: u32,
    /// How often to refresh reputation proof cache in background (seconds).
    pub proof_refresh_secs: u64,
    /// Comma-separated allowed CORS origins. "*" allows all (dev only).
    pub cors_origins: Vec<String>,
    /// If set, /metrics requires this token as Bearer auth. Leave unset for open access (behind firewall).
    pub metrics_token: Option<String>,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        let api_keys = std::env::var("BYZ_API_KEYS")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        Self {
            host: std::env::var("GATEWAY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("GATEWAY_PORT")
                .ok().and_then(|p| p.parse().ok()).unwrap_or(8080),
            trust_check_timeout_ms: 180,
            api_keys,
            rate_limit_per_min: std::env::var("RATE_LIMIT_PER_MIN")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(600),
            proof_refresh_secs: std::env::var("PROOF_REFRESH_SECS")
                .ok().and_then(|v| v.parse().ok()).unwrap_or(60),
            cors_origins: std::env::var("BYZ_CORS_ORIGINS")
                .unwrap_or_else(|_| "http://localhost:3000".to_string())
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            metrics_token: std::env::var("BYZ_METRICS_TOKEN").ok().filter(|s| !s.is_empty()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://byzantium:byzantium@localhost:5432/byzantium".to_string()),
            max_connections: 10,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct RedisConfig {
    pub url: String,
    pub proof_cache_ttl_secs: u64,
}

impl Default for RedisConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("REDIS_URL")
                .unwrap_or_else(|_| "redis://localhost:6379".to_string()),
            proof_cache_ttl_secs: 300,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Neo4jConfig {
    pub uri: String,
    pub username: String,
    pub password: String,
}

impl Default for Neo4jConfig {
    fn default() -> Self {
        Self {
            uri: std::env::var("NEO4J_URI")
                .unwrap_or_else(|_| "bolt://localhost:7687".to_string()),
            username: std::env::var("NEO4J_USERNAME").unwrap_or_else(|_| "neo4j".to_string()),
            password: std::env::var("NEO4J_PASSWORD").unwrap_or_else(|_| "byzantium".to_string()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ImmudbConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub database: String,
}

impl Default for ImmudbConfig {
    fn default() -> Self {
        Self {
            host: std::env::var("IMMUDB_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port: 3322,
            username: std::env::var("IMMUDB_USERNAME").unwrap_or_else(|_| "immudb".to_string()),
            password: std::env::var("IMMUDB_PASSWORD").unwrap_or_else(|_| "immudb".to_string()),
            database: std::env::var("IMMUDB_DATABASE")
                .unwrap_or_else(|_| "byzantium".to_string()),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ReputationConfig {
    pub default_threshold: u32,
    pub score_refresh_interval_secs: u64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            default_threshold: 600,
            score_refresh_interval_secs: 3600,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZkMeConfig {
    pub api_url: String,
    pub api_key: String,
}

impl Default for ZkMeConfig {
    fn default() -> Self {
        Self {
            api_url: std::env::var("ZKME_API_URL")
                .unwrap_or_else(|_| "https://api.zkme.io".to_string()),
            api_key: std::env::var("ZKME_API_KEY").unwrap_or_default(),
        }
    }
}

impl Config {
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        Self::default()
    }
}
