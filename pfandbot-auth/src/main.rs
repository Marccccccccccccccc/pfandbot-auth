use axum::{
    extract::{Query, Request},
    http::{StatusCode, Method, header},
    response::Json,
    routing::{get, post},
    Router,
    body::Body,
};
use azalea_auth;
use clap::{Parser, Subcommand};
use dialoguer::{Input, Password, Confirm};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower_http::cors::{CorsLayer, Any};

#[derive(Parser)]
#[command(name = "pfandbot-auth")]
#[command(about = "Multi-account Microsoft authentication proxy for Minecraft", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Start {
        #[arg(short, long)]
        port: Option<u16>,
    },
    Setup,
    AddAccount,
    ListAccounts,
    GenerateKey,
}

#[derive(Serialize, Deserialize, Clone)]
struct Config {
    server: ServerConfig,
    api_keys: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct ServerConfig {
    host: String,
    port: u16,
}

impl Config {
    fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string("config.json")?;
        Ok(serde_json::from_str(&content)?)
    }

    fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(&self)?;
        std::fs::write("config.json", content)?;
        Ok(())
    }

    fn default() -> Self {
        Self {
            server: ServerConfig {
                host: "0.0.0.0".to_string(),
                port: 3000,
            },
            api_keys: vec!["change-me-please".to_string()],
        }
    }
}

fn log(prefix: &str, message: &str) {
    let now = chrono::Local::now();
    println!("[{}] [{}] {}", now.format("%H:%M:%S"), prefix, message);
}

#[derive(Serialize, Deserialize, Clone)]
struct TokenResponse {
    access_token: String,
    uuid: String,
    username: String,
}

#[derive(Deserialize)]
struct TokenRequest {
    key: String,
    account: Option<usize>, // Account number (0, 1, 2, etc.)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Account {
    email: String,
    display_name: String,
}

#[derive(Clone, Serialize, Deserialize)]
struct CacheEntry {
    token: TokenResponse,
    #[serde(with = "serde_system_time")]
    expires_at: std::time::SystemTime,
}

impl CacheEntry {
    fn is_valid(&self) -> bool {
        std::time::SystemTime::now() < self.expires_at
    }
}

mod serde_system_time {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::time::{SystemTime, UNIX_EPOCH};

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let duration = time.duration_since(UNIX_EPOCH).unwrap();
        duration.as_secs().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let secs = u64::deserialize(deserializer)?;
        Ok(UNIX_EPOCH + std::time::Duration::from_secs(secs))
    }
}

// cache for multiple accounts
struct AuthCache {
    entries: HashMap<usize, CacheEntry>,
    cache_file: String,
}

impl AuthCache {
    fn new() -> Self {
        let cache_file = "token_cache.json".to_string();
        let mut cache = Self {
            entries: HashMap::new(),
            cache_file,
        };
        cache.load_from_file();
        cache
    }

    fn load_from_file(&mut self) {
        if let Ok(content) = std::fs::read_to_string(&self.cache_file) {
            if let Ok(entries) = serde_json::from_str::<HashMap<usize, CacheEntry>>(&content) {
                self.entries = entries.into_iter().filter(|(_, e)| e.is_valid()).collect();
                log("CACHE", &format!("Loaded {} cached token(s) from file", self.entries.len()));
            }
        }
    }

    fn save_to_file(&self) {
        if let Ok(content) = serde_json::to_string_pretty(&self.entries) {
            if let Err(e) = std::fs::write(&self.cache_file, content) {
                log("CACHE", &format!("Failed to save cache to file: {}", e));
            } else {
                log("CACHE", &format!("Saved {} token(s) to file", self.entries.len()));
            }
        }
    }

    fn get(&self, account_id: usize) -> Option<&CacheEntry> {
        self.entries.get(&account_id).filter(|e| e.is_valid())
    }

    fn set(&mut self, account_id: usize, token: TokenResponse, duration: std::time::Duration) {
        self.entries.insert(
            account_id,
            CacheEntry {
                token,
                expires_at: std::time::SystemTime::now() + duration,
            },
        );
        self.save_to_file();
    }
}

async fn authenticate_with_microsoft(account: &Account) -> Result<TokenResponse, String> {
    let auth_result = azalea_auth::auth(
        &account.email,
        azalea_auth::AuthOpts::default(),
    )
        .await
        .map_err(|e| format!("Auth failed: {:?}", e))?;

    Ok(TokenResponse {
        access_token: auth_result.access_token,
        uuid: auth_result.profile.id.to_string(),
        username: auth_result.profile.name,
    })
}

async fn get_token(
    Query(params): Query<TokenRequest>,
    cache: Arc<RwLock<AuthCache>>,
    accounts: Arc<Vec<Account>>,
    config: Arc<Config>,
) -> Result<Json<TokenResponse>, StatusCode> {
    if !config.api_keys.contains(&params.key) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let account_id = params.account.unwrap_or(0);

    let account = accounts.get(account_id).ok_or(StatusCode::BAD_REQUEST)?;

    {
        let cache_read = cache.read().await;
        if let Some(entry) = cache_read.get(account_id) {
            return Ok(Json(entry.token.clone()));
        }
    }

    // reauth
    let token = authenticate_with_microsoft(account)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    {
        let mut cache_write = cache.write().await;
        cache_write.set(account_id, token.clone(), std::time::Duration::from_secs(23 * 3600));
    }

    Ok(Json(token))
}

// Yggdrasil-style authentication
#[derive(Deserialize)]
struct YggdrasilAuthRequest {
    username: String,  // Account number (counting form 0)
    password: String,  // api key
}

#[derive(Serialize)]
struct YggdrasilAuthResponse {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "selectedProfile")]
    selected_profile: YggdrasilProfile,
}

#[derive(Serialize)]
struct YggdrasilProfile {
    id: String,
    name: String,
}

async fn yggdrasil_authenticate(
    Json(payload): Json<YggdrasilAuthRequest>,
    cache: Arc<RwLock<AuthCache>>,
    accounts: Arc<Vec<Account>>,
    config: Arc<Config>,
) -> Result<Json<YggdrasilAuthResponse>, StatusCode> {
    log("AUTH", &format!("Received authentication request for username: {}", payload.username));

    if !config.api_keys.contains(&payload.password) {
        log("AUTH", "Invalid API key provided");
        return Err(StatusCode::FORBIDDEN);
    }

    let account_id: usize = payload.username.parse().map_err(|e| {
        log("AUTH", &format!("Failed to parse account ID from '{}': {:?}", payload.username, e));
        StatusCode::BAD_REQUEST
    })?;

    log("AUTH", &format!("Using account ID: {}", account_id));

    let account = accounts.get(account_id).ok_or_else(|| {
        log("AUTH", &format!("Account {} not found (only {} accounts available)", account_id, accounts.len()));
        StatusCode::BAD_REQUEST
    })?;

    log("AUTH", &format!("Account found: {} ({})", account.display_name, account.email));

    {
        let cache_read = cache.read().await;
        if let Some(entry) = cache_read.get(account_id) {
            log("AUTH", &format!("Using cached token for account {}", account_id));
            let response = YggdrasilAuthResponse {
                access_token: entry.token.access_token.clone(),
                selected_profile: YggdrasilProfile {
                    id: entry.token.uuid.clone(),
                    name: entry.token.username.clone(),
                },
            };
            log("AUTH", &format!("Returning cached response - UUID: {}, Username: {}", response.selected_profile.id, response.selected_profile.name));
            return Ok(Json(response));
        }
    }

    log("AUTH", "No cached token found, authenticating with Microsoft...");

    // reauth
    let token = authenticate_with_microsoft(account)
        .await
        .map_err(|e| {
            log("AUTH", &format!("Microsoft authentication failed: {}", e));
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    log("AUTH", &format!("Microsoft authentication successful - UUID: {}, Username: {}", token.uuid, token.username));

    {
        let mut cache_write = cache.write().await;
        cache_write.set(account_id, token.clone(), std::time::Duration::from_secs(23 * 3600));
    }

    let response = YggdrasilAuthResponse {
        access_token: token.access_token,
        selected_profile: YggdrasilProfile {
            id: token.uuid,
            name: token.username,
        },
    };

    log("AUTH", "Authentication complete, returning response");
    Ok(Json(response))
}

#[derive(Deserialize)]
struct YggdrasilRefreshRequest {
    #[serde(rename = "accessToken")]
    access_token: String,
}

async fn yggdrasil_refresh(
    Json(payload): Json<YggdrasilRefreshRequest>,
    cache: Arc<RwLock<AuthCache>>,
) -> Result<Json<YggdrasilAuthResponse>, StatusCode> {
    let cache_read = cache.read().await;

    for (_account_id, entry) in cache_read.entries.iter() {
        if entry.is_valid() && entry.token.access_token == payload.access_token {
            return Ok(Json(YggdrasilAuthResponse {
                access_token: entry.token.access_token.clone(),
                selected_profile: YggdrasilProfile {
                    id: entry.token.uuid.clone(),
                    name: entry.token.username.clone(),
                },
            }));
        }
    }

    Err(StatusCode::FORBIDDEN)
}

#[derive(Deserialize)]
struct YggdrasilValidateRequest {
    #[serde(rename = "accessToken")]
    access_token: String,
}

async fn yggdrasil_validate(
    Json(payload): Json<YggdrasilValidateRequest>,
    cache: Arc<RwLock<AuthCache>>,
) -> StatusCode {
    let cache_read = cache.read().await;

    for (_account_id, entry) in cache_read.entries.iter() {
        if entry.is_valid() && entry.token.access_token == payload.access_token {
            return StatusCode::NO_CONTENT;
        }
    }

    StatusCode::FORBIDDEN
}

#[derive(Deserialize)]
struct SessionJoinRequest {
    #[serde(rename = "accessToken")]
    access_token: String,
    #[serde(rename = "selectedProfile")]
    selected_profile: String,
    #[serde(rename = "serverId")]
    server_id: String,
}

async fn session_join(
    Json(payload): Json<SessionJoinRequest>,
    cache: Arc<RwLock<AuthCache>>,
) -> StatusCode {
    log("SESSION", &format!("Join request received - Server ID: {}, Selected Profile: {}",
        payload.server_id, payload.selected_profile));
    log("SESSION", &format!("Access token (first 20 chars): {}",
        &payload.access_token.chars().take(20).collect::<String>()));

    let cache_read = cache.read().await;

    log("SESSION", &format!("Checking against {} cached entries", cache_read.entries.len()));

    for (account_id, entry) in cache_read.entries.iter() {
        log("SESSION", &format!("Checking account {}: UUID={}, Username={}",
            account_id, entry.token.uuid, entry.token.username));

        if entry.is_valid() && entry.token.access_token == payload.access_token {
            log("SESSION", &format!("✓ Valid token found for UUID: {}", entry.token.uuid));
            return StatusCode::NO_CONTENT;
        }
    }

    log("SESSION", "✗ Invalid or expired token - no match found");
    StatusCode::FORBIDDEN
}

#[derive(Serialize)]
struct SessionProfile {
    id: String,
    name: String,
    properties: Vec<SessionProperty>,
}

#[derive(Serialize)]
struct SessionProperty {
    name: String,
    value: String,
    signature: Option<String>,
}

async fn session_has_joined(
    Query(params): Query<HashMap<String, String>>,
    cache: Arc<RwLock<AuthCache>>,
) -> Result<Json<SessionProfile>, StatusCode> {
    log("SESSION", &format!("Has joined check - Query params: {:?}", params));

    let username = params.get("username").ok_or(StatusCode::BAD_REQUEST)?;
    let server_id = params.get("serverId").ok_or(StatusCode::BAD_REQUEST)?;

    log("SESSION", &format!("Has joined check for username: {}, server ID: {}", username, server_id));

    let cache_read = cache.read().await;

    log("SESSION", &format!("Checking against {} cached entries", cache_read.entries.len()));

    // find user by username
    for (account_id, entry) in cache_read.entries.iter() {
        log("SESSION", &format!("Checking account {}: UUID={}, Username={}",
            account_id, entry.token.uuid, entry.token.username));

        if entry.is_valid() && entry.token.username == *username {
            log("SESSION", &format!("✓ Found valid session for {}", username));
            return Ok(Json(SessionProfile {
                id: entry.token.uuid.clone(),
                name: entry.token.username.clone(),
                properties: vec![],
            }));
        }
    }

    log("SESSION", &format!("✗ No valid session found for {}", username));
    Err(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct PublicKeysResponse {
    #[serde(rename = "profilePropertyKeys")]
    profile_property_keys: Vec<PublicKey>,
    #[serde(rename = "playerCertificateKeys")]
    player_certificate_keys: Vec<PublicKey>,
}

#[derive(Serialize)]
struct PublicKey {
    #[serde(rename = "publicKey")]
    public_key: String,
}

async fn get_public_keys() -> Json<PublicKeysResponse> {
    log("KEYS", "Public keys endpoint requested");
    // dummy public key (fine in this case)
    Json(PublicKeysResponse {
        profile_property_keys: vec![],
        player_certificate_keys: vec![],
    })
}

#[derive(Serialize)]
struct ServerInfo {
    #[serde(rename = "signaturePublickey")]
    signature_publickey: String,
    #[serde(rename = "skinDomains")]
    skin_domains: Vec<String>,
}

async fn get_server_info() -> Json<ServerInfo> {
    log("INFO", "Server info requested");
    // dummy public key (fine in this case)
    Json(ServerInfo {
        signature_publickey: "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\n-----END PUBLIC KEY-----".to_string(),
        skin_domains: vec!["textures.minecraft.net".to_string()],
    })
}

async fn log_request(req: Request<Body>) -> StatusCode {
    log("DEBUG", &format!("Received request: {} {}", req.method(), req.uri()));
    log("DEBUG", &format!("Headers: {:?}", req.headers()));
    StatusCode::NOT_FOUND
}

fn load_accounts() -> Vec<Account> {
    if let Ok(content) = std::fs::read_to_string("accounts.json") {
        if let Ok(accounts) = serde_json::from_str::<Vec<AccountConfig>>(&content) {
            return accounts
                .into_iter()
                .map(|cfg| Account {
                    email: cfg.email,
                    display_name: cfg.display_name,
                })
                .collect();
        }
    }

    // Default accounts if config doesn't exist
    vec![
        Account {
            email: "account1@qq.com".to_string(),
            display_name: "Account 1".to_string(),
        },
        Account {
            email: "account2@example.com".to_string(),
            display_name: "Account 2".to_string(),
        },
    ]
}

#[derive(Deserialize)]
struct AccountConfig {
    email: String,
    display_name: String,
}

async fn run_setup() {
    println!("=== PfandBot Auth Setup ===\n");

    let host: String = Input::new()
        .with_prompt("Bind address")
        .default("0.0.0.0".to_string())
        .interact()
        .unwrap();

    let port: u16 = Input::new()
        .with_prompt("Port")
        .default(3000)
        .interact()
        .unwrap();

    let api_key: String = Password::new()
        .with_prompt("API Key (leave empty to generate)")
        .allow_empty_password(true)
        .interact()
        .unwrap();

    let api_key = if api_key.is_empty() {
        use rand::distr::{Alphanumeric, SampleString};
        let key = Alphanumeric.sample_string(&mut rand::rng(), 32);
        println!("Generated API key: {}", key);
        key
    } else {
        api_key
    };

    let config = Config {
        server: ServerConfig { host, port },
        api_keys: vec![api_key],
    };

    config.save().expect("Failed to save config");
    println!("\n✓ Configuration saved to config.json");

    if Confirm::new()
        .with_prompt("Do you want to add an account now?")
        .default(true)
        .interact()
        .unwrap()
    {
        add_account_interactive().await;
    }
}

async fn add_account_interactive() {
    let email: String = Input::new()
        .with_prompt("Microsoft account email")
        .interact()
        .unwrap();

    let display_name: String = Input::new()
        .with_prompt("Display name")
        .default(format!("Account {}", email))
        .interact()
        .unwrap();

    let mut accounts = load_accounts();
    accounts.push(Account {
        email,
        display_name,
    });

    let content = serde_json::to_string_pretty(&accounts).unwrap();
    std::fs::write("accounts.json", content).expect("Failed to save accounts");
    println!("✓ Account added successfully");
}

fn list_accounts() {
    let accounts = load_accounts();
    println!("=== Configured Accounts ===");
    for (i, account) in accounts.iter().enumerate() {
        println!("  [{}] {} ({})", i, account.display_name, account.email);
    }
    println!("\nTotal: {} account(s)", accounts.len());
}

fn generate_api_key() {
    use rand::distr::{Alphanumeric, SampleString};
    let key = Alphanumeric.sample_string(&mut rand::rng(), 32);

    println!("Generated API key: {}", key);
    println!("\nAdd this to your config.json api_keys array:");
    println!("  \"{}\"", key);
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Setup) => {
            run_setup().await;
            return;
        }
        Some(Commands::AddAccount) => {
            add_account_interactive().await;
            return;
        }
        Some(Commands::ListAccounts) => {
            list_accounts();
            return;
        }
        Some(Commands::GenerateKey) => {
            generate_api_key();
            return;
        }
        Some(Commands::Start { port: cmd_port }) => {
            // Load config or create default
            let mut config = Config::load().unwrap_or_else(|_| {
                println!("No config.json found. Run 'pfandbot-auth setup' to configure.");
                println!("Using default configuration...\n");
                let cfg = Config::default();
                cfg.save().ok();
                cfg
            });

            // Override port if specified
            if let Some(p) = cmd_port {
                config.server.port = p;
            }

            let config = Arc::new(config);
            let cache = Arc::new(RwLock::new(AuthCache::new()));
            let accounts = Arc::new(load_accounts());

            println!("Loaded {} account(s):", accounts.len());
            for (i, account) in accounts.iter().enumerate() {
                println!("  [{}] {} ({})", i, account.display_name, account.email);
            }
            println!();

            start_server(config, cache, accounts).await;
        }
        None => {
            // Same as Start without port override
            let config = Config::load().unwrap_or_else(|_| {
                println!("No config.json found. Run 'pfandbot-auth setup' to configure.");
                println!("Using default configuration...\n");
                let cfg = Config::default();
                cfg.save().ok();
                cfg
            });

            let config = Arc::new(config);
            let cache = Arc::new(RwLock::new(AuthCache::new()));
            let accounts = Arc::new(load_accounts());

            println!("Loaded {} account(s):", accounts.len());
            for (i, account) in accounts.iter().enumerate() {
                println!("  [{}] {} ({})", i, account.display_name, account.email);
            }
            println!();

            start_server(config, cache, accounts).await;
        }
    }
}

async fn start_server(
    config: Arc<Config>,
    cache: Arc<RwLock<AuthCache>>,
    accounts: Arc<Vec<Account>>,
) {

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE]);

    let app = Router::new()
        .route("/", get(get_server_info))
        .route("/token", get({
            let cache = Arc::clone(&cache);
            let accounts = Arc::clone(&accounts);
            let config = Arc::clone(&config);
            move |query| get_token(query, cache, accounts, config)
        }))
        // Public keys endpoint
        .route("/publickeys", get(get_public_keys))
        // For Meteor Rejects Auth
        .route("/authserver/authenticate", post({
            let cache = Arc::clone(&cache);
            let accounts = Arc::clone(&accounts);
            let config = Arc::clone(&config);
            move |payload| yggdrasil_authenticate(payload, cache.clone(), accounts.clone(), config.clone())
        }))
        .route("/authserver/refresh", post({
            let cache = Arc::clone(&cache);
            move |payload| yggdrasil_refresh(payload, cache.clone())
        }))
        .route("/authserver/validate", post({
            let cache = Arc::clone(&cache);
            move |payload| yggdrasil_validate(payload, cache.clone())
        }))
        // Session endpoints for joining servers
        .route("/session/minecraft/join", post({
            let cache = Arc::clone(&cache);
            move |payload| session_join(payload, cache.clone())
        }))
        .route("/session/minecraft/hasJoined", get({
            let cache = Arc::clone(&cache);
            move |query| session_has_joined(query, cache.clone())
        }))
        // Also support full Yggdrasil paths
        .route("/api/yggdrasil/authserver/authenticate", post({
            let cache = Arc::clone(&cache);
            let accounts = Arc::clone(&accounts);
            let config = Arc::clone(&config);
            move |payload| yggdrasil_authenticate(payload, cache, accounts, config)
        }))
        .route("/api/yggdrasil/authserver/refresh", post({
            let cache = Arc::clone(&cache);
            move |payload| yggdrasil_refresh(payload, cache)
        }))
        .route("/api/yggdrasil/authserver/validate", post({
            let cache = Arc::clone(&cache);
            move |payload| yggdrasil_validate(payload, cache)
        }))
        .fallback(log_request)
        .layer(cors);

    let bind_addr = format!("{}:{}", config.server.host, config.server.port);
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .expect("Failed to bind to address");

    println!("Token proxy running on http://{}", bind_addr);
    println!("\nAPI Keys configured: {}", config.api_keys.len());
    println!("\nAPI Usage:");
    println!("  HTTP: /token?key=YOUR_KEY&account=N");
    println!("  Username/Email: <account_number> (e.g., 0, 1, 2)");
    println!("  Password: <your_api_key>");
    println!("  Server: http://localhost:{}", config.server.port);
    println!("\nFirst request per account will trigger MS auth in browser");
    axum::serve(listener, app).await.unwrap();
}