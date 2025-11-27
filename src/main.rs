use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post, delete},
    Router,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, error};
use ratelimit::RateLimitLayer;
use axum::middleware;
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa::openapi::security::{ApiKey, ApiKeyValue, HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa_swagger_ui::SwaggerUi;
use uuid::Uuid;
use validator::Validate;
use rand::Rng;

mod scraper;
mod database;
mod auth;
mod email;
mod ratelimit;
use scraper::{ScrapedData, ScraperConfig, ScraperError, WebScraper};
use database::{Database, User as DbUser};
use auth::AuthService;
use email::EmailService;

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct SignUpRequest {
    #[validate(length(min = 1, max = 100, message = "Name must be between 1 and 100 characters"))]
    pub name: String,
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, message = "Password must be at least 6 characters"))]
    pub password: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct VerifyOtpRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    #[validate(length(min = 6, max = 6, message = "OTP must be 6 digits"))]
    pub otp: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SignUpResponse {
    pub message: String,
    pub email: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyOtpResponse {
    pub message: String,
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UnverifiedEmailResponse {
    pub message: String,
    pub email: String,
    pub requires_verification: bool,
    pub verification_endpoint: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(email(message = "Invalid email format"))]
    pub email: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserResponse {
    pub id: Uuid,
    pub name: Option<String>,
    pub email: String,
    pub credits: i32,
    pub avatar_url: Option<String>,
    pub auth_provider: String,
}

fn user_to_response(user: &DbUser) -> UserResponse {
    UserResponse {
        id: user.id,
        name: user.name.clone(),
        email: user.email.clone(),
        credits: user.credits,
        avatar_url: user.avatar_url.clone(),
        auth_provider: if user.google_id.is_some() {
            "google".to_string()
        } else {
            "password".to_string()
        },
    }
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct BuyCreditsRequest {
    pub amount: i32,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct CreateApiKeyRequest {
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct GoogleSignInRequest {
    pub id_token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub key: String,
    pub name: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ApiKeyListResponse {
    pub id: Uuid,
    pub name: Option<String>,
    pub last_used_at: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Deserialize, Validate, ToSchema)]
pub struct ScrapeRequest {
    #[validate(url(message = "Invalid URL format"))]
    pub url: String,
    #[serde(default)]
    pub context: Option<String>,
    #[serde(default)]
    pub config: Option<ScrapeConfigRequest>,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ScrapeConfigRequest {
    #[serde(default = "default_max_pages")]
    pub max_pages: usize,
    #[serde(default = "default_max_depth")]
    pub max_depth: usize,
    #[serde(default = "default_delay_ms")]
    pub delay_ms: u64,
    #[serde(default = "default_follow_external_links")]
    pub follow_external_links: bool,
}

fn default_max_pages() -> usize { 10 }
fn default_max_depth() -> usize { 2 }
fn default_delay_ms() -> u64 { 1000 }
fn default_follow_external_links() -> bool { false }

#[derive(Debug, Serialize, ToSchema)]
pub struct ScrapeResponse {
    pub job_id: Uuid,
    pub status: String,
    pub message: String,
    pub cached: bool,
    pub data: Option<Vec<ScrapedData>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct JobStatusResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub message: String,
    pub progress: Option<JobProgress>,
    pub results: Option<Vec<ScrapedData>>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct JobProgress {
    pub pages_scraped: usize,
    pub total_links_found: usize,
    pub current_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ListJobsResponse {
    pub jobs: Vec<JobSummary>,
    pub total: usize,
}
#[derive(Debug, Serialize, ToSchema)]
pub struct JobSummary {
    pub job_id: Uuid,
    pub url: String,
    pub status: JobStatus,
    pub pages_scraped: usize,
    pub created_at: String,
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ListJobsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub status: Option<JobStatus>,
}

fn default_limit() -> usize { 20 }

#[derive(Clone)]
pub struct AppState {
    db: Arc<Database>,
    google_client_id: Arc<String>,
    email_service: Arc<EmailService>,
}

impl AppState {
    pub fn new(db: Database, google_client_id: String) -> Self {
        Self {
            db: Arc::new(db),
            google_client_id: Arc::new(google_client_id),
            email_service: Arc::new(EmailService::new()),
        }
    }

    pub fn google_client_id(&self) -> &str {
        self.google_client_id.as_ref()
    }
}

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi
            .components
            .get_or_insert_with(Default::default);

        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("JWT")
                    .build(),
            ),
        );

        components.add_security_scheme(
            "api_key",
            SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
        );
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Unauthorized: {0}")]
    Unauthorized(String),
    #[error("Job not found: {0}")]
    JobNotFound(Uuid),
    #[error("Insufficient credits")]
    InsufficientCredits,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid API key")]
    InvalidApiKey,
    #[error("API key not found")]
    ApiKeyNotFound,
    #[error("Scraper error: {0}")]
    Scraper(#[from] ScraperError),
    #[error("Internal server error: {0}")]
    Internal(String),
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            ApiError::JobNotFound(id) => (StatusCode::NOT_FOUND, format!("Job {} not found", id)),
            ApiError::InsufficientCredits => (StatusCode::PAYMENT_REQUIRED, "Insufficient credits".to_string()),
            ApiError::UserNotFound => (StatusCode::NOT_FOUND, "User not found".to_string()),
            ApiError::InvalidApiKey => (StatusCode::UNAUTHORIZED, "Invalid API key".to_string()),
            ApiError::ApiKeyNotFound => (StatusCode::NOT_FOUND, "API key not found".to_string()),
            ApiError::Scraper(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            ApiError::RateLimitExceeded(msg) => (StatusCode::TOO_MANY_REQUESTS, msg),
        };

        // Build response body
        let mut body = serde_json::json!({
            "error": message,
            "status": status.as_u16()
        });

        // Add verification endpoint info for unverified email errors
        if message.contains("Email not verified") {
            body["requires_verification"] = serde_json::json!(true);
            body["verification_endpoint"] = serde_json::json!("/api/auth/verify-otp");
            body["message"] = serde_json::json!(message);
        }

        (status, Json(body)).into_response()
    }
}

#[utoipa::path(
    post,
    path = "/api/auth/signup",
    request_body = SignUpRequest,
    responses(
        (status = 200, description = "OTP sent to email", body = SignUpResponse),
        (status = 400, description = "Validation error"),
    ),
    tag = "auth",
)]
pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignUpRequest>,
) -> Result<Json<SignUpResponse>, ApiError> {
    if let Err(validation_errors) = request.validate() {
        return Err(ApiError::Validation(format!("{}", validation_errors)));
    }

    // Check if user already exists
    if let Some(existing_user) = state.db.get_user_by_email(&request.email).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))? {
        // If user exists and is verified, return error
        if existing_user.email_verified {
            return Err(ApiError::Validation(
                "Email already registered. Please login instead.".to_string()
            ));
        }
        // If user exists but not verified, return error with guidance
        return Err(ApiError::Validation(
            "Email already registered but not verified.".to_string()
        ));
    }
    
    // Create unverified user account
    let password_hash = AuthService::hash_password(&request.password)
        .map_err(|e| ApiError::Internal(e))?;

    let user_id = state.db.create_user(&request.name, &request.email, &password_hash).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    // Automatically allocate 5 credits to new users as a welcome bonus
    state.db.add_credits(user_id, 5, Some("Welcome bonus - new user signup")).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
    info!("✅ Allocated 5 welcome credits to new user: {}", user_id);

    // Generate 6-digit OTP
    let otp_code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
    
    // Set expiration to 10 minutes from now
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    // Store OTP in database
    state.db.create_otp(&request.email, &otp_code, expires_at).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    // Send OTP email (non-blocking - don't wait for email to complete)
    // This prevents the endpoint from hanging if email sending is slow or fails
    let email_service = state.email_service.clone();
    let email_clone = request.email.clone();
    let otp_clone = otp_code.clone();
    info!("📧 Attempting to send OTP email to: {}", email_clone);
    tokio::spawn(async move {
        info!("📧 Starting email send task for: {}", email_clone);
        match email_service.send_otp_email(&email_clone, &otp_clone).await {
            Ok(_) => {
                info!("✅ OTP email sent successfully to {}", email_clone);
                println!("✅ OTP email sent successfully to {}", email_clone);
            }
            Err(e) => {
                error!("❌ Failed to send OTP email to {}: {}", email_clone, e);
                eprintln!("❌ Failed to send OTP email to {}: {}", email_clone, e);
                eprintln!("   OTP Code for {}: {}", email_clone, otp_clone);
            }
        }
    });

    Ok(Json(SignUpResponse {
        message: "OTP sent to your email. Please verify your email to complete registration.".to_string(),
        email: request.email,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/verify-otp",
    request_body = VerifyOtpRequest,
    responses(
        (status = 200, description = "Email verified successfully", body = VerifyOtpResponse),
        (status = 400, description = "Invalid or expired OTP"),
    ),
    tag = "auth",
)]
pub async fn verify_otp(
    State(state): State<AppState>,
    Json(request): Json<VerifyOtpRequest>,
) -> Result<Json<VerifyOtpResponse>, ApiError> {
    if let Err(validation_errors) = request.validate() {
        return Err(ApiError::Validation(format!("{}", validation_errors)));
    }

    // Verify OTP
    let is_valid = state.db.verify_otp(&request.email, &request.otp).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    if !is_valid {
        return Err(ApiError::Validation("Invalid or expired OTP".to_string()));
    }

    // Get user and verify email
    let user = state.db.get_user_by_email(&request.email).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::UserNotFound)?;

    // Mark email as verified
    state.db.verify_user_email(user.id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    // Get updated user
    let verified_user = state.db.get_user_by_id(user.id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::UserNotFound)?;

    // Generate token
    let token = AuthService::generate_token(verified_user.id, verified_user.email.clone())
        .map_err(|e| ApiError::Internal(e))?;

    let user_response = user_to_response(&verified_user);

    Ok(Json(VerifyOtpResponse {
        message: "Email verified successfully".to_string(),
        token,
        user: user_response,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/resend-otp",
    request_body = SignUpRequest,
    responses(
        (status = 200, description = "OTP resent successfully", body = SignUpResponse),
        (status = 400, description = "Validation error"),
    ),
    tag = "auth",
)]
pub async fn resend_otp(
    State(state): State<AppState>,
    Json(request): Json<SignUpRequest>,
) -> Result<Json<SignUpResponse>, ApiError> {
    if let Err(validation_errors) = request.validate() {
        return Err(ApiError::Validation(format!("{}", validation_errors)));
    }

    // Check if user exists
    let user = state.db.get_user_by_email(&request.email).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::Validation("Email not found. Please sign up first.".to_string()))?;

    // Check if already verified
    if user.email_verified {
        return Err(ApiError::Validation("Email already verified".to_string()));
    }

    // Verify password to ensure it's the correct user
    let password_hash = user.password_hash.as_ref()
        .ok_or_else(|| ApiError::Unauthorized("Invalid account type".to_string()))?;

    let valid = AuthService::verify_password(&request.password, password_hash)
        .map_err(|e| ApiError::Internal(e))?;

    if !valid {
        return Err(ApiError::Unauthorized("Invalid password".to_string()));
    }

    // Generate new 6-digit OTP
    let otp_code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
    
    // Set expiration to 10 minutes from now
    let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

    // Store OTP in database
    state.db.create_otp(&request.email, &otp_code, expires_at).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    // Send OTP email (non-blocking - don't wait for email to complete)
    let email_service = state.email_service.clone();
    let email_clone = request.email.clone();
    let otp_clone = otp_code.clone();
    info!("📧 Attempting to resend OTP email to: {}", email_clone);
    tokio::spawn(async move {
        info!("📧 Starting email resend task for: {}", email_clone);
        match email_service.send_otp_email(&email_clone, &otp_clone).await {
            Ok(_) => {
                info!("✅ OTP email resent successfully to {}", email_clone);
                println!("✅ OTP email resent successfully to {}", email_clone);
            }
            Err(e) => {
                error!("❌ Failed to resend OTP email to {}: {}", email_clone, e);
                eprintln!("❌ Failed to resend OTP email to {}: {}", email_clone, e);
                eprintln!("   OTP Code for {}: {}", email_clone, otp_clone);
            }
        }
    });

    Ok(Json(SignUpResponse {
        message: "OTP resent to your email. Please verify your email to complete registration.".to_string(),
        email: request.email,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 401, description = "Invalid credentials or email not verified"),
    ),
    tag = "auth",
)]
pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    if let Err(validation_errors) = request.validate() {
        return Err(ApiError::Validation(format!("{}", validation_errors)));
    }

    let user = state.db.get_user_by_email(&request.email).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::Unauthorized("Invalid email or password".to_string()))?;

    let password_hash = user.password_hash.as_ref()
        .ok_or_else(|| ApiError::Unauthorized("Please sign in with Google for this account".to_string()))?;

    let valid = AuthService::verify_password(&request.password, password_hash)
        .map_err(|e| ApiError::Internal(e))?;

    if !valid {
        return Err(ApiError::Unauthorized("Invalid email or password".to_string()));
    }

    // Check if email is verified
    if !user.email_verified {
        // Automatically resend OTP for unverified users
        info!("📧 User {} attempted login but email not verified. Resending OTP...", request.email);
        
        // Generate new 6-digit OTP
        let otp_code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));
        
        // Set expiration to 10 minutes from now
        let expires_at = chrono::Utc::now() + chrono::Duration::minutes(10);

        // Store OTP in database
        if let Err(e) = state.db.create_otp(&request.email, &otp_code, expires_at).await {
            error!("Failed to create OTP for unverified user: {}", e);
            return Err(ApiError::Internal(format!("Failed to generate verification code: {}", e)));
        }

        // Send OTP email (non-blocking)
        let email_service = state.email_service.clone();
        let email_clone = request.email.clone();
        let otp_clone = otp_code.clone();
        tokio::spawn(async move {
            info!("📧 Auto-resending OTP email to unverified user: {}", email_clone);
            match email_service.send_otp_email(&email_clone, &otp_clone).await {
                Ok(_) => {
                    info!("✅ OTP email auto-sent successfully to {}", email_clone);
                    println!("✅ OTP email auto-sent successfully to {}", email_clone);
                }
                Err(e) => {
                    error!("❌ Failed to auto-send OTP email to {}: {}", email_clone, e);
                    eprintln!("❌ Failed to auto-send OTP email to {}: {}", email_clone, e);
                    eprintln!("   OTP Code for {}: {}", email_clone, otp_clone);
                }
            }
        });

        // Return response indicating user needs to verify
        // The frontend should redirect to /api/auth/verify-otp endpoint
        return Err(ApiError::Unauthorized(
            format!(
                "Email not verified. A new verification code has been sent to {}.",
                request.email
            )
        ));
    }

    let token = AuthService::generate_token(user.id, user.email.clone())
        .map_err(|e| ApiError::Internal(e))?;

    let user_response = user_to_response(&user);

    Ok(Json(AuthResponse {
        token,
        user: user_response,
    }))
}

#[utoipa::path(
    post,
    path = "/api/auth/google",
    request_body = GoogleSignInRequest,
    responses(
        (status = 200, description = "Google sign-in successful", body = AuthResponse),
        (status = 401, description = "Invalid Google token"),
    ),
    tag = "auth",
)]
pub async fn google_sign_in(
    State(state): State<AppState>,
    Json(request): Json<GoogleSignInRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    #[derive(Debug, Deserialize)]
    struct GoogleTokenInfo {
        aud: String,
        sub: String,
        email: Option<String>,
        email_verified: Option<String>,
        picture: Option<String>,
    }

    let client = Client::new();
    let response = client
        .get("https://oauth2.googleapis.com/tokeninfo")
        .query(&[("id_token", request.id_token.as_str())])
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to verify Google token: {}", e)))?;

    if !response.status().is_success() {
        return Err(ApiError::Unauthorized("Invalid Google token".to_string()));
    }

    let token_info: GoogleTokenInfo = response
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Failed to parse Google token info: {}", e)))?;

    if token_info.aud != state.google_client_id() {
        return Err(ApiError::Unauthorized("Google token audience mismatch".to_string()));
    }

    if let Some(verified) = token_info.email_verified.as_deref() {
        if verified != "true" {
            return Err(ApiError::Unauthorized("Google email is not verified".to_string()));
        }
    }

    let email = token_info
        .email
        .ok_or_else(|| ApiError::Unauthorized("Google account does not provide an email".to_string()))?;
    let google_id = token_info.sub;
    let picture = token_info.picture;

    let user = if let Some(existing) = state.db.get_user_by_google_id(&google_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))? {
        state.db.update_google_profile(existing.id, &email, picture.as_deref())
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        state.db.get_user_by_id(existing.id).await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
            .ok_or_else(|| ApiError::UserNotFound)?
    } else if let Some(existing_email_user) = state.db.get_user_by_email(&email).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))? {
        state.db.link_google_account(existing_email_user.id, &google_id, picture.as_deref())
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        state.db.update_google_profile(existing_email_user.id, &email, picture.as_deref())
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        state.db.get_user_by_id(existing_email_user.id).await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
            .ok_or_else(|| ApiError::UserNotFound)?
    } else {
        let user_id = state.db.create_user_with_google(&google_id, &email, picture.as_deref())
            .await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        
        // Automatically allocate 5 credits to new Google users as a welcome bonus
        state.db.add_credits(user_id, 5, Some("Welcome bonus - new user signup (Google)")).await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
        info!("✅ Allocated 5 welcome credits to new Google user: {}", user_id);
        
        state.db.get_user_by_id(user_id).await
            .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
            .ok_or_else(|| ApiError::UserNotFound)?
    };

    let token = AuthService::generate_token(user.id, user.email.clone())
        .map_err(|e| ApiError::Internal(e))?;

    let user_response = user_to_response(&user);

    Ok(Json(AuthResponse {
        token,
        user: user_response,
    }))
}

#[utoipa::path(
    get,
    path = "/api/user",
    responses(
        (status = 200, description = "Current user info", body = UserResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "user",
)]
pub async fn get_current_user(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<UserResponse>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let user = state.db.get_user_by_id(claims.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::UserNotFound)?;

    Ok(Json(user_to_response(&user)))
}

#[utoipa::path(
    post,
    path = "/api/user/credits",
    request_body = BuyCreditsRequest,
    responses(
        (status = 200, description = "Credits added successfully"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "user",
)]
pub async fn buy_credits(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<BuyCreditsRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    if request.amount <= 0 {
        return Err(ApiError::Validation("Amount must be greater than 0".to_string()));
    }

    state.db.add_credits(claims.user_id, request.amount, Some("Credit purchase")).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    let credits = state.db.get_user_credits(claims.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    Ok(Json(serde_json::json!({
        "message": "Credits added successfully",
        "credits": credits
    })))
}

#[utoipa::path(
    post,
    path = "/api/api-keys",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 200, description = "API key created", body = ApiKeyResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "api-keys",
)]
pub async fn create_api_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyResponse>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let api_key = format!("sk_{}", Uuid::new_v4().to_string().replace("-", ""));
    let key_hash = AuthService::hash_api_key(&api_key);

    let api_key_id = state.db.create_api_key(claims.user_id, &key_hash, request.name.as_deref()).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    Ok(Json(ApiKeyResponse {
        id: api_key_id,
        key: api_key,
        name: request.name,
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/api-keys",
    responses(
        (status = 200, description = "List of API keys", body = Vec<ApiKeyListResponse>),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "api-keys",
)]
pub async fn list_api_keys(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<Vec<ApiKeyListResponse>>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let api_keys = state.db.list_api_keys(claims.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    Ok(Json(api_keys.into_iter().map(|k| ApiKeyListResponse {
        id: k.id,
        name: k.name,
        last_used_at: k.last_used_at.map(|d| d.to_rfc3339()),
        created_at: k.created_at.to_rfc3339(),
    }).collect()))
}

#[utoipa::path(
    delete,
    path = "/api/api-keys/{api_key_id}",
    params(
        ("api_key_id" = Uuid, Path, description = "API key ID")
    ),
    responses(
        (status = 200, description = "API key deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "API key not found"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "api-keys",
)]
pub async fn delete_api_key(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(api_key_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let deleted = state.db.delete_api_key(api_key_id, claims.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    if deleted {
        Ok(Json(serde_json::json!({
            "message": "API key deleted successfully"
        })))
    } else {
        Err(ApiError::ApiKeyNotFound)
    }
}

#[utoipa::path(
    get,
    path = "/api/user/dashboard",
    responses(
        (status = 200, description = "Dashboard stats"),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "user",
)]
pub async fn get_dashboard_stats(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let user = state.db.get_user_by_id(claims.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::UserNotFound)?;

    let job_count = state.db.get_user_job_count(claims.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    let transactions = state.db.get_user_recent_transactions(claims.user_id, 10).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    // Get credit usage for the last 30 days for graph
    let credit_usage = state.db.get_user_credit_usage_last_30_days(claims.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    // Format credit usage data for graph (ensure all 30 days are included, even if 0)
    let usage_map: HashMap<chrono::NaiveDate, i32> = credit_usage.into_iter().collect();
    let mut graph_data = Vec::new();
    let today = chrono::Utc::now().date_naive();
    
    // Generate data for last 30 days
    for i in 0..30 {
        let date = today - chrono::Duration::days(29 - i);
        let credits_used = usage_map.get(&date).copied().unwrap_or(0);
        graph_data.push(serde_json::json!({
            "date": date.format("%Y-%m-%d").to_string(),
            "credits_used": credits_used,
        }));
    }

    let user_summary = user_to_response(&user);

    Ok(Json(serde_json::json!({
        "user": user_summary,
        "stats": {
            "total_jobs": job_count,
            "credits": user.credits,
        },
        "recent_transactions": transactions.into_iter().map(|t| serde_json::json!({
            "id": t.id,
            "amount": t.amount,
            "type": t.transaction_type,
            "description": t.description,
            "created_at": t.created_at.to_rfc3339(),
        })).collect::<Vec<_>>(),
        "credit_usage_last_30_days": graph_data,
    })))
}

// API Handlers
#[utoipa::path(
    post,
    path = "/api/v1/scrape",
    request_body = ScrapeRequest,
    responses(
        (status = 200, description = "Scraping job started or cached data returned", body = ScrapeResponse),
        (status = 401, description = "Invalid API key"),
        (status = 402, description = "Insufficient credits"),
    ),
    security(
        ("api_key" = [])
    ),
    tag = "scraping",
)]
pub async fn start_scraping(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<ScrapeRequest>,
) -> Result<Json<ScrapeResponse>, ApiError> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        return Err(ApiError::Validation(format!("{}", validation_errors)));
    }

    let api_key = headers
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ApiError::InvalidApiKey)?;

    let key_hash = AuthService::hash_api_key(api_key);
    let api_key_info = state.db.get_api_key_by_hash(&key_hash).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or_else(|| ApiError::InvalidApiKey)?;

    state.db.update_api_key_last_used(api_key_info.id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    const CACHE_HOURS: i64 = 24;
    match state.db.get_cached_url(&request.url, CACHE_HOURS).await {
        Ok(Some((cached_job_id, cached_data))) => {
            info!("Returning cached data for URL: {} (job: {})", request.url, cached_job_id);
            return Ok(Json(ScrapeResponse {
                job_id: cached_job_id,
                status: "completed".to_string(),
                message: format!("Data served from cache for URL: {}", request.url),
                cached: true,
                data: Some(cached_data),
            }));
        }
        Ok(None) => {
            info!("No cached data found for URL: {}, will scrape fresh", request.url);
        }
        Err(e) => {
            warn!("Cache check failed for URL {}: {}, proceeding with fresh scrape", request.url, e);
        }
    }

    let has_credits = state.db.deduct_credit(api_key_info.user_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    if !has_credits {
        return Err(ApiError::InsufficientCredits);
    }

    let job_id = Uuid::new_v4();
    info!("Starting scrape job {} for URL: {} (user: {})", job_id, request.url, api_key_info.user_id);

    let scraper_config = match request.config {
        Some(config) => ScraperConfig {
            max_pages: config.max_pages.min(100), // Cap at 100 pages for API
            max_depth: config.max_depth.min(5),   // Cap at 5 levels deep
            delay_ms: config.delay_ms.max(500),   // Minimum 500ms delay
            follow_external_links: config.follow_external_links,
            max_concurrent: 3,
            respect_robots_txt: true,
        },
        None => ScraperConfig {
            max_pages: 10,
            max_depth: 2,
            delay_ms: 1000,
            max_concurrent: 3,
            follow_external_links: false,
            respect_robots_txt: true,
        },
    };

    // Store job in database
    info!("Creating job {} in database", job_id);
    match state.db.create_job(
        job_id,
        api_key_info.user_id,
        Some(api_key_info.id),
        &request.url,
        request.context.as_deref(),
        scraper_config.max_pages as i32,
        scraper_config.max_depth as i32,
        scraper_config.delay_ms as i32,
        scraper_config.follow_external_links,
    ).await {
        Ok(_) => info!("Job {} created successfully in database", job_id),
        Err(e) => {
            error!("Failed to create job {} in database: {}", job_id, e);
            // Refund credit if job creation fails
            if let Err(refund_err) = state.db.add_credits(api_key_info.user_id, 1, Some("Refund - job creation failed")).await {
                error!("Failed to refund credit: {}", refund_err);
            }
            return Err(ApiError::Internal(format!("Database error: {}", e)));
        }
    }

    let state_clone = state.clone();
    let url_clone = request.url.clone();
    tokio::spawn(async move {
        run_scraping_job(state_clone, job_id, url_clone, scraper_config).await;
    });

    Ok(Json(ScrapeResponse {
        job_id,
        status: "started".to_string(),
        message: format!("Scraping job started for URL: {}", request.url),
        cached: false,
        data: None,
    }))
}

#[utoipa::path(
    get,
    path = "/api/jobs/{job_id}",
    params(
        ("job_id" = Uuid, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job status", body = JobStatusResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "jobs",
)]
pub async fn get_job_status(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobStatusResponse>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let job = state.db.get_job(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or(ApiError::JobNotFound(job_id))?;

    if job.user_id != claims.user_id {
        return Err(ApiError::Unauthorized("Job does not belong to user".to_string()));
    }

    let status = match job.status.as_str() {
        "pending" => JobStatus::Pending,
        "running" => JobStatus::Running,
        "completed" => JobStatus::Completed,
        "failed" => JobStatus::Failed,
        _ => JobStatus::Failed,
    };

    let progress = JobProgress {
        pages_scraped: job.pages_scraped as usize,
        total_links_found: job.total_links_found as usize,
        current_url: job.current_url.clone(),
    };

    let message = match status {
        JobStatus::Pending => "Job is pending".to_string(),
        JobStatus::Running => format!("Job is running. Scraped {} pages", job.pages_scraped),
        JobStatus::Completed => format!("Job completed successfully. Scraped {} pages", job.pages_scraped),
        JobStatus::Failed => "Job failed".to_string(),
    };

    Ok(Json(JobStatusResponse {
        job_id,
        status,
        message,
        progress: Some(progress),
        results: None,
        error: job.error,
    }))
}

#[utoipa::path(
    get,
    path = "/api/jobs/{job_id}/results",
    params(
        ("job_id" = Uuid, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job results", body = Vec<ScrapedData>),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "jobs",
)]
pub async fn get_job_results(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<Vec<ScrapedData>>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let job = state.db.get_job(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or(ApiError::JobNotFound(job_id))?;

    if job.user_id != claims.user_id {
        return Err(ApiError::Unauthorized("Job does not belong to user".to_string()));
    }

    if job.status != "completed" {
        return Err(ApiError::Internal("Job not yet completed".to_string()));
    }

    let results = state.db.get_scraped_data(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    Ok(Json(results))
}

#[utoipa::path(
    get,
    path = "/api/jobs",
    params(
        ("limit" = Option<usize>, Query, description = "Limit number of jobs"),
        ("status" = Option<JobStatus>, Query, description = "Filter by status"),
    ),
    responses(
        (status = 200, description = "List of jobs", body = ListJobsResponse),
        (status = 401, description = "Unauthorized"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "jobs",
)]
pub async fn list_jobs(
    headers: HeaderMap,
    State(state): State<AppState>,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<ListJobsResponse>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let status_filter = query.status.as_ref().map(|s| match s {
        JobStatus::Pending => "pending",
        JobStatus::Running => "running",
        JobStatus::Completed => "completed",
        JobStatus::Failed => "failed",
    });

    let db_jobs = state.db.list_jobs(claims.user_id, query.limit as i64, status_filter).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    let job_summaries: Vec<JobSummary> = db_jobs
        .into_iter()
        .map(|db_job| JobSummary {
            job_id: db_job.job_id,
            url: db_job.url,
            status: match db_job.status.as_str() {
                "pending" => JobStatus::Pending,
                "running" => JobStatus::Running,
                "completed" => JobStatus::Completed,
                "failed" => JobStatus::Failed,
                _ => JobStatus::Failed,
            },
            pages_scraped: db_job.pages_scraped as usize,
            created_at: db_job.created_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(ListJobsResponse {
        total: job_summaries.len(),
        jobs: job_summaries,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/jobs/{job_id}",
    params(
        ("job_id" = Uuid, Path, description = "Job ID")
    ),
    responses(
        (status = 200, description = "Job deleted"),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "Job not found"),
    ),
    security(
        ("bearer" = [])
    ),
    tag = "jobs",
)]
pub async fn delete_job(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let token = headers
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(|| ApiError::Unauthorized("Missing Authorization header".to_string()))?;

    let claims = AuthService::verify_token(token)
        .map_err(|_| ApiError::Unauthorized("Invalid token".to_string()))?;

    let job = state.db.get_job(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or(ApiError::JobNotFound(job_id))?;

    if job.user_id != claims.user_id {
        return Err(ApiError::Unauthorized("Job does not belong to user".to_string()));
    }

    let deleted = state.db.delete_job(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;
    
    if deleted {
        info!("Deleted job: {}", job_id);
        Ok(Json(serde_json::json!({
            "message": format!("Job {} deleted successfully", job_id)
        })))
    } else {
        Err(ApiError::JobNotFound(job_id))
    }
}

#[utoipa::path(
    get,
    path = "/health",
    responses(
        (status = 200, description = "Service is healthy"),
    ),
    tag = "health",
)]
pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "web-scraper-api"
    }))
}

async fn run_scraping_job(
    state: AppState,
    job_id: Uuid,
    url: String,
    config: ScraperConfig,
) {
    info!("Running scraping job {} for URL: {}", job_id, url);

    state.db.update_job_status(job_id, "running", Some(&url)).await
        .unwrap_or_else(|e| error!("Failed to update job status: {}", e));

    match WebScraper::new(config) {
        Ok(mut scraper) => {
            match scraper.scrape(&url).await {
                Ok(results) => {
                    info!("Scraping job {} completed successfully with {} pages", job_id, results.len());
                    
                    if let Err(e) = state.db.store_scraped_data(job_id, &results).await {
                        error!("Failed to store scraped data: {}", e);
                    } else {
                        if let Err(e) = state.db.upsert_url_cache(&url, job_id).await {
                            warn!("Failed to update URL cache for job {}: {}", job_id, e);
                        }
                    }
                    
                    let total_links: usize = results.iter().map(|r| r.links.len()).sum();
                    if let Err(e) = state.db.update_job_progress(job_id, results.len() as i32, total_links as i32).await {
                        error!("Failed to update job progress: {}", e);
                    }
                    
                    if let Err(e) = state.db.update_job_status(job_id, "completed", None).await {
                        error!("Failed to update job status: {}", e);
                    }
                }
                Err(e) => {
                    warn!("Scraping job {} failed: {}", job_id, e);
                    
                    if let Err(db_e) = state.db.update_job_error(job_id, &e.to_string()).await {
                        error!("Failed to update job error: {}", db_e);
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to create scraper for job {}: {}", job_id, e);
            
            if let Err(db_e) = state.db.update_job_error(job_id, &format!("Failed to initialize scraper: {}", e)).await {
                error!("Failed to update job error: {}", db_e);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = dotenvy::dotenv() {
        tracing::warn!("dotenv not loaded: {}", e);
    }
    tracing_subscriber::fmt::init();

    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/tafhub_scrapper".to_string());
    
    info!("Connecting to database: {}", database_url);
    
    let db = Database::new(&database_url).await
        .expect("Failed to connect to database");
    
    info!("Successfully connected to database");
    
    let google_client_id = std::env::var("GOOGLE_CLIENT_ID")
        .expect("GOOGLE_CLIENT_ID environment variable must be set");
    
    let state = AppState::new(db, google_client_id);

    #[derive(OpenApi)]
    #[openapi(
        paths(
            health_check,
            signup,
            verify_otp,
            resend_otp,
            login,
            google_sign_in,
            get_current_user,
            buy_credits,
            get_dashboard_stats,
            create_api_key,
            list_api_keys,
            delete_api_key,
            start_scraping,
            list_jobs,
            get_job_status,
            get_job_results,
            delete_job,
        ),
        components(schemas(
            SignUpRequest,
            VerifyOtpRequest,
            SignUpResponse,
            VerifyOtpResponse,
            LoginRequest,
            GoogleSignInRequest,
            AuthResponse,
            UserResponse,
            BuyCreditsRequest,
            CreateApiKeyRequest,
            ApiKeyResponse,
            ApiKeyListResponse,
            ScrapeRequest,
            ScrapeConfigRequest,
            ScrapeResponse,
            ScrapedData,
            JobStatusResponse,
            JobProgress,
            JobStatus,
            ListJobsResponse,
            JobSummary,
        )),
        tags(
            (name = "health", description = "Health check endpoints"),
            (name = "auth", description = "Authentication endpoints"),
            (name = "user", description = "User management endpoints"),
            (name = "api-keys", description = "API key management endpoints"),
            (name = "scraping", description = "Web scraping endpoints"),
            (name = "jobs", description = "Job management endpoints"),
        ),
        modifiers(&SecurityAddon)
    )]
    struct ApiDoc;

    // Rate limiting configurations
    // Strict rate limit for authentication endpoints: 5 requests per minute per IP
    let auth_rate_limit = RateLimitLayer::new(5, std::time::Duration::from_secs(60));
    
    // Moderate rate limit for API endpoints: 30 requests per minute per IP
    let api_rate_limit = RateLimitLayer::new(30, std::time::Duration::from_secs(60));
    
    // General rate limit for other endpoints: 60 requests per minute per IP
    let general_rate_limit = RateLimitLayer::new(60, std::time::Duration::from_secs(60));

    // Create separate routers with different rate limits
    let auth_routes = Router::new()
        .route("/api/auth/signup", post(signup))
        .route("/api/auth/verify-otp", post(verify_otp))
        .route("/api/auth/resend-otp", post(resend_otp))
        .route("/api/auth/login", post(login))
        .route("/api/auth/google", post(google_sign_in))
        .layer(middleware::from_fn(move |req, next| {
            RateLimitLayer::rate_limit_middleware(auth_rate_limit.limiter().clone(), req, next)
        }));

    let api_routes = Router::new()
        .route("/api/v1/scrape", post(start_scraping))
        .layer(middleware::from_fn(move |req, next| {
            RateLimitLayer::rate_limit_middleware(api_rate_limit.limiter().clone(), req, next)
        }));

    let general_routes = Router::new()
        .route("/api/user", get(get_current_user))
        .route("/api/user/credits", post(buy_credits))
        .route("/api/user/dashboard", get(get_dashboard_stats))
        .route("/api/api-keys", post(create_api_key))
        .route("/api/api-keys", get(list_api_keys))
        .route("/api/api-keys/:api_key_id", delete(delete_api_key))
        .route("/api/jobs", get(list_jobs))
        .route("/api/jobs/:job_id", get(get_job_status))
        .route("/api/jobs/:job_id", delete(delete_job))
        .route("/api/jobs/:job_id/results", get(get_job_results))
        .layer(middleware::from_fn(move |req, next| {
            RateLimitLayer::rate_limit_middleware(general_rate_limit.limiter().clone(), req, next)
        }));

    let app = Router::new()
        .merge(SwaggerUi::new("/swagger-ui").url("/api-docs/openapi.json", ApiDoc::openapi()))
        .route("/health", get(health_check))
        .merge(auth_routes)
        .merge(api_routes)
        .merge(general_routes)
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3001").await.unwrap();
    info!("🚀 Web Scraper API server starting on http://0.0.0.0:3001");
    println!("\n📋 Available Endpoints:");
    println!("\n🔓 Public Endpoints:");
    println!("  GET  /health                    - Health check");
    println!("  POST /api/auth/signup           - Sign up with email & password");
    println!("  POST /api/auth/login            - Email/password login");
    println!("  POST /api/auth/google           - Sign in with Google ID token");
    println!("\n🔐 Protected Endpoints (Bearer Token):");
    println!("  GET  /api/user                  - Get current user");
    println!("  POST /api/user/credits          - Buy credits");
    println!("  GET  /api/user/dashboard        - Get dashboard stats");
    println!("  POST /api/api-keys              - Create API key");
    println!("  GET  /api/api-keys              - List API keys");
    println!("  DELETE /api/api-keys/:id        - Delete API key");
    println!("  GET  /api/jobs                  - List jobs");
    println!("  GET  /api/jobs/:job_id          - Get job status");
    println!("  GET  /api/jobs/:job_id/results  - Get job results");
    println!("  DELETE /api/jobs/:job_id        - Delete job");
    println!("\n🔑 API Key Protected:");
    println!("  POST /api/v1/scrape             - Start scraping (uses X-API-Key header)");
    println!("\n📖 Example Usage:");
    println!("  # Sign up:");
    println!("  curl -X POST http://localhost:3001/api/auth/signup \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d '{{\"email\": \"user@example.com\", \"password\": \"password123\"}}'");
    println!("\n  # Sign in with Google:");
    println!("  curl -X POST http://localhost:3001/api/auth/google \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d '{{\"id_token\": \"<GOOGLE_ID_TOKEN>\"}}'");
    println!("\n  # Scrape with API key:");
    println!("  curl -X POST http://localhost:3001/api/v1/scrape \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -H 'X-API-Key: sk_your-api-key' \\");
    println!("    -d '{{\"url\": \"https://example.com\", \"context\": \"get all emails\"}}'");
    println!("\n📚 API Documentation:");
    println!("  Swagger UI: http://localhost:3001/swagger-ui");
    println!("  OpenAPI JSON: http://localhost:3001/api-docs/openapi.json");
    println!();

    axum::serve(listener, app).await.unwrap();
}

