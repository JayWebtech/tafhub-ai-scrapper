use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn, error};
use uuid::Uuid;
use validator::Validate;

mod scraper;
mod database;
use scraper::{ScrapedData, ScraperConfig, ScraperError, WebScraper};
use database::Database;

// API Request/Response types
#[derive(Debug, Deserialize, Validate)]
pub struct ScrapeRequest {
    #[validate(url(message = "Invalid URL format"))]
    pub url: String,
    #[serde(default)]
    pub config: Option<ScrapeConfigRequest>,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Serialize)]
pub struct ScrapeResponse {
    pub job_id: Uuid,
    pub status: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct JobStatusResponse {
    pub job_id: Uuid,
    pub status: JobStatus,
    pub message: String,
    pub progress: Option<JobProgress>,
    pub results: Option<Vec<ScrapedData>>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct JobProgress {
    pub pages_scraped: usize,
    pub total_links_found: usize,
    pub current_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum JobStatus {
    Pending,
    Running,
    Completed,
    Failed,
}



#[derive(Debug, Serialize)]
pub struct ListJobsResponse {
    pub jobs: Vec<JobSummary>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct JobSummary {
    pub job_id: Uuid,
    pub url: String,
    pub status: JobStatus,
    pub pages_scraped: usize,
    pub created_at: String,
}

// Query parameters
#[derive(Debug, Deserialize)]
pub struct ListJobsQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    #[serde(default)]
    pub status: Option<JobStatus>,
}

fn default_limit() -> usize { 20 }

// Application state
#[derive(Clone)]
pub struct AppState {
    db: Arc<Database>,
}

impl AppState {
    pub fn new(db: Database) -> Self {
        Self {
            db: Arc::new(db),
        }
    }
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Job not found: {0}")]
    JobNotFound(Uuid),
    #[error("Scraper error: {0}")]
    Scraper(#[from] ScraperError),
    #[error("Internal server error: {0}")]
    Internal(String),
}

impl axum::response::IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match self {
            ApiError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
            ApiError::JobNotFound(id) => (StatusCode::NOT_FOUND, format!("Job {} not found", id)),
            ApiError::Scraper(err) => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
            ApiError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = serde_json::json!({
            "error": message,
            "status": status.as_u16()
        });

        (status, Json(body)).into_response()
    }
}

// API Handlers
pub async fn start_scraping(
    State(state): State<AppState>,
    Json(request): Json<ScrapeRequest>,
) -> Result<Json<ScrapeResponse>, ApiError> {
    // Validate request
    if let Err(validation_errors) = request.validate() {
        return Err(ApiError::Validation(format!("{}", validation_errors)));
    }

    let job_id = Uuid::new_v4();
    info!("Starting scrape job {} for URL: {}", job_id, request.url);

    // Convert request config to scraper config
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
        &request.url,
        scraper_config.max_pages as i32,
        scraper_config.max_depth as i32,
        scraper_config.delay_ms as i32,
        scraper_config.follow_external_links,
    ).await {
        Ok(_) => info!("Job {} created successfully in database", job_id),
        Err(e) => {
            error!("Failed to create job {} in database: {}", job_id, e);
            return Err(ApiError::Internal(format!("Database error: {}", e)));
        }
    }

    // Spawn scraping task
    let state_clone = state.clone();
    let url_clone = request.url.clone();
    tokio::spawn(async move {
        run_scraping_job(state_clone, job_id, url_clone, scraper_config).await;
    });

    Ok(Json(ScrapeResponse {
        job_id,
        status: "started".to_string(),
        message: format!("Scraping job started for URL: {}", request.url),
    }))
}

pub async fn get_job_status(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<JobStatusResponse>, ApiError> {
    let job = state.db.get_job(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or(ApiError::JobNotFound(job_id))?;

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
        results: None, // We'll get results from a separate endpoint
        error: job.error,
    }))
}

pub async fn get_job_results(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<Vec<ScrapedData>>, ApiError> {
    // First check if job exists and is completed
    let job = state.db.get_job(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?
        .ok_or(ApiError::JobNotFound(job_id))?;

    if job.status != "completed" {
        return Err(ApiError::Internal("Job not yet completed".to_string()));
    }

    // Get scraped data from database
    let results = state.db.get_scraped_data(job_id).await
        .map_err(|e| ApiError::Internal(format!("Database error: {}", e)))?;

    Ok(Json(results))
}

pub async fn list_jobs(
    State(state): State<AppState>,
    Query(query): Query<ListJobsQuery>,
) -> Result<Json<ListJobsResponse>, ApiError> {
    let status_filter = query.status.as_ref().map(|s| match s {
        JobStatus::Pending => "pending",
        JobStatus::Running => "running",
        JobStatus::Completed => "completed",
        JobStatus::Failed => "failed",
    });

    let db_jobs = state.db.list_jobs(query.limit as i64, status_filter).await
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

pub async fn delete_job(
    State(state): State<AppState>,
    Path(job_id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, ApiError> {
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

pub async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "service": "web-scraper-api"
    }))
}

// Background scraping job runner
async fn run_scraping_job(
    state: AppState,
    job_id: Uuid,
    url: String,
    config: ScraperConfig,
) {
    info!("Running scraping job {} for URL: {}", job_id, url);

    // Update job status to running
    state.db.update_job_status(job_id, "running", Some(&url)).await
        .unwrap_or_else(|e| error!("Failed to update job status: {}", e));

    // Run the scraper
    match WebScraper::new(config) {
        Ok(mut scraper) => {
            match scraper.scrape(&url).await {
                Ok(results) => {
                    info!("Scraping job {} completed successfully with {} pages", job_id, results.len());
                    
                    // Store scraped data in database
                    if let Err(e) = state.db.store_scraped_data(job_id, &results).await {
                        error!("Failed to store scraped data: {}", e);
                    }
                    
                    // Update job status and progress
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
                    
                    // Update job with error
                    if let Err(db_e) = state.db.update_job_error(job_id, &e.to_string()).await {
                        error!("Failed to update job error: {}", db_e);
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to create scraper for job {}: {}", job_id, e);
            
            // Update job with error
            if let Err(db_e) = state.db.update_job_error(job_id, &format!("Failed to initialize scraper: {}", e)).await {
                error!("Failed to update job error: {}", db_e);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    // Initialize logging
    tracing_subscriber::fmt::init();

    // Database connection
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgresql://localhost/scrapper".to_string());
    
    info!("Connecting to database: {}", database_url);
    
    let db = Database::new(&database_url).await
        .expect("Failed to connect to database");
    
    info!("Successfully connected to database");
    
    let state = AppState::new(db);

    // Build the application with routes
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/scrape", post(start_scraping))
        .route("/jobs/:job_id", get(get_job_status))
        .route("/jobs/:job_id", axum::routing::delete(delete_job))
        .route("/jobs/:job_id/results", get(get_job_results))
        .route("/jobs", get(list_jobs))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Start the server
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    info!("🚀 Web Scraper API server starting on http://0.0.0.0:3000");
    
    // Print available endpoints
    println!("\n📋 Available Endpoints:");
    println!("  GET  /health                    - Health check");
    println!("  POST /scrape                    - Start scraping job");
    println!("  GET  /jobs                      - List all jobs");
    println!("  GET  /jobs/:job_id              - Get job status");
    println!("  GET  /jobs/:job_id/results      - Get job results");
    println!("  DELETE /jobs/:job_id            - Delete job");
    println!("\n📖 Example Usage:");
    println!("  curl -X POST http://localhost:3000/scrape \\");
    println!("    -H 'Content-Type: application/json' \\");
    println!("    -d '{{\"url\": \"https://example.com\"}}'");
    println!();

    axum::serve(listener, app).await.unwrap();
}

