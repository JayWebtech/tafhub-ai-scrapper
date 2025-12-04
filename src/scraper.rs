use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info};
use url::Url;
use utoipa::ToSchema;

#[derive(Debug, thiserror::Error)]
pub enum ScraperError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),
    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),
    #[error("Selector parse error: {0}")]
    Selector(String),
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ScrapedData {
    pub url: String,
    pub title: Option<String>,
    pub links: Vec<String>,
    pub text_content: Vec<String>,
    pub images: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ScraperConfig {
    pub max_pages: usize,
    pub max_depth: usize,
    pub delay_ms: u64,
    #[allow(dead_code)]
    pub max_concurrent: usize, // Reserved for future concurrent scraping implementation
    pub follow_external_links: bool,
    #[allow(dead_code)]
    pub respect_robots_txt: bool, // Reserved for future robots.txt support
}

impl Default for ScraperConfig {
    fn default() -> Self {
        Self {
            max_pages: 100,
            max_depth: 3,
            delay_ms: 1000,
            max_concurrent: 5,
            follow_external_links: false,
            respect_robots_txt: true,
        }
    }
}

pub struct WebScraper {
    client: Client,
    config: ScraperConfig,
    visited_urls: HashSet<String>,
    scraped_data: Vec<ScrapedData>,
}

impl WebScraper {
    pub fn new(config: ScraperConfig) -> Result<Self, ScraperError> {
        // Use a realistic browser User-Agent to avoid bot detection
        let user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        
        let client = Client::builder()
            .user_agent(user_agent)
            .timeout(Duration::from_secs(30))
            .cookie_store(true) // Enable cookie storage for session handling
            .build()?;

        Ok(Self {
            client,
            config,
            visited_urls: HashSet::new(),
            scraped_data: Vec::new(),
        })
    }

    pub async fn scrape(&mut self, start_url: &str) -> Result<Vec<ScrapedData>, ScraperError> {
        info!("Starting scrape from: {}", start_url);
        
        let base_url = Url::parse(start_url)?;
        let mut url_queue = VecDeque::new();
        url_queue.push_back((start_url.to_string(), 0)); // (url, depth)

        while let Some((current_url, depth)) = url_queue.pop_front() {
            // Check limits
            if self.scraped_data.len() >= self.config.max_pages {
                info!("Reached max pages limit: {}", self.config.max_pages);
                break;
            }

            if depth > self.config.max_depth {
                continue;
            }

            // Skip if already visited
            if self.visited_urls.contains(&current_url) {
                continue;
            }

            // Mark as visited
            self.visited_urls.insert(current_url.clone());

            // Scrape the page
            match self.scrape_page(&current_url).await {
                Ok(data) => {
                    info!("Successfully scraped: {}", current_url);
                    
                    // Add new links to queue if within depth limit
                    if depth < self.config.max_depth {
                        for link in &data.links {
                            if self.should_follow_link(link, &base_url) {
                                url_queue.push_back((link.clone(), depth + 1));
                            }
                        }
                    }

                    self.scraped_data.push(data);
                }
                Err(e) => {
                    error!("Failed to scrape {}: {}", current_url, e);
                }
            }

            // Rate limiting
            if self.config.delay_ms > 0 {
                sleep(Duration::from_millis(self.config.delay_ms)).await;
            }
        }

        info!("Scraping completed. Total pages: {}", self.scraped_data.len());
        Ok(self.scraped_data.clone())
    }

    async fn scrape_page(&self, url: &str) -> Result<ScrapedData, ScraperError> {
        info!("Scraping page: {}", url);

        // Parse URL to extract domain for referer
        let parsed_url = Url::parse(url)?;
        let base_domain = format!("{}://{}", parsed_url.scheme(), parsed_url.host_str().unwrap_or(""));

        // Build request with browser-like headers to avoid bot detection
        let response = self.client
            .get(url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("Referer", &base_domain)
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "same-origin")
            .header("Sec-Ch-Ua", r#""Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120""#)
            .header("Sec-Ch-Ua-Mobile", "?0")
            .header("Sec-Ch-Ua-Platform", r#""Windows""#)
            .header("Upgrade-Insecure-Requests", "1")
            .header("Connection", "keep-alive")
            .header("Cache-Control", "max-age=0")
            .send()
            .await?;
        
        let status = response.status();
        if !status.is_success() {
            // Log response body for debugging if available
            let error_body = response.text().await.unwrap_or_default();
            let error_preview = if error_body.len() > 500 {
                format!("{}...", &error_body[..500])
            } else {
                error_body
            };
            
            return Err(ScraperError::Selector(format!(
                "HTTP error: {} for URL: {}\nResponse preview: {}",
                status,
                url,
                error_preview
            )));
        }

        let body = response.text().await?;
        
        // Log response size for debugging
        info!("Response size for {}: {} bytes", url, body.len());
        
        // Check if response is empty or suspiciously small (might be a block page)
        if body.trim().is_empty() {
            error!("Empty response body for URL: {}. Site may be blocking the request.", url);
            return Err(ScraperError::Selector(format!(
                "Empty response body for URL: {}. Site may be blocking the request. This could indicate:\n\
                - Bot detection/anti-scraping measures\n\
                - JavaScript-rendered content (SPA sites)\n\
                - Rate limiting or IP blocking\n\
                - Invalid or blocked User-Agent",
                url
            )));
        }
        
        // Check for common bot detection indicators in the HTML
        let body_lower = body.to_lowercase();
        let blocking_indicators = [
            ("access denied", "Access denied page detected"),
            ("blocked", "Blocking page detected"),
            ("cloudflare", "Cloudflare protection detected"),
            ("checking your browser", "Cloudflare browser check detected"),
            ("please enable javascript", "JavaScript required - site may be SPA"),
            ("captcha", "CAPTCHA challenge detected"),
            ("forbidden", "403 Forbidden response"),
        ];
        
        for (indicator, message) in &blocking_indicators {
            if body_lower.contains(indicator) {
                error!("{} for URL: {}", message, url);
                return Err(ScraperError::Selector(format!(
                    "{} for URL: {}\n\
                    This site may require:\n\
                    - JavaScript execution (SPA/React sites)\n\
                    - CAPTCHA solving\n\
                    - Additional verification steps\n\
                    - Browser fingerprinting\n\
                    \n\
                    Note: This scraper only handles static HTML. JavaScript-rendered content \
                    requires a headless browser like Puppeteer or Playwright.",
                    message,
                    url
                )));
            }
        }
        
        let document = Html::parse_document(&body);

        let data = ScrapedData {
            url: url.to_string(),
            title: self.extract_title(&document),
            links: self.extract_links(&document, url)?,
            text_content: self.extract_text_content(&document),
            images: self.extract_images(&document, url)?,
        };

        Ok(data)
    }

    fn extract_title(&self, document: &Html) -> Option<String> {
        let title_selector = Selector::parse("title").ok()?;
        document
            .select(&title_selector)
            .next()
            .map(|element| element.text().collect::<Vec<_>>().join(" ").trim().to_string())
    }

    fn extract_links(&self, document: &Html, base_url: &str) -> Result<Vec<String>, ScraperError> {
        let link_selector = Selector::parse("a[href]")
            .map_err(|e| ScraperError::Selector(format!("Invalid selector: {:?}", e)))?;
        
        let base = Url::parse(base_url)?;
        let mut links = Vec::new();

        for element in document.select(&link_selector) {
            if let Some(href) = element.value().attr("href") {
                if let Ok(absolute_url) = base.join(href) {
                    let url_str = absolute_url.to_string();
                    if !links.contains(&url_str) {
                        links.push(url_str);
                    }
                }
            }
        }

        Ok(links)
    }

    fn extract_text_content(&self, document: &Html) -> Vec<String> {
        let content_selectors = [
            "p", "h1", "h2", "h3", "h4", "h5", "h6", 
            "article", "main", ".content", "#content"
        ];

        let mut text_content = Vec::new();

        for selector_str in &content_selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                for element in document.select(&selector) {
                    let text = element.text().collect::<Vec<_>>().join(" ");
                    let cleaned_text = text.trim().to_string();
                    if !cleaned_text.is_empty() && cleaned_text.len() > 10 {
                        text_content.push(cleaned_text);
                    }
                }
            }
        }

        text_content
    }

    fn extract_images(&self, document: &Html, base_url: &str) -> Result<Vec<String>, ScraperError> {
        let img_selector = Selector::parse("img[src]")
            .map_err(|e| ScraperError::Selector(format!("Invalid selector: {:?}", e)))?;
        
        let base = Url::parse(base_url)?;
        let mut images = Vec::new();

        for element in document.select(&img_selector) {
            if let Some(src) = element.value().attr("src") {
                if let Ok(absolute_url) = base.join(src) {
                    let url_str = absolute_url.to_string();
                    if !images.contains(&url_str) {
                        images.push(url_str);
                    }
                }
            }
        }

        Ok(images)
    }

    fn should_follow_link(&self, link: &str, base_url: &Url) -> bool {
        // Parse the link URL
        let link_url = match Url::parse(link) {
            Ok(url) => url,
            Err(_) => return false,
        };

        // Check if it's an external link
        if !self.config.follow_external_links {
            if link_url.domain() != base_url.domain() {
                return false;
            }
        }

        // Skip common non-content files
        let path = link_url.path().to_lowercase();
        let skip_extensions = [
            ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
            ".zip", ".rar", ".tar", ".gz", ".exe", ".dmg", ".pkg",
            ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico",
            ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flv",
            ".css", ".js", ".xml", ".rss", ".json"
        ];

        for ext in &skip_extensions {
            if path.ends_with(ext) {
                return false;
            }
        }

        // Skip mailto, javascript, and tel links
        let scheme = link_url.scheme();
        if matches!(scheme, "mailto" | "javascript" | "tel" | "ftp") {
            return false;
        }

        true
    }
}