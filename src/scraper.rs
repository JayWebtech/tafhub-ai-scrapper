use reqwest::Client;
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::time::Duration;
use tokio::time::sleep;
use tracing::{error, info, warn};
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
            .danger_accept_invalid_certs(false) // Keep SSL verification
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

        // Build request with realistic browser headers
        let response = self.client
            .get(url)
            .header("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
            .header("Accept-Language", "en-US,en;q=0.9")
            .header("Accept-Encoding", "gzip, deflate, br")
            .header("DNT", "1")
            .header("Connection", "keep-alive")
            .header("Upgrade-Insecure-Requests", "1")
            .header("Sec-Fetch-Dest", "document")
            .header("Sec-Fetch-Mode", "navigate")
            .header("Sec-Fetch-Site", "none")
            .header("Sec-Fetch-User", "?1")
            .header("Cache-Control", "max-age=0")
            .send()
            .await?;
        
        let status = response.status();
        info!("Response status for {}: {}", url, status);
        
        if !status.is_success() {
            return Err(ScraperError::Selector(format!(
                "HTTP error: {} for URL: {}",
                status,
                url
            )));
        }

        let body = response.text().await?;
        let body_length = body.len();
        info!("Received {} bytes from {}", body_length, url);
        
        // Log first 500 chars for debugging
        if body_length > 0 {
            let preview = body.chars().take(500).collect::<String>();
            info!("Body preview (first 500 chars): {}", preview);
        } else {
            warn!("Empty response body from {}", url);
        }

        let document = Html::parse_document(&body);

        let title = self.extract_title(&document);
        let links = self.extract_links(&document, url)?;
        let text_content = self.extract_text_content(&document);
        let images = self.extract_images(&document, url)?;

        info!("Extracted from {}: title={:?}, links={}, text_blocks={}, images={}", 
            url, 
            title.is_some(), 
            links.len(), 
            text_content.len(), 
            images.len()
        );

        // Check if we got meaningful content
        if text_content.is_empty() && links.is_empty() && images.is_empty() {
            warn!("No content extracted from {} - page might be JavaScript-rendered, blocked, or have anti-bot protection", url);
            warn!("Consider: 1) Website requires JavaScript rendering (needs headless browser), 2) Anti-bot protection, 3) Rate limiting");
        }

        let data = ScrapedData {
            url: url.to_string(),
            title,
            links,
            text_content,
            images,
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
        // Expanded selectors for better content extraction
        let content_selectors = [
            // Common content containers
            "article", "main", "section", ".content", "#content",
            // Text elements
            "p", "h1", "h2", "h3", "h4", "h5", "h6",
            // E-commerce specific
            ".product", ".product-title", ".product-description",
            ".item", ".listing", ".card", ".card-body",
            // Generic content classes
            ".text", ".description", ".summary", ".details",
            // List items
            "li", ".list-item",
            // Divs with common content classes
            "div.content", "div.text", "div.description",
        ];

        let mut text_content = Vec::new();
        let mut seen_text = HashSet::new(); // Avoid duplicates

        for selector_str in &content_selectors {
            if let Ok(selector) = Selector::parse(selector_str) {
                for element in document.select(&selector) {
                    let text = element.text().collect::<Vec<_>>().join(" ");
                    let cleaned_text = text.trim().to_string();
                    
                    // Filter out very short or duplicate text
                    if !cleaned_text.is_empty() 
                        && cleaned_text.len() > 10 
                        && !seen_text.contains(&cleaned_text) {
                        text_content.push(cleaned_text.clone());
                        seen_text.insert(cleaned_text);
                    }
                }
            }
        }

        // If we still don't have content, try extracting from body directly
        if text_content.is_empty() {
            let body_selector = Selector::parse("body").ok();
            if let Some(selector) = body_selector {
                for element in document.select(&selector) {
                    let text = element.text().collect::<Vec<_>>().join(" ");
                    let cleaned_text = text.trim().to_string();
                    
                    // Split into sentences/paragraphs
                    for sentence in cleaned_text.split(&['.', '!', '?', '\n'][..]) {
                        let sentence = sentence.trim().to_string();
                        if sentence.len() > 20 && !seen_text.contains(&sentence) {
                            text_content.push(sentence.clone());
                            seen_text.insert(sentence);
                            if text_content.len() >= 50 { // Limit fallback extraction
                                break;
                            }
                        }
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