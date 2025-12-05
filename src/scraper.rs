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
        let client = Client::builder()
            .user_agent("Mozilla/5.0 (compatible; RustScraper/1.0)")
            .timeout(Duration::from_secs(30))
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

        let response = self.client.get(url).send().await?;
        
        if !response.status().is_success() {
            return Err(ScraperError::Selector(format!(
                "HTTP error: {} for URL: {}",
                response.status(),
                url
            )));
        }

        let body = response.text().await?;
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