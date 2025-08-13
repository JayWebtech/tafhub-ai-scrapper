use sqlx::{PgPool, Row};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::scraper::ScrapedData;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub id: Uuid,
    pub url: String,
    pub status: String,
    pub max_pages: i32,
    pub max_depth: i32,
    pub delay_ms: i32,
    pub follow_external_links: bool,
    pub pages_scraped: i32,
    pub total_links_found: i32,
    pub current_url: Option<String>,
    pub error: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobSummary {
    pub job_id: Uuid,
    pub url: String,
    pub status: String,
    pub pages_scraped: i32,
    pub created_at: DateTime<Utc>,
}

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }

    pub async fn create_job(
        &self,
        job_id: Uuid,
        url: &str,
        max_pages: i32,
        max_depth: i32,
        delay_ms: i32,
        follow_external_links: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO jobs (id, url, status, max_pages, max_depth, delay_ms, follow_external_links)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            "#,
        )
        .bind(job_id)
        .bind(url)
        .bind("pending")
        .bind(max_pages)
        .bind(max_depth)
        .bind(delay_ms)
        .bind(follow_external_links)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_job_status(
        &self,
        job_id: Uuid,
        status: &str,
        current_url: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE jobs 
            SET status = $2, current_url = $3, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(status)
        .bind(current_url)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_job_progress(
        &self,
        job_id: Uuid,
        pages_scraped: i32,
        total_links_found: i32,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE jobs 
            SET pages_scraped = $2, total_links_found = $3, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(pages_scraped)
        .bind(total_links_found)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_job_error(
        &self,
        job_id: Uuid,
        error: &str,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE jobs 
            SET status = 'failed', error = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .bind(error)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_job(&self, job_id: Uuid) -> Result<Option<JobInfo>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, url, status, max_pages, max_depth, delay_ms, follow_external_links,
                   pages_scraped, total_links_found, current_url, error, created_at, updated_at
            FROM jobs 
            WHERE id = $1
            "#,
        )
        .bind(job_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| JobInfo {
            id: r.get("id"),
            url: r.get("url"),
            status: r.get("status"),
            max_pages: r.get("max_pages"),
            max_depth: r.get("max_depth"),
            delay_ms: r.get("delay_ms"),
            follow_external_links: r.get("follow_external_links"),
            pages_scraped: r.get("pages_scraped"),
            total_links_found: r.get("total_links_found"),
            current_url: r.get("current_url"),
            error: r.get("error"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn list_jobs(
        &self,
        limit: i64,
        status: Option<&str>,
    ) -> Result<Vec<JobSummary>, sqlx::Error> {
        let rows = if let Some(status_filter) = status {
            sqlx::query(
                r#"
                SELECT id, url, status, pages_scraped, created_at
                FROM jobs 
                WHERE status = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(status_filter)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, url, status, pages_scraped, created_at
                FROM jobs 
                ORDER BY created_at DESC
                LIMIT $1
                "#,
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };

        Ok(rows
            .into_iter()
            .map(|r| JobSummary {
                job_id: r.get("id"),
                url: r.get("url"),
                status: r.get("status"),
                pages_scraped: r.get("pages_scraped"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    pub async fn delete_job(&self, job_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM jobs WHERE id = $1")
            .bind(job_id)
            .execute(&self.pool)
            .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn store_scraped_data(
        &self,
        job_id: Uuid,
        scraped_data: &[ScrapedData],
    ) -> Result<(), sqlx::Error> {
        for data in scraped_data {
                    let text_content_json = serde_json::to_value(&data.text_content)
            .map_err(|_| sqlx::Error::Protocol("JSON serialization error".into()))?;
        let links_json = serde_json::to_value(&data.links)
            .map_err(|_| sqlx::Error::Protocol("JSON serialization error".into()))?;
        let images_json = serde_json::to_value(&data.images)
            .map_err(|_| sqlx::Error::Protocol("JSON serialization error".into()))?;
            
            sqlx::query(
                r#"
                INSERT INTO scraped_data (job_id, url, title, text_content, links, images)
                VALUES ($1, $2, $3, $4, $5, $6)
                "#,
            )
            .bind(job_id)
            .bind(&data.url)
            .bind(&data.title)
            .bind(text_content_json)
            .bind(links_json)
            .bind(images_json)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn get_scraped_data(&self, job_id: Uuid) -> Result<Vec<ScrapedData>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT url, title, text_content, links, images
            FROM scraped_data 
            WHERE job_id = $1
            ORDER BY id
            "#,
        )
        .bind(job_id)
        .fetch_all(&self.pool)
        .await?;

        let mut scraped_data = Vec::new();
        for row in rows {
            let text_content: Vec<String> = serde_json::from_value(row.get("text_content"))
                .unwrap_or_default();
            let links: Vec<String> = serde_json::from_value(row.get("links"))
                .unwrap_or_default();
            let images: Vec<String> = serde_json::from_value(row.get("images"))
                .unwrap_or_default();
            
            scraped_data.push(ScrapedData {
                url: row.get("url"),
                title: row.get("title"),
                text_content,
                links,
                images,
            });
        }
        
        Ok(scraped_data)
    }
}
