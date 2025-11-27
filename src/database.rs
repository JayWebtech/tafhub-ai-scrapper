use sqlx::{PgPool, Row};
use uuid::Uuid;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use crate::scraper::ScrapedData;
use sha2::{Digest, Sha256};
use hex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JobInfo {
    pub id: Uuid,
    pub user_id: Uuid,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub name: Option<String>,
    pub email: String,
    pub password_hash: Option<String>,
    pub google_id: Option<String>,
    pub avatar_url: Option<String>,
    pub credits: i32,
    pub email_verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtpVerification {
    pub id: Uuid,
    pub email: String,
    pub otp_code: String,
    pub expires_at: DateTime<Utc>,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub key_hash: String,
    pub name: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreditTransaction {
    pub id: Uuid,
    pub user_id: Uuid,
    pub amount: i32,
    pub transaction_type: String,
    pub description: Option<String>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Payment {
    pub id: Uuid,
    pub user_id: Uuid,
    pub stripe_payment_intent_id: Option<String>,
    pub stripe_checkout_session_id: Option<String>,
    pub amount_cents: i32,
    pub credits: i32,
    pub status: String,
    pub currency: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

pub struct Database {
    pool: PgPool,
}

impl Database {
    pub async fn new(database_url: &str) -> Result<Self, sqlx::Error> {
        let pool = PgPool::connect(database_url).await?;
        Ok(Self { pool })
    }

    pub async fn create_user_with_google(
        &self,
        google_id: &str,
        email: &str,
        avatar_url: Option<&str>,
    ) -> Result<Uuid, sqlx::Error> {
        let user_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO users (id, name, email, password_hash, google_id, avatar_url, email_verified)
            VALUES ($1, NULL, $2, NULL, $3, $4, true)
            "#,
        )
        .bind(user_id)
        .bind(email)
        .bind(google_id)
        .bind(avatar_url)
        .execute(&self.pool)
        .await?;

        Ok(user_id)
    }

    pub async fn get_user_by_google_id(&self, google_id: &str) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, name, email, password_hash, google_id, avatar_url, credits, email_verified, created_at, updated_at
            FROM users
            WHERE google_id = $1
            "#,
        )
        .bind(google_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            name: r.try_get("name").ok(),
            email: r.get("email"),
            password_hash: r.try_get("password_hash").ok(),
            google_id: r.try_get("google_id").ok(),
            avatar_url: r.try_get("avatar_url").ok(),
            credits: r.get("credits"),
            email_verified: r.get("email_verified"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn link_google_account(
        &self,
        user_id: Uuid,
        google_id: &str,
        avatar_url: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE users
            SET google_id = $2,
                avatar_url = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(google_id)
        .bind(avatar_url)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_google_profile(
        &self,
        user_id: Uuid,
        email: &str,
        avatar_url: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE users
            SET email = $2,
                avatar_url = $3,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(email)
        .bind(avatar_url)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn create_user(
        &self,
        name: &str,
        email: &str,
        password_hash: &str,
    ) -> Result<Uuid, sqlx::Error> {
        let user_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO users (id, name, email, password_hash, google_id, avatar_url, email_verified)
            VALUES ($1, $2, $3, $4, NULL, NULL, false)
            "#,
        )
        .bind(user_id)
        .bind(name)
        .bind(email)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;

        Ok(user_id)
    }

    pub async fn verify_user_email(&self, user_id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE users
            SET email_verified = true, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn get_user_by_email(&self, email: &str) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, name, email, password_hash, google_id, avatar_url, credits, email_verified, created_at, updated_at
            FROM users 
            WHERE email = $1
            "#,
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            name: r.try_get("name").ok(),
            email: r.get("email"),
            password_hash: r.try_get("password_hash").ok(),
            google_id: r.try_get("google_id").ok(),
            avatar_url: r.try_get("avatar_url").ok(),
            credits: r.get("credits"),
            email_verified: r.get("email_verified"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn get_user_by_id(&self, user_id: Uuid) -> Result<Option<User>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, name, email, password_hash, google_id, avatar_url, credits, email_verified, created_at, updated_at
            FROM users 
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| User {
            id: r.get("id"),
            name: r.try_get("name").ok(),
            email: r.get("email"),
            password_hash: r.try_get("password_hash").ok(),
            google_id: r.try_get("google_id").ok(),
            avatar_url: r.try_get("avatar_url").ok(),
            credits: r.get("credits"),
            email_verified: r.get("email_verified"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn add_credits(
        &self,
        user_id: Uuid,
        amount: i32,
        description: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Update user credits
        sqlx::query(
            r#"
            UPDATE users 
            SET credits = credits + $1, updated_at = NOW()
            WHERE id = $2
            "#,
        )
        .bind(amount)
        .bind(user_id)
        .execute(&mut *tx)
        .await?;

        // Record transaction
        sqlx::query(
            r#"
            INSERT INTO credit_transactions (id, user_id, amount, transaction_type, description)
            VALUES (gen_random_uuid(), $1, $2, 'purchase', $3)
            "#,
        )
        .bind(user_id)
        .bind(amount)
        .bind(description)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn deduct_credit(&self, user_id: Uuid) -> Result<bool, sqlx::Error> {
        let mut tx = self.pool.begin().await?;

        // Check if user has credits
        let user = sqlx::query(
            r#"
            SELECT credits FROM users WHERE id = $1 FOR UPDATE
            "#,
        )
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;

        if let Some(row) = user {
            let credits: i32 = row.get("credits");
            if credits >= 1 {
                // Deduct credit
                sqlx::query(
                    r#"
                    UPDATE users 
                    SET credits = credits - 1, updated_at = NOW()
                    WHERE id = $1
                    "#,
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?;

                // Record transaction
                sqlx::query(
                    r#"
                    INSERT INTO credit_transactions (id, user_id, amount, transaction_type, description)
                    VALUES (gen_random_uuid(), $1, -1, 'deduction', 'Scraping job')
                    "#,
                )
                .bind(user_id)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                return Ok(true);
            }
        }

        tx.rollback().await?;
        Ok(false)
    }

    pub async fn get_user_credits(&self, user_id: Uuid) -> Result<i32, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT credits FROM users WHERE id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get("credits"))
    }

    // API Key operations
    pub async fn create_api_key(
        &self,
        user_id: Uuid,
        key_hash: &str,
        name: Option<&str>,
    ) -> Result<Uuid, sqlx::Error> {
        let api_key_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO api_keys (id, user_id, key_hash, name)
            VALUES ($1, $2, $3, $4)
            "#,
        )
        .bind(api_key_id)
        .bind(user_id)
        .bind(key_hash)
        .bind(name)
        .execute(&self.pool)
        .await?;

        Ok(api_key_id)
    }

    pub async fn get_api_key_by_hash(
        &self,
        key_hash: &str,
    ) -> Result<Option<ApiKey>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, key_hash, name, last_used_at, created_at
            FROM api_keys 
            WHERE key_hash = $1
            "#,
        )
        .bind(key_hash)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| ApiKey {
            id: r.get("id"),
            user_id: r.get("user_id"),
            key_hash: r.get("key_hash"),
            name: r.get("name"),
            last_used_at: r.get("last_used_at"),
            created_at: r.get("created_at"),
        }))
    }

    pub async fn list_api_keys(&self, user_id: Uuid) -> Result<Vec<ApiKey>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, key_hash, name, last_used_at, created_at
            FROM api_keys 
            WHERE user_id = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| ApiKey {
                id: r.get("id"),
                user_id: r.get("user_id"),
                key_hash: r.get("key_hash"),
                name: r.get("name"),
                last_used_at: r.get("last_used_at"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    pub async fn delete_api_key(&self, api_key_id: Uuid, user_id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM api_keys 
            WHERE id = $1 AND user_id = $2
            "#,
        )
        .bind(api_key_id)
        .bind(user_id)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    pub async fn update_api_key_last_used(
        &self,
        api_key_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE api_keys 
            SET last_used_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(api_key_id)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Job operations (updated to include user_id and api_key_id)
    pub async fn create_job(
        &self,
        job_id: Uuid,
        user_id: Uuid,
        api_key_id: Option<Uuid>,
        url: &str,
        context: Option<&str>,
        max_pages: i32,
        max_depth: i32,
        delay_ms: i32,
        follow_external_links: bool,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            INSERT INTO jobs (id, user_id, api_key_id, url, context, status, max_pages, max_depth, delay_ms, follow_external_links)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
            "#,
        )
        .bind(job_id)
        .bind(user_id)
        .bind(api_key_id)
        .bind(url)
        .bind(context)
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
            SELECT id, user_id, url, status, max_pages, max_depth, delay_ms, follow_external_links,
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
            user_id: r.get("user_id"),
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
        user_id: Uuid,
        limit: i64,
        status: Option<&str>,
    ) -> Result<Vec<JobSummary>, sqlx::Error> {
        let rows = if let Some(status_filter) = status {
            sqlx::query(
                r#"
                SELECT id, url, status, pages_scraped, created_at
                FROM jobs 
                WHERE user_id = $1 AND status = $2
                ORDER BY created_at DESC
                LIMIT $3
                "#,
            )
            .bind(user_id)
            .bind(status_filter)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT id, url, status, pages_scraped, created_at
                FROM jobs 
                WHERE user_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
            )
            .bind(user_id)
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

    pub async fn get_user_job_count(&self, user_id: Uuid) -> Result<i64, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT COUNT(*) as count
            FROM jobs 
            WHERE user_id = $1
            "#,
        )
        .bind(user_id)
        .fetch_one(&self.pool)
        .await?;

        Ok(row.get("count"))
    }

    pub async fn get_user_recent_transactions(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<CreditTransaction>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, amount, transaction_type, description, created_at
            FROM credit_transactions 
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| CreditTransaction {
                id: r.get("id"),
                user_id: r.get("user_id"),
                amount: r.get("amount"),
                transaction_type: r.get("transaction_type"),
                description: r.get("description"),
                created_at: r.get("created_at"),
            })
            .collect())
    }

    /// Get daily credit usage (deductions) for the last 30 days
    /// Returns a vector of (date, credits_used) tuples
    pub async fn get_user_credit_usage_last_30_days(
        &self,
        user_id: Uuid,
    ) -> Result<Vec<(chrono::NaiveDate, i32)>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT 
                DATE(created_at) as usage_date,
                SUM(ABS(amount)) as credits_used
            FROM credit_transactions 
            WHERE user_id = $1
                AND transaction_type = 'deduction'
                AND created_at >= NOW() - INTERVAL '30 days'
            GROUP BY DATE(created_at)
            ORDER BY usage_date ASC
            "#,
        )
        .bind(user_id)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                let date: chrono::NaiveDate = r.get("usage_date");
                let credits: i64 = r.get("credits_used");
                (date, credits as i32)
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

    // URL cache operations
    pub fn normalize_and_hash_url(url: &str) -> String {
        // Normalize URL for consistent caching
        // Remove trailing slashes, convert to lowercase, remove fragment
        let normalized = url
            .trim()
            .to_lowercase()
            .trim_end_matches('/')
            .split('#')
            .next()
            .unwrap_or("")
            .to_string();
        
        let mut hasher = Sha256::new();
        hasher.update(normalized.as_bytes());
        hex::encode(hasher.finalize())
    }

    pub async fn get_cached_url(
        &self,
        url: &str,
        cache_hours: i64,
    ) -> Result<Option<(Uuid, Vec<ScrapedData>)>, sqlx::Error> {
        let url_hash = Self::normalize_and_hash_url(url);
        
        // Use a transaction for atomic cache check
        let mut tx = self.pool.begin().await?;
        
        let row = sqlx::query(
            r#"
            SELECT job_id, last_scraped_at
            FROM url_cache 
            WHERE url_hash = $1
            AND last_scraped_at > NOW() - INTERVAL '1 hour' * $2
            ORDER BY last_scraped_at DESC
            LIMIT 1
            FOR SHARE
            "#,
        )
        .bind(&url_hash)
        .bind(cache_hours)
        .fetch_optional(&mut *tx)
        .await?;

        let result = if let Some(row) = row {
            let job_id: Uuid = row.get("job_id");
            
            // Commit transaction before fetching data (to avoid long locks)
            tx.commit().await?;
            
            // Verify job is completed
            let job = self.get_job(job_id).await?
                .ok_or_else(|| sqlx::Error::RowNotFound)?;
            
            if job.status == "completed" {
                // Get the scraped data for this job
                let scraped_data = self.get_scraped_data(job_id).await?;
                
                if !scraped_data.is_empty() {
                    Some((job_id, scraped_data))
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            tx.commit().await?;
            None
        };

        Ok(result)
    }

    pub async fn upsert_url_cache(
        &self,
        url: &str,
        job_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        let url_hash = Self::normalize_and_hash_url(url);
        
        // Use a transaction for atomic upsert
        let mut tx = self.pool.begin().await?;
        
        sqlx::query(
            r#"
            INSERT INTO url_cache (url, url_hash, job_id, last_scraped_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (url_hash) 
            DO UPDATE SET 
                job_id = EXCLUDED.job_id,
                last_scraped_at = NOW(),
                url = EXCLUDED.url
            "#,
        )
        .bind(url)
        .bind(&url_hash)
        .bind(job_id)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        Ok(())
    }

    pub async fn cleanup_old_cache(&self, days: i64) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM url_cache 
            WHERE last_scraped_at < NOW() - INTERVAL '1 day' * $1
            "#,
        )
        .bind(days)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // OTP verification operations
    pub async fn create_otp(
        &self,
        email: &str,
        otp_code: &str,
        expires_at: DateTime<Utc>,
    ) -> Result<Uuid, sqlx::Error> {
        // Invalidate any existing unverified OTPs for this email
        sqlx::query(
            r#"
            UPDATE otp_verifications
            SET verified = true
            WHERE email = $1 AND verified = false AND expires_at > NOW()
            "#,
        )
        .bind(email)
        .execute(&self.pool)
        .await?;

        // Create new OTP
        let otp_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO otp_verifications (id, email, otp_code, expires_at, verified)
            VALUES ($1, $2, $3, $4, false)
            "#,
        )
        .bind(otp_id)
        .bind(email)
        .bind(otp_code)
        .bind(expires_at)
        .execute(&self.pool)
        .await?;

        Ok(otp_id)
    }

    pub async fn verify_otp(&self, email: &str, otp_code: &str) -> Result<bool, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, expires_at, verified
            FROM otp_verifications
            WHERE email = $1 AND otp_code = $2 AND verified = false
            ORDER BY created_at DESC
            LIMIT 1
            "#,
        )
        .bind(email)
        .bind(otp_code)
        .fetch_optional(&self.pool)
        .await?;

        if let Some(r) = row {
            let expires_at: DateTime<Utc> = r.get("expires_at");
            let otp_id: Uuid = r.get("id");

            // Check if OTP is expired
            if expires_at < Utc::now() {
                return Ok(false);
            }

            // Mark OTP as verified
            sqlx::query(
                r#"
                UPDATE otp_verifications
                SET verified = true
                WHERE id = $1
                "#,
            )
            .bind(otp_id)
            .execute(&self.pool)
            .await?;

            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub async fn cleanup_expired_otps(&self) -> Result<u64, sqlx::Error> {
        let result = sqlx::query(
            r#"
            DELETE FROM otp_verifications
            WHERE expires_at < NOW() OR verified = true
            "#,
        )
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }

    // User profile update methods
    pub async fn update_user_name(&self, user_id: Uuid, name: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE users
            SET name = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(name)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    pub async fn update_user_password(&self, user_id: Uuid, password_hash: &str) -> Result<(), sqlx::Error> {
        sqlx::query(
            r#"
            UPDATE users
            SET password_hash = $2, updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(user_id)
        .bind(password_hash)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    // Payment methods
    pub async fn create_payment(
        &self,
        user_id: Uuid,
        stripe_checkout_session_id: &str,
        amount_cents: i32,
        credits: i32,
    ) -> Result<Uuid, sqlx::Error> {
        let payment_id = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO payments (id, user_id, stripe_checkout_session_id, amount_cents, credits, status, currency)
            VALUES ($1, $2, $3, $4, $5, 'pending', 'usd')
            "#,
        )
        .bind(payment_id)
        .bind(user_id)
        .bind(stripe_checkout_session_id)
        .bind(amount_cents)
        .bind(credits)
        .execute(&self.pool)
        .await?;

        Ok(payment_id)
    }

    pub async fn update_payment_status(
        &self,
        stripe_checkout_session_id: &str,
        status: &str,
        stripe_payment_intent_id: Option<&str>,
    ) -> Result<(), sqlx::Error> {
        if let Some(payment_intent_id) = stripe_payment_intent_id {
            sqlx::query(
                r#"
                UPDATE payments
                SET status = $3, stripe_payment_intent_id = $2, updated_at = NOW()
                WHERE stripe_checkout_session_id = $1
                "#,
            )
            .bind(stripe_checkout_session_id)
            .bind(payment_intent_id)
            .bind(status)
            .execute(&self.pool)
            .await?;
        } else {
            sqlx::query(
                r#"
                UPDATE payments
                SET status = $2, updated_at = NOW()
                WHERE stripe_checkout_session_id = $1
                "#,
            )
            .bind(stripe_checkout_session_id)
            .bind(status)
            .execute(&self.pool)
            .await?;
        }

        Ok(())
    }

    pub async fn get_payment_by_checkout_session(
        &self,
        stripe_checkout_session_id: &str,
    ) -> Result<Option<Payment>, sqlx::Error> {
        let row = sqlx::query(
            r#"
            SELECT id, user_id, stripe_payment_intent_id, stripe_checkout_session_id, 
                   amount_cents, credits, status, currency, created_at, updated_at
            FROM payments
            WHERE stripe_checkout_session_id = $1
            "#,
        )
        .bind(stripe_checkout_session_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.map(|r| Payment {
            id: r.get("id"),
            user_id: r.get("user_id"),
            stripe_payment_intent_id: r.try_get("stripe_payment_intent_id").ok(),
            stripe_checkout_session_id: r.try_get("stripe_checkout_session_id").ok(),
            amount_cents: r.get("amount_cents"),
            credits: r.get("credits"),
            status: r.get("status"),
            currency: r.get("currency"),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    pub async fn get_user_payments(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<Payment>, sqlx::Error> {
        let rows = sqlx::query(
            r#"
            SELECT id, user_id, stripe_payment_intent_id, stripe_checkout_session_id, 
                   amount_cents, credits, status, currency, created_at, updated_at
            FROM payments
            WHERE user_id = $1
            ORDER BY created_at DESC
            LIMIT $2
            "#,
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| Payment {
                id: r.get("id"),
                user_id: r.get("user_id"),
                stripe_payment_intent_id: r.try_get("stripe_payment_intent_id").ok(),
                stripe_checkout_session_id: r.try_get("stripe_checkout_session_id").ok(),
                amount_cents: r.get("amount_cents"),
                credits: r.get("credits"),
                status: r.get("status"),
                currency: r.get("currency"),
                created_at: r.get("created_at"),
                updated_at: r.get("updated_at"),
            })
            .collect())
    }
}
