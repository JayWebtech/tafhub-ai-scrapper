use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::env;
use tracing::{info, warn};

/// Email service for sending OTP verification emails via Resend API
#[derive(Clone)]
pub struct EmailService {
    resend_enabled: bool,
    resend_api_key: Option<String>,
    from_email: String,
    client: Client,
}

#[derive(Serialize)]
struct ResendEmailRequest {
    from: String,
    to: Vec<String>,
    subject: String,
    text: String,
}

#[derive(Deserialize)]
struct ResendEmailResponse {
    id: String,
}

impl EmailService {
    /// Create a new email service instance
    /// Reads configuration from environment variables
    pub fn new() -> Self {
        let resend_enabled = env::var("RESEND_ENABLED")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        let resend_api_key = env::var("RESEND_API_KEY").ok();
        // Use Resend's default testing domain if RESEND_FROM_EMAIL is not set
        // This works without domain verification: onboarding@resend.dev
        let from_email = env::var("RESEND_FROM_EMAIL")
            .or_else(|_| env::var("SMTP_FROM_EMAIL"))
            .unwrap_or_else(|_| "onboarding@resend.dev".to_string());

        // Log configuration status
        println!("📧 Email Service Configuration (Resend):");
        println!("   RESEND_ENABLED: {}", resend_enabled);
        if resend_enabled {
            println!("   RESEND_API_KEY: {}", if resend_api_key.is_some() { "SET" } else { "NOT SET" });
            if from_email == "onboarding@resend.dev" {
                println!("   RESEND_FROM_EMAIL: {} (using Resend default - no domain verification needed)", from_email);
            } else {
                println!("   RESEND_FROM_EMAIL: {}", from_email);
            }
        } else {
            println!("   ⚠️  Resend disabled - OTPs will be logged to console");
        }

        Self {
            resend_enabled,
            resend_api_key,
            from_email,
            client: Client::new(),
        }
    }

    /// Send OTP verification email via Resend API
    /// If Resend is not configured, logs the OTP instead (useful for development)
    pub async fn send_otp_email(&self, to_email: &str, otp_code: &str) -> Result<(), String> {
        println!("📧 send_otp_email called for: {}", to_email);
        println!("   RESEND_ENABLED: {}", self.resend_enabled);
        
        if self.resend_enabled {
            println!("📧 Attempting to send via Resend API...");
            match self.send_via_resend(to_email, otp_code).await {
                Ok(_) => {
                    println!("✅ Resend email sent successfully");
                    Ok(())
                }
                Err(e) => {
                    println!("❌ Resend email failed: {}", e);
                    eprintln!("❌ Resend Error details: {}", e);
                    Err(e)
                }
            }
        } else {
            // Development mode: just log the OTP
            warn!(
                "Resend not configured. OTP for {}: {}",
                to_email, otp_code
            );
            info!(
                "📧 OTP Email (dev mode) - To: {}, OTP: {}",
                to_email, otp_code
            );
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("📧 OTP EMAIL (Development Mode)");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            println!("To: {}", to_email);
            println!("OTP Code: {}", otp_code);
            println!("Expires in: 10 minutes");
            println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
            Ok(())
        }
    }

    /// Send email via Resend API
    async fn send_via_resend(&self, to_email: &str, otp_code: &str) -> Result<(), String> {
        println!("📧 send_via_resend: Starting Resend API request...");
        
        let api_key = self
            .resend_api_key
            .as_ref()
            .ok_or_else(|| {
                let err = "RESEND_API_KEY not configured".to_string();
                eprintln!("❌ {}", err);
                err
            })?;
        
        println!("   API Key: [HIDDEN]");
        println!("   From: {}", self.from_email);
        println!("   To: {}", to_email);

        let email_body = format!(
            r#"Hello,

Thank you for signing up! Please use the following code to verify your email address:

{}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
TafHub API Team"#,
            otp_code
        );

        let email_request = ResendEmailRequest {
            from: self.from_email.clone(),
            to: vec![to_email.to_string()],
            subject: "Verify your email address".to_string(),
            text: email_body,
        };

        println!("📧 Sending email via Resend API...");
        
        let response = self
            .client
            .post("https://api.resend.com/emails")
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&email_request)
            .send()
            .await
            .map_err(|e| {
                let err = format!("Failed to send request to Resend API: {}", e);
                eprintln!("❌ {}", err);
                err
            })?;

        let status = response.status();
        println!("   Response status: {}", status);

        if status.is_success() {
            let resend_response: ResendEmailResponse = response
                .json()
                .await
                .map_err(|e| {
                    let err = format!("Failed to parse Resend API response: {}", e);
                    eprintln!("❌ {}", err);
                    err
                })?;
            
            println!("✅ Resend email sent successfully to {} (ID: {})", to_email, resend_response.id);
            info!("OTP email sent successfully to {} via Resend (ID: {})", to_email, resend_response.id);
            Ok(())
        } else {
            let error_text = response
                .text()
                .await
                .unwrap_or_else(|_| "Unknown error".to_string());
            
            let err = format!(
                "Resend API returned error status {}: {}",
                status, error_text
            );
            eprintln!("❌ {}", err);
            eprintln!("   Common issues:");
            eprintln!("   - Invalid RESEND_API_KEY");
            eprintln!("   - Unverified sender domain");
            eprintln!("   - Rate limit exceeded");
            eprintln!("   - Check Resend dashboard for more details");
            Err(err)
        }
    }
}

impl Default for EmailService {
    fn default() -> Self {
        Self::new()
    }
}
