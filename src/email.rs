use lettre::{
    message::{header::ContentType, Mailbox, MessageBuilder, SinglePart},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Tokio1Executor,
};
use std::env;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{info, warn};

/// Email service for sending OTP verification emails
#[derive(Clone)]
pub struct EmailService {
    smtp_enabled: bool,
    smtp_host: Option<String>,
    smtp_port: Option<u16>,
    smtp_username: Option<String>,
    smtp_password: Option<String>,
    from_email: String,
}

impl EmailService {
    /// Create a new email service instance
    /// Reads configuration from environment variables
    pub fn new() -> Self {
        let smtp_enabled = env::var("SMTP_ENABLED")
            .unwrap_or_else(|_| "false".to_string())
            .parse::<bool>()
            .unwrap_or(false);

        let smtp_host = env::var("SMTP_HOST").ok();
        let smtp_port = env::var("SMTP_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok());
        let smtp_username = env::var("SMTP_USERNAME").ok();
        let smtp_password = env::var("SMTP_PASSWORD").ok();
        let from_email = env::var("SMTP_FROM_EMAIL")
            .unwrap_or_else(|_| "noreply@example.com".to_string());

        // Log configuration status
        println!("📧 Email Service Configuration:");
        println!("   SMTP_ENABLED: {}", smtp_enabled);
        if smtp_enabled {
            println!("   SMTP_HOST: {:?}", smtp_host.as_ref().unwrap_or(&"NOT SET".to_string()));
            println!("   SMTP_PORT: {:?}", smtp_port);
            println!("   SMTP_USERNAME: {}", if smtp_username.is_some() { "SET" } else { "NOT SET" });
            println!("   SMTP_PASSWORD: {}", if smtp_password.is_some() { "SET" } else { "NOT SET" });
            println!("   SMTP_FROM_EMAIL: {}", from_email);
        } else {
            println!("   ⚠️  SMTP disabled - OTPs will be logged to console");
        }

        Self {
            smtp_enabled,
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            from_email,
        }
    }

    /// Send OTP verification email
    /// If SMTP is not configured, logs the OTP instead (useful for development)
    pub async fn send_otp_email(&self, to_email: &str, otp_code: &str) -> Result<(), String> {
        println!("📧 send_otp_email called for: {}", to_email);
        println!("   SMTP_ENABLED: {}", self.smtp_enabled);
        
        if self.smtp_enabled {
            println!("📧 Attempting to send via SMTP...");
            match self.send_via_smtp(to_email, otp_code).await {
                Ok(_) => {
                    println!("✅ SMTP email sent successfully");
                    Ok(())
                }
                Err(e) => {
                    println!("❌ SMTP email failed: {}", e);
                    eprintln!("❌ SMTP Error details: {}", e);
                    Err(e)
                }
            }
        } else {
            // Development mode: just log the OTP
            warn!(
                "SMTP not configured. OTP for {}: {}",
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

    /// Send email via SMTP
    async fn send_via_smtp(&self, to_email: &str, otp_code: &str) -> Result<(), String> {
        println!("📧 send_via_smtp: Starting SMTP connection...");
        
        let smtp_host = self
            .smtp_host
            .as_ref()
            .ok_or_else(|| {
                let err = "SMTP_HOST not configured".to_string();
                eprintln!("❌ {}", err);
                err
            })?;
        println!("   SMTP_HOST: {}", smtp_host);
        
        let smtp_port = self
            .smtp_port
            .ok_or_else(|| {
                let err = "SMTP_PORT not configured".to_string();
                eprintln!("❌ {}", err);
                err
            })?;
        println!("   SMTP_PORT: {}", smtp_port);
        
        let smtp_username = self
            .smtp_username
            .as_ref()
            .ok_or_else(|| {
                let err = "SMTP_USERNAME not configured".to_string();
                eprintln!("❌ {}", err);
                err
            })?;
        
        // Warn if username looks like a placeholder
        if smtp_username.contains("your-email") || smtp_username.contains("example.com") {
            eprintln!("⚠️  WARNING: SMTP_USERNAME looks like a placeholder: {}", smtp_username);
            eprintln!("   Please update your .env file with your actual email address");
        }
        println!("   SMTP_USERNAME: {}", smtp_username);
        
        let smtp_password = self
            .smtp_password
            .as_ref()
            .ok_or_else(|| {
                let err = "SMTP_PASSWORD not configured".to_string();
                eprintln!("❌ {}", err);
                err
            })?;
        println!("   SMTP_PASSWORD: [HIDDEN]");

        println!("📧 Parsing email addresses...");
        let from_mailbox: Mailbox = self
            .from_email
            .parse()
            .map_err(|e| {
                let err = format!("Invalid from email '{}': {}", self.from_email, e);
                eprintln!("❌ {}", err);
                err
            })?;
        println!("   From: {}", self.from_email);
        
        let to_mailbox: Mailbox = to_email
            .parse()
            .map_err(|e| {
                let err = format!("Invalid to email '{}': {}", to_email, e);
                eprintln!("❌ {}", err);
                err
            })?;
        println!("   To: {}", to_email);

        let email_body = format!(
            r#"
Hello,

Thank you for signing up! Please use the following code to verify your email address:

{}

This code will expire in 10 minutes.

If you didn't request this code, please ignore this email.

Best regards,
TafHub API Team
"#,
            otp_code
        );

        println!("📧 Building email message...");
        let email = MessageBuilder::new()
            .from(from_mailbox)
            .to(to_mailbox)
            .subject("Verify your email address")
            .singlepart(
                SinglePart::builder()
                    .header(ContentType::TEXT_PLAIN)
                    .body(email_body),
            )
            .map_err(|e| {
                let err = format!("Failed to build email: {}", e);
                eprintln!("❌ {}", err);
                err
            })?;
        println!("   Email message built successfully");

        // Create SMTP transport
        println!("📧 Creating SMTP transport...");
        let creds = Credentials::new(smtp_username.clone(), smtp_password.clone());
        
        // For Gmail, we need to use STARTTLS
        let mailer = if smtp_host.contains("gmail.com") {
            println!("   Detected Gmail - using STARTTLS configuration");
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(smtp_host)
                .map_err(|e| {
                    let err = format!("Failed to create Gmail SMTP relay for '{}': {}", smtp_host, e);
                    eprintln!("❌ {}", err);
                    err
                })?
                .port(smtp_port)
                .credentials(creds)
                .build()
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(smtp_host)
                .map_err(|e| {
                    let err = format!("Failed to create SMTP relay for '{}': {}", smtp_host, e);
                    eprintln!("❌ {}", err);
                    err
                })?
                .port(smtp_port)
                .credentials(creds)
                .build()
        };
        println!("   SMTP transport created successfully");

        // Send email with timeout (30 seconds)
        println!("📧 Sending email via SMTP (30s timeout)...");
        let send_result = timeout(
            Duration::from_secs(30),
            mailer.send(email)
        ).await;

        match send_result {
            Ok(Ok(_)) => {
                println!("✅ SMTP email sent successfully to {}", to_email);
                info!("OTP email sent successfully to {}", to_email);
                Ok(())
            }
            Ok(Err(e)) => {
                let err = format!("Failed to send email via SMTP: {}", e);
                eprintln!("❌ {}", err);
                eprintln!("   Error details: {:?}", e);
                eprintln!("   Common issues:");
                eprintln!("   - Invalid SMTP credentials");
                eprintln!("   - Gmail requires App Password (not regular password)");
                eprintln!("   - Check if 'Less secure app access' is enabled (for older accounts)");
                eprintln!("   - Verify SMTP_HOST and SMTP_PORT are correct");
                Err(err)
            }
            Err(_) => {
                let err = "SMTP send operation timed out after 30 seconds".to_string();
                eprintln!("❌ {}", err);
                eprintln!("   The SMTP server did not respond in time");
                eprintln!("   Possible causes:");
                eprintln!("   - Network connectivity issues");
                eprintln!("   - SMTP server is down or unreachable");
                eprintln!("   - Firewall blocking the connection");
                eprintln!("   - Incorrect SMTP_HOST or SMTP_PORT");
                Err(err)
            }
        }
    }
}

impl Default for EmailService {
    fn default() -> Self {
        Self::new()
    }
}

