//! Email notifications via SMTP.
//!
//! Uses the `lettre` crate for SMTP transport with TLS support.
//! SMTP password is read from the `HARDENER_SMTP_PASSWORD` environment variable.

use super::{NotificationResult, Notifier};
use crate::config::EmailConfig;
use crate::runner::ScanSummary;
use async_trait::async_trait;
use lettre::{
    message::{header::ContentType, Mailbox},
    transport::smtp::authentication::Credentials,
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
};
use std::env;
use tracing::{debug, error};

/// Environment variable for SMTP password.
const SMTP_PASSWORD_ENV: &str = "HARDENER_SMTP_PASSWORD";

/// Sends email notification via SMTP.
pub struct EmailNotifier {
    config: EmailConfig,
    transport: AsyncSmtpTransport<Tokio1Executor>,
}

impl EmailNotifier {
    /// Creates a new EmailNotifier from configuration.
    ///
    /// # Errors
    /// Returns `None` if:
    /// - Email is disabled in config
    /// - Required fields are missing (host, from, recipients)
    /// - SMTP transport cannot be built
    pub fn new(config: &EmailConfig) -> Option<Self> {
        if !config.enabled {
            debug!("Email notifications disabled");
            return None;
        }

        if config.smtp_host.is_empty() {
            error!("Email enabled but SMTP host is empty");
            return None;
        }

        if config.from_address.is_empty() || config.recipients.is_empty() {
            error!("Email enabled but from_address or recipients missing");
            return None;
        }

        let transport = Self::build_transport(config)?;

        Some(Self {
            config: config.clone(),
            transport,
        })
    }

    /// Build the SMTP transport with TLS and authentication.
    fn build_transport(config: &EmailConfig) -> Option<AsyncSmtpTransport<Tokio1Executor>> {
        let password = env::var(SMTP_PASSWORD_ENV).unwrap_or_default();

        let builder = if config.smtp_tls {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
        } else {
            AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host)
        };

        let builder = match builder {
            Ok(b) => b,
            Err(e) => {
                error!("Failed to create SMTP relay: {}", e);
                return None;
            }
        };

        let transport = builder
            .port(config.smtp_port)
            .credentials(Credentials::new(config.smtp_username.clone(), password))
            .build();

        Some(transport)
    }

    /// Formats the email subject line.
    fn format_subject(&self, summary: &ScanSummary) -> String {
        let severity = if summary.critical_count > 0 {
            "CRITICAL"
        } else if summary.high_count > 0 {
            "HIGH"
        } else if summary.medium_count > 0 {
            "MEDIUM"
        } else {
            "LOW"
        };

        format!(
            "[{}] Security Scan: {} findings on {}",
            severity, summary.total_findings, summary.host
        )
    }

    /// Formats the email body with scan details.
    fn format_body(&self, summary: &ScanSummary) -> String {
        let mut body = String::with_capacity(1024);

        body.push_str("Linux System Hardener - Security Scan Report\n");
        body.push_str("============================================\n\n");

        body.push_str(&format!("Host: {}\n", summary.host));
        body.push_str(&format!("Session ID: {}\n", summary.session_id));
        body.push_str(&format!(
            "Plugins scanned: {}\n\n",
            summary.plugins_scanned.join(", ")
        ));

        body.push_str("Findings Summary\n");
        body.push_str("----------------\n");
        body.push_str(&format!("  Critical: {}\n", summary.critical_count));
        body.push_str(&format!("  High:     {}\n", summary.high_count));
        body.push_str(&format!("  Medium:   {}\n", summary.medium_count));
        body.push_str(&format!("  Low:      {}\n", summary.low_count));
        body.push_str(&format!("  Info:     {}\n", summary.info_count));
        body.push_str("  ─────────────\n");
        body.push_str(&format!("  Total:    {}\n\n", summary.total_findings));

        if let Some(ref path) = summary.json_path {
            body.push_str(&format!("Full report: {}\n", path));
        }

        if summary.had_errors {
            body.push_str("\n⚠ Some plugins encountered errors during scanning.\n");
        }

        body
    }
}

#[async_trait]
impl Notifier for EmailNotifier {
    async fn send(&self, summary: &ScanSummary) -> NotificationResult {
        let from: Mailbox = match self.config.from_address.parse() {
            Ok(m) => m,
            Err(e) => {
                return NotificationResult::failed(
                    self.channel(),
                    format!("Invalid from address: {}", e),
                )
            }
        };

        let subject = self.format_subject(summary);
        let body = self.format_body(summary);

        // Send to each recipient
        for recipient in &self.config.recipients {
            let to: Mailbox = match recipient.parse() {
                Ok(m) => m,
                Err(e) => {
                    error!("Invalid recipient '{}': {}", recipient, e);
                    continue;
                }
            };

            let message = match Message::builder()
                .from(from.clone())
                .to(to)
                .subject(&subject)
                .header(ContentType::TEXT_PLAIN)
                .body(body.clone())
            {
                Ok(m) => m,
                Err(e) => {
                    return NotificationResult::failed(
                        self.channel(),
                        format!("Failed to build message: {}", e),
                    )
                }
            };

            if let Err(e) = self.transport.send(message).await {
                return NotificationResult::failed(
                    self.channel(),
                    format!("SMTP send failed: {}", e),
                );
            }

            debug!("Email sent to {}", recipient);
        }

        NotificationResult::ok(self.channel())
    }

    fn channel(&self) -> &str {
        "email"
    }
}
