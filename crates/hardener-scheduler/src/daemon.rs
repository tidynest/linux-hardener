//! Scheduled scanning daemon.
//!
//! Provides cron-based scheduling for automated security scans
//! with graceful shutdown on Unix signals.

use crate::{
    config::SchedulerConfig,
    db::ScanHistoryManager,
    json_store::JsonStore,
    runner::{ScanRunner, ScanSummary, TriggerType},
};
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Context, PluginManager};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::broadcast;
use tokio_cron_scheduler::JobScheduler;
use tracing::{debug, error, info, warn};

/// Scheduled scanning daemon using tokio-cron-scheduler.
///
/// Manages the lifecycle of scheduled security scans, handling
/// cron-based scheduling and graceful shutdown on Unix signals.
pub struct Daemon {
    /// Scheduler configuration (schedule expression, enabled state).
    daemon_config: SchedulerConfig,
    /// Scan execution runner.
    daemon_runner: Arc<ScanRunner>,
    /// Cron job scheduler instance (created during start).
    daemon_scheduler: Option<JobScheduler>,
    /// Shutdown signal sender for coordinating graceful stop.
    daemon_shutdown_tx: Option<broadcast::Sender<()>>,
    /// Flag indicating if a scan is currently running.
    daemon_scan_in_progress: Arc<AtomicBool>,
}

impl Daemon {
    /// Creates a new Daemon instance from configuration.
    ///
    /// # Arguments
    /// * `config` - Scheduler configuration with cron expression and settings
    /// * `db` - Initialised database manager for scan history
    /// * `json_store` - Initialised JSON store for exports
    ///
    /// # Returns
    /// A new Daemon ready to be started.
    pub fn new(
        config: SchedulerConfig,
        db: Arc<ScanHistoryManager>,
        json_store: Arc<JsonStore>,
    ) -> Daemon {
        let runner = Arc::new(ScanRunner::new(&config, db, json_store));

        Daemon {
            daemon_config: config,
            daemon_runner: runner,
            daemon_scheduler: None,
            daemon_shutdown_tx: None,
            daemon_scan_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Executes a single scan immediately.
    ///
    /// Useful for testing or manual triggering without starting
    /// the full scheduler loop.
    ///
    /// # Arguments
    /// * `plugin_manager` - Configured plugin manager with resolved dependencies
    /// * `ctx` - Execution context for plugins
    /// * `trigger` - What initiated this scan
    ///
    /// # Returns
    /// Summary of the scan results.
    ///
    /// # Errors
    /// Returns an error if a scan is already in progress.
    pub async fn run_once(
        &self,
        plugin_manager: &PluginManager,
        ctx: &Context,
        trigger: TriggerType,
    ) -> Result<ScanSummary> {
        // Atomically check and set scan_in_progress
        if self.daemon_scan_in_progress.swap(true, Ordering::SeqCst) {
            return Err(HardeningError::State(
                "Scan already in progress".to_string(),
            ));
        }

        debug!("Starting manual scan with trigger {:?}", trigger);

        // Execute the scan, ensuring we clear the flag even on error
        let result = self.daemon_runner.run(plugin_manager, ctx, trigger).await;

        self.daemon_scan_in_progress.store(false, Ordering::SeqCst);

        result
    }

    /// Internal method called by the scheduler job.
    ///
    /// This is a static async function because tokio-cron-scheduler
    /// requires the job closure to own all its data (no `&self`).
    async fn execute_scan(
        runner: Arc<ScanRunner>,
        plugin_manager: Arc<PluginManager>,
        ctx: Arc<Context>,
        scan_in_progress: Arc<AtomicBool>,
    ) {
        // Check if scan already running (skip if so)
        if scan_in_progress.swap(true, Ordering::SeqCst) {
            warn!("Scheduled scan skipped: previous scan still in progress");
            return;
        }

        info!("Scheduled scan triggered");

        let result = runner
            .run(
                plugin_manager.as_ref(),
                ctx.as_ref(),
                TriggerType::Scheduled,
            )
            .await;

        scan_in_progress.store(false, Ordering::SeqCst);

        match result {
            Ok(summary) => {
                info!(
                    "Scheduled scan completed: {} findings ({} critical, {} high)",
                    summary.total_findings, summary.critical_count, summary.high_count
                );
            }
            Err(e) => {
                error!("Scheduled scan failed: {}", e);
            }
        }
    }

    /// Starts the daemon scheduler loop.
    ///
    /// Creates a cron job based on the configuration schedule and begins
    /// listening for shutdown signals. This method blocks until shutdown
    /// is triggered via signal or `stop()`.
    ///
    /// # Arguments
    /// * `plugin_manager` - Configured plugin manager with resolved dependencies
    /// * `ctx` - Execution context for plugins
    ///
    /// # Errors
    /// Returns an error if:
    /// - Scheduler is disabled in configuration
    /// - Cron expression is invalid
    /// - Scheduler fails to start
    pub async fn start(
        &mut self,
        plugin_manager: Arc<PluginManager>,
        ctx: Arc<Context>,
    ) -> Result<()> {
        // Validate scheduler is enabled
        if !self.daemon_config.enabled {
            return Err(HardeningError::Config(
                "Scheduler is disabled in configuration".to_string(),
            ));
        }

        info!(
            "Starting daemon with schedule '{}'",
            self.daemon_config.schedule
        );

        // Create the job scheduler
        let scheduler = JobScheduler::new()
            .await
            .map_err(|e| HardeningError::State(format!("Failed to create scheduler: {}", e)))?;

        // Clone Arc references for the job closure
        let runner = self.daemon_runner.clone();
        let pm = plugin_manager.clone();
        let context = ctx.clone();
        let scan_flag = self.daemon_scan_in_progress.clone();

        // Create the cron job
        let job = tokio_cron_scheduler::Job::new_async(
            self.daemon_config.schedule.as_str(),
            move |_uuid, _lock| {
                let runner = runner.clone();
                let pm = pm.clone();
                let ctx = context.clone();
                let flag = scan_flag.clone();

                Box::pin(async move { Self::execute_scan(runner, pm, ctx, flag).await })
            },
        )
        .map_err(|e| HardeningError::Config(format!("Invalid cron expression: {}", e)))?;

        scheduler
            .add(job)
            .await
            .map_err(|e| HardeningError::State(format!("Failed to add job: {}", e)))?;

        // Set up shutdown channel
        let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);
        self.daemon_shutdown_tx = Some(shutdown_tx.clone());

        // Spawn signal handler
        tokio::spawn(Self::signal_handler(shutdown_tx));

        // start the scheduler
        scheduler
            .start()
            .await
            .map_err(|e| HardeningError::State(format!("Failed to start scheduler: {}", e)))?;

        self.daemon_scheduler = Some(scheduler);

        info!("Daemon running, waiting for shutdown signal");

        // Wait for shutdown signal
        let _ = shutdown_rx.recv().await;

        info!("Shutdown signal received");
        self.shutdown_scheduler().await
    }

    /// Handles Unix signals for graceful shutdown.
    ///
    /// Listens for SIGTERM and SIGINT, then sends shutdown signal
    /// to the broadcast channel.
    async fn signal_handler(shutdown_tx: broadcast::Sender<()>) {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register SIGTERM handler: {}", e);
                return;
            }
        };

        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                error!("Failed to register SIGINT handler: {}", e);
                return;
            }
        };

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating shutdown");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating shutdown");
            }
        }

        let _ = shutdown_tx.send(());
    }

    /// Gracefully stops the daemon.
    ///
    /// Signals shutdown and waits for any in-progress scan to complete
    /// before stopping the scheduler.
    ///
    /// # Errors
    /// Returns an error if the scheduler fails to stop cleanly.
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stop requested");

        // Send shutdown signal if channel exists
        if let Some(tx) = &self.daemon_shutdown_tx {
            let _ = tx.send(());
        }

        self.shutdown_scheduler().await
    }

    /// Internal helper to shutdown the scheduler and wait for scans.
    async fn shutdown_scheduler(&mut self) -> Result<()> {
        // Wait for in-progress scan to complete
        while self.daemon_scan_in_progress.load(Ordering::SeqCst) {
            debug!("Waiting for in-progress scan to complete...");
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }

        // Shutdown the scheduler
        if let Some(mut scheduler) = self.daemon_scheduler.take() {
            scheduler.shutdown().await.map_err(|e| {
                HardeningError::State(format!("Failed to shut down scheduler: {}", e))
            })?;
        }

        self.daemon_shutdown_tx = None;

        info!("Daemon stopped gracefully");
        Ok(())
    }
}

#[cfg(test)]
mod tests;
