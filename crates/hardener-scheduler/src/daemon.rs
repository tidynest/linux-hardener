//! Scheduled scanning daemon.
//!
//! Provides cron-based scheduling for automated security scans
//! with graceful shutdown on Unix signals.

use crate::{
    config::SchedulerConfig,
    db::ScanHistoryManager,
    json_store::JsonStore,
    runner::{ScanRunner, ScanSummary, TriggerType},
    schedule::{Schedule, wait_step},
};
use hardener_common::error::{HardeningError, Result};
use hardener_core::{Context, PluginManager};
use hardener_types::time::{self, Timestamp};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::{
    sync::broadcast,
    task::{JoinError, JoinHandle},
};
use tracing::{debug, error, info, warn};

/// Scheduled scanning daemon.
///
/// Manages the lifecycle of scheduled security scans: a task of its own
/// waits for each firing of the cron expression, and Unix signals end it
/// gracefully.
pub struct Daemon {
    /// Scheduler configuration (schedule expression, enabled state).
    daemon_config: SchedulerConfig,
    /// Scan execution runner.
    daemon_runner: Arc<ScanRunner>,
    /// The task running [`run_schedule`], created during start.
    daemon_scheduler: Option<JoinHandle<()>>,
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

    /// Runs one scheduled scan.
    ///
    /// An associated function with no `&self`, because each scan runs as a
    /// task of its own and has to own everything it uses.
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
    /// Reads the configured cron expression and spawns [`run_schedule`] with
    /// a scan as its job. It then waits for SIGTERM or SIGINT. If the
    /// schedule task ends first, the wait ends with it. Either way this
    /// returns once any scan in progress has finished. `stop` cannot be called
    /// while this runs, since this holds `&mut self`.
    ///
    /// # Arguments
    /// * `plugin_manager` - Configured plugin manager with resolved dependencies
    /// * `ctx` - Execution context for plugins
    ///
    /// # Errors
    /// Returns an error before anything is spawned when the scheduler is
    /// disabled in the configuration or the cron expression cannot be read.
    /// Returns an error after the wait when the schedule task panicked.
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
            "Starting daemon with schedule '{}' in UTC",
            self.daemon_config.schedule
        );

        let schedule = Schedule::parse(&self.daemon_config.schedule)?;

        // Clone Arc references for the scan closure
        let runner = self.daemon_runner.clone();
        let scan_flag = self.daemon_scan_in_progress.clone();
        let on_due = move || {
            Self::execute_scan(
                runner.clone(),
                plugin_manager.clone(),
                ctx.clone(),
                scan_flag.clone(),
            )
        };

        // Set up shutdown channel. The loop subscribes before it is spawned,
        // so a shutdown sent from here on reaches it.
        let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);
        let schedule_shutdown = shutdown_tx.subscribe();
        self.daemon_shutdown_tx = Some(shutdown_tx.clone());

        // Spawn signal handler
        tokio::spawn(Self::signal_handler(shutdown_tx));

        self.daemon_scheduler = Some(tokio::spawn(run_schedule(
            schedule,
            time::now,
            schedule_shutdown,
            on_due,
        )));

        info!("Daemon running, waiting for shutdown signal");

        self.wait_then_shut_down(shutdown_rx).await
    }

    /// The wait at the end of [`start`](Self::start), followed by the
    /// shutdown, which receives the wait's result. It is a method of its own
    /// so a test can hand it a schedule task that panics while the shutdown
    /// sender stays alive.
    async fn wait_then_shut_down(&mut self, shutdown: broadcast::Receiver<()>) -> Result<()> {
        let ended = wait_for_shutdown(shutdown, &mut self.daemon_scheduler).await;
        if ended.is_ok() {
            info!("Shutdown signal received");
        }
        self.shutdown_scheduler(ended).await
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
    /// Signals shutdown and waits for the schedule task to end. Then it waits
    /// for any scan in progress to finish.
    ///
    /// # Errors
    /// Returns an error if the schedule task panicked.
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stop requested");
        self.shutdown_scheduler(Ok(())).await
    }

    /// Internal helper to shutdown the scheduler and wait for scans.
    ///
    /// `start` sets the sender and the task together and this takes both, so
    /// a task is never left waiting for a shutdown nobody can send. The task
    /// ends before the wait for a scan, so it cannot start one the wait has
    /// already passed. `joined` is how the task ended if the caller has
    /// already awaited it and emptied the slot. Otherwise it is `Ok(())`.
    async fn shutdown_scheduler(
        &mut self,
        joined: std::result::Result<(), JoinError>,
    ) -> Result<()> {
        if let Some(sender) = self.daemon_shutdown_tx.take() {
            let _ = sender.send(());
        }
        let ended = match self.daemon_scheduler.take() {
            Some(task) => task.await,
            None => joined,
        };

        // Wait for in-progress scan to complete
        while self.daemon_scan_in_progress.load(Ordering::SeqCst) {
            debug!("Waiting for in-progress scan to complete...");
            tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
        }

        ended.map_err(|failure| {
            error!("The schedule task failed: {failure}");
            HardeningError::State(format!("The schedule task failed: {failure}"))
        })?;

        info!("Daemon stopped gracefully");
        Ok(())
    }
}

/// The wait in [`Daemon::start`]: for a shutdown, or for the task in `slot`
/// to end, whichever comes first.
///
/// A shutdown leaves the handle in `slot`, for the shutdown helper to await.
/// A task that ends first has a finished handle, which must not be awaited
/// again. So the slot is emptied and the task's own result is returned.
///
/// A normal shutdown ends the task as well, so both arms can be ready at
/// once. Either answer is then a clean end, because the task ends by itself
/// only on a shutdown or a panic. With an empty slot only a shutdown ends the
/// wait.
async fn wait_for_shutdown(
    mut shutdown: broadcast::Receiver<()>,
    slot: &mut Option<JoinHandle<()>>,
) -> std::result::Result<(), JoinError> {
    let Some(task) = slot.as_mut() else {
        let _ = shutdown.recv().await;
        return Ok(());
    };
    let ended = tokio::select! {
        _ = shutdown.recv() => return Ok(()),
        ended = task => ended,
    };
    *slot = None;
    ended
}

/// Runs `on_due` at each occurrence until `shutdown` fires.
///
/// The wait reads `clock` again after each sleep of at most
/// [`LONGEST_WAIT_STEP`](crate::schedule::LONGEST_WAIT_STEP), because a tokio
/// sleep stops while the machine is suspended. A firing missed during a
/// suspend runs once on resume, and the next one is then found from the later
/// of the clock and the instant just run. So a clock set back never brings an
/// instant round twice, and missed firings never queue up. Any outcome of
/// `shutdown.recv` ends the wait, a lagged or closed channel included.
async fn run_schedule<Clock, Due, Fut>(
    schedule: Schedule,
    clock: Clock,
    mut shutdown: broadcast::Receiver<()>,
    on_due: Due,
) where
    Clock: Fn() -> Timestamp,
    Due: Fn() -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut due = schedule.next_after(clock());
    while let Some(instant) = due {
        match wait_step(clock(), instant) {
            // Shutdown wins when both arms are ready, so a waiting shutdown
            // is never passed over for one more scan.
            Some(step) => tokio::select! {
                biased;
                _ = shutdown.recv() => return,
                () = tokio::time::sleep(step) => {}
            },
            None => {
                tokio::spawn(on_due());
                due = schedule.next_after(clock().max(instant));
            }
        }
    }
    warn!("The schedule has no next firing, so no scan runs until the daemon stops");
    let _ = shutdown.recv().await;
}

#[cfg(test)]
mod tests;
