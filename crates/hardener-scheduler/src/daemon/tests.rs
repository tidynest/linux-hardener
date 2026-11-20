#![cfg(test)]
//
// The module declaration that pulls this file in is already gated, so this
// inner attribute changes nothing about what is compiled. It is here so the
// file says what it is on its own terms: several validators decide test
// context by looking for `cfg(test)` in the file they are reading, and a test
// module that moved out of its source file would otherwise be judged as
// production code by every one of them.

//! Unit tests for [`daemon`](super).
//!
//! Split out of `daemon.rs`. This file sits in the `daemon/` directory beside
//! it, which the 2018 path rules allow with no `mod.rs` and no `#[path]`,
//! so `super` still resolves to `crate::daemon` and every import carried
//! across unchanged, private items included.

use super::*;
use std::sync::atomic::{AtomicI64, AtomicUsize};
use std::time::Duration;
use tempfile::tempdir;
use tokio::{task::JoinHandle, time::timeout};

/// Helper to create test infrastructure.
async fn setup_test_daemon() -> (Daemon, tempfile::TempDir) {
    let dir = tempdir().unwrap();
    let db = Arc::new(
        ScanHistoryManager::new(&dir.path().join("test.db"))
            .await
            .unwrap(),
    );
    let json_store = Arc::new(JsonStore::new(dir.path()).await.unwrap());
    let config = SchedulerConfig::default();

    (Daemon::new(config, db, json_store), dir)
}

#[tokio::test]
async fn new_creates_daemon_with_defaults() {
    let (daemon, _dir) = setup_test_daemon().await;

    assert!(!daemon.daemon_config.enabled);
    assert!(daemon.daemon_scheduler.is_none());
    assert!(daemon.daemon_shutdown_tx.is_none());
    assert!(!daemon.daemon_scan_in_progress.load(Ordering::SeqCst));
}

#[tokio::test]
async fn start_fails_when_disabled() {
    let (mut daemon, _dir) = setup_test_daemon().await;

    let registry = hardener_core::PluginRegistry::new();
    let pm = Arc::new(PluginManager::new(registry));
    let ctx = Arc::new(Context::new());

    let result = daemon.start(pm, ctx).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("disabled"));
}

#[tokio::test]
async fn run_once_rejects_concurrent_scans() {
    let (daemon, _dir) = setup_test_daemon().await;

    // Simulate a scan in progress
    daemon.daemon_scan_in_progress.store(true, Ordering::SeqCst);

    let registry = hardener_core::PluginRegistry::new();
    let pm = PluginManager::new(registry);
    let ctx = Context::new();

    let result = daemon.run_once(&pm, &ctx, TriggerType::Manual).await;

    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.to_string().contains("already in progress"));
}

#[test]
fn scan_in_progress_flag_is_atomic() {
    let flag = Arc::new(AtomicBool::new(false));
    let flag_clone = flag.clone();

    // First swap should succeed (false -> true, returns false)
    assert!(!flag.swap(true, Ordering::SeqCst));

    // Second swap should indicate already set (true -> true, returns true)
    assert!(flag_clone.swap(true, Ordering::SeqCst));

    // Reset
    flag.store(false, Ordering::SeqCst);
    assert!(!flag.load(Ordering::SeqCst));
}

#[tokio::test]
async fn start_refuses_a_schedule_it_cannot_read() {
    let (mut daemon, _dir) = setup_test_daemon().await;
    daemon.daemon_config.enabled = true;
    daemon.daemon_config.schedule = "not a schedule".into();
    let plugins = Arc::new(PluginManager::new(hardener_core::PluginRegistry::new()));
    let context = Arc::new(Context::new());

    let result = timeout(Duration::from_secs(5), daemon.start(plugins, context))
        .await
        .expect("start returns without waiting for a shutdown");

    let error = result.expect_err("an unreadable schedule is refused");
    assert!(
        error.to_string().contains("Invalid cron expression"),
        "{error}"
    );
}

/// Polls the history every 100 ms until it holds a session with the
/// scheduled trigger.
async fn a_scheduled_session_appears(history: &ScanHistoryManager) {
    let scheduled = TriggerType::Scheduled.as_str();
    loop {
        let sessions = history
            .list_sessions(&crate::db::SessionFilter::default())
            .await
            .unwrap();
        if sessions
            .iter()
            .any(|session| session.trigger_type == scheduled)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// `start` with the scheduler on and a schedule that fires every second
/// writes a scheduled session to the history database.
///
/// `start` runs until a shutdown, so it races a poll of the history that has
/// a deadline of 15 seconds. Once the race ends, `stop` shuts the loop down
/// and waits for a running scan, so the scans are done before the temporary
/// directory goes. The signal handler `start` spawned waits on until the
/// test's runtime drops it. Its hooks for SIGTERM and SIGINT stay installed
/// in the test process, as tokio never removes one.
///
/// The registry holds one mock plugin, because a scan refuses a manager with
/// no resolved plugin before it writes a session. `ScanRunner::run` loads the
/// on-disk configuration, which can only filter that plugin out of the scan.
/// The session row is written either way, and the test reads nothing but its
/// trigger.
#[tokio::test]
async fn start_runs_a_scheduled_scan_through_its_own_loop() {
    let (mut daemon, dir) = setup_test_daemon().await;
    daemon.daemon_config.enabled = true;
    daemon.daemon_config.schedule = "* * * * * *".into();
    let registry = hardener_core::PluginRegistry::new();
    registry
        .register(Box::new(hardener_core::testing::MockPlugin::new("probe")))
        .unwrap();
    let mut manager = PluginManager::new(registry);
    manager.resolve_dependencies().unwrap();
    let plugins = Arc::new(manager);
    let context = Arc::new(Context::new());
    let history = ScanHistoryManager::new(&dir.path().join("test.db"))
        .await
        .unwrap();

    let found = tokio::select! {
        outcome = daemon.start(plugins, context) => panic!("start ended by itself: {outcome:?}"),
        found = timeout(Duration::from_secs(15), a_scheduled_session_appears(&history)) => found.is_ok(),
    };
    // Only `start` leaving its wait empties the slot, and nothing has sent a
    // shutdown, so an empty slot means the loop ended or panicked.
    let still_waiting = daemon.daemon_scheduler.is_some();
    let stopped = timeout(Duration::from_secs(15), daemon.stop())
        .await
        .expect("stop returns once the loop and any scan have ended");

    assert!(found, "no scheduled session within 15 seconds");
    assert!(still_waiting, "start left its wait before the race ended");
    assert!(stopped.is_ok(), "{stopped:?}");
}

/// A schedule task that panics as soon as it runs.
fn task_that_panics() -> JoinHandle<()> {
    tokio::spawn(async { panic!("the schedule task fails") })
}

#[tokio::test]
async fn stop_reports_a_schedule_task_that_panicked() {
    let (mut daemon, _dir) = setup_test_daemon().await;
    daemon.daemon_scheduler = Some(task_that_panics());

    let result = timeout(Duration::from_secs(5), daemon.stop())
        .await
        .expect("stop returns with no shutdown sender to send on");

    assert!(result.is_err(), "a panic is not a clean stop");
}

/// The end of `start` with a schedule task that panics. The sender stays
/// alive, so only the task can end the wait, and its failure has to come out.
#[tokio::test]
async fn the_end_of_start_reports_a_schedule_task_that_panicked() {
    let (mut daemon, _dir) = setup_test_daemon().await;
    let (_sender, receiver) = broadcast::channel(1);
    daemon.daemon_scheduler = Some(task_that_panics());

    let result = timeout(Duration::from_secs(5), daemon.wait_then_shut_down(receiver))
        .await
        .expect("a panicked task ends the wait");

    assert!(result.is_err(), "a panic is not a clean stop");
}

/// With the slot already emptied by the wait, the shutdown passes on the
/// failure it is given, as there is no handle left to learn it from.
#[tokio::test]
async fn shutdown_passes_on_a_failure_the_wait_already_took() {
    let (mut daemon, _dir) = setup_test_daemon().await;
    let failure = task_that_panics()
        .await
        .expect_err("the schedule task panics");

    let result = timeout(
        Duration::from_secs(5),
        daemon.shutdown_scheduler(Err(failure)),
    )
    .await
    .expect("an empty slot leaves nothing to wait for");

    assert!(result.is_err(), "a panic is not a clean stop");
}

#[tokio::test]
async fn the_wait_in_start_ends_when_the_schedule_task_panics() {
    // The sender stays alive, so only the task can end the wait.
    let (_sender, receiver) = broadcast::channel(1);
    let mut slot = Some(task_that_panics());

    let ended = timeout(
        Duration::from_secs(5),
        wait_for_shutdown(receiver, &mut slot),
    )
    .await
    .expect("a panicked task ends the wait");

    assert!(
        matches!(&ended, Err(failure) if failure.is_panic()),
        "{ended:?}"
    );
    assert!(
        slot.is_none(),
        "a finished handle is left to be awaited again"
    );
}

/// A task that ends when `sender` sends, as the schedule loop does.
fn task_ending_on(sender: &broadcast::Sender<()>) -> JoinHandle<()> {
    let mut shutdown = sender.subscribe();
    tokio::spawn(async move {
        let _ = shutdown.recv().await;
    })
}

/// A normal shutdown ends the task too, so `start` may see either arm first.
/// Each order is set up here so that only one arm is ready.
#[tokio::test]
async fn a_normal_shutdown_ends_the_wait_in_start_cleanly_in_either_order() {
    // The shutdown is seen first: the task has not run when the wait begins,
    // and the handle stays in the slot for the shutdown helper to await.
    let (sender, receiver) = broadcast::channel(1);
    let mut slot = Some(task_ending_on(&sender));
    sender.send(()).unwrap();
    let shutdown_first = timeout(
        Duration::from_secs(5),
        wait_for_shutdown(receiver, &mut slot),
    )
    .await
    .expect("a shutdown ends the wait");
    assert!(shutdown_first.is_ok(), "{shutdown_first:?}");
    let task = slot.take().expect("a shutdown leaves the handle in place");
    assert!(task.await.is_ok());

    // The task is seen first: it ended before the wait began, and the wait's
    // receiver subscribed after the send, so it holds no message.
    let (sender, _) = broadcast::channel(1);
    let mut slot = Some(task_ending_on(&sender));
    sender.send(()).unwrap();
    let task_first = timeout(Duration::from_secs(5), async {
        while slot.as_ref().is_some_and(|task| !task.is_finished()) {
            tokio::task::yield_now().await;
        }
        wait_for_shutdown(sender.subscribe(), &mut slot).await
    })
    .await
    .expect("a finished task ends the wait");
    assert!(task_first.is_ok(), "{task_first:?}");
    assert!(
        slot.is_none(),
        "a finished handle is left to be awaited again"
    );
}

/// 2026-01-01T01:00:00Z.
const NEW_YEAR_AT_ONE: i64 = 1_767_229_200;
/// 2026-01-01T02:00:00Z, the first firing of the default schedule after `NEW_YEAR_AT_ONE`.
const NEW_YEAR_AT_TWO: i64 = 1_767_232_800;
/// The default schedule, 02:00 UTC daily.
const DAILY_AT_TWO: &str = "0 0 2 * * *";

/// More clock reads than any test here needs. A loop that spins reaches it
/// and panics, so the test fails where it would otherwise hang.
const READ_LIMIT: usize = 100;

/// A `run_schedule` task on a clock the test sets by hand, in Unix seconds.
struct ScheduleLoop {
    clock: Arc<AtomicI64>,
    reads: Arc<AtomicUsize>,
    calls: Arc<AtomicUsize>,
    shutdown: broadcast::Sender<()>,
    task: JoinHandle<()>,
}

impl ScheduleLoop {
    fn start(expression: &str, seconds: i64) -> Self {
        Self::start_with(expression, seconds, |_| {})
    }

    /// As [`start`](Self::start), with `on_call` run at each call before the
    /// loop reads the clock again.
    ///
    /// Pauses tokio time first, so a sleep in the test moves it on without
    /// waiting. Pausing here rather than with `start_paused` keeps the plain
    /// `#[tokio::test]` attribute, the one the repository's test counters and
    /// assertion check match.
    fn start_with(
        expression: &str,
        seconds: i64,
        on_call: impl Fn(&AtomicI64) + Send + 'static,
    ) -> Self {
        tokio::time::pause();
        let clock = Arc::new(AtomicI64::new(seconds));
        let reads = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(AtomicUsize::new(0));
        let (shutdown, receiver) = broadcast::channel(1);
        let read_clock = {
            let (clock, reads) = (clock.clone(), reads.clone());
            move || {
                let read = reads.fetch_add(1, Ordering::SeqCst);
                assert!(read < READ_LIMIT, "the loop spins");
                time::from_unix_seconds(clock.load(Ordering::SeqCst)).unwrap()
            }
        };
        let on_due = {
            let (clock, calls) = (clock.clone(), calls.clone());
            move || {
                on_call(&clock);
                let calls = calls.clone();
                async move {
                    calls.fetch_add(1, Ordering::SeqCst);
                }
            }
        };
        let schedule = Schedule::parse(expression).unwrap();
        let task = tokio::spawn(run_schedule(schedule, read_clock, receiver, on_due));
        Self {
            clock,
            reads,
            calls,
            shutdown,
            task,
        }
    }

    fn set_clock(&self, seconds: i64) {
        self.clock.store(seconds, Ordering::SeqCst);
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn reads(&self) -> usize {
        self.reads.load(Ordering::SeqCst)
    }

    /// Sends shutdown and gives the task a second of tokio time to end. The
    /// paused clock moves on by itself once every task waits, so a task that
    /// misses the shutdown fails the timeout and does not hang the run.
    async fn stop(self) {
        let _ = self.shutdown.send(());
        timeout(Duration::from_secs(1), self.task)
            .await
            .expect("the loop ends on shutdown")
            .expect("the loop does not panic");
    }
}

/// Lets `seconds` of tokio time pass, running every timer due on the way.
async fn pass(seconds: u64) {
    tokio::time::sleep(Duration::from_secs(seconds)).await;
}

#[tokio::test]
async fn the_job_runs_once_when_its_instant_arrives() {
    let schedule = ScheduleLoop::start(DAILY_AT_TWO, NEW_YEAR_AT_TWO - 10);
    pass(30).await;
    assert_eq!(schedule.calls(), 0, "the wall clock has not reached 02:00");

    schedule.set_clock(NEW_YEAR_AT_TWO);
    pass(30).await;
    assert_eq!(schedule.calls(), 1);
    schedule.stop().await;
}

#[tokio::test]
async fn a_tick_missed_during_a_suspend_runs_once() {
    let schedule = ScheduleLoop::start("0 0 * * * *", NEW_YEAR_AT_ONE);
    pass(1).await;

    // Four hourly firings fall inside the suspend, and tokio time does not
    // count it.
    schedule.set_clock(NEW_YEAR_AT_ONE + 4 * 3600);
    pass(30).await;
    assert_eq!(schedule.calls(), 1);
    pass(60).await;
    assert_eq!(schedule.calls(), 1, "no missed firing is made up later");
    schedule.stop().await;
}

#[tokio::test]
async fn a_schedule_with_no_next_instant_idles_until_shutdown() {
    let schedule = ScheduleLoop::start("0 0 0 30 2 *", NEW_YEAR_AT_ONE);
    pass(1).await;
    let reads = schedule.reads();

    pass(3600).await;
    assert_eq!(schedule.calls(), 0);
    assert_eq!(
        schedule.reads(),
        reads,
        "an idle loop leaves the clock alone"
    );
    schedule.stop().await;
}

#[tokio::test]
async fn shutdown_ends_the_wait() {
    let schedule = ScheduleLoop::start(DAILY_AT_TWO, NEW_YEAR_AT_TWO - 10);
    pass(1).await;

    let calls = schedule.calls.clone();
    schedule.stop().await;
    assert_eq!(calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn a_clock_set_backwards_delays_the_job_and_does_not_repeat_it() {
    let schedule = ScheduleLoop::start(DAILY_AT_TWO, NEW_YEAR_AT_TWO - 10);
    pass(1).await;

    schedule.set_clock(NEW_YEAR_AT_ONE);
    pass(60).await;
    assert_eq!(schedule.calls(), 0, "02:00 has not come round yet");

    schedule.set_clock(NEW_YEAR_AT_TWO);
    pass(30).await;
    assert_eq!(schedule.calls(), 1);
    pass(60).await;
    assert_eq!(schedule.calls(), 1);
    schedule.stop().await;
}

#[tokio::test]
async fn a_clock_set_back_after_a_firing_does_not_repeat_it() {
    // A step back of one second as the job starts, as NTP can make, lands
    // before the loop reads the clock for the next firing.
    let schedule = ScheduleLoop::start_with(DAILY_AT_TWO, NEW_YEAR_AT_TWO - 10, |clock| {
        clock.store(NEW_YEAR_AT_TWO - 1, Ordering::SeqCst);
    });
    pass(5).await;

    schedule.set_clock(NEW_YEAR_AT_TWO);
    pass(10).await;
    assert_eq!(schedule.calls(), 1);

    schedule.set_clock(NEW_YEAR_AT_TWO + 30);
    pass(60).await;
    assert_eq!(schedule.calls(), 1, "02:00 ran once already");
    schedule.stop().await;
}
