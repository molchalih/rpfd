//! The bound a test puts on one wait on the daemon, and the watchdog that ends
//! the wait rather than the test binary. Shared by both frontends' tests.

use std::{
    io::Write as _,
    process::{Child, ExitStatus},
};

/// How long anything waits on a served process before the wait is a failure,
/// where the work being waited for does not set its own bound.
pub const PATIENCE: std::time::Duration = std::time::Duration::from_secs(60);

/// How long a fired deadline gives the wait it unstuck to report itself before
/// it ends the process instead.
const GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// How often [`Deadline::reap`] asks a handed-over process whether it has gone.
const POLL: std::time::Duration = std::time::Duration::from_millis(10);

/// A bound on one wait, naming what the wait is for. [`Deadline::check`] fails
/// a loop that returns; the watchdog unsticks a wait blocked inside a read.
pub struct Deadline {
    what: &'static str,
    patience: std::time::Duration,
    started: std::time::Instant,
    met: std::sync::Arc<std::sync::atomic::AtomicBool>,
    child: std::sync::Arc<std::sync::Mutex<Option<Child>>>,
}

impl Deadline {
    /// A deadline of [`PATIENCE`] on waiting for `what`.
    pub fn on(what: &'static str) -> Self {
        Self::within(what, PATIENCE)
    }

    /// A deadline of `patience` on waiting for `what`.
    pub fn within(what: &'static str, patience: std::time::Duration) -> Self {
        let met = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let child = std::sync::Arc::new(std::sync::Mutex::new(None));
        let watching = std::sync::Arc::clone(&met);
        let watched = std::sync::Arc::clone(&child);
        // One clock for the watchdog and for `check`, so a wait the watchdog has
        // given up on cannot find its own budget unspent.
        let started = std::time::Instant::now();
        std::thread::spawn(move || {
            while !watching.load(std::sync::atomic::Ordering::Relaxed) {
                if started.elapsed() >= patience {
                    Self::give_up(what, patience, &watching, &watched);
                    return;
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });
        Self {
            what,
            patience,
            started,
            met,
            child,
        }
    }

    /// Says what was waited for, ends the process the wait is on, and ends this
    /// process if that did not release the wait within [`GRACE`].
    fn give_up(
        what: &str,
        patience: std::time::Duration,
        watching: &std::sync::atomic::AtomicBool,
        watched: &std::sync::Mutex<Option<Child>>,
    ) {
        // Straight at the descriptor: the harness captures what the print macros
        // write and drops it when the process ends this way.
        let said = format!("waited {patience:?} for {what}, and it never arrived\n");
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(said.as_bytes());
        let _ = stderr.flush();
        // Killing the served process ends the read or the write the test is
        // blocked in, so the test itself reports the timeout and the other tests
        // keep their results — and nothing is left scanning under `ppid 1`.
        if let Ok(mut held) = watched.lock()
            && let Some(child) = held.as_mut()
        {
            let _ = child.kill();
        }
        let released = std::time::Instant::now();
        while released.elapsed() < GRACE {
            if watching.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        // A wait no kill released cannot be reported from here: a panic on this
        // thread fails no test.
        std::process::abort();
    }

    /// Hands the process the wait is on to the deadline, to be killed if it
    /// fires. Hand it over before the first write to it: a wait blocked on a
    /// full pipe is one the deadline can only unstick if it holds the process.
    pub fn watching(&self, child: Child) {
        *self.child.lock().expect("the deadline is usable") = Some(child);
    }

    /// The process id of the process handed over by [`Deadline::watching`],
    /// while the deadline still holds it.
    pub fn pid(&self) -> Option<u32> {
        self.child
            .lock()
            .expect("the deadline is usable")
            .as_ref()
            .map(Child::id)
    }

    /// Waits for the process handed over by [`Deadline::watching`], if any, and
    /// answers how it ended. The process stays in the deadline's hands
    /// throughout, so a wait on one that lingers is still one the deadline can
    /// end.
    pub fn reap(&self) -> Option<ExitStatus> {
        loop {
            let mut held = self.child.lock().expect("the deadline is usable");
            let child = held.as_mut()?;
            match child.try_wait() {
                Ok(Some(status)) => {
                    *held = None;
                    return Some(status);
                }
                Err(_) => {
                    *held = None;
                    return None;
                }
                Ok(None) => drop(held),
            }
            std::thread::sleep(POLL);
        }
    }

    /// Fails, naming what was being waited for, once the patience is spent.
    #[track_caller]
    pub fn check(&self) {
        assert!(
            self.started.elapsed() < self.patience,
            "waited {:?} for {}, and it never arrived",
            self.patience,
            self.what
        );
    }
}

impl Drop for Deadline {
    fn drop(&mut self) {
        self.met.store(true, std::sync::atomic::Ordering::Relaxed);
        let taken = self.child.lock().map(|mut held| held.take());
        if let Ok(Some(mut child)) = taken {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
