//! What an accept error means for the socket door's loop (ledger #720).
//!
//! The twin of `ikigai-web`'s `accept` module, which carries the full table, the reasoning,
//! and what was matched against axum. In short: one connection's failure is skipped,
//! exhaustion (`EMFILE`, `ENFILE`, `ENOBUFS`, `ENOMEM`, and anything unrecognized) is backed
//! off from 10ms to 1s and retried with the episode logged once, and only a dead listener
//! (`EBADF`, `ENOTSOCK`, `EINVAL`, `EFAULT`) ends [`serve`](crate::serve). This loop is
//! synchronous, so the wait is a thread sleep. ⚠ Change both tables or neither.
//!
//! One addition the HTTP door does not need: this loop spawns an OS thread per connection,
//! and a failed spawn (`EAGAIN`, out of threads) is the same kind of exhaustion, so it is
//! backed off the same way rather than panicking the accept loop as `thread::spawn` would.

use std::io;
use std::time::Duration;

/// The first wait after an exhaustion error.
pub(crate) const BACKOFF_FLOOR: Duration = Duration::from_millis(10);
/// The longest wait between retries during one exhaustion episode.
pub(crate) const BACKOFF_CEILING: Duration = Duration::from_secs(1);

/// What the accept loop does about one error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Fault {
    /// One connection's problem: take the next connection at once.
    Skip,
    /// Out of a resource, or unrecognized: wait, then retry.
    BackOff,
    /// The listener cannot accept again: end the loop with this error.
    Fatal,
}

/// Classify one accept error.
pub(crate) fn classify(e: &io::Error) -> Fault {
    if let Some(code) = e.raw_os_error() {
        return match code {
            libc::EBADF | libc::ENOTSOCK | libc::EINVAL | libc::EFAULT => Fault::Fatal,
            libc::EMFILE | libc::ENFILE | libc::ENOBUFS | libc::ENOMEM => Fault::BackOff,
            libc::ECONNABORTED
            | libc::ECONNRESET
            | libc::ECONNREFUSED
            | libc::EINTR
            | libc::EAGAIN
            | libc::EPROTO
            | libc::EPERM
            | libc::ETIMEDOUT
            | libc::ENETDOWN
            | libc::ENETUNREACH
            | libc::EHOSTDOWN
            | libc::EHOSTUNREACH
            | libc::ENOPROTOOPT
            | libc::EOPNOTSUPP => Fault::Skip,
            _ => Fault::BackOff,
        };
    }
    match e.kind() {
        io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionRefused
        | io::ErrorKind::Interrupted
        | io::ErrorKind::WouldBlock => Fault::Skip,
        _ => Fault::BackOff,
    }
}

/// One exhaustion episode: the next wait, and what to say when it ends. Logs exactly twice
/// per episode — at its start and at the next successful accept.
#[derive(Debug, Default)]
pub(crate) struct Backoff {
    /// The next wait; `None` outside an episode.
    next: Option<Duration>,
    /// Failures in this episode.
    failures: u32,
    /// Total time waited in this episode (summed waits, not a clock reading).
    waited: Duration,
}

impl Backoff {
    /// Record an exhaustion error and return how long to wait before retrying.
    pub(crate) fn failed(&mut self, e: &io::Error) -> Duration {
        let wait = match self.next {
            None => {
                eprintln!(
                    "ikigai-ipc: accept failing ({e}); backing off up to {}ms and retrying",
                    BACKOFF_CEILING.as_millis()
                );
                BACKOFF_FLOOR
            }
            Some(wait) => wait,
        };
        self.next = Some((wait * 2).min(BACKOFF_CEILING));
        self.failures += 1;
        self.waited += wait;
        wait
    }

    /// Record a connection handed to its thread, closing the episode if one was open.
    pub(crate) fn succeeded(&mut self) {
        if self.next.take().is_some() {
            eprintln!(
                "ikigai-ipc: accept recovered after {} failed attempts (~{}ms backed off)",
                self.failures,
                self.waited.as_millis()
            );
            self.failures = 0;
            self.waited = Duration::ZERO;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhaustion_backs_off_a_dead_listener_is_fatal_one_connection_is_skipped() {
        let os = io::Error::from_raw_os_error;
        for code in [libc::EMFILE, libc::ENFILE, libc::ENOBUFS, libc::ENOMEM] {
            assert_eq!(classify(&os(code)), Fault::BackOff, "errno {code}");
        }
        for code in [libc::EBADF, libc::ENOTSOCK, libc::EINVAL, libc::EFAULT] {
            assert_eq!(classify(&os(code)), Fault::Fatal, "errno {code}");
        }
        for code in [
            libc::ECONNABORTED,
            libc::ECONNRESET,
            libc::EPROTO,
            libc::EINTR,
        ] {
            assert_eq!(classify(&os(code)), Fault::Skip, "errno {code}");
        }
        assert_eq!(classify(&os(libc::EIO)), Fault::BackOff);
    }

    #[test]
    fn the_backoff_doubles_from_the_floor_to_the_ceiling_and_resets_on_success() {
        let e = io::Error::other("exhausted");
        let mut backoff = Backoff::default();
        let waits: Vec<u128> = (0..10).map(|_| backoff.failed(&e).as_millis()).collect();
        assert_eq!(waits, [10, 20, 40, 80, 160, 320, 640, 1000, 1000, 1000]);
        backoff.succeeded();
        assert_eq!(
            backoff.failed(&e),
            BACKOFF_FLOOR,
            "a new episode starts at the floor"
        );
    }
}
