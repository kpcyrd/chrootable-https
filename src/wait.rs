// Copied from reqwest/src/wait.rs
// (c) Sean McArthur <sean@seanmonstar.com>
// Published as MIT/Apache-2.0

use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use futures::{Async, Future};
use futures::executor::{self, Notify};


pub fn timeout<F>(fut: F, timeout: Option<Duration>) -> Result<F::Item, Waited<F::Error>>
where F: Future {
    if let Some(dur) = timeout {
        let start = Instant::now();
        let deadline = start + dur;
        let mut task = executor::spawn(fut);
        let notify = Arc::new(ThreadNotify {
            thread: thread::current(),
        });

        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(Waited::TimedOut);
            }
            match task.poll_future_notify(&notify, 0)? {
                Async::Ready(val) => return Ok(val),
                Async::NotReady => {
                    thread::park_timeout(deadline - now);
                }
            }
        }
    } else {
        fut.wait().map_err(From::from)
    }
}

#[derive(Debug)]
pub enum Waited<E> {
    TimedOut,
    Err(E),
}

impl<E> From<E> for Waited<E> {
    fn from(err: E) -> Waited<E> {
        Waited::Err(err)
    }
}

struct ThreadNotify {
    thread: thread::Thread,
}

impl Notify for ThreadNotify {
    fn notify(&self, _id: usize) {
        self.thread.unpark();
    }
}
