//! Cooperative async for overlapping hardware waits.
//!
//! Boot-time device bring-up is dominated by fixed delays and polling loops
//! (port power-on, resets, link training, controller ready bits). Drivers
//! express those waits as futures so that independent controllers and ports
//! wait concurrently instead of back-to-back.
//!
//! There are no interrupts and no wakers: [`block_on`] busy-polls the
//! top-level future and every pending leaf re-checks its condition when
//! polled. This is the same spinning the synchronous helpers in
//! [`crate::time`] do, just interleaved.
//!
//! Rules for async driver code:
//! - Never hold a lock (spin `Mutex`, `LocalCell` borrow, ...) across an
//!   `.await`: another task polled in the meantime would deadlock on it.
//! - Hardware sequences that must not interleave with other tasks (e.g. a
//!   PCI config address/data pair) must not contain an `.await`.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

pub use embassy_futures::block_on;
pub use embassy_futures::join::join;
pub use embassy_futures::yield_now;

use crate::cell::{Local, LocalCell};
use crate::time::Timeout;

/// A heap-allocated future, for heterogeneous or recursive async calls.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

static BACKGROUND: Background = Background::new();

/// Schedule a future to be polled from firmware idle loops.
pub fn spawn(task: impl Future<Output = ()> + 'static) {
    BACKGROUND.spawn(task);
}

/// Poll each existing background task once, without waiting for any of them.
/// Calls made from a background task are ignored.
pub fn poll_background() {
    BACKGROUND.poll();
}

/// Permanently stop background work, retaining task storage for OS handoff.
pub(crate) fn stop_background() {
    BACKGROUND.stopped.set(true);
}

struct Background {
    tasks: Local<Vec<Option<BoxFuture<'static, ()>>>>,
    polling: LocalCell<bool>,
    stopped: LocalCell<bool>,
}

impl Background {
    const fn new() -> Self {
        Self {
            tasks: Local::new(Vec::new()),
            polling: LocalCell::new(false),
            stopped: LocalCell::new(false),
        }
    }

    fn spawn(&self, task: impl Future<Output = ()> + 'static) {
        if !self.stopped.get() {
            self.tasks.borrow_mut().push(Some(Box::pin(task)));
        }
    }

    fn poll(&self) {
        if self.polling.get() || self.stopped.get() {
            return;
        }
        let _polling = self.polling.scoped_set(true);
        let mut cx = Context::from_waker(Waker::noop());
        let len = self.tasks.borrow().len();
        for i in 0..len {
            if self.stopped.get() {
                return;
            }
            // Poll without a borrow so a task can spawn another task.
            let task = self.tasks.borrow_mut()[i].take();
            let Some(mut task) = task else { continue };
            let result = task.as_mut().poll(&mut cx);
            if result.is_pending() || self.stopped.get() {
                self.tasks.borrow_mut()[i] = Some(task);
            }
            if self.stopped.get() {
                return;
            }
        }
        if !self.stopped.get() {
            self.tasks.borrow_mut().retain(Option::is_some);
        }
    }
}

/// Wait at least `us` microseconds, letting other tasks run meanwhile.
pub async fn sleep_us(us: u64) {
    let timeout = Timeout::from_us(us);
    while !timeout.is_expired() {
        yield_now().await;
    }
}

/// Wait at least `ms` milliseconds, letting other tasks run meanwhile.
pub async fn sleep_ms(ms: u64) {
    sleep_us(ms * 1000).await;
}

/// Async counterpart of [`crate::time::wait_for`].
///
/// Returns `true` as soon as `condition()` holds, `false` once `timeout_ms`
/// expired without it holding. The condition is checked one final time after
/// expiry so a slow poll interleaving cannot turn success into a timeout.
pub async fn wait_for(timeout_ms: u64, mut condition: impl FnMut() -> bool) -> bool {
    let timeout = Timeout::from_ms(timeout_ms);
    loop {
        if condition() {
            return true;
        }
        if timeout.is_expired() {
            return condition();
        }
        yield_now().await;
    }
}

/// Run all futures concurrently and return their outputs in input order.
pub async fn join_all<'a, T>(futures: Vec<BoxFuture<'a, T>>) -> Vec<T> {
    JoinAll {
        slots: futures.into_iter().map(Slot::Pending).collect(),
    }
    .await
}

enum Slot<'a, T> {
    Pending(BoxFuture<'a, T>),
    Done(Option<T>),
}

struct JoinAll<'a, T> {
    slots: Vec<Slot<'a, T>>,
}

// Outputs are never pinned: they are only moved in once their future is done.
impl<T> Unpin for JoinAll<'_, T> {}

impl<T> Future for JoinAll<'_, T> {
    type Output = Vec<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Vec<T>> {
        let this = self.get_mut();
        let mut all_done = true;
        for slot in this.slots.iter_mut() {
            if let Slot::Pending(future) = slot {
                match future.as_mut().poll(cx) {
                    Poll::Ready(value) => *slot = Slot::Done(Some(value)),
                    Poll::Pending => all_done = false,
                }
            }
        }
        if !all_done {
            return Poll::Pending;
        }
        Poll::Ready(
            this.slots
                .iter_mut()
                .map(|slot| match slot {
                    Slot::Done(value) => value.take().expect("join_all output taken once"),
                    Slot::Pending(_) => unreachable!("all slots are done"),
                })
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn background_poll_is_not_reentrant() {
        let background = alloc::rc::Rc::new(Background::new());
        let polled = alloc::rc::Rc::new(LocalCell::new(false));
        let nested = background.clone();
        let next = polled.clone();
        background.spawn(async move {
            nested.spawn(async move { next.set(true) });
            nested.poll();
        });
        background.poll();
        assert!(!polled.get());
        background.poll();
        assert!(polled.get());
    }

    #[test]
    fn background_drops_finished_tasks() {
        struct RecordDrop(alloc::rc::Rc<LocalCell<bool>>);
        impl Future for RecordDrop {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
                Poll::Ready(())
            }
        }
        impl Drop for RecordDrop {
            fn drop(&mut self) {
                self.0.set(true);
            }
        }
        let background = Background::new();
        let dropped = alloc::rc::Rc::new(LocalCell::new(false));
        background.spawn(RecordDrop(dropped.clone()));
        assert!(!dropped.get());
        background.poll();
        assert!(dropped.get());
        assert!(background.tasks.borrow().is_empty());
    }

    #[test]
    fn background_stop_retains_task_storage_without_polling() {
        let background = Background::new();
        let captured = alloc::rc::Rc::new(());
        let task_capture = captured.clone();
        background.spawn(async move {
            yield_now().await;
            drop(task_capture);
        });
        background.stopped.set(true);
        background.poll();
        background.poll();
        assert_eq!(alloc::rc::Rc::strong_count(&captured), 2);
        assert_eq!(background.tasks.borrow().len(), 1);
    }

    #[test]
    fn join_all_preserves_order() {
        let futures: Vec<BoxFuture<'_, u32>> = (0..4u32)
            .rev()
            .map(|n| {
                Box::pin(async move {
                    // Later inputs finish first.
                    for _ in 0..n {
                        yield_now().await;
                    }
                    n
                }) as BoxFuture<'_, u32>
            })
            .collect();
        assert_eq!(block_on(join_all(futures)), vec![3, 2, 1, 0]);
    }
}
