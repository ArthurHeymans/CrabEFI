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
use core::task::{Context, Poll};

pub use embassy_futures::block_on;
pub use embassy_futures::join::join;
pub use embassy_futures::yield_now;

use crate::time::Timeout;

/// A heap-allocated future, for heterogeneous or recursive async calls.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

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
