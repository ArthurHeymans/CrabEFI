//! SATA link debounce with a final stability check after delayed polling.

use core::future::Future;

pub(super) async fn debounce<F: Future<Output = ()>>(
    mut read_det: impl FnMut() -> u32,
    mut is_expired: impl FnMut() -> bool,
    mut sleep_ms: impl FnMut(u64) -> F,
) -> bool {
    loop {
        sleep_ms(5).await;
        let det = read_det();
        let expired = is_expired();
        // A sibling task may have consumed the deadline while this link
        // trained. Give an established link one final stability interval.
        if expired && det != 3 {
            return false;
        }
        if det != 1 {
            sleep_ms(100).await;
            if read_det() == det {
                return det == 3;
            }
        }
        // Do not retry an unstable link indefinitely after the deadline.
        if expired {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;
    use core::future::ready;

    fn delayed_poll(read_det: impl Fn(u64) -> u32) -> (bool, u64) {
        let now = Cell::new(0);
        let result = crate::exec::block_on(debounce(
            || read_det(now.get()),
            || now.get() >= 2000,
            |ms| {
                // The first stability wait is delayed by a synchronous
                // command in another controller's initialization task.
                let elapsed = if now.get() == 5 && ms == 100 {
                    3000
                } else {
                    ms
                };
                now.set(now.get() + elapsed);
                ready(())
            },
        ));
        (result, now.get())
    }

    #[test]
    fn accepts_link_that_trained_while_polling_was_delayed() {
        assert_eq!(delayed_poll(|ms| if ms < 50 { 0 } else { 3 }), (true, 3110));
    }

    #[test]
    fn rejects_link_that_changes_during_final_stability_check() {
        assert_eq!(
            delayed_poll(|ms| if (50..3100).contains(&ms) { 3 } else { 0 }),
            (false, 3110),
        );
    }

    #[test]
    fn times_out_while_link_is_still_training() {
        let now = Cell::new(0);
        assert!(!crate::exec::block_on(debounce(
            || 1,
            || now.get() >= 2000,
            |ms| {
                now.set(now.get() + ms);
                ready(())
            },
        )));
        assert_eq!(now.get(), 2000);
    }
}
