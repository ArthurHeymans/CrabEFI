#!/usr/bin/env bash
# Run every Kani harness by exact name. A renamed or deleted harness fails
# here instead of silently dropping out of CI.
set -euo pipefail
cd "$(dirname "$0")/.."

harnesses=(
    crabefi-bounds:proofs::pages_cover_exactly_the_length
    crabefi-bounds:proofs::mask_admits_only_allocations_whose_last_byte_is_visible
    crabefi-bounds:proofs::dma_translation_maps_every_byte_into_the_window
    crabefi-bounds:proofs::subrange_is_half_open_and_inside_the_buffer
    crabefi-bounds:proofs::cache_maintenance_covers_the_buffer_and_at_most_one_extra_line_each_side
    crabefi-bounds:proofs::block_range_stays_inside_the_device
    crabefi-bounds:proofs::mmio_access_is_aligned_and_inside_the_region
    crabefi-bounds:proofs::mmio_region_is_nonempty_nonnull_and_does_not_wrap
    crabefi-memmap:proofs::descriptor_and_owner_splits_agree
    crabefi-memmap:proofs::owner_split_keeps_every_page_owned_once
    crabefi-memmap:proofs::exact_cover_requires_an_exact_tiling
)

for entry in "${harnesses[@]}"; do
    package=${entry%%:*}
    harness=${entry#*:}
    echo "::group::$package $harness"
    cargo kani -p "$package" --exact --harness "$harness" --output-format terse
    echo "::endgroup::"
done
