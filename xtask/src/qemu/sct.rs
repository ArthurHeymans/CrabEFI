//! Fail-closed validation of the SCT StandardTest summary format.
use anyhow::{Context, Result, bail, ensure};

const TESTS: [&str; 6] = [
    "Stall_Func",
    "CopyMem_Func",
    "SetMem_Func",
    "CalculateCrc32_Func",
    "AllocatePool_Conf",
    "FreePool_Conf",
];

fn count(line: &str, label: &str) -> Result<u64> {
    let value = line
        .trim()
        .strip_prefix(label)
        .context("missing SCT assertion counter")?;
    ensure!(value.starts_with('.'), "malformed SCT assertion counter");
    value
        .trim_start_matches('.')
        .trim()
        .parse()
        .context("invalid SCT assertion count")
}

pub(super) fn validate(serial: &str, summary: &str) -> Result<()> {
    let start = serial
        .find("CRABEFI_SCT_SMOKE_START")
        .context("SCT start marker missing")?;
    let done = serial
        .find("CRABEFI_SCT_SMOKE_DONE")
        .context("SCT completion marker missing")?;
    ensure!(start < done, "SCT completion preceded its start");
    ensure!(
        serial.contains("Done!"),
        "SCT did not report command completion"
    );
    for text in [serial, summary] {
        for marker in [
            "CRABEFI_SCT_SMOKE_NOT_FOUND",
            "ERROR: Cannot",
            "Invalid command line",
            "FAILURE",
            "-- FAIL",
            "[FAILED]",
            "[NOT SUPPORTED]",
            "[PASSED WITH WARNINGS]",
        ] {
            ensure!(!text.contains(marker), "SCT failure marker: {marker}");
        }
        // Counters are decimal, not a fixed list of single-digit failures.
        for line in text.lines().map(str::trim) {
            if line.starts_with("Errors.") {
                ensure!(count(line, "Errors")? == 0, "SCT reported assertion errors");
            }
            if let Some(value) = line.strip_prefix("Failures:") {
                ensure!(value.trim().parse::<u64>()? == 0, "SCT reported failures");
            }
            if let Some(value) = line.strip_prefix("Returned Status Code:") {
                ensure!(value.trim() == "Success", "SCT returned {value}");
            }
        }
    }
    let lines: Vec<_> = summary.lines().map(str::trim).collect();
    for name in TESTS {
        let prefix = format!("{name}:");
        let results: Vec<_> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.starts_with(&prefix))
            .collect();
        let [(index, status)] = results.as_slice() else {
            bail!("{name}: expected exactly one terminal SCT result");
        };
        ensure!(
            status.strip_prefix(&prefix).map(str::trim) == Some("[PASSED]"),
            "{name}: {status}"
        );
        let counters = lines
            .get(index + 1..index + 4)
            .context("truncated SCT result counters")?;
        ensure!(
            count(counters[0], "Passes")? > 0,
            "{name}: no assertions passed"
        );
        ensure!(
            count(counters[1], "Warnings")? == 0,
            "{name}: assertion warnings"
        );
        ensure!(
            count(counters[2], "Errors")? == 0,
            "{name}: assertion errors"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    const SERIAL: &str = "CRABEFI_SCT_SMOKE_START\nDone!\nCRABEFI_SCT_SMOKE_DONE\n";
    fn summary() -> String {
        TESTS.iter().map(|name| format!(
            "{name}\nReturned Status Code: Success\n{name}: [PASSED]\n  Passes........... 12\n  Warnings......... 0\n  Errors........... 0\n"
        )).collect()
    }
    #[test]
    fn requires_explicit_success_and_complete_zero_error_counters() {
        let good = summary();
        validate(SERIAL, &good).unwrap();
        validate(SERIAL, &good.replace('\n', "\r\n")).unwrap();
        for bad in [
            good.replace("[PASSED]", "[FAILED]"),
            good.replace("Errors........... 0", "Errors........... 10"),
            good.replace("Errors........... 0", "Errors........... unknown"),
            good.replace("Warnings......... 0", "Warnings......... 1"),
            good.replace("Passes........... 12", "Passes........... 0"),
            good.replace("FreePool_Conf:", "Other_Conf:"),
            good.replace(
                "Returned Status Code: Success",
                "Returned Status Code: Device Error",
            ),
            TESTS.join("\n"),
            format!("{good}\nStall_Func: [PASSED]\n"),
            format!("{good}\nassertion -- FAIL\n"),
            format!("{good}\nFailures: 123\n"),
            good[..good.len() - 6].to_owned(),
            String::new(),
        ] {
            assert!(validate(SERIAL, &bad).is_err(), "accepted: {bad}");
        }
        for bad in [
            "CRABEFI_SCT_SMOKE_START\nDone!",
            "CRABEFI_SCT_SMOKE_DONE\nDone!\nCRABEFI_SCT_SMOKE_START",
            "CRABEFI_SCT_SMOKE_START\nCRABEFI_SCT_SMOKE_DONE",
            "",
        ] {
            assert!(validate(bad, &good).is_err());
        }
        assert!(validate(&format!("{SERIAL}\nassertion -- FAIL"), &good).is_err());
    }
}
