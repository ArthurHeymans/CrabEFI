//! Fail-closed validation of the SCT StandardTest summary format.
use anyhow::{Context, Result, ensure};
use std::collections::{BTreeMap, BTreeSet};

pub(crate) const SMOKE_SEQUENCE: &str = include_str!("../../../ci/sct/smoke.seq");

/// The same sequence controls both SCT dispatch and fail-closed validation.
pub(crate) struct Sequence {
    pub text: String,
    pub names: Vec<String>,
}

impl Sequence {
    pub fn parse(text: &str) -> Result<Self> {
        let mut sections = text.split("[Test Case]");
        ensure!(
            sections.next().unwrap().lines().all(|line| {
                let line = line.trim();
                line.is_empty() || line.starts_with('#') || line.starts_with(';')
            }),
            "unexpected SCT sequence preamble"
        );
        let mut guids = BTreeSet::new();
        let names = sections
            .enumerate()
            .map(|(index, section)| {
                let mut fields = BTreeMap::new();
                for line in section.lines().map(str::trim).filter(|line| {
                    !line.is_empty() && !line.starts_with('#') && !line.starts_with(';')
                }) {
                    let (key, value) =
                        line.split_once('=').context("invalid SCT sequence field")?;
                    ensure!(
                        fields.insert(key.trim(), value.trim()).is_none(),
                        "duplicate SCT field"
                    );
                }
                ensure!(
                    fields.len() == 5,
                    "each SCT case requires exactly five fields"
                );
                let field = |name| {
                    fields
                        .get(name)
                        .copied()
                        .context("missing SCT sequence field")
                };
                let number = |name| -> Result<u64> {
                    let value = field(name)?;
                    Ok(if let Some(hex) = value.strip_prefix("0x") {
                        u64::from_str_radix(hex, 16)?
                    } else {
                        value.parse()?
                    })
                };
                ensure!(
                    number("Revision")? == 0x10000,
                    "unsupported SCT sequence revision"
                );
                ensure!(
                    number("Order")? == index as u64,
                    "SCT cases must have consecutive orders"
                );
                ensure!(
                    number("Iterations")? == 1,
                    "SCT cases must run exactly once"
                );
                let guid = field("Guid")?;
                ensure!(
                    guid.len() == 36
                        && guid.bytes().enumerate().all(|(i, byte)| {
                            if [8, 13, 18, 23].contains(&i) {
                                byte == b'-'
                            } else {
                                byte.is_ascii_hexdigit()
                            }
                        }),
                    "invalid SCT test GUID"
                );
                ensure!(
                    guids.insert(guid.to_ascii_lowercase()),
                    "duplicate SCT test GUID"
                );
                let name = field("Name")?;
                ensure!(
                    !name.is_empty()
                        && name
                            .bytes()
                            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
                    "invalid SCT test name"
                );
                Ok(name.to_owned())
            })
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !names.is_empty(),
            "SCT sequence must select at least one case"
        );
        ensure!(
            names.iter().collect::<BTreeSet<_>>().len() == names.len(),
            "duplicate SCT test name"
        );
        Ok(Self {
            text: text.to_owned(),
            names,
        })
    }
}

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

/// Check the framework's dispatch records, including every protocol instance.
fn dispatched_instances(serial: &str, sequence: &Sequence) -> Result<BTreeMap<String, usize>> {
    let mut pending = None;
    let mut progress: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    for line in serial.lines().map(str::trim) {
        let dispatch = [
            "Generic services test:",
            "Boot services test:",
            "Runtime services test:",
            "Protocol test:",
        ]
        .iter()
        .find_map(|prefix| {
            line.strip_prefix(prefix)
                .map(|name| (name.trim(), *prefix == "Protocol test:"))
        });
        if let Some((name, protocol)) = dispatch {
            ensure!(pending.is_none(), "incomplete SCT dispatch record");
            ensure!(
                sequence.names.iter().any(|selected| selected == name),
                "unexpected SCT case {name}"
            );
            pending = Some((name, protocol, None));
        } else if let Some(value) = line.strip_prefix("Instances:") {
            let (_, protocol, instances) =
                pending.as_mut().context("SCT instance without a case")?;
            ensure!(
                *protocol && instances.is_none(),
                "unexpected SCT instance record"
            );
            let (index, total) = value
                .trim()
                .split_once('/')
                .context("malformed SCT instance record")?;
            *instances = Some((index.parse::<usize>()?, total.parse::<usize>()?));
        } else if let Some(value) = line.strip_prefix("Iterations:") {
            let (name, protocol, instances) =
                pending.take().context("SCT iteration without a case")?;
            ensure!(value.trim() == "1/1", "unexpected SCT iteration count");
            let (index, total) = if protocol {
                instances.context("missing SCT instance count")?
            } else {
                (1, 1)
            };
            let (seen, declared) = progress.entry(name).or_insert((0, total));
            ensure!(
                total > 0 && total == *declared && index == *seen + 1 && index <= total,
                "duplicate or incomplete SCT instance for {name}"
            );
            *seen += 1;
        }
    }
    ensure!(pending.is_none(), "truncated SCT dispatch record");
    sequence
        .names
        .iter()
        .map(|name| {
            let (seen, total) = progress
                .get(name.as_str())
                .context("SCT case was not dispatched")?;
            ensure!(seen == total, "{name}: missing protocol instances");
            Ok((name.clone(), *total))
        })
        .collect()
}

pub(super) fn validate(serial: &str, summary: &str, sequence: &Sequence) -> Result<usize> {
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
    let instances = dispatched_instances(&serial[start..done], sequence)?;
    let lines: Vec<_> = summary.lines().map(str::trim).collect();
    for line in &lines {
        if let Some((name, status)) = line.split_once(':') {
            if status.trim().starts_with('[') {
                ensure!(
                    instances.contains_key(name.trim()),
                    "unexpected SCT result {name}"
                );
            }
        }
    }
    for name in &sequence.names {
        let results: Vec<_> = lines
            .iter()
            .enumerate()
            .filter_map(|(index, line)| {
                let (reported, status) = line.split_once(':')?;
                (reported.trim() == name).then_some((index, status.trim()))
            })
            .collect();
        ensure!(
            results.len() == instances[name],
            "{name}: expected {} terminal SCT results, found {}",
            instances[name],
            results.len()
        );
        for (index, status) in results {
            ensure!(status == "[PASSED]", "{name}: {status}");
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
    }
    Ok(instances.values().sum())
}

#[cfg(test)]
mod tests {
    use super::*;
    const SERIAL: &str = concat!(
        "CRABEFI_SCT_SMOKE_START\n",
        "Boot services test: Stall_Func\nIterations: 1/1\n",
        "Boot services test: CopyMem_Func\nIterations: 1/1\n",
        "Boot services test: SetMem_Func\nIterations: 1/1\n",
        "Boot services test: CalculateCrc32_Func\nIterations: 1/1\n",
        "Boot services test: AllocatePool_Conf\nIterations: 1/1\n",
        "Boot services test: FreePool_Conf\nIterations: 1/1\n",
        "Done!\nCRABEFI_SCT_SMOKE_DONE\n",
    );
    fn validate(serial: &str, summary: &str) -> Result<()> {
        super::validate(serial, summary, &Sequence::parse(SMOKE_SEQUENCE)?).map(|_| ())
    }
    fn summary() -> String {
        Sequence::parse(SMOKE_SEQUENCE).unwrap().names.iter().map(|name| format!(
            "{name}\nReturned Status Code: Success\n{name}: [PASSED]\n  Passes........... 12\n  Warnings......... 0\n  Errors........... 0\n"
        )).collect()
    }
    #[test]
    fn checked_in_sequences_are_well_formed() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../ci/sct");
        for directory in [&root, &root.join("characterization")] {
            for entry in std::fs::read_dir(directory).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_some_and(|extension| extension == "seq") {
                    let text = std::fs::read_to_string(&path).unwrap();
                    Sequence::parse(&text).unwrap_or_else(|error| {
                        panic!("{}: {error}", path.display());
                    });
                }
            }
        }
    }

    #[test]
    fn sequence_is_the_validation_manifest() {
        let sequence = Sequence::parse(SMOKE_SEQUENCE).unwrap();
        assert_eq!(sequence.names.len(), 6);
        for bad in [
            String::new(),
            SMOKE_SEQUENCE.replace("Iterations = 0x00000001", "Iterations = 0x00000002"),
            SMOKE_SEQUENCE.replace("Order      = 0x00000005", "Order      = 0x00000004"),
            SMOKE_SEQUENCE.replace("FreePool_Conf", "AllocatePool_Conf"),
            SMOKE_SEQUENCE.replace(
                "Guid       = 49709F9F-A4D8-42D6-A684-4975EE0099DB",
                "Guid       = not-a-guid",
            ),
            SMOKE_SEQUENCE.replace(
                "49709F9F-A4D8-42D6-A684-4975EE0099DB",
                "90023546-6c92-430a-b253-70110d9efdff",
            ),
            format!("{SMOKE_SEQUENCE}\nUnknown = field\n"),
        ] {
            assert!(Sequence::parse(&bad).is_err(), "accepted {bad}");
        }
        let short = SMOKE_SEQUENCE.split("\n\n").next().unwrap();
        let short = Sequence::parse(short).unwrap();
        let serial = "CRABEFI_SCT_SMOKE_START\nProtocol test: Stall_Func\nInstances: 1/2\nIterations: 1/1\nProtocol test: Stall_Func\nInstances: 2/2\nIterations: 1/1\nDone!\nCRABEFI_SCT_SMOKE_DONE";
        let one = summary().split("CopyMem_Func\n").next().unwrap().to_owned();
        assert_eq!(
            super::validate(serial, &format!("{one}{one}"), &short).unwrap(),
            2
        );
        for bad in [
            serial.replace("2/2", "1/2"),
            serial.replace("2/2", "2/3"),
            serial.replace("Iterations: 1/1", "Iterations: 1/2"),
        ] {
            assert!(super::validate(&bad, &format!("{one}{one}"), &short).is_err());
        }
        assert!(super::validate(serial, &one, &short).is_err());
        assert!(super::validate(serial, &format!("{one}{one}{one}"), &short).is_err());
        assert!(super::validate(serial, "Other_Func: [PASSED]", &short).is_err());
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
            Sequence::parse(SMOKE_SEQUENCE).unwrap().names.join("\n"),
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
