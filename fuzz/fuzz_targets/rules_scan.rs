#![no_main]

use libfuzzer_sys::fuzz_target;

// The first 0x00 byte separates TOML rule source from scanned content.
fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let split = data
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(data.len());
    let Ok(source) = std::str::from_utf8(&data[..split]) else {
        return;
    };
    let input = data.get(split + 1..).unwrap_or_default();
    let Ok(validation) = banshee::rules::validate_source(source) else {
        return;
    };
    let report = banshee::rules::scan_source(source, input).expect("validated rules scan");
    assert_eq!(report.rules_loaded, validation.rule_count);
    assert!(report.matched_rules <= report.rules_loaded);
    assert_eq!(report.input_bytes, input.len());
});
