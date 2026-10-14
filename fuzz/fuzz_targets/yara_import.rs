#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(source) = std::str::from_utf8(data) else {
        return;
    };
    // Every converted rule set must compile; skipped rules carry a reason.
    if let Ok(conversion) = banshee::rules::yara::import_source(source) {
        if conversion.converted > 0 {
            banshee::rules::validate_source(&conversion.output).expect("import output validates");
        }
        assert!(
            conversion
                .skipped
                .iter()
                .all(|rule| !rule.reason.is_empty())
        );
    }
});
