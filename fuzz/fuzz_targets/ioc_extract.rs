#![no_main]

use banshee::ioc::{ExtractOptions, IocKind, extract};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let options = ExtractOptions {
        context_lines: 2,
        max_matches: 512,
        max_locations: 8,
        ..ExtractOptions::default()
    };
    let max_context_chars = options.max_context_chars;
    let report = extract(text, options);
    assert!(report.total_occurrences <= 512);
    for ioc in &report.iocs {
        assert!(ioc.locations.len() <= 8);
        for location in &ioc.locations {
            for line in &location.context {
                assert!(line.text.chars().count() <= max_context_chars);
            }
        }
        // Secrets are redacted unless the caller explicitly opts in.
        if matches!(ioc.kind, IocKind::Secret | IocKind::PrivateKey) {
            assert!(ioc.redacted);
        }
    }
});
