#![no_main]

use banshee::analysis::Analyzer;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let analyzer = Analyzer::new(8);
    let report = analyzer.analyze_bytes(data);
    assert!(report.layers.len() <= 8);
    if let Ok(text) = std::str::from_utf8(data) {
        let report = analyzer.analyze(text);
        assert!(report.layers.len() <= 8);
    }
});
