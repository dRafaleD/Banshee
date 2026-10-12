#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(report) = banshee::jwt::inspect(token) {
        assert!(report.header.is_object());
        assert!(report.payload.is_object());
        assert!(!report.signature.verified);
    }
});
