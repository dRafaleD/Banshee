#![no_main]

use libfuzzer_sys::fuzz_target;

// The first newline separates the recipe expression from its input bytes.
fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let split = data
        .iter()
        .position(|byte| *byte == b'\n')
        .unwrap_or(data.len());
    let Ok(recipe) = std::str::from_utf8(&data[..split]) else {
        return;
    };
    let input = data.get(split + 1..).unwrap_or_default().to_vec();
    if let Ok(result) = banshee::recipe::run(recipe, input) {
        assert!(result.report.steps.len() <= 32);
        assert_eq!(result.report.final_bytes, result.output.len());
    }
});
