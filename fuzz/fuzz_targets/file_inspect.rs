#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 1024 * 1024 {
        return;
    }
    if let Ok(report) = banshee::file_inspect::inspect_bytes(data, "synthetic-fuzz".into(), 8) {
        assert_eq!(report.size, data.len());
        if let Some(archive) = report.archive {
            assert!(archive.entries.len() <= 8);
            assert!(archive.total_entries >= archive.entries.len());
        }
        if let Some(compression) = report.compression {
            assert!(compression.decompressed_bytes <= 64 * 1024 * 1024);
        }
        if let Some(executable) = report.executable {
            assert!(executable.section_details.len() <= 256);
            assert!(executable.imports.len() <= 256);
            assert!(
                executable
                    .imports
                    .iter()
                    .map(|library| library.symbols.len())
                    .sum::<usize>()
                    <= 4096
            );
            assert!(executable.exports.len() <= 4096);
            assert!(executable.needed_libraries.len() <= 4096);
        }
    }
});
