#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 256 * 1024 {
        return;
    }
    let single = banshee::cert::inspect_bytes(data);
    if let Ok(chain) = banshee::cert::inspect_chain_bytes(data) {
        assert!(!chain.certificates.is_empty());
        assert!(chain.certificates.len() <= 64);
        assert_eq!(chain.links.len(), chain.certificates.len() - 1);
        assert!(single.is_ok());
    }
});
