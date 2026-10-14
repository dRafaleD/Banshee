#![no_main]

use banshee::codec::{Codec, decode, encode_bytes};
use clap::ValueEnum;
use libfuzzer_sys::fuzz_target;

const BINARY_SAFE: &[Codec] = &[
    Codec::Base64,
    Codec::Base64url,
    Codec::Base32,
    Codec::Base85,
    Codec::Hex,
    Codec::Binary,
    Codec::Octal,
];

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    for codec in BINARY_SAFE {
        let encoded = encode_bytes(data, *codec).expect("binary-safe codec encodes bytes");
        let decoded = decode(&encoded, *codec).expect("encoded output decodes");
        assert_eq!(decoded, data, "{codec:?} round trip");
    }
    if let Ok(text) = std::str::from_utf8(data) {
        for codec in Codec::value_variants() {
            let _ = decode(text, *codec);
        }
    }
});
