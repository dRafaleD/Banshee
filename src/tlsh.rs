//! TLSH, the locality-sensitive hash by Trend Micro. Digests use the
//! reference implementation's default layout (128 buckets, 1-byte checksum,
//! `T1` prefix), so they match `tlsh.hash()` and can be compared with
//! digests from other tools. Lower distances mean more similar inputs.

use anyhow::{Context, Result, bail};

/// Inputs shorter than this have no digest, as in the reference.
pub const MIN_BYTES: usize = 50;
const BUCKETS: usize = 128;
const CODE_BYTES: usize = BUCKETS / 4;
const DIGEST_HEX: usize = 2 * (3 + CODE_BYTES);

// Tables from the reference implementation (tlsh_impl.cpp, tlsh_util.cpp).
const PEARSON: [u8; 256] = [
    1, 87, 49, 12, 176, 178, 102, 166, 121, 193, 6, 84, 249, 230, 44, 163, 14, 197, 213, 181, 161,
    85, 218, 80, 64, 239, 24, 226, 236, 142, 38, 200, 110, 177, 104, 103, 141, 253, 255, 50, 77,
    101, 81, 18, 45, 96, 31, 222, 25, 107, 190, 70, 86, 237, 240, 34, 72, 242, 20, 214, 244, 227,
    149, 235, 97, 234, 57, 22, 60, 250, 82, 175, 208, 5, 127, 199, 111, 62, 135, 248, 174, 169,
    211, 58, 66, 154, 106, 195, 245, 171, 17, 187, 182, 179, 0, 243, 132, 56, 148, 75, 128, 133,
    158, 100, 130, 126, 91, 13, 153, 246, 216, 219, 119, 68, 223, 78, 83, 88, 201, 99, 122, 11, 92,
    32, 136, 114, 52, 10, 138, 30, 48, 183, 156, 35, 61, 26, 143, 74, 251, 94, 129, 162, 63, 152,
    170, 7, 115, 167, 241, 206, 3, 150, 55, 59, 151, 220, 90, 53, 23, 131, 125, 173, 15, 238, 79,
    95, 89, 16, 105, 137, 225, 224, 217, 160, 37, 123, 118, 73, 2, 157, 46, 116, 9, 145, 134, 228,
    207, 212, 202, 215, 69, 229, 27, 188, 67, 124, 168, 252, 42, 4, 29, 108, 21, 247, 19, 205, 39,
    203, 233, 40, 186, 147, 198, 192, 155, 33, 164, 191, 98, 204, 165, 180, 117, 76, 140, 36, 210,
    172, 41, 54, 159, 8, 185, 232, 113, 196, 231, 47, 146, 120, 51, 65, 28, 144, 254, 221, 93, 189,
    194, 139, 112, 43, 71, 109, 184, 209,
];

const LENGTH_BOUNDS: [u32; 170] = [
    1, 2, 3, 5, 7, 11, 17, 25, 38, 57, 86, 129, 194, 291, 437, 656, 854, 1110, 1443, 1876, 2439,
    3171, 3475, 3823, 4205, 4626, 5088, 5597, 6157, 6772, 7450, 8195, 9014, 9916, 10907, 11998,
    13198, 14518, 15970, 17567, 19323, 21256, 23382, 25720, 28292, 31121, 34233, 37656, 41422,
    45564, 50121, 55133, 60646, 66711, 73382, 80721, 88793, 97672, 107439, 118183, 130002, 143002,
    157302, 173032, 190335, 209369, 230306, 253337, 278670, 306538, 337191, 370911, 408002, 448802,
    493682, 543050, 597356, 657091, 722800, 795081, 874589, 962048, 1058252, 1164078, 1280486,
    1408534, 1549388, 1704327, 1874759, 2062236, 2268459, 2495305, 2744836, 3019320, 3321252,
    3653374, 4018711, 4420582, 4862641, 5348905, 5883796, 6472176, 7119394, 7831333, 8614467,
    9475909, 10423501, 11465851, 12612437, 13873681, 15261050, 16787154, 18465870, 20312458,
    22343706, 24578077, 27035886, 29739474, 32713425, 35984770, 39583245, 43541573, 47895730,
    52685306, 57953837, 63749221, 70124148, 77136564, 84850228, 93335252, 102668779, 112935659,
    124229227, 136652151, 150317384, 165349128, 181884040, 200072456, 220079703, 242087671,
    266296456, 292926096, 322218735, 354440623, 389884688, 428873168, 471760495, 518936559,
    570830240, 627913311, 690704607, 759775136, 835752671, 919327967, 1011260767, 1112386880,
    1223623232, 1345985727, 1480584256, 1628642751, 1791507135, 1970657856, 2167723648, 2384496256,
    2622945920, 2885240448, 3173764736, 3491141248, 3840255616, 4224281216,
];

fn mapping(salt: u8, i: u8, j: u8, k: u8) -> usize {
    let mut hash = PEARSON[usize::from(salt)];
    hash = PEARSON[usize::from(hash ^ i)];
    hash = PEARSON[usize::from(hash ^ j)];
    usize::from(PEARSON[usize::from(hash ^ k)])
}

fn swap_nibbles(byte: u8) -> u8 {
    byte.rotate_left(4)
}

/// A parsed digest.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Digest {
    checksum: u8,
    length: u8,
    q1_ratio: u8,
    q2_ratio: u8,
    code: [u8; CODE_BYTES],
}

impl Digest {
    fn to_hex(&self) -> String {
        let mut bytes = vec![
            swap_nibbles(self.checksum),
            swap_nibbles(self.length),
            swap_nibbles(self.q1_ratio | (self.q2_ratio << 4)),
        ];
        bytes.extend(self.code.iter().rev());
        let hex: String = bytes.iter().map(|byte| format!("{byte:02X}")).collect();
        format!("T1{hex}")
    }

    fn parse(digest: &str) -> Result<Self> {
        let digest = digest.trim();
        let hex = digest
            .strip_prefix("T1")
            .or_else(|| digest.strip_prefix("t1"))
            .unwrap_or(digest);
        if hex.len() != DIGEST_HEX || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            bail!("expected a TLSH digest of {DIGEST_HEX} hex digits, optionally prefixed with T1");
        }
        let bytes = (0..hex.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&hex[index..index + 2], 16))
            .collect::<std::result::Result<Vec<u8>, _>>()
            .context("invalid hex in TLSH digest")?;
        let quartiles = swap_nibbles(bytes[2]);
        let mut code = [0; CODE_BYTES];
        for (index, byte) in bytes[3..].iter().rev().enumerate() {
            code[index] = *byte;
        }
        Ok(Self {
            checksum: swap_nibbles(bytes[0]),
            length: swap_nibbles(bytes[1]),
            q1_ratio: quartiles & 0x0F,
            q2_ratio: quartiles >> 4,
            code,
        })
    }
}

/// TLSH digest of `data`, or `None` when the input is shorter than
/// [`MIN_BYTES`] or too uniform for a meaningful digest.
pub fn tlsh(data: &[u8]) -> Option<String> {
    if data.len() < MIN_BYTES || u32::try_from(data.len()).is_err() {
        return None;
    }
    let mut buckets = [0_u32; 256];
    let mut checksum = 0_u8;
    for window in data.windows(5) {
        let [a0, a1, a2, a3, a4] = [window[0], window[1], window[2], window[3], window[4]];
        checksum = mapping(0, a4, a3, checksum) as u8;
        buckets[mapping(2, a4, a3, a2)] += 1;
        buckets[mapping(3, a4, a3, a1)] += 1;
        buckets[mapping(5, a4, a2, a1)] += 1;
        buckets[mapping(7, a4, a2, a0)] += 1;
        buckets[mapping(11, a4, a3, a0)] += 1;
        buckets[mapping(13, a4, a1, a0)] += 1;
    }

    let mut sorted = buckets;
    sorted[..BUCKETS].sort_unstable();
    let (q1, q2, q3) = (sorted[31], sorted[63], sorted[95]);
    if q3 == 0
        || buckets[..BUCKETS]
            .iter()
            .filter(|count| **count > 0)
            .count()
            <= BUCKETS / 2
    {
        return None;
    }

    let mut code = [0_u8; CODE_BYTES];
    for (index, byte) in code.iter_mut().enumerate() {
        for (pair, count) in buckets[4 * index..4 * index + 4].iter().enumerate() {
            let level = if *count > q3 {
                3
            } else if *count > q2 {
                2
            } else {
                u8::from(*count > q1)
            };
            *byte |= level << (pair * 2);
        }
    }
    let length = data.len() as u32;
    let ratio = |quartile: u32| (u64::from(quartile) * 100 / u64::from(q3) % 16) as u8;
    Some(
        Digest {
            checksum,
            length: LENGTH_BOUNDS.partition_point(|bound| *bound < length) as u8,
            q1_ratio: ratio(q1),
            q2_ratio: ratio(q2),
            code,
        }
        .to_hex(),
    )
}

fn mod_diff(left: u8, right: u8, range: i32) -> i32 {
    let direct = (i32::from(left) - i32::from(right)).abs();
    direct.min(range - direct)
}

/// Distance between two TLSH digests, as the reference `diff()` with the
/// length term included. 0 means identical; values below about 100 usually
/// indicate closely related inputs.
pub fn distance(left: &str, right: &str) -> Result<u32> {
    let left = Digest::parse(left).context("left digest")?;
    let right = Digest::parse(right).context("right digest")?;
    let mut distance = match mod_diff(left.length, right.length, 256) {
        difference @ (0 | 1) => difference,
        difference => difference * 12,
    };
    for (a, b) in [
        (left.q1_ratio, right.q1_ratio),
        (left.q2_ratio, right.q2_ratio),
    ] {
        let difference = mod_diff(a, b, 16);
        distance += if difference <= 1 {
            difference
        } else {
            (difference - 1) * 12
        };
    }
    if left.checksum != right.checksum {
        distance += 1;
    }
    for (a, b) in left.code.iter().zip(&right.code) {
        for shift in (0..8).step_by(2) {
            let difference = (i32::from((a >> shift) & 3) - i32::from((b >> shift) & 3)).abs();
            distance += if difference == 3 { 6 } else { difference };
        }
    }
    Ok(distance as u32)
}

#[cfg(test)]
mod tests {
    use super::{MIN_BYTES, distance, tlsh};

    /// Deterministic pseudo-random bytes, so vectors need no fixture files.
    fn sample(length: usize, seed: u32) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                (state >> 16) as u8
            })
            .collect()
    }

    fn text() -> Vec<u8> {
        b"The quick brown fox jumps over the lazy dog. ".repeat(40)
    }

    // Expected values from py-tlsh 5.0.0 (`tlsh.hash`, `tlsh.diff`).
    #[test]
    fn matches_reference_digests() {
        let cases = [
            (
                sample(50, 1),
                "T1009002052505D5014106EAA908EC718951100296E20C122194101553C5501188780046",
            ),
            (
                sample(51, 2),
                "T1D0900288855905448D6255A3654D1025CA1108841A634551A2590DB615853080510888",
            ),
            (
                sample(256, 3),
                "T15ED02B429A258E4B6058A8B39170225D6C478B5DC19464B420ED486362169DCA74482C",
            ),
            (
                sample(1000, 4),
                "T18D11A545658BC03943434526AF0D2C8762043D8BBB957A68409A53699D9CDA87616389",
            ),
            (
                sample(5000, 5),
                "T134A17F08B317C999C194FC7A720D17A60592E7CFC49648C4B6AB4D46E70F7EDFA99380",
            ),
            (
                sample(70_000, 6),
                "T1E9630134AC2C36CBBD9A23AE477C1B843A0B4FC053F4D29CD49B2F6A377429991E5605",
            ),
            (
                text(),
                "T1A231024A311C1794658A1888438D95B2D2C9C910612114116570604219482359CD8551",
            ),
        ];
        for (data, expected) in cases {
            assert_eq!(
                tlsh(&data).as_deref(),
                Some(expected),
                "{} bytes",
                data.len()
            );
        }
    }

    #[test]
    fn matches_reference_distances() {
        let original = sample(5000, 5);
        let mut edited = original.clone();
        edited[100..200].copy_from_slice(&sample(100, 9));
        let edited = tlsh(&edited).unwrap();
        assert_eq!(
            edited,
            "T1EFA17F08B317C599C098EC69710D1AE60592E7CFC4964884BAAB4D85E70F7DDEA89340"
        );
        let original = tlsh(&original).unwrap();
        assert_eq!(distance(&original, &edited).unwrap(), 19);
        assert_eq!(
            distance(&original, &tlsh(&sample(1000, 4)).unwrap()).unwrap(),
            369
        );
        let text = text();
        let shorter = tlsh(&text[..text.len() - 300]).unwrap();
        assert_eq!(distance(&tlsh(&text).unwrap(), &shorter).unwrap(), 16);
        assert_eq!(distance(&original, &original).unwrap(), 0);
        // The prefix is optional and case does not matter.
        assert_eq!(
            distance(&original[2..].to_lowercase(), &original).unwrap(),
            0
        );
    }

    #[test]
    fn short_or_uniform_input_has_no_digest_and_bad_digests_fail() {
        assert_eq!(tlsh(&sample(MIN_BYTES - 1, 1)), None);
        assert_eq!(tlsh(&[b'a'; 100]), None);
        assert!(distance("T1ABC", "T1ABC").is_err());
        assert!(distance(&"Z".repeat(72), &"Z".repeat(72)).is_err());
    }
}
