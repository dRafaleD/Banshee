//! ssdeep-compatible context-triggered piecewise hashing (CTPH).
//!
//! Follows the ssdeep 2.x `fuzzy.c` algorithm: a 7-byte rolling hash triggers
//! piece boundaries for a ladder of block sizes, each piece contributes one
//! Base64 character, and the digest is `block_size:digest:double_digest`.
//! Comparison scores 0-100 using ssdeep's weighted edit distance. Similarity is
//! an analyst signal for related samples, not proof of shared origin.

use anyhow::{Context, Result, bail};

const ROLLING_WINDOW: usize = 7;
const MIN_BLOCKSIZE: u32 = 3;
const HASH_PRIME: u32 = 0x0100_0193;
const HASH_INIT: u32 = 0x2802_1967;
const NUM_BLOCKHASHES: usize = 31;
const SPAMSUM_LENGTH: usize = 64;
const BASE64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const fn block_size(index: usize) -> u64 {
    (MIN_BLOCKSIZE as u64) << index
}

#[derive(Default)]
struct RollingHash {
    window: [u8; ROLLING_WINDOW],
    h1: u32,
    h2: u32,
    h3: u32,
    n: usize,
}

impl RollingHash {
    fn update(&mut self, byte: u8) {
        let value = u32::from(byte);
        self.h2 = self
            .h2
            .wrapping_sub(self.h1)
            .wrapping_add(ROLLING_WINDOW as u32 * value);
        self.h1 = self.h1.wrapping_add(value);
        let slot = self.n % ROLLING_WINDOW;
        self.h1 = self.h1.wrapping_sub(u32::from(self.window[slot]));
        self.window[slot] = byte;
        self.n = self.n.wrapping_add(1);
        self.h3 = (self.h3 << 5) ^ value;
    }

    fn sum(&self) -> u32 {
        self.h1.wrapping_add(self.h2).wrapping_add(self.h3)
    }
}

#[derive(Clone)]
struct BlockHash {
    h: u32,
    half_h: u32,
    digest: Vec<u8>,
    /// Character written past a full digest; emitted only when the final
    /// rolling hash is zero (ssdeep's `digest[dindex]`).
    tail: Option<u8>,
    /// Last half-length character while the digest is at least half full.
    half_digest: Option<u8>,
}

impl BlockHash {
    fn new(h: u32, half_h: u32) -> Self {
        Self {
            h,
            half_h,
            digest: Vec::with_capacity(SPAMSUM_LENGTH),
            tail: None,
            half_digest: None,
        }
    }
}

fn sum_hash(byte: u8, hash: u32) -> u32 {
    hash.wrapping_mul(HASH_PRIME) ^ u32::from(byte)
}

fn base64(hash: u32) -> u8 {
    BASE64[(hash % 64) as usize]
}

/// Computes the ssdeep digest of `data`, for example `3:hMCEpn:hcp`.
pub fn ssdeep(data: &[u8]) -> String {
    let total = data.len() as u64;
    let mut roll = RollingHash::default();
    let mut hashes = vec![BlockHash::new(HASH_INIT, HASH_INIT)];
    let mut start = 0;

    for &byte in data {
        roll.update(byte);
        let trigger = u64::from(roll.sum());
        for hash in &mut hashes[start..] {
            hash.h = sum_hash(byte, hash.h);
            hash.half_h = sum_hash(byte, hash.half_h);
        }
        let mut index = start;
        while index < hashes.len() {
            let size = block_size(index);
            if trigger % size != size - 1 {
                break;
            }
            // The first boundary at a block size starts the next larger one.
            if hashes[index].digest.is_empty() && hashes.len() < NUM_BLOCKHASHES {
                let last = hashes.last().expect("at least one block hash");
                let fork = BlockHash::new(last.h, last.half_h);
                hashes.push(fork);
            }
            let hash = &mut hashes[index];
            let character = base64(hash.h);
            hash.half_digest = Some(base64(hash.half_h));
            if hash.digest.len() < SPAMSUM_LENGTH - 1 {
                hash.digest.push(character);
                hash.h = HASH_INIT;
                if hash.digest.len() < SPAMSUM_LENGTH / 2 {
                    hash.half_h = HASH_INIT;
                    hash.half_digest = None;
                }
            } else {
                hash.tail = Some(character);
                // A full digest keeps its characters and stops resetting `h`, so
                // the tail folds into the final character emitted at the end.
                // Drop the smallest block size once a larger one is long enough.
                if hashes.len() - start >= 2
                    && block_size(start) * (SPAMSUM_LENGTH as u64) < total
                    && hashes[start + 1].digest.len() >= SPAMSUM_LENGTH / 2
                {
                    start += 1;
                }
            }
            index += 1;
        }
    }

    let trigger = roll.sum();
    let mut index = start;
    while block_size(index) * (SPAMSUM_LENGTH as u64) < total && index + 1 < NUM_BLOCKHASHES {
        index += 1;
    }
    while index >= hashes.len() {
        index -= 1;
    }
    while index > start && hashes[index].digest.len() < SPAMSUM_LENGTH / 2 {
        index -= 1;
    }

    let mut first = String::from_utf8(hashes[index].digest.clone()).expect("Base64 digest");
    let mut second = String::new();
    // A zero final rolling hash (for example after trailing zero bytes) uses
    // the stored characters instead of the running piece hashes.
    let first_tail = if trigger != 0 {
        Some(base64(hashes[index].h))
    } else {
        hashes[index].tail
    };
    first.extend(first_tail.map(char::from));
    if index + 1 < hashes.len() {
        let next = &hashes[index + 1];
        let length = next.digest.len().min(SPAMSUM_LENGTH / 2 - 1);
        second.push_str(std::str::from_utf8(&next.digest[..length]).expect("Base64 digest"));
        let second_tail = if trigger != 0 {
            Some(base64(next.half_h))
        } else {
            next.half_digest
        };
        second.extend(second_tail.map(char::from));
    } else if trigger != 0 && index == 0 {
        second.push(char::from(base64(hashes[0].h)));
    }
    format!("{}:{first}:{second}", block_size(index))
}

struct ParsedDigest<'a> {
    block_size: u64,
    first: Vec<u8>,
    second: Vec<u8>,
    raw: (&'a str, &'a str),
}

fn parse(digest: &str) -> Result<ParsedDigest<'_>> {
    let mut parts = digest.trim().splitn(3, ':');
    let (Some(size), Some(first), Some(second)) = (parts.next(), parts.next(), parts.next()) else {
        bail!("ssdeep digest must look like BLOCKSIZE:DIGEST:DIGEST");
    };
    // Some tools append `,"filename"`; it is not part of the digest.
    let second = second.split(',').next().unwrap_or_default();
    let block_size = size.parse::<u64>().context("invalid ssdeep block size")?;
    if block_size < u64::from(MIN_BLOCKSIZE)
        || first.len() > SPAMSUM_LENGTH
        || second.len() > SPAMSUM_LENGTH
        || !first
            .bytes()
            .chain(second.bytes())
            .all(|byte| BASE64.contains(&byte))
    {
        bail!("invalid ssdeep digest");
    }
    Ok(ParsedDigest {
        block_size,
        first: eliminate_sequences(first.as_bytes()),
        second: eliminate_sequences(second.as_bytes()),
        raw: (first, second),
    })
}

/// Collapses runs longer than three identical characters, as ssdeep does
/// before comparing.
fn eliminate_sequences(value: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(value.len());
    for (index, byte) in value.iter().enumerate() {
        if index < 3
            || *byte != value[index - 1]
            || *byte != value[index - 2]
            || *byte != value[index - 3]
        {
            output.push(*byte);
        }
    }
    output
}

fn has_common_substring(left: &[u8], right: &[u8]) -> bool {
    if left.len() < ROLLING_WINDOW || right.len() < ROLLING_WINDOW {
        return false;
    }
    left.windows(ROLLING_WINDOW)
        .any(|window| right.windows(ROLLING_WINDOW).any(|other| other == window))
}

/// Edit distance with insertion and deletion cost 1 and substitution cost 2.
fn edit_distance(left: &[u8], right: &[u8]) -> u64 {
    let mut previous = (0..=right.len() as u64).collect::<Vec<_>>();
    let mut current = vec![0_u64; right.len() + 1];
    for (row, left_byte) in left.iter().enumerate() {
        current[0] = row as u64 + 1;
        for (column, right_byte) in right.iter().enumerate() {
            let substitution = previous[column] + if left_byte == right_byte { 0 } else { 2 };
            current[column + 1] = substitution
                .min(previous[column + 1] + 1)
                .min(current[column] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }
    previous[right.len()]
}

fn score_strings(left: &[u8], right: &[u8], block_size: u64) -> u64 {
    if left.len() > SPAMSUM_LENGTH || right.len() > SPAMSUM_LENGTH {
        return 0;
    }
    if !has_common_substring(left, right) {
        return 0;
    }
    let distance = edit_distance(left, right);
    let scaled = distance * SPAMSUM_LENGTH as u64 / (left.len() + right.len()) as u64;
    let scaled = 100 * scaled / SPAMSUM_LENGTH as u64;
    if scaled >= 100 {
        return 0;
    }
    let score = 100 - scaled;
    let cap_threshold =
        (99 + ROLLING_WINDOW as u64) / ROLLING_WINDOW as u64 * u64::from(MIN_BLOCKSIZE);
    if block_size >= cap_threshold {
        return score;
    }
    // Small block sizes cannot support high scores for short digests.
    let cap = block_size / u64::from(MIN_BLOCKSIZE) * left.len().min(right.len()) as u64;
    score.min(cap)
}

/// Compares two ssdeep digests and returns a 0-100 similarity score.
pub fn compare(left: &str, right: &str) -> Result<u8> {
    let left = parse(left).context("left digest")?;
    let right = parse(right).context("right digest")?;
    let (small, large) = (
        left.block_size.min(right.block_size),
        left.block_size.max(right.block_size),
    );
    if large != small && large != small * 2 {
        return Ok(0);
    }
    if left.block_size == right.block_size && left.raw == right.raw {
        return Ok(100);
    }
    let score = if left.block_size == right.block_size {
        score_strings(&left.first, &right.first, left.block_size).max(score_strings(
            &left.second,
            &right.second,
            left.block_size * 2,
        ))
    } else if left.block_size == right.block_size * 2 {
        score_strings(&left.first, &right.second, left.block_size)
    } else {
        score_strings(&left.second, &right.first, right.block_size)
    };
    Ok(score.min(100) as u8)
}

#[cfg(test)]
mod tests {
    use super::{compare, eliminate_sequences, ssdeep};

    fn sample(seed: u64, length: usize) -> Vec<u8> {
        let mut state = seed;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                b"abcdefghij klmnopqrstuvwxyz\n0123456789"[(state % 38) as usize]
            })
            .collect()
    }

    #[test]
    fn small_and_empty_inputs_use_the_minimum_block_size() {
        assert_eq!(ssdeep(b""), "3::");
        assert!(ssdeep(b"abc").starts_with("3:"));
    }

    #[test]
    fn identical_inputs_score_100_and_unrelated_inputs_score_0() {
        let left = ssdeep(&sample(1, 40_000));
        assert_eq!(compare(&left, &left).expect("compare"), 100);
        let unrelated = ssdeep(&sample(2, 40_000));
        assert_eq!(compare(&left, &unrelated).expect("compare"), 0);
    }

    #[test]
    fn small_edits_keep_a_high_similarity() {
        let original = sample(3, 60_000);
        let mut edited = original.clone();
        edited.splice(30_000..30_010, b"PATCHED!!!".iter().copied());
        edited.extend_from_slice(b"appended trailer");
        let score = compare(&ssdeep(&original), &ssdeep(&edited)).expect("compare");
        assert!(score >= 70, "score {score}");
    }

    #[test]
    fn digests_are_validated_and_sequences_collapsed() {
        assert!(compare("3:abc", "3:abc:def").is_err());
        assert!(compare("x:abc:def", "3:abc:def").is_err());
        assert!(compare("3:a!c:def", "3:abc:def").is_err());
        assert_eq!(compare("3:abc:def", "12:abc:def").expect("compare"), 0);
        assert_eq!(eliminate_sequences(b"aaaaabbbbbc"), b"aaabbbc");
        // Trailing file names from ssdeep CSV output are ignored.
        assert_eq!(
            compare("3:abcdefgh:ij,\"a.bin\"", "3:abcdefgh:ij").expect("compare"),
            100
        );
    }
}
