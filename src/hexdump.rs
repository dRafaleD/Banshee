//! Canonical hex dump (`hexdump -C` style): offset, hex bytes and printable
//! ASCII, for a bounded window of the input.

use std::fmt::Write as _;

/// Renders `bytes[offset..offset + length]`, `width` bytes per line. Offsets
/// shown are absolute positions in the input.
pub fn render(bytes: &[u8], offset: usize, length: usize, width: usize) -> String {
    let width = width.clamp(1, 64);
    let start = offset.min(bytes.len());
    let end = start.saturating_add(length).min(bytes.len());
    let mut output = String::new();
    for (line, chunk) in bytes[start..end].chunks(width).enumerate() {
        let position = start + line * width;
        write!(output, "{position:08x}  ").expect("string write");
        for index in 0..width {
            match chunk.get(index) {
                Some(byte) => write!(output, "{byte:02x} ").expect("string write"),
                None => output.push_str("   "),
            }
            // Extra space between the two halves of a line, as hexdump -C does.
            if width >= 8 && index + 1 == width / 2 {
                output.push(' ');
            }
        }
        output.push_str(" |");
        output.extend(chunk.iter().map(|byte| {
            if byte.is_ascii_graphic() || *byte == b' ' {
                char::from(*byte)
            } else {
                '.'
            }
        }));
        output.push_str("|\n");
    }
    writeln!(output, "{end:08x}").expect("string write");
    output
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn matches_the_canonical_layout() {
        let dump = render(b"MZ\x90\x00hello, world!\x00\xff", 0, 1024, 16);
        let lines: Vec<&str> = dump.lines().collect();
        assert_eq!(
            lines[0],
            "00000000  4d 5a 90 00 68 65 6c 6c  6f 2c 20 77 6f 72 6c 64  |MZ..hello, world|"
        );
        // A short last line keeps the ASCII column aligned with full lines.
        assert!(lines[1].starts_with("00000010  21 00 ff "), "{}", lines[1]);
        assert_eq!(lines[1].find('|'), lines[0].find('|'));
        assert!(lines[1].ends_with("|!..|"), "{}", lines[1]);
        assert_eq!(lines[2], "00000013");
    }

    #[test]
    fn windows_are_clamped_to_the_input() {
        let data: Vec<u8> = (0..40).collect();
        let dump = render(&data, 32, 100, 8);
        assert!(
            dump.starts_with("00000020  20 21 22 23  24 25 26 27  | !\"#$%&'|\n"),
            "{dump}"
        );
        assert!(dump.ends_with("00000028\n"), "{dump}");
        assert_eq!(render(&data, 500, 10, 16), "00000028\n");
    }
}
