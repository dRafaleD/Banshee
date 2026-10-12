//! Generate harmless seed files for parser fuzzing. Never execute these fixtures.
use std::fs;
use std::io::{Cursor, Write};
use std::path::PathBuf;

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let directory = PathBuf::from(
        std::env::args()
            .nth(1)
            .context("usage: cargo run --example fuzz_seeds -- OUTPUT_DIRECTORY")?,
    );
    fs::create_dir_all(&directory)?;
    let mut pe = vec![0_u8; 512];
    pe[..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
    pe[64..68].copy_from_slice(b"PE\0\0");
    pe[68..70].copy_from_slice(&0x8664_u16.to_le_bytes());
    pe[70..72].copy_from_slice(&1_u16.to_le_bytes());
    pe[84..86].copy_from_slice(&240_u16.to_le_bytes());
    pe[88..90].copy_from_slice(&0x20b_u16.to_le_bytes());
    pe[156..158].copy_from_slice(&3_u16.to_le_bytes());
    pe[328..336].copy_from_slice(b".text\0\0\0");
    pe[364..368].copy_from_slice(&0x6000_0020_u32.to_le_bytes());
    write_seed(&directory, "pe64", &pe)?;
    for (name, class, little) in [("elf64-le", 2, true), ("elf32-be", 1, false)] {
        let mut elf = vec![0_u8; 128];
        elf[..4].copy_from_slice(b"\x7fELF");
        elf[4] = class;
        elf[5] = if little { 1 } else { 2 };
        elf[6] = 1;
        let kind = if little {
            2_u16.to_le_bytes()
        } else {
            2_u16.to_be_bytes()
        };
        elf[16..18].copy_from_slice(&kind);
        write_seed(&directory, name, &elf)?;
    }
    let mut tar = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "synthetic.txt", b"safe".as_slice())?;
    let tar = tar.into_inner()?;
    write_seed(&directory, "tar", &tar)?;
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("synthetic.txt", zip::write::SimpleFileOptions::default())?;
    zip.write_all(b"safe")?;
    let zip = zip.finish()?.into_inner();
    write_seed(&directory, "zip", &zip)?;
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    gzip.write_all(&tar)?;
    write_seed(&directory, "gzip-tar", &gzip.finish()?)?;
    let mut bzip = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
    bzip.write_all(&tar)?;
    write_seed(&directory, "bzip2-tar", &bzip.finish()?)?;
    let mut xz = xz2::write::XzEncoder::new(Vec::new(), 1);
    xz.write_all(&tar)?;
    write_seed(&directory, "xz-tar", &xz.finish()?)?;

    // Document structures only; none of these carry macros or scripts.
    let mut ooxml = zip::ZipWriter::new(Cursor::new(Vec::new()));
    for (name, data) in [
        ("[Content_Types].xml", b"<Types/>".as_slice()),
        (
            "word/_rels/settings.xml.rels",
            br#"<Relationships><Relationship Type="x/attachedTemplate" Target="http://seed.example.test/t" TargetMode="External"/></Relationships>"#,
        ),
        ("word/document.xml", b"<w:document/>"),
    ] {
        ooxml.start_file(name, zip::write::SimpleFileOptions::default())?;
        ooxml.write_all(data)?;
    }
    write_seed(&directory, "ooxml", &ooxml.finish()?.into_inner())?;
    let mut ole = vec![0_u8; 1536];
    ole[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
    ole[0x1E..0x20].copy_from_slice(&9_u16.to_le_bytes());
    ole[0x2C..0x30].copy_from_slice(&1_u32.to_le_bytes());
    ole[0x30..0x34].copy_from_slice(&1_u32.to_le_bytes());
    ole[512..516].copy_from_slice(&0xFFFF_FFFD_u32.to_le_bytes());
    ole[516..520].copy_from_slice(&0xFFFF_FFFE_u32.to_le_bytes());
    let name = "WordDocument"
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect::<Vec<_>>();
    ole[1024..1024 + name.len()].copy_from_slice(&name);
    ole[1024 + 0x40..1024 + 0x42].copy_from_slice(&(name.len() as u16).to_le_bytes());
    ole[1024 + 0x42] = 2;
    write_seed(&directory, "ole", &ole)?;
    write_seed(
        &directory,
        "pdf",
        b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /URI (http://seed.example.test/) >> endobj\n%%EOF",
    )?;
    let mut lnk = vec![0_u8; 0x4C];
    lnk[..4].copy_from_slice(&0x4C_u32.to_le_bytes());
    lnk[4..20].copy_from_slice(&[
        0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x46,
    ]);
    lnk[0x14..0x18].copy_from_slice(&(0x20_u32 | 0x80).to_le_bytes());
    let arguments = "/c echo seed".encode_utf16().collect::<Vec<_>>();
    lnk.extend((arguments.len() as u16).to_le_bytes());
    lnk.extend(arguments.iter().flat_map(|unit| unit.to_le_bytes()));
    write_seed(&directory, "lnk", &lnk)?;

    println!(
        "Validated 12 synthetic corpus seeds in {}",
        directory.display()
    );
    Ok(())
}

fn write_seed(directory: &std::path::Path, name: &str, data: &[u8]) -> Result<()> {
    banshee::file_inspect::inspect_bytes(data, name.into(), 8)
        .with_context(|| format!("invalid synthetic seed: {name}"))?;
    let path = directory.join(name);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)?;
    file.write_all(data)?;
    Ok(())
}
