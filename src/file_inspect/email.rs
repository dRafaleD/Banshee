//! Internet message (`.eml`, RFC 5322 + MIME) inspection: headers, the
//! Received chain, authentication results, attachments and links. Bodies are
//! decoded (base64, quoted-printable) only to hash attachments and read links;
//! nothing is rendered, opened or fetched.

use std::sync::OnceLock;

use base64::Engine as _;
use regex::Regex;
use sha2::{Digest, Sha256};

use super::document::DocumentReport;

const MAX_PARTS: usize = 256;
const MAX_DEPTH: usize = 8;
const MAX_LINKS: usize = 200;
const MAX_HEADER_CHARS: usize = 512;

/// Attachment extensions that run code or hide it when opened on Windows.
const RISKY_EXTENSIONS: &[&str] = &[
    "exe", "scr", "com", "pif", "bat", "cmd", "ps1", "vbs", "vbe", "js", "jse", "wsf", "hta",
    "lnk", "iso", "img", "vhd", "vhdx", "msi", "dll", "cpl", "jar", "reg", "chm", "one", "docm",
    "xlsm", "pptm", "xlam", "html", "htm", "svg", "url",
];
/// Extensions an attacker shows before the real one (`invoice.pdf.exe`).
const DECOY_EXTENSIONS: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "jpg", "jpeg", "png", "txt", "zip", "rar",
];

/// Header-looking start: `Name: value` lines including From and a date or subject.
pub(super) fn looks_like_email(path: &str, bytes: &[u8]) -> bool {
    if path.to_ascii_lowercase().ends_with(".eml") {
        return true;
    }
    let head = String::from_utf8_lossy(&bytes[..bytes.len().min(4096)]);
    let Some((headers, _)) = head
        .split_once("\r\n\r\n")
        .or_else(|| head.split_once("\n\n"))
    else {
        return false;
    };
    let names: Vec<String> = headers
        .lines()
        .filter(|line| !line.starts_with([' ', '\t']))
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| {
            !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .map(|(name, _)| name.to_ascii_lowercase())
        .collect();
    names.iter().any(|name| name == "from")
        && names.iter().any(|name| name == "subject" || name == "date")
        && names
            .iter()
            .any(|name| name == "received" || name == "message-id" || name == "mime-version")
}

/// Unfolded headers in order, and the body after the blank line.
fn split_message(text: &str) -> (Vec<(String, String)>, &str) {
    let (head, body) = text
        .split_once("\r\n\r\n")
        .or_else(|| text.split_once("\n\n"))
        .unwrap_or((text, ""));
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in head.lines() {
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = headers.last_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
        } else if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    (headers, body)
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

/// Decodes RFC 2047 encoded words (`=?charset?B|Q?text?=`). Only UTF-8 and
/// ASCII-compatible text is decoded; other charsets are read lossily.
fn decode_words(value: &str) -> String {
    static WORD: OnceLock<Regex> = OnceLock::new();
    let word = WORD.get_or_init(|| {
        Regex::new(r"=\?([^?]{1,40})\?([bBqQ])\?([^?]*)\?=").expect("valid encoded-word regex")
    });
    let decoded = word.replace_all(value, |captures: &regex::Captures<'_>| {
        let text = &captures[3];
        let bytes = if captures[2].eq_ignore_ascii_case("b") {
            base64::engine::general_purpose::STANDARD
                .decode(text)
                .unwrap_or_else(|_| text.as_bytes().to_vec())
        } else {
            quoted_printable(&text.replace('_', " "))
        };
        String::from_utf8_lossy(&bytes).into_owned()
    });
    // Whitespace between adjacent encoded words is not significant.
    decoded.chars().take(MAX_HEADER_CHARS).collect()
}

fn quoted_printable(text: &str) -> Vec<u8> {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'=' if bytes
                .get(index + 1..index + 3)
                .is_some_and(|pair| pair == b"\r\n") =>
            {
                index += 3
            }
            b'=' if bytes.get(index + 1) == Some(&b'\n') => index += 2,
            b'=' => {
                let pair = bytes
                    .get(index + 1..index + 3)
                    .and_then(|pair| std::str::from_utf8(pair).ok())
                    .and_then(|pair| u8::from_str_radix(pair, 16).ok());
                match pair {
                    Some(byte) => {
                        output.push(byte);
                        index += 3;
                    }
                    None => {
                        output.push(b'=');
                        index += 1;
                    }
                }
            }
            byte => {
                output.push(byte);
                index += 1;
            }
        }
    }
    output
}

/// A header parameter such as `boundary` or `filename`, quoted or not.
fn parameter(value: &str, name: &str) -> Option<String> {
    value.split(';').skip(1).find_map(|part| {
        let (key, raw) = part.trim().split_once('=')?;
        let key = key.trim().to_ascii_lowercase();
        // `filename*` (RFC 2231) carries charset''percent-encoded text.
        if key == format!("{name}*") {
            let encoded = raw.trim().trim_matches('"');
            let text = encoded.rsplit("''").next().unwrap_or(encoded);
            return Some(
                percent_encoding::percent_decode_str(text)
                    .decode_utf8_lossy()
                    .into_owned(),
            );
        }
        (key == name).then(|| decode_words(raw.trim().trim_matches('"')))
    })
}

fn domain(address: &str) -> Option<String> {
    let address = match (address.rfind('<'), address.rfind('>')) {
        (Some(start), Some(end)) if start < end => &address[start + 1..end],
        _ => address,
    };
    let (_, domain) = address.trim().rsplit_once('@')?;
    let domain = domain
        .trim_matches(|character: char| {
            character.is_whitespace() || matches!(character, '"' | '\'' | '>' | ')')
        })
        .to_ascii_lowercase();
    (!domain.is_empty()).then_some(domain)
}

/// The registrable part of a host name, approximated by its last two labels
/// (three when the second-level label is short, as in `example.co.uk`).
fn base_domain(host: &str) -> String {
    let labels: Vec<&str> = host.trim_end_matches('.').split('.').collect();
    let keep = if labels.len() >= 3 && labels[labels.len() - 2].len() <= 3 {
        3
    } else {
        2
    };
    labels[labels.len().saturating_sub(keep)..].join(".")
}

struct Part {
    content_type: String,
    filename: Option<String>,
    disposition: String,
    data: Vec<u8>,
}

fn decode_body(body: &str, encoding: &str) -> Vec<u8> {
    match encoding.trim().to_ascii_lowercase().as_str() {
        "base64" => {
            let compact: String = body
                .chars()
                .filter(|character| !character.is_whitespace())
                .collect();
            base64::engine::general_purpose::STANDARD
                .decode(compact.trim_end_matches('='))
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD_NO_PAD
                        .decode(compact.trim_end_matches('='))
                })
                .unwrap_or_default()
        }
        "quoted-printable" => quoted_printable(body),
        _ => body.as_bytes().to_vec(),
    }
}

/// Flattens the MIME tree into leaf parts.
fn collect_parts(headers: &[(String, String)], body: &str, depth: usize, parts: &mut Vec<Part>) {
    if parts.len() >= MAX_PARTS || depth > MAX_DEPTH {
        return;
    }
    let content_type = header(headers, "content-type")
        .unwrap_or("text/plain")
        .to_owned();
    let media = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if media.starts_with("multipart/")
        && let Some(boundary) = parameter(&content_type, "boundary")
    {
        let delimiter = format!("--{boundary}");
        for chunk in body.split(delimiter.as_str()).skip(1) {
            if chunk.starts_with("--") {
                break;
            }
            let chunk = chunk.trim_start_matches(['\r', '\n']);
            let (part_headers, part_body) = split_message(chunk);
            collect_parts(&part_headers, part_body, depth + 1, parts);
        }
        return;
    }
    let disposition = header(headers, "content-disposition")
        .unwrap_or_default()
        .to_owned();
    let filename = parameter(&disposition, "filename").or_else(|| parameter(&content_type, "name"));
    let encoding = header(headers, "content-transfer-encoding").unwrap_or_default();
    parts.push(Part {
        content_type: media,
        filename,
        disposition: disposition.to_ascii_lowercase(),
        data: decode_body(body, encoding),
    });
}

fn extension(name: &str) -> Option<String> {
    name.rsplit_once('.')
        .map(|(_, extension)| extension.trim().to_ascii_lowercase())
}

pub(super) fn inspect(bytes: &[u8]) -> DocumentReport {
    static LINK: OnceLock<Regex> = OnceLock::new();
    static ANCHOR: OnceLock<Regex> = OnceLock::new();
    static RESULT: OnceLock<Regex> = OnceLock::new();
    let text = String::from_utf8_lossy(bytes);
    let (headers, body) = split_message(&text);
    let mut report = DocumentReport::new("Email message");
    report.macros_present = None;

    for name in [
        "from",
        "sender",
        "reply-to",
        "return-path",
        "to",
        "cc",
        "subject",
        "date",
        "message-id",
    ] {
        if let Some(value) = header(&headers, name) {
            report.property(name, decode_words(value));
        }
    }
    let received = headers
        .iter()
        .filter(|(name, _)| name == "received")
        .count();
    report.property("received hops", received.to_string());
    if let Some(first) = headers.iter().rev().find(|(name, _)| name == "received") {
        report.property("first received", decode_words(&first.1));
    }

    // Authentication-Results: spf=, dkim=, dmarc= verdicts.
    let result = RESULT.get_or_init(|| {
        Regex::new(r"(?i)\b(spf|dkim|dmarc)\s*=\s*([a-z]+)").expect("valid auth result regex")
    });
    for (_, value) in headers
        .iter()
        .filter(|(name, _)| name == "authentication-results")
    {
        for captures in result.captures_iter(value) {
            let mechanism = captures[1].to_ascii_lowercase();
            let verdict = captures[2].to_ascii_lowercase();
            report.property(&mechanism, verdict.clone());
            if matches!(verdict.as_str(), "fail" | "softfail" | "permerror") {
                report.suspicious_properties.push(format!(
                    "Email {} check result is {verdict}",
                    mechanism.to_ascii_uppercase()
                ));
            }
        }
    }

    let from_domain = header(&headers, "from").and_then(domain);
    for name in ["reply-to", "return-path"] {
        if let (Some(from), Some(other)) = (&from_domain, header(&headers, name).and_then(domain))
            && base_domain(from) != base_domain(&other)
        {
            report.suspicious_properties.push(format!(
                "Email {name} domain ({other}) differs from the From domain ({from})"
            ));
        }
    }
    if let Some(from) = header(&headers, "from") {
        let decoded = decode_words(from);
        // A display name that is itself an address on another domain.
        if let Some((display, _)) = decoded.split_once('<')
            && let (Some(shown), Some(actual)) = (domain(display), &from_domain)
            && base_domain(&shown) != base_domain(actual)
        {
            report.suspicious_properties.push(format!(
                "Email From display name shows {shown} but the address is on {actual}"
            ));
        }
    }

    let mut parts = Vec::new();
    collect_parts(&headers, body, 0, &mut parts);
    report.property("MIME parts", parts.len().to_string());
    if parts.len() >= MAX_PARTS {
        report
            .notes
            .push(format!("only the first {MAX_PARTS} MIME parts were read"));
    }

    let link = LINK.get_or_init(|| {
        Regex::new(r#"(?i)\bhttps?://[^\s"'<>()]{1,2048}"#).expect("valid link regex")
    });
    let anchor = ANCHOR.get_or_init(|| {
        Regex::new(r#"(?is)<a\b[^>]*?href\s*=\s*["']?(https?://[^"'\s>]{1,2048})["']?[^>]*>(.{0,512}?)</a>"#)
            .expect("valid anchor regex")
    });
    let mut links = Vec::<String>::new();
    for part in &parts {
        let is_attachment = part.filename.is_some() || part.disposition.starts_with("attachment");
        if is_attachment {
            let name = part
                .filename
                .clone()
                .unwrap_or_else(|| "(unnamed)".to_owned());
            let digest = format!("{:x}", Sha256::digest(&part.data));
            report.property(
                "attachment",
                format!(
                    "{name} ({}, {} bytes, sha256 {digest})",
                    part.content_type,
                    part.data.len()
                ),
            );
            let lowered = name.to_ascii_lowercase();
            let pieces: Vec<&str> = lowered.split('.').collect();
            if let Some(last) = extension(&lowered) {
                if RISKY_EXTENSIONS.contains(&last.as_str()) {
                    report
                        .suspicious_properties
                        .push(format!("Email attachment has a risky type: {name}"));
                }
                if pieces.len() >= 3
                    && DECOY_EXTENSIONS.contains(&pieces[pieces.len() - 2])
                    && !DECOY_EXTENSIONS.contains(&last.as_str())
                {
                    report.suspicious_properties.push(format!(
                        "Email attachment hides its real type behind a double extension: {name}"
                    ));
                }
            }
            continue;
        }
        if !part.content_type.starts_with("text/") {
            continue;
        }
        let content = String::from_utf8_lossy(&part.data);
        if part.content_type == "text/html" {
            for captures in anchor.captures_iter(&content) {
                let href = &captures[1];
                let shown = &captures[2];
                if let (Some(shown_url), Ok(target)) = (link.find(shown), url::Url::parse(href))
                    && let (Ok(shown_url), Some(target_host)) =
                        (url::Url::parse(shown_url.as_str()), target.host_str())
                    && let Some(shown_host) = shown_url.host_str()
                    && base_domain(shown_host) != base_domain(target_host)
                {
                    report.suspicious_properties.push(format!(
                        "Email link text shows {shown_host} but points to {target_host}"
                    ));
                }
            }
        }
        for found in link.find_iter(&content) {
            let value = found.as_str().trim_end_matches(['.', ',', ';']).to_owned();
            if links.len() < MAX_LINKS && !links.contains(&value) {
                links.push(value);
            }
        }
    }
    for value in &links {
        report.target("link", value);
    }
    report.suspicious_properties.dedup();
    report
}

#[cfg(test)]
mod tests {
    use super::{base_domain, decode_words, inspect, looks_like_email, quoted_printable};

    const PHISH: &str = "Received: from mx.attacker.test ([203.0.113.7])\r\n\
by mx.victim.example.test; Mon, 12 Oct 2026 10:00:00 +0000\r\n\
Authentication-Results: mx.victim.example.test; spf=fail smtp.mailfrom=bank.test;\r\n \
dkim=none; dmarc=fail\r\n\
From: \"support@bank.test\" <alerts@attacker.test>\r\n\
Reply-To: billing@collector.test\r\n\
To: user@victim.example.test\r\n\
Subject: =?UTF-8?B?RmF0dXJhIMO2ZGVtZXNp?=\r\n\
Date: Mon, 12 Oct 2026 10:00:00 +0000\r\n\
Message-ID: <1@attacker.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"b1\"\r\n\
\r\n\
--b1\r\n\
Content-Type: text/html; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
<p>Pay now: <a href=3D\"http://login.evil.test/pay\">https://www.bank=\r\n\
.test/account</a></p>\r\n\
--b1\r\n\
Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\r\n\
Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAA=\r\n\
--b1--\r\n";

    #[test]
    fn detects_email_by_extension_or_headers() {
        assert!(looks_like_email("mail.EML", b""));
        assert!(looks_like_email("noext", PHISH.as_bytes()));
        assert!(!looks_like_email("notes.txt", b"From: me\nhello there\n"));
    }

    #[test]
    fn decodes_encoded_words_and_quoted_printable() {
        assert_eq!(
            decode_words("=?UTF-8?B?RmF0dXJhIMO2ZGVtZXNp?="),
            "Fatura ödemesi"
        );
        assert_eq!(
            decode_words("=?utf-8?Q?caf=C3=A9_au_lait?="),
            "café au lait"
        );
        assert_eq!(quoted_printable("a=3Db=\r\nc"), b"a=bc");
        assert_eq!(base_domain("mail.bank.example.test"), "example.test");
        assert_eq!(base_domain("www.example.co.uk"), "example.co.uk");
    }

    #[test]
    fn reports_a_phishing_message() {
        let report = inspect(PHISH.as_bytes());
        let property = |name: &str| {
            report
                .properties
                .iter()
                .filter(|property| property.name == name)
                .map(|property| property.value.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(property("subject"), ["Fatura ödemesi"]);
        assert_eq!(property("spf"), ["fail"]);
        assert_eq!(property("received hops"), ["1"]);
        let attachment = property("attachment").join("");
        assert!(
            attachment.starts_with("invoice.pdf.exe (application/octet-stream, 32 bytes, sha256 "),
            "{attachment}"
        );
        assert!(
            report
                .external_targets
                .iter()
                .any(|target| target.target == "http://login.evil.test/pay")
        );

        let findings = report.suspicious_properties.join("\n");
        for expected in [
            "SPF check result is fail",
            "DMARC check result is fail",
            "reply-to domain (collector.test) differs",
            "display name shows bank.test",
            "risky type: invoice.pdf.exe",
            "double extension: invoice.pdf.exe",
            "link text shows www.bank.test but points to login.evil.test",
        ] {
            assert!(
                findings.contains(expected),
                "missing {expected}:\n{findings}"
            );
        }
    }

    #[test]
    fn a_plain_message_has_no_findings() {
        let message = "From: Alice <alice@example.test>\nTo: bob@example.test\nSubject: lunch\n\
Date: Mon, 12 Oct 2026 10:00:00 +0000\nMessage-ID: <2@example.test>\n\nSee https://example.test/menu today.\n";
        let report = inspect(message.as_bytes());
        assert!(
            report.suspicious_properties.is_empty(),
            "{:?}",
            report.suspicious_properties
        );
        assert_eq!(
            report.external_targets[0].target,
            "https://example.test/menu"
        );
    }

    #[test]
    fn deep_or_broken_mime_does_not_panic() {
        let mut message = String::from("From: a@b.test\nSubject: x\nMessage-ID: <x>\n");
        message.push_str("Content-Type: multipart/mixed; boundary=z\n\n");
        for _ in 0..20 {
            message.push_str("--z\nContent-Type: multipart/mixed; boundary=z\n\n");
        }
        message.push_str("--z\nContent-Transfer-Encoding: base64\n\n@@@not base64@@@\n");
        let _ = inspect(message.as_bytes());
        let _ = inspect(b"\xff\xfe\x00garbage");
    }
}
