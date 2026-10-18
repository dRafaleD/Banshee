//! Windows XML Event Log (EVTX) inspection. The file header and every 64 KiB
//! chunk are checked against their CRC32 checksums, records are counted and
//! dated, and the binary XML of each record is walked far enough to read its
//! event ID, provider and channel. String values from the event data feed
//! content analysis, so command lines and paths in the log reach IOC
//! extraction. Nothing is rendered to XML and no template is executed.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::document::DocumentReport;

const FILE_HEADER_BYTES: usize = 4_096;
const CHUNK_BYTES: usize = 65_536;
const CHUNK_HEADER_BYTES: usize = 512;
const RECORD_HEADER_BYTES: usize = 24;
const MAX_RECORDS: usize = 2_000_000;
/// Binary XML tokens walked per template, against crafted loops.
const MAX_TEMPLATE_TOKENS: usize = 4_096;
const MAX_SUBSTITUTIONS: usize = 1_024;
const MAX_LISTED_EVENT_IDS: usize = 32;
const MAX_LISTED_NAMES: usize = 16;
const MAX_TEXT_VALUES: usize = 4_096;
const MAX_TEXT_BYTES: usize = 1024 * 1024;
const MAX_TEXT_VALUE_CHARS: usize = 4_096;
/// Seconds between 1601-01-01 (FILETIME epoch) and 1970-01-01.
const FILETIME_UNIX_OFFSET: i64 = 11_644_473_600;

/// Event IDs worth pointing out, with the provider fragment that must match.
const NOTEWORTHY: &[(u16, &str, &str)] = &[
    (1102, "eventlog", "audit log cleared"),
    (104, "eventlog", "event log cleared"),
    (4719, "security-auditing", "audit policy changed"),
    (4720, "security-auditing", "user account created"),
    (4726, "security-auditing", "user account deleted"),
    (
        4728,
        "security-auditing",
        "member added to a global security group",
    ),
    (
        4732,
        "security-auditing",
        "member added to a local security group",
    ),
    (
        4756,
        "security-auditing",
        "member added to a universal security group",
    ),
    (4697, "security-auditing", "service installed"),
    (4698, "security-auditing", "scheduled task created"),
    (7045, "service control manager", "service installed"),
    (4104, "powershell", "PowerShell script block logged"),
    (1116, "defender", "Microsoft Defender detected malware"),
    (1117, "defender", "Microsoft Defender acted on malware"),
    (
        5001,
        "defender",
        "Microsoft Defender real-time protection disabled",
    ),
];

pub(super) fn is_evtx(bytes: &[u8]) -> bool {
    bytes.starts_with(b"ElfFile\0")
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn crc32(parts: &[&[u8]]) -> u32 {
    let mut crc = flate2::Crc::new();
    for part in parts {
        crc.update(part);
    }
    crc.sum()
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16_lossy(&units)
}

fn filetime(value: u64) -> Option<OffsetDateTime> {
    let seconds = i64::try_from(value / 10_000_000).ok()? - FILETIME_UNIX_OFFSET;
    OffsetDateTime::from_unix_timestamp(seconds).ok()
}

/// Where a template takes one of the fields Banshee reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
enum Field {
    #[default]
    Missing,
    Literal(String),
    Substitution(u16),
}

impl Field {
    fn set(&mut self, value: Self) {
        if *self == Self::Missing {
            *self = value;
        }
    }
}

#[derive(Debug, Clone, Default)]
struct TemplateFields {
    event_id: Field,
    provider: Field,
    channel: Field,
}

/// Reads an element or attribute name stored at a chunk offset, returning it
/// with the bytes it takes when stored inline at that offset.
fn name_at(chunk: &[u8], offset: usize) -> Option<(String, usize)> {
    let count = usize::from(u16_at(chunk, offset.checked_add(6)?)?);
    let start = offset + 8;
    let text = utf16(chunk.get(start..start.checked_add(count * 2)?)?);
    Some((text, 8 + count * 2 + 2))
}

/// Walks a template body and notes where the event ID, provider name and
/// channel come from. Stops at the first token it does not understand.
fn walk_template(chunk: &[u8], mut position: usize, end: usize) -> TemplateFields {
    let mut fields = TemplateFields::default();
    let mut stack: Vec<String> = Vec::new();
    let mut attribute: Option<String> = None;
    let end = end.min(chunk.len());

    let mut record = |stack: &[String], attribute: &Option<String>, value: Field| {
        let element = stack.last().map(String::as_str);
        match (element, attribute.as_deref()) {
            (Some("Provider"), Some("Name")) => fields.provider.set(value),
            (Some("EventID"), None) => fields.event_id.set(value),
            (Some("Channel"), None) => fields.channel.set(value),
            _ => {}
        }
    };

    for _ in 0..MAX_TEMPLATE_TOKENS {
        if position >= end {
            break;
        }
        let token = chunk[position];
        let more = token & 0x40 != 0;
        match token & !0x40 {
            0x00 => break,
            0x0F => position += 4,
            0x01 => {
                let Some(name_offset) = u32_at(chunk, position + 7) else {
                    break;
                };
                position += 11;
                let Some((name, inline)) = name_at(chunk, name_offset as usize) else {
                    break;
                };
                if name_offset as usize == position {
                    position += inline;
                }
                if more {
                    position += 4;
                }
                stack.push(name);
                attribute = None;
            }
            0x02 => {
                position += 1;
                attribute = None;
            }
            0x03 | 0x04 => {
                position += 1;
                stack.pop();
                attribute = None;
            }
            0x06 => {
                let Some(name_offset) = u32_at(chunk, position + 1) else {
                    break;
                };
                position += 5;
                let Some((name, inline)) = name_at(chunk, name_offset as usize) else {
                    break;
                };
                if name_offset as usize == position {
                    position += inline;
                }
                attribute = Some(name);
            }
            0x05 => {
                // Only string values (type 0x01) appear in templates in practice.
                if chunk.get(position + 1) != Some(&0x01) {
                    break;
                }
                let Some(count) = u16_at(chunk, position + 2) else {
                    break;
                };
                let start = position + 4;
                let Some(text) = chunk.get(start..start + usize::from(count) * 2) else {
                    break;
                };
                record(&stack, &attribute, Field::Literal(utf16(text)));
                position = start + usize::from(count) * 2;
            }
            0x0D | 0x0E => {
                let Some(index) = u16_at(chunk, position + 1) else {
                    break;
                };
                record(&stack, &attribute, Field::Substitution(index));
                position += 4;
            }
            0x07 | 0x0B => {
                let Some(count) = u16_at(chunk, position + 1) else {
                    break;
                };
                position += 3 + usize::from(count) * 2;
            }
            0x08 => position += 3,
            0x09 | 0x0A => {
                let Some(name_offset) = u32_at(chunk, position + 1) else {
                    break;
                };
                position += 5;
                if name_offset as usize == position {
                    let Some((_, inline)) = name_at(chunk, position) else {
                        break;
                    };
                    position += inline;
                }
            }
            _ => break,
        }
    }
    fields
}

/// One substitution value: its type and raw bytes.
struct Value<'a> {
    kind: u8,
    bytes: &'a [u8],
}

fn substitutions(chunk: &[u8], position: usize, end: usize) -> Option<Vec<Value<'_>>> {
    let count = u32_at(chunk, position)? as usize;
    if count > MAX_SUBSTITUTIONS {
        return None;
    }
    let mut descriptors = Vec::with_capacity(count);
    let mut cursor = position + 4;
    for _ in 0..count {
        descriptors.push((usize::from(u16_at(chunk, cursor)?), *chunk.get(cursor + 2)?));
        cursor += 4;
    }
    let mut values = Vec::with_capacity(count);
    for (size, kind) in descriptors {
        let next = cursor.checked_add(size)?;
        if next > end {
            return None;
        }
        values.push(Value {
            kind,
            bytes: &chunk[cursor..next],
        });
        cursor = next;
    }
    Some(values)
}

fn resolve_text(field: &Field, values: &[Value<'_>]) -> Option<String> {
    match field {
        Field::Missing => None,
        Field::Literal(text) => Some(text.clone()),
        Field::Substitution(index) => {
            let value = values.get(usize::from(*index))?;
            match value.kind {
                0x01 => Some(utf16(value.bytes)),
                0x02 => Some(String::from_utf8_lossy(value.bytes).into_owned()),
                _ => None,
            }
        }
    }
}

fn resolve_event_id(field: &Field, values: &[Value<'_>]) -> Option<u16> {
    match field {
        Field::Missing => None,
        Field::Literal(text) => text.trim().parse().ok(),
        Field::Substitution(index) => {
            let value = values.get(usize::from(*index))?;
            match (value.kind, value.bytes.len()) {
                (0x06, 2) => u16_at(value.bytes, 0),
                (0x08, 4) => u32_at(value.bytes, 0).map(|id| id as u16),
                (0x04, 1) => Some(u16::from(value.bytes[0])),
                _ => None,
            }
        }
    }
}

#[derive(Default)]
struct Event {
    id: Option<u16>,
    provider: Option<String>,
    channel: Option<String>,
}

/// Collects strings from event data for content analysis, within limits.
#[derive(Default)]
struct TextCollector {
    seen: BTreeSet<String>,
    bytes: usize,
    truncated: bool,
}

impl TextCollector {
    fn add(&mut self, text: String) {
        let text = text.trim();
        if text.chars().count() < 4 || self.seen.contains(text) {
            return;
        }
        let text: String = text.chars().take(MAX_TEXT_VALUE_CHARS).collect();
        if self.seen.len() >= MAX_TEXT_VALUES || self.bytes + text.len() > MAX_TEXT_BYTES {
            self.truncated = true;
            return;
        }
        self.bytes += text.len();
        self.seen.insert(text);
    }
}

/// Reads the event fields of one record whose binary XML spans
/// `position..end` of the chunk. Templates are cached by chunk offset.
fn parse_event(
    chunk: &[u8],
    mut position: usize,
    end: usize,
    templates: &mut HashMap<usize, TemplateFields>,
    text: &mut TextCollector,
) -> Option<Event> {
    if chunk.get(position) == Some(&0x0F) {
        position += 4;
    }
    if chunk.get(position) != Some(&0x0C) {
        return None;
    }
    let definition = u32_at(chunk, position + 6)? as usize;
    position += 10;
    let size = u32_at(chunk, definition.checked_add(20)?)? as usize;
    let body = definition + 24;
    if definition == position {
        position = body.checked_add(size)?;
    }
    let fields = templates
        .entry(definition)
        .or_insert_with(|| walk_template(chunk, body, body.saturating_add(size)))
        .clone();
    let values = substitutions(chunk, position, end)?;
    for value in &values {
        if value.kind == 0x01 {
            text.add(utf16(value.bytes));
        }
    }
    Some(Event {
        id: resolve_event_id(&fields.event_id, &values),
        provider: resolve_text(&fields.provider, &values),
        channel: resolve_text(&fields.channel, &values),
    })
}

#[derive(Default)]
struct Totals {
    chunks: usize,
    unused_chunks: usize,
    bad_chunk_headers: usize,
    bad_record_checksums: usize,
    records: usize,
    unresolved: usize,
    record_ids: Vec<u64>,
    first_time: Option<OffsetDateTime>,
    last_time: Option<OffsetDateTime>,
    event_ids: BTreeMap<u16, usize>,
    providers: BTreeMap<String, usize>,
    channels: BTreeMap<String, usize>,
    noteworthy: BTreeMap<(u16, &'static str), usize>,
    record_limit_reached: bool,
}

fn scan_chunk(chunk: &[u8], totals: &mut Totals, text: &mut TextCollector) {
    let header_crc = u32_at(chunk, 124).unwrap_or_default();
    if crc32(&[&chunk[..120], &chunk[128..CHUNK_HEADER_BYTES]]) != header_crc {
        totals.bad_chunk_headers += 1;
    }
    let free_space =
        (u32_at(chunk, 48).unwrap_or_default() as usize).clamp(CHUNK_HEADER_BYTES, CHUNK_BYTES);
    if crc32(&[&chunk[CHUNK_HEADER_BYTES..free_space]]) != u32_at(chunk, 52).unwrap_or_default() {
        totals.bad_record_checksums += 1;
    }

    let mut templates = HashMap::new();
    let mut position = CHUNK_HEADER_BYTES;
    while position + RECORD_HEADER_BYTES <= free_space {
        if chunk[position..position + 4] != *b"**\0\0" {
            break;
        }
        let size = u32_at(chunk, position + 4).unwrap_or_default() as usize;
        if size < RECORD_HEADER_BYTES + 4 || position + size > CHUNK_BYTES {
            break;
        }
        if totals.records >= MAX_RECORDS {
            totals.record_limit_reached = true;
            return;
        }
        totals.records += 1;
        if let Some(id) = u64_at(chunk, position + 8) {
            totals.record_ids.push(id);
        }
        if let Some(time) = u64_at(chunk, position + 16).and_then(filetime) {
            totals.first_time = Some(totals.first_time.map_or(time, |first| first.min(time)));
            totals.last_time = Some(totals.last_time.map_or(time, |last| last.max(time)));
        }
        let event = parse_event(
            chunk,
            position + RECORD_HEADER_BYTES,
            position + size - 4,
            &mut templates,
            text,
        )
        .unwrap_or_default();
        match event.id {
            Some(id) => *totals.event_ids.entry(id).or_default() += 1,
            None => totals.unresolved += 1,
        }
        if let Some(provider) = &event.provider {
            *totals.providers.entry(provider.clone()).or_default() += 1;
        }
        if let Some(channel) = event.channel {
            *totals.channels.entry(channel).or_default() += 1;
        }
        if let (Some(id), Some(provider)) = (event.id, &event.provider) {
            let provider = provider.to_ascii_lowercase();
            for (known, fragment, label) in NOTEWORTHY {
                if *known == id && provider.contains(fragment) {
                    *totals.noteworthy.entry((id, label)).or_default() += 1;
                }
            }
        }
        position += size;
    }
}

fn top<K: Clone + Ord>(counts: &BTreeMap<K, usize>, limit: usize) -> Vec<(K, usize)> {
    let mut entries: Vec<(K, usize)> = counts
        .iter()
        .map(|(key, count)| (key.clone(), *count))
        .collect();
    entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    entries.truncate(limit);
    entries
}

fn format_time(time: OffsetDateTime) -> String {
    time.format(&Rfc3339).unwrap_or_else(|_| time.to_string())
}

/// Missing record IDs between the lowest and highest one found.
fn record_id_gaps(ids: &mut [u64]) -> (u64, Option<(u64, u64)>) {
    ids.sort_unstable();
    let mut missing = 0_u64;
    let mut first = None;
    for pair in ids.windows(2) {
        if pair[1] > pair[0] + 1 {
            missing += pair[1] - pair[0] - 1;
            first.get_or_insert((pair[0], pair[1]));
        }
    }
    (missing, first)
}

pub(super) fn inspect(bytes: &[u8]) -> DocumentReport {
    let mut report = DocumentReport::new("Windows event log (EVTX)");
    report.notes.push(
        "Records are read from binary XML templates without rendering them; event IDs, \
         providers and channels that a template does not expose are counted as unresolved"
            .to_owned(),
    );

    let Some(header) = bytes.get(..128) else {
        report
            .suspicious_properties
            .push("EVTX file header is truncated".to_owned());
        return report;
    };
    let major = u16_at(header, 38).unwrap_or_default();
    let minor = u16_at(header, 36).unwrap_or_default();
    report.property("Format version", format!("{major}.{minor}"));
    let declared_chunks = u16_at(header, 42).unwrap_or_default();
    let flags = u32_at(header, 120).unwrap_or_default();
    let mut state = Vec::new();
    if flags & 0x1 != 0 {
        state.push("dirty (not closed cleanly)");
    }
    if flags & 0x2 != 0 {
        state.push("full");
    }
    if !state.is_empty() {
        report.property("File state", state.join(", "));
    }
    if crc32(&[&header[..120]]) != u32_at(header, 124).unwrap_or_default() {
        report.suspicious_properties.push(
            "EVTX file header checksum does not match, which suggests editing or corruption"
                .to_owned(),
        );
    }

    let mut totals = Totals::default();
    let mut text = TextCollector::default();
    let mut offset = FILE_HEADER_BYTES;
    while let Some(chunk) = bytes.get(offset..offset + CHUNK_BYTES) {
        if chunk.starts_with(b"ElfChnk\0") {
            totals.chunks += 1;
            scan_chunk(chunk, &mut totals, &mut text);
            if totals.record_limit_reached {
                break;
            }
        } else {
            totals.unused_chunks += 1;
        }
        offset += CHUNK_BYTES;
    }
    if offset < bytes.len() && !totals.record_limit_reached {
        report.notes.push(format!(
            "{} trailing bytes do not form a full chunk and were not read",
            bytes.len() - offset
        ));
    }
    if totals.record_limit_reached {
        report.notes.push(format!(
            "record limit of {MAX_RECORDS} reached; later chunks were not read"
        ));
    }

    report.property(
        "Chunks",
        format!("{} (header declares {declared_chunks})", totals.chunks),
    );
    if totals.unused_chunks > 0 {
        report.property("Unused chunks", totals.unused_chunks.to_string());
    }
    report.property("Records", totals.records.to_string());
    if let (Some(first), Some(last)) = (
        totals.record_ids.iter().min(),
        totals.record_ids.iter().max(),
    ) {
        report.property("Record IDs", format!("{first}-{last}"));
    }
    if let (Some(first), Some(last)) = (totals.first_time, totals.last_time) {
        report.property(
            "Time range (UTC)",
            format!("{} to {}", format_time(first), format_time(last)),
        );
    }
    if !totals.event_ids.is_empty() {
        let listed = top(&totals.event_ids, MAX_LISTED_EVENT_IDS)
            .into_iter()
            .map(|(id, count)| format!("{id} x{count}"))
            .collect::<Vec<_>>();
        let more = totals.event_ids.len().saturating_sub(listed.len());
        let suffix = if more > 0 {
            format!(" (+{more} more)")
        } else {
            String::new()
        };
        report.property("Event IDs", format!("{}{suffix}", listed.join(", ")));
    }
    if totals.unresolved > 0 {
        report.property(
            "Records without a resolved event ID",
            totals.unresolved.to_string(),
        );
    }
    for (label, counts) in [
        ("Providers", &totals.providers),
        ("Channels", &totals.channels),
    ] {
        if !counts.is_empty() {
            let listed = top(counts, MAX_LISTED_NAMES)
                .into_iter()
                .map(|(name, count)| format!("{name} x{count}"))
                .collect::<Vec<_>>();
            report.property(label, listed.join(", "));
        }
    }
    for ((id, label), count) in &totals.noteworthy {
        report.property(&format!("Event {id}"), format!("{label} x{count}"));
    }

    for ((id, label), count) in &totals.noteworthy {
        if matches!(id, 1102 | 104) {
            report.suspicious_properties.push(format!(
                "log contains {count} record(s) of event {id} ({label}); earlier events may have been removed"
            ));
        }
    }
    if totals.bad_chunk_headers > 0 || totals.bad_record_checksums > 0 {
        report.suspicious_properties.push(format!(
            "{} chunk header(s) and {} record area(s) fail their CRC32 check, which suggests editing or corruption",
            totals.bad_chunk_headers, totals.bad_record_checksums
        ));
    }
    let (missing, first_gap) = record_id_gaps(&mut totals.record_ids);
    if let Some((before, after)) = first_gap {
        report.suspicious_properties.push(format!(
            "{missing} record ID(s) are missing between the first and last record (first gap after {before}, next is {after}); records may have been deleted or damaged"
        ));
    }
    if text.truncated {
        report.notes.push(format!(
            "event data text passed to content analysis was capped at {MAX_TEXT_VALUES} values or {} KiB",
            MAX_TEXT_BYTES / 1024
        ));
    }
    report.extra_text = text.seen.into_iter().collect();
    report
}

#[cfg(test)]
mod tests {
    use super::{CHUNK_BYTES, CHUNK_HEADER_BYTES, FILE_HEADER_BYTES, crc32, inspect, is_evtx};

    /// Binary XML writer that knows the chunk offset of every byte it emits,
    /// so names can be stored inline the way Windows writes them.
    struct Xml {
        bytes: Vec<u8>,
        base: usize,
    }

    impl Xml {
        fn at(&self) -> usize {
            self.base + self.bytes.len()
        }

        fn name(&mut self, name: &str) {
            let units: Vec<u16> = name.encode_utf16().collect();
            self.bytes.extend(0u32.to_le_bytes());
            self.bytes.extend(0u16.to_le_bytes());
            self.bytes.extend((units.len() as u16).to_le_bytes());
            for unit in units {
                self.bytes.extend(unit.to_le_bytes());
            }
            self.bytes.extend(0u16.to_le_bytes());
        }

        fn open(&mut self, name: &str, attributes: bool) {
            self.bytes.push(if attributes { 0x41 } else { 0x01 });
            self.bytes.extend(0xFFFFu16.to_le_bytes());
            self.bytes.extend(0u32.to_le_bytes());
            let inline = self.at() + 4;
            self.bytes.extend((inline as u32).to_le_bytes());
            self.name(name);
            if attributes {
                self.bytes.extend(0u32.to_le_bytes());
            }
        }

        fn attribute(&mut self, name: &str) {
            self.bytes.push(0x06);
            let inline = self.at() + 4;
            self.bytes.extend((inline as u32).to_le_bytes());
            self.name(name);
        }

        fn text(&mut self, text: &str) {
            let units: Vec<u16> = text.encode_utf16().collect();
            self.bytes.extend([0x05, 0x01]);
            self.bytes.extend((units.len() as u16).to_le_bytes());
            for unit in units {
                self.bytes.extend(unit.to_le_bytes());
            }
        }

        fn substitution(&mut self, index: u16, kind: u8) {
            self.bytes.push(0x0D);
            self.bytes.extend(index.to_le_bytes());
            self.bytes.push(kind);
        }
    }

    /// Template: <Event><System><Provider Name="..."/><EventID>{0}</EventID>
    /// <Channel>{1}</Channel></System><EventData>{2}</EventData></Event>
    fn template(base: usize, provider: &str) -> Vec<u8> {
        let mut xml = Xml {
            bytes: vec![0x0F, 0x01, 0x01, 0x00],
            base,
        };
        xml.open("Event", false);
        xml.bytes.push(0x02);
        xml.open("System", false);
        xml.bytes.push(0x02);
        xml.open("Provider", true);
        xml.attribute("Name");
        xml.text(provider);
        xml.bytes.push(0x03);
        xml.open("EventID", false);
        xml.bytes.push(0x02);
        xml.substitution(0, 0x06);
        xml.bytes.push(0x04);
        xml.open("Channel", false);
        xml.bytes.push(0x02);
        xml.substitution(1, 0x01);
        xml.bytes.push(0x04);
        xml.bytes.push(0x04);
        xml.open("EventData", false);
        xml.bytes.push(0x02);
        xml.substitution(2, 0x01);
        xml.bytes.push(0x04);
        xml.bytes.push(0x04);
        xml.bytes.push(0x00);
        xml.bytes
    }

    fn utf16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// One record at chunk offset `at`; `template_at` is the definition
    /// offset, written inline when it equals the offset after the token.
    fn record(at: usize, id: u64, event: u16, data: &str, template_at: Option<usize>) -> Vec<u8> {
        let mut body = vec![0x0F, 0x01, 0x01, 0x00, 0x0C, 0x01];
        body.extend(1u32.to_le_bytes());
        let inline = at + 24 + body.len() + 4;
        body.extend((template_at.unwrap_or(inline) as u32).to_le_bytes());
        if template_at.is_none() {
            let definition = template(inline + 24, "Microsoft-Windows-Eventlog");
            body.extend(0u32.to_le_bytes());
            body.extend([0; 16]);
            body.extend((definition.len() as u32).to_le_bytes());
            body.extend(definition);
        }
        let channel = utf16("Security");
        let data = utf16(data);
        body.extend(3u32.to_le_bytes());
        for (size, kind) in [(2, 0x06), (channel.len(), 0x01), (data.len(), 0x01)] {
            body.extend((size as u16).to_le_bytes());
            body.extend([kind, 0]);
        }
        body.extend(event.to_le_bytes());
        body.extend(channel);
        body.extend(data);

        let size = 24 + body.len() + 4;
        let mut record = b"**\0\0".to_vec();
        record.extend((size as u32).to_le_bytes());
        record.extend(id.to_le_bytes());
        // 2024-01-01T00:00:00Z as FILETIME.
        record.extend(133_485_408_000_000_000u64.to_le_bytes());
        record.extend(body);
        record.extend((size as u32).to_le_bytes());
        record
    }

    fn evtx(ids: &[(u64, u16)]) -> Vec<u8> {
        let mut chunk = vec![0; CHUNK_BYTES];
        chunk[..8].copy_from_slice(b"ElfChnk\0");
        let mut at = CHUNK_HEADER_BYTES;
        let mut template_at = None;
        for (index, (id, event)) in ids.iter().enumerate() {
            let data = format!("cmd.exe /c whoami record {index}");
            let bytes = record(at, *id, *event, &data, template_at);
            template_at.get_or_insert(at + 24 + 14);
            chunk[at..at + bytes.len()].copy_from_slice(&bytes);
            at += bytes.len();
        }
        chunk[48..52].copy_from_slice(&(at as u32).to_le_bytes());
        let records = crc32(&[&chunk[CHUNK_HEADER_BYTES..at]]);
        chunk[52..56].copy_from_slice(&records.to_le_bytes());
        let header = crc32(&[&chunk[..120], &chunk[128..CHUNK_HEADER_BYTES]]);
        chunk[124..128].copy_from_slice(&header.to_le_bytes());

        let mut file = vec![0; FILE_HEADER_BYTES];
        file[..8].copy_from_slice(b"ElfFile\0");
        file[32..36].copy_from_slice(&128u32.to_le_bytes());
        file[36..38].copy_from_slice(&1u16.to_le_bytes());
        file[38..40].copy_from_slice(&3u16.to_le_bytes());
        file[42..44].copy_from_slice(&1u16.to_le_bytes());
        let checksum = crc32(&[&file[..120]]);
        file[124..128].copy_from_slice(&checksum.to_le_bytes());
        file.extend(chunk);
        file
    }

    fn property<'a>(report: &'a crate::file_inspect::DocumentReport, name: &str) -> &'a str {
        report
            .properties
            .iter()
            .find(|property| property.name == name)
            .map(|property| property.value.as_str())
            .unwrap_or_else(|| panic!("missing {name}: {:?}", report.properties))
    }

    #[test]
    fn reads_records_event_ids_providers_and_channels() {
        let bytes = evtx(&[(1, 4624), (2, 4624), (3, 1102)]);
        assert!(is_evtx(&bytes));
        let report = inspect(&bytes);
        assert_eq!(property(&report, "Format version"), "3.1");
        assert_eq!(property(&report, "Records"), "3");
        assert_eq!(property(&report, "Record IDs"), "1-3");
        assert_eq!(property(&report, "Event IDs"), "4624 x2, 1102 x1");
        assert_eq!(
            property(&report, "Providers"),
            "Microsoft-Windows-Eventlog x3"
        );
        assert_eq!(property(&report, "Channels"), "Security x3");
        assert!(property(&report, "Time range (UTC)").starts_with("2024-01-01T00:00:00Z"));
        assert_eq!(property(&report, "Event 1102"), "audit log cleared x1");
        assert_eq!(
            report.suspicious_properties.len(),
            1,
            "{:?}",
            report.suspicious_properties
        );
        assert!(report.suspicious_properties[0].contains("event 1102"));
        assert!(
            report
                .analysis_text()
                .contains("cmd.exe /c whoami record 2")
        );
    }

    #[test]
    fn flags_checksum_mismatches_and_record_id_gaps() {
        let mut bytes = evtx(&[(10, 4624), (11, 4624), (15, 4624)]);
        bytes[FILE_HEADER_BYTES + 600] ^= 0xFF;
        let report = inspect(&bytes);
        let findings = report.suspicious_properties.join("\n");
        assert!(findings.contains("CRC32"), "{findings}");
        assert!(
            findings.contains("3 record ID(s) are missing"),
            "{findings}"
        );
    }

    #[test]
    fn survives_truncated_and_garbage_input() {
        let report = inspect(b"ElfFile\0short");
        assert!(report.suspicious_properties[0].contains("truncated"));

        let mut bytes = evtx(&[(1, 4624)]);
        for byte in bytes[FILE_HEADER_BYTES + CHUNK_HEADER_BYTES..]
            .iter_mut()
            .step_by(7)
        {
            *byte = 0xA5;
        }
        let report = inspect(&bytes);
        assert_eq!(property(&report, "Chunks"), "1 (header declares 1)");

        let mut truncated = evtx(&[(1, 4624)]);
        truncated.truncate(FILE_HEADER_BYTES + 1000);
        let report = inspect(&truncated);
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("trailing bytes"))
        );
    }
}
