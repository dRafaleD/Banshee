//! Packet capture (pcap and pcapng) inspection. Packets are decoded down to
//! IP and TCP/UDP headers to count conversations and service ports, and a
//! few cleartext fields are read from the first bytes of each payload: DNS
//! question names, HTTP request hosts and paths, and the TLS ClientHello
//! server name. Streams are not reassembled, so a field split across
//! packets is missed. Names and addresses feed IOC extraction.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::document::DocumentReport;

const MAX_PACKETS: usize = 5_000_000;
const MAX_TRACKED: usize = 10_000;
const MAX_LISTED: usize = 32;
const MAX_TOP: usize = 10;
const MAX_TEXT_VALUES: usize = 8_192;

pub(super) fn is_pcap(bytes: &[u8]) -> bool {
    matches!(
        bytes.get(..4),
        Some(
            [0xD4, 0xC3, 0xB2, 0xA1]
                | [0xA1, 0xB2, 0xC3, 0xD4]
                | [0x4D, 0x3C, 0xB2, 0xA1]
                | [0xA1, 0xB2, 0x3C, 0x4D]
                | [0x0A, 0x0D, 0x0D, 0x0A]
        )
    )
}

#[derive(Clone, Copy)]
struct Order(bool);

impl Order {
    fn u16(self, bytes: &[u8], offset: usize) -> Option<u16> {
        let raw: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
        Some(if self.0 {
            u16::from_le_bytes(raw)
        } else {
            u16::from_be_bytes(raw)
        })
    }

    fn u32(self, bytes: &[u8], offset: usize) -> Option<u32> {
        let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
        Some(if self.0 {
            u32::from_le_bytes(raw)
        } else {
            u32::from_be_bytes(raw)
        })
    }
}

fn be16(bytes: &[u8], offset: usize) -> Option<u16> {
    Order(false).u16(bytes, offset)
}

struct Packet<'a> {
    /// Seconds since the Unix epoch, when the capture records it.
    time: Option<f64>,
    link: u32,
    data: &'a [u8],
}

/// Walks a classic pcap file. Returns a parse note when the file ends early.
fn classic(bytes: &[u8], visit: &mut dyn FnMut(Packet<'_>) -> bool) -> Option<String> {
    let (order, nanoseconds) = match bytes.get(..4)? {
        [0xD4, 0xC3, 0xB2, 0xA1] => (Order(true), false),
        [0xA1, 0xB2, 0xC3, 0xD4] => (Order(false), false),
        [0x4D, 0x3C, 0xB2, 0xA1] => (Order(true), true),
        _ => (Order(false), true),
    };
    let Some(link) = order.u32(bytes, 20) else {
        return Some("pcap header is truncated".to_owned());
    };
    let mut position = 24;
    while position < bytes.len() {
        let (Some(seconds), Some(fraction), Some(length)) = (
            order.u32(bytes, position),
            order.u32(bytes, position + 4),
            order.u32(bytes, position + 8),
        ) else {
            return Some(format!("packet record at offset {position} is truncated"));
        };
        let start = position + 16;
        let Some(data) = bytes.get(start..start.saturating_add(length as usize)) else {
            return Some(format!("packet data at offset {start} is truncated"));
        };
        let divisor = if nanoseconds { 1e9 } else { 1e6 };
        let time = f64::from(seconds) + f64::from(fraction) / divisor;
        if !visit(Packet {
            time: Some(time),
            link,
            data,
        }) {
            return None;
        }
        position = start + data.len();
    }
    None
}

struct Interface {
    link: u32,
    /// Timestamp units per second.
    resolution: f64,
}

fn interface_resolution(order: Order, block: &[u8]) -> f64 {
    // Options follow LinkType (2), reserved (2) and SnapLen (4).
    let mut position = 16;
    while let (Some(code), Some(length)) =
        (order.u16(block, position), order.u16(block, position + 2))
    {
        if code == 0 {
            break;
        }
        let value = position + 4;
        if code == 9
            && length >= 1
            && let Some(raw) = block.get(value)
        {
            let exponent = i32::from(raw & 0x7F);
            return if raw & 0x80 == 0 {
                10f64.powi(exponent)
            } else {
                2f64.powi(exponent)
            };
        }
        position = value + usize::from(length).div_ceil(4) * 4;
    }
    1e6
}

/// Walks a pcapng file. Returns a parse note when a block is malformed.
fn pcapng(bytes: &[u8], visit: &mut dyn FnMut(Packet<'_>) -> bool) -> Option<String> {
    let mut order = Order(true);
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut position = 0;
    while position + 12 <= bytes.len() {
        let block_type = Order(true).u32(bytes, position)?;
        if block_type == 0x0A0D_0D0A {
            order = match bytes.get(position + 8..position + 12)? {
                [0x4D, 0x3C, 0x2B, 0x1A] => Order(true),
                [0x1A, 0x2B, 0x3C, 0x4D] => Order(false),
                _ => {
                    return Some(format!(
                        "section header at offset {position} has an unknown byte order"
                    ));
                }
            };
            interfaces.clear();
        }
        let block_type = order.u32(bytes, position)?;
        let length = order.u32(bytes, position + 4)? as usize;
        if length < 12 || length % 4 != 0 {
            return Some(format!(
                "block at offset {position} has an invalid length {length}"
            ));
        }
        let Some(block) = bytes.get(position..position + length) else {
            return Some(format!("block at offset {position} is truncated"));
        };
        match block_type {
            1 => interfaces.push(Interface {
                link: u32::from(order.u16(block, 8).unwrap_or_default()),
                resolution: interface_resolution(order, block),
            }),
            6 | 2 => {
                let interface = if block_type == 6 {
                    order.u32(block, 8).unwrap_or_default() as usize
                } else {
                    usize::from(order.u16(block, 8).unwrap_or_default())
                };
                let (Some(high), Some(low), Some(captured)) = (
                    order.u32(block, 12),
                    order.u32(block, 16),
                    order.u32(block, 20),
                ) else {
                    return Some(format!("packet block at offset {position} is truncated"));
                };
                let Some(data) = block.get(28..28usize.saturating_add(captured as usize)) else {
                    return Some(format!(
                        "packet block at offset {position} overruns its length"
                    ));
                };
                let interface = interfaces.get(interface);
                let ticks = (u64::from(high) << 32) | u64::from(low);
                if !visit(Packet {
                    time: interface.map(|interface| ticks as f64 / interface.resolution),
                    link: interface.map_or(1, |interface| interface.link),
                    data,
                }) {
                    return None;
                }
            }
            3 => {
                let original = order.u32(block, 8).unwrap_or_default() as usize;
                let data = &block[12.min(block.len())..block.len().saturating_sub(4).max(12)];
                let data = &data[..data.len().min(original)];
                if !visit(Packet {
                    time: None,
                    link: interfaces.first().map_or(1, |interface| interface.link),
                    data,
                }) {
                    return None;
                }
            }
            _ => {}
        }
        position += length;
    }
    None
}

/// EtherType of a raw IP packet, from its version nibble.
fn by_version(data: &[u8]) -> Option<(u16, &[u8])> {
    match data.first()? >> 4 {
        4 => Some((0x0800, data)),
        6 => Some((0x86DD, data)),
        _ => None,
    }
}

/// Network-layer packet extracted from a link-layer frame.
fn network(link: u32, frame: &[u8]) -> Option<(u16, &[u8])> {
    match link {
        1 => {
            let mut ethertype = be16(frame, 12)?;
            let mut offset = 14;
            for _ in 0..2 {
                if matches!(ethertype, 0x8100 | 0x88A8) {
                    ethertype = be16(frame, offset + 2)?;
                    offset += 4;
                }
            }
            Some((ethertype, frame.get(offset..)?))
        }
        0 | 108 => {
            let family = u32::from_le_bytes(frame.get(..4)?.try_into().ok()?);
            let family = if family > 0xFFFF {
                family.swap_bytes()
            } else {
                family
            };
            match family {
                2 => Some((0x0800, frame.get(4..)?)),
                24 | 28 | 30 => Some((0x86DD, frame.get(4..)?)),
                _ => None,
            }
        }
        12 | 14 | 101 => by_version(frame),
        228 => Some((0x0800, frame)),
        229 => Some((0x86DD, frame)),
        113 => Some((be16(frame, 14)?, frame.get(16..)?)),
        276 => Some((be16(frame, 0)?, frame.get(20..)?)),
        _ => None,
    }
}

struct Transport<'a> {
    source: IpAddr,
    destination: IpAddr,
    protocol: u8,
    ports: Option<(u16, u16)>,
    payload: &'a [u8],
}

fn transport(ethertype: u16, packet: &[u8]) -> Option<Transport<'_>> {
    let (source, destination, mut protocol, mut payload) = match ethertype {
        0x0800 => {
            let header = usize::from(packet.first()? & 0x0F) * 4;
            // A crafted header length beyond the packet yields no payload.
            let total = usize::from(be16(packet, 2)?).min(packet.len());
            let source = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(12..16)?).ok()?);
            let destination = Ipv4Addr::from(<[u8; 4]>::try_from(packet.get(16..20)?).ok()?);
            let fragment = be16(packet, 6)? & 0x1FFF;
            let payload = if fragment == 0 {
                packet.get(header..total).unwrap_or_default()
            } else {
                &[][..]
            };
            (
                IpAddr::V4(source),
                IpAddr::V4(destination),
                *packet.get(9)?,
                payload,
            )
        }
        0x86DD => {
            let source = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(8..24)?).ok()?);
            let destination = Ipv6Addr::from(<[u8; 16]>::try_from(packet.get(24..40)?).ok()?);
            (
                IpAddr::V6(source),
                IpAddr::V6(destination),
                *packet.get(6)?,
                packet.get(40..)?,
            )
        }
        _ => return None,
    };
    // IPv6 extension headers: hop-by-hop, routing, destination, fragment.
    for _ in 0..8 {
        match protocol {
            0 | 43 | 60 => {
                let length = (usize::from(*payload.get(1)?) + 1) * 8;
                protocol = *payload.first()?;
                payload = payload.get(length..)?;
            }
            44 => {
                protocol = *payload.first()?;
                payload = payload.get(8..)?;
            }
            _ => break,
        }
    }
    let (ports, payload) = match protocol {
        6 => {
            let offset = usize::from(payload.get(12)? >> 4) * 4;
            (
                Some((be16(payload, 0)?, be16(payload, 2)?)),
                payload.get(offset..).unwrap_or_default(),
            )
        }
        17 => (
            Some((be16(payload, 0)?, be16(payload, 2)?)),
            payload.get(8..).unwrap_or_default(),
        ),
        _ => (None, payload),
    };
    Some(Transport {
        source,
        destination,
        protocol,
        ports,
        payload,
    })
}

/// First question name of a DNS message.
fn dns_question(message: &[u8]) -> Option<String> {
    if be16(message, 4)? == 0 {
        return None;
    }
    let mut labels = Vec::new();
    let mut position = 12;
    loop {
        let length = usize::from(*message.get(position)?);
        if length == 0 {
            break;
        }
        if length & 0xC0 != 0 || labels.len() >= 127 {
            return None;
        }
        let label = message.get(position + 1..position + 1 + length)?;
        if !label
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        position += 1 + length;
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

/// Host and path of a cleartext HTTP request at the start of a payload.
fn http_request(payload: &[u8]) -> Option<(String, String)> {
    const METHODS: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"PUT ",
        b"HEAD ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
    ];
    if !METHODS.iter().any(|method| payload.starts_with(method)) {
        return None;
    }
    let head = String::from_utf8_lossy(&payload[..payload.len().min(4096)]);
    let mut lines = head.split("\r\n");
    let path = lines.next()?.split(' ').nth(1)?.to_owned();
    let host = lines.take_while(|line| !line.is_empty()).find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host")
            .then(|| value.trim().to_owned())
    })?;
    (!host.is_empty() && host.len() <= 255).then_some((host, path))
}

/// Server name from a TLS ClientHello at the start of a payload.
fn tls_server_name(payload: &[u8]) -> Option<String> {
    if payload.first() != Some(&0x16) || payload.get(1) != Some(&3) || payload.get(5) != Some(&1) {
        return None;
    }
    let mut position = 5 + 4 + 2 + 32;
    position += 1 + usize::from(*payload.get(position)?);
    position += 2 + usize::from(be16(payload, position)?);
    position += 1 + usize::from(*payload.get(position)?);
    let end = (position + 2 + usize::from(be16(payload, position)?)).min(payload.len());
    position += 2;
    while position + 4 <= end {
        let kind = be16(payload, position)?;
        let length = usize::from(be16(payload, position + 2)?);
        let body = payload.get(position + 4..position + 4 + length)?;
        if kind == 0 && body.get(2) == Some(&0) {
            let name_length = usize::from(be16(body, 3)?);
            let name = body.get(5..5 + name_length)?;
            return name
                .iter()
                .all(|byte| byte.is_ascii_graphic())
                .then(|| String::from_utf8_lossy(name).to_ascii_lowercase());
        }
        position += 4 + length;
    }
    None
}

fn link_name(link: u32) -> String {
    match link {
        0 => "BSD loopback".to_owned(),
        1 => "Ethernet".to_owned(),
        12 | 14 | 101 => "raw IP".to_owned(),
        108 => "OpenBSD loopback".to_owned(),
        113 => "Linux cooked (SLL)".to_owned(),
        228 => "raw IPv4".to_owned(),
        229 => "raw IPv6".to_owned(),
        276 => "Linux cooked (SLL2)".to_owned(),
        other => format!("link type {other}"),
    }
}

/// Counts with a cap on distinct keys, so a crafted capture cannot grow
/// the maps without bound.
struct Counter<K: Ord> {
    counts: BTreeMap<K, usize>,
    truncated: bool,
}

impl<K: Ord + Clone> Counter<K> {
    fn new() -> Self {
        Self {
            counts: BTreeMap::new(),
            truncated: false,
        }
    }

    fn add(&mut self, key: K) {
        if let Some(count) = self.counts.get_mut(&key) {
            *count += 1;
        } else if self.counts.len() < MAX_TRACKED {
            self.counts.insert(key, 1);
        } else {
            self.truncated = true;
        }
    }

    fn top(&self, limit: usize) -> Vec<(K, usize)> {
        let mut entries: Vec<(K, usize)> = self
            .counts
            .iter()
            .map(|(key, count)| (key.clone(), *count))
            .collect();
        entries.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        entries.truncate(limit);
        entries
    }
}

fn format_time(seconds: f64) -> Option<String> {
    OffsetDateTime::from_unix_timestamp(seconds as i64)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

pub(super) fn inspect(bytes: &[u8]) -> DocumentReport {
    let ng = bytes.starts_with(&[0x0A, 0x0D, 0x0D, 0x0A]);
    let mut report = DocumentReport::new(if ng {
        "Packet capture (pcapng)"
    } else {
        "Packet capture (pcap)"
    });
    report.notes.push(
        "packets are decoded to IP and TCP/UDP headers; DNS, HTTP and TLS fields are read \
         from single packets without stream reassembly"
            .to_owned(),
    );

    let mut packets = 0_usize;
    let mut captured = 0_usize;
    let mut decoded = 0_usize;
    let (mut first, mut last) = (f64::INFINITY, f64::NEG_INFINITY);
    let mut links = BTreeSet::new();
    let mut conversations = Counter::<(IpAddr, IpAddr)>::new();
    let mut services = Counter::<(&'static str, u16)>::new();
    let mut dns = Counter::<String>::new();
    let mut http_hosts = Counter::<String>::new();
    let mut sni = Counter::<String>::new();
    let mut addresses = BTreeSet::<IpAddr>::new();
    let mut urls = BTreeSet::<String>::new();
    let mut raw_ip_http = BTreeSet::<String>::new();
    let mut limit_reached = false;

    let mut visit = |packet: Packet<'_>| -> bool {
        if packets >= MAX_PACKETS {
            limit_reached = true;
            return false;
        }
        packets += 1;
        captured += packet.data.len();
        if let Some(time) = packet.time.filter(|time| time.is_finite() && *time > 0.0) {
            first = first.min(time);
            last = last.max(time);
        }
        links.insert(packet.link);
        let Some(segment) = network(packet.link, packet.data)
            .and_then(|(ethertype, data)| transport(ethertype, data))
        else {
            return true;
        };
        decoded += 1;
        let (low, high) = if segment.source <= segment.destination {
            (segment.source, segment.destination)
        } else {
            (segment.destination, segment.source)
        };
        conversations.add((low, high));
        for address in [segment.source, segment.destination] {
            if addresses.len() < MAX_TEXT_VALUES {
                addresses.insert(address);
            }
        }
        let Some((source_port, destination_port)) = segment.ports else {
            return true;
        };
        let name = if segment.protocol == 6 { "tcp" } else { "udp" };
        services.add((name, source_port.min(destination_port)));
        if segment.protocol == 17 && (source_port == 53 || destination_port == 53) {
            if let Some(name) = dns_question(segment.payload) {
                dns.add(name);
            }
        } else if segment.protocol == 6 {
            if let Some((host, path)) = http_request(segment.payload) {
                let url = format!("http://{host}{path}");
                let bare = host
                    .rsplit_once(':')
                    .map_or(host.as_str(), |(name, _)| name);
                if bare.parse::<IpAddr>().is_ok() && raw_ip_http.len() < MAX_LISTED {
                    raw_ip_http.insert(url.clone());
                }
                if urls.len() < MAX_TEXT_VALUES {
                    urls.insert(url);
                }
                http_hosts.add(host);
            } else if let Some(name) = tls_server_name(segment.payload) {
                sni.add(name);
            }
        }
        true
    };
    let problem = if ng {
        pcapng(bytes, &mut visit)
    } else {
        classic(bytes, &mut visit)
    };
    drop(visit);

    if let Some(problem) = problem {
        report.notes.push(problem);
    }
    if limit_reached {
        report.notes.push(format!(
            "packet limit of {MAX_PACKETS} reached; later packets were not read"
        ));
    }
    report.property(
        "Link types",
        links
            .iter()
            .map(|link| link_name(*link))
            .collect::<Vec<_>>()
            .join(", "),
    );
    report.property("Packets", packets.to_string());
    report.property("Captured bytes", captured.to_string());
    report.property("IP packets decoded", decoded.to_string());
    if first.is_finite()
        && let (Some(start), Some(end)) = (format_time(first), format_time(last))
    {
        report.property("Time range (UTC)", format!("{start} to {end}"));
    }
    let listed = |entries: Vec<String>| entries.join(", ");
    if !conversations.counts.is_empty() {
        report.property(
            "Top conversations",
            listed(
                conversations
                    .top(MAX_TOP)
                    .into_iter()
                    .map(|((left, right), count)| format!("{left} <-> {right} x{count}"))
                    .collect(),
            ),
        );
    }
    if !services.counts.is_empty() {
        report.property(
            "Top service ports",
            listed(
                services
                    .top(MAX_TOP)
                    .into_iter()
                    .map(|((protocol, port), count)| format!("{protocol}/{port} x{count}"))
                    .collect(),
            ),
        );
    }
    for (label, counter) in [
        ("DNS queries", &dns),
        ("HTTP hosts", &http_hosts),
        ("TLS server names", &sni),
    ] {
        if counter.counts.is_empty() {
            continue;
        }
        let names = counter
            .top(MAX_LISTED)
            .into_iter()
            .map(|(name, count)| format!("{name} x{count}"))
            .collect::<Vec<_>>();
        let more = counter.counts.len().saturating_sub(names.len());
        let suffix = if more > 0 || counter.truncated {
            format!(" (+{more} more)")
        } else {
            String::new()
        };
        report.property(label, format!("{}{suffix}", names.join(", ")));
    }
    if conversations.truncated || services.truncated {
        report.notes.push(format!(
            "only the first {MAX_TRACKED} distinct conversations and ports are counted"
        ));
    }
    for url in &raw_ip_http {
        report.suspicious_properties.push(format!(
            "cleartext HTTP request to an IP address host: {url}"
        ));
    }

    report.extra_text = dns
        .counts
        .into_keys()
        .chain(http_hosts.counts.into_keys())
        .chain(sni.counts.into_keys())
        .chain(urls)
        .chain(addresses.into_iter().map(|address| address.to_string()))
        .take(MAX_TEXT_VALUES * 2)
        .collect();
    report
}

#[cfg(test)]
mod tests {
    use super::{inspect, is_pcap};

    fn ipv4_udp(
        source: [u8; 4],
        destination: [u8; 4],
        ports: (u16, u16),
        payload: &[u8],
    ) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend(ports.0.to_be_bytes());
        udp.extend(ports.1.to_be_bytes());
        udp.extend(((8 + payload.len()) as u16).to_be_bytes());
        udp.extend([0, 0]);
        udp.extend(payload);
        ipv4(17, source, destination, &udp)
    }

    fn ipv4_tcp(
        source: [u8; 4],
        destination: [u8; 4],
        ports: (u16, u16),
        payload: &[u8],
    ) -> Vec<u8> {
        let mut tcp = Vec::new();
        tcp.extend(ports.0.to_be_bytes());
        tcp.extend(ports.1.to_be_bytes());
        tcp.extend([0; 8]);
        tcp.extend([0x50, 0x18, 0xFF, 0xFF, 0, 0, 0, 0]);
        tcp.extend(payload);
        ipv4(6, source, destination, &tcp)
    }

    fn ipv4(protocol: u8, source: [u8; 4], destination: [u8; 4], body: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x45, 0];
        packet.extend(((20 + body.len()) as u16).to_be_bytes());
        packet.extend([0, 0, 0x40, 0, 64, protocol, 0, 0]);
        packet.extend(source);
        packet.extend(destination);
        packet.extend(body);
        packet
    }

    fn ethernet(packet: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x02; 12];
        frame.extend([0x08, 0x00]);
        frame.extend(packet);
        frame
    }

    fn dns_query(name: &str) -> Vec<u8> {
        let mut message = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            message.push(label.len() as u8);
            message.extend(label.as_bytes());
        }
        message.extend([0, 0, 1, 0, 1]);
        message
    }

    fn client_hello(name: &str) -> Vec<u8> {
        let mut extension = Vec::new();
        extension.extend(((name.len() + 3) as u16).to_be_bytes());
        extension.push(0);
        extension.extend((name.len() as u16).to_be_bytes());
        extension.extend(name.as_bytes());
        let mut extensions = vec![0, 0];
        extensions.extend((extension.len() as u16).to_be_bytes());
        extensions.extend(extension);
        let mut hello = vec![3, 3];
        hello.extend([0; 32]);
        hello.extend([0, 0, 2, 0x13, 0x01, 1, 0]);
        hello.extend((extensions.len() as u16).to_be_bytes());
        hello.extend(extensions);
        let mut handshake = vec![1, 0];
        handshake.extend((hello.len() as u16).to_be_bytes());
        handshake.extend(hello);
        let mut record = vec![0x16, 3, 1];
        record.extend((handshake.len() as u16).to_be_bytes());
        record.extend(handshake);
        record
    }

    fn frames() -> Vec<Vec<u8>> {
        let client = [192, 0, 2, 10];
        vec![
            ethernet(&ipv4_udp(
                client,
                [192, 0, 2, 53],
                (50000, 53),
                &dns_query("update.example.net"),
            )),
            ethernet(&ipv4_tcp(
                client,
                [198, 51, 100, 7],
                (50001, 80),
                b"GET /payload.bin HTTP/1.1\r\nHost: 198.51.100.7\r\nUser-Agent: x\r\n\r\n",
            )),
            ethernet(&ipv4_tcp(
                client,
                [203, 0, 113, 5],
                (50002, 443),
                &client_hello("cdn.example.org"),
            )),
        ]
    }

    fn classic(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut file = vec![0xD4, 0xC3, 0xB2, 0xA1, 2, 0, 4, 0];
        file.extend([0; 8]);
        file.extend(65535u32.to_le_bytes());
        file.extend(1u32.to_le_bytes());
        for (index, frame) in frames.iter().enumerate() {
            file.extend((1_700_000_000u32 + index as u32).to_le_bytes());
            file.extend(250_000u32.to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend((frame.len() as u32).to_le_bytes());
            file.extend(frame);
        }
        file
    }

    fn block(kind: u32, body: &[u8]) -> Vec<u8> {
        let padded = body.len().div_ceil(4) * 4;
        let length = (12 + padded) as u32;
        let mut block = kind.to_le_bytes().to_vec();
        block.extend(length.to_le_bytes());
        block.extend(body);
        block.extend(vec![0; padded - body.len()]);
        block.extend(length.to_le_bytes());
        block
    }

    fn pcapng(frames: &[Vec<u8>]) -> Vec<u8> {
        let mut section = 0x1A2B_3C4Du32.to_le_bytes().to_vec();
        section.extend([1, 0, 0, 0]);
        section.extend(u64::MAX.to_le_bytes());
        let mut file = block(0x0A0D_0D0A, &section);
        // Ethernet, snaplen 65535, if_tsresol = 10^-9.
        let mut interface = vec![1, 0, 0, 0];
        interface.extend(65535u32.to_le_bytes());
        interface.extend([9, 0, 1, 0, 9, 0, 0, 0, 0, 0, 0, 0]);
        file.extend(block(1, &interface));
        for frame in frames {
            let ticks = 1_700_000_000_000_000_000u64;
            let mut packet = 0u32.to_le_bytes().to_vec();
            packet.extend(((ticks >> 32) as u32).to_le_bytes());
            packet.extend((ticks as u32).to_le_bytes());
            packet.extend((frame.len() as u32).to_le_bytes());
            packet.extend((frame.len() as u32).to_le_bytes());
            packet.extend(frame);
            file.extend(block(6, &packet));
        }
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
    fn reads_classic_and_ng_captures_alike() {
        for (bytes, kind) in [(classic(&frames()), "pcap"), (pcapng(&frames()), "pcapng")] {
            assert!(is_pcap(&bytes), "{kind}");
            let report = inspect(&bytes);
            assert!(report.kind.contains(kind));
            assert_eq!(property(&report, "Packets"), "3", "{kind}");
            assert_eq!(property(&report, "IP packets decoded"), "3", "{kind}");
            assert_eq!(property(&report, "Link types"), "Ethernet");
            assert_eq!(property(&report, "DNS queries"), "update.example.net x1");
            assert_eq!(property(&report, "HTTP hosts"), "198.51.100.7 x1");
            assert_eq!(property(&report, "TLS server names"), "cdn.example.org x1");
            assert!(property(&report, "Top service ports").contains("tcp/443 x1"));
            assert!(property(&report, "Time range (UTC)").starts_with("2023-11-14T22:13:20Z"));
            assert_eq!(
                report.suspicious_properties,
                ["cleartext HTTP request to an IP address host: http://198.51.100.7/payload.bin"]
            );
            let text = report.analysis_text();
            for value in ["update.example.net", "cdn.example.org", "203.0.113.5"] {
                assert!(text.contains(value), "{kind}: {value}");
            }
        }
    }

    #[test]
    fn truncated_and_garbage_captures_are_noted() {
        let mut bytes = classic(&frames());
        bytes.truncate(bytes.len() - 10);
        let report = inspect(&bytes);
        assert_eq!(property(&report, "Packets"), "2");
        assert!(report.notes.iter().any(|note| note.contains("truncated")));

        let mut garbage = vec![0x0A, 0x0D, 0x0D, 0x0A];
        garbage.extend([0xFF; 64]);
        let report = inspect(&garbage);
        assert_eq!(property(&report, "Packets"), "0");
        assert!(!is_pcap(b"GIF89a"));
    }
}
