//! .NET (CLI) metadata inspection for managed PE files, following ECMA-335
//! partition II: the CLI header, the metadata root and its streams, and the
//! `#~` table stream, from which the assembly identity, referenced assemblies,
//! P/Invoke imports and member references are read. IL is never executed or
//! decompiled; every read is bounds-checked.

use serde::Serialize;

use super::binary::{read_c_string, read_u16, read_u32};

const MAX_LIST: usize = 512;
const MAX_NAME_BYTES: usize = 1_024;
/// Rows read from one table; larger tables are counted but not listed.
const MAX_ROWS_READ: u32 = 200_000;

#[derive(Debug, Clone, Serialize)]
pub struct DotNetReport {
    pub runtime_version: String,
    pub flags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assembly_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assembly_version: Option<String>,
    pub type_count: u32,
    pub method_count: u32,
    pub assembly_references: Vec<String>,
    pub native_modules: Vec<String>,
    /// P/Invoke imports as `module!function`.
    pub pinvoke_imports: Vec<String>,
    /// Member references worth attention, as `Namespace.Type::Member`.
    pub notable_references: Vec<String>,
    pub lists_truncated: bool,
}

// Table numbers used by name.
const MODULE: usize = 0x00;
const TYPE_REF: usize = 0x01;
const TYPE_DEF: usize = 0x02;
const FIELD: usize = 0x04;
const METHOD_DEF: usize = 0x06;
const PARAM: usize = 0x08;
const INTERFACE_IMPL: usize = 0x09;
const MEMBER_REF: usize = 0x0A;
const DECL_SECURITY: usize = 0x0E;
const STAND_ALONE_SIG: usize = 0x11;
const EVENT: usize = 0x14;
const PROPERTY: usize = 0x17;
const MODULE_REF: usize = 0x1A;
const TYPE_SPEC: usize = 0x1B;
const IMPL_MAP: usize = 0x1C;
const ASSEMBLY: usize = 0x20;
const ASSEMBLY_REF: usize = 0x23;
const FILE: usize = 0x26;
const EXPORTED_TYPE: usize = 0x27;
const MANIFEST_RESOURCE: usize = 0x28;
const GENERIC_PARAM: usize = 0x2A;
const METHOD_SPEC: usize = 0x2B;
const GENERIC_PARAM_CONSTRAINT: usize = 0x2C;
/// Tag value with no table, used by `CustomAttributeType`.
const NONE: usize = usize::MAX;

#[derive(Clone, Copy)]
enum Coded {
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshal,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    CustomAttributeType,
    ResolutionScope,
}

impl Coded {
    fn tables(self) -> &'static [usize] {
        match self {
            Self::TypeDefOrRef => &[TYPE_DEF, TYPE_REF, TYPE_SPEC],
            Self::HasConstant => &[FIELD, PARAM, PROPERTY],
            Self::HasCustomAttribute => &[
                METHOD_DEF,
                FIELD,
                TYPE_REF,
                TYPE_DEF,
                PARAM,
                INTERFACE_IMPL,
                MEMBER_REF,
                MODULE,
                DECL_SECURITY,
                PROPERTY,
                EVENT,
                STAND_ALONE_SIG,
                MODULE_REF,
                TYPE_SPEC,
                ASSEMBLY,
                ASSEMBLY_REF,
                FILE,
                EXPORTED_TYPE,
                MANIFEST_RESOURCE,
                GENERIC_PARAM,
                GENERIC_PARAM_CONSTRAINT,
                METHOD_SPEC,
            ],
            Self::HasFieldMarshal => &[FIELD, PARAM],
            Self::HasDeclSecurity => &[TYPE_DEF, METHOD_DEF, ASSEMBLY],
            Self::MemberRefParent => &[TYPE_DEF, TYPE_REF, MODULE_REF, METHOD_DEF, TYPE_SPEC],
            Self::HasSemantics => &[EVENT, PROPERTY],
            Self::MethodDefOrRef => &[METHOD_DEF, MEMBER_REF],
            Self::MemberForwarded => &[FIELD, METHOD_DEF],
            Self::CustomAttributeType => &[NONE, NONE, METHOD_DEF, MEMBER_REF, NONE],
            Self::ResolutionScope => &[MODULE, MODULE_REF, ASSEMBLY_REF, TYPE_REF],
        }
    }

    fn tag_bits(self) -> u32 {
        let count = self.tables().len() as u32;
        u32::BITS - (count - 1).leading_zeros()
    }
}

#[derive(Clone, Copy)]
enum Column {
    U16,
    U32,
    /// Two one-byte fields stored together (Constant.Type and padding).
    Pad2,
    Str,
    Guid,
    Blob,
    Index(usize),
    CodedIndex(Coded),
}

/// Row layouts of tables 0x00..=0x23 (ECMA-335 II.22). Tables after
/// AssemblyRef are never read, so their layouts are not needed.
fn schema(table: usize) -> Option<&'static [Column]> {
    use Coded as C;
    use Column::*;
    Some(match table {
        0x00 => &[U16, Str, Guid, Guid, Guid],
        0x01 => &[CodedIndex(C::ResolutionScope), Str, Str],
        0x02 => &[
            U32,
            Str,
            Str,
            CodedIndex(C::TypeDefOrRef),
            Index(FIELD),
            Index(METHOD_DEF),
        ],
        0x03 => &[Index(FIELD)],
        0x04 => &[U16, Str, Blob],
        0x05 => &[Index(METHOD_DEF)],
        0x06 => &[U32, U16, U16, Str, Blob, Index(PARAM)],
        0x07 => &[Index(PARAM)],
        0x08 => &[U16, U16, Str],
        0x09 => &[Index(TYPE_DEF), CodedIndex(C::TypeDefOrRef)],
        0x0A => &[CodedIndex(C::MemberRefParent), Str, Blob],
        0x0B => &[Pad2, CodedIndex(C::HasConstant), Blob],
        0x0C => &[
            CodedIndex(C::HasCustomAttribute),
            CodedIndex(C::CustomAttributeType),
            Blob,
        ],
        0x0D => &[CodedIndex(C::HasFieldMarshal), Blob],
        0x0E => &[U16, CodedIndex(C::HasDeclSecurity), Blob],
        0x0F => &[U16, U32, Index(TYPE_DEF)],
        0x10 => &[U32, Index(FIELD)],
        0x11 => &[Blob],
        0x12 => &[Index(TYPE_DEF), Index(EVENT)],
        0x13 => &[Index(EVENT)],
        0x14 => &[U16, Str, CodedIndex(C::TypeDefOrRef)],
        0x15 => &[Index(TYPE_DEF), Index(PROPERTY)],
        0x16 => &[Index(PROPERTY)],
        0x17 => &[U16, Str, Blob],
        0x18 => &[U16, Index(METHOD_DEF), CodedIndex(C::HasSemantics)],
        0x19 => &[
            Index(TYPE_DEF),
            CodedIndex(C::MethodDefOrRef),
            CodedIndex(C::MethodDefOrRef),
        ],
        0x1A => &[Str],
        0x1B => &[Blob],
        0x1C => &[U16, CodedIndex(C::MemberForwarded), Str, Index(MODULE_REF)],
        0x1D => &[U32, Index(FIELD)],
        0x1E => &[U32, U32],
        0x1F => &[U32],
        0x20 => &[U32, U16, U16, U16, U16, U32, Blob, Str, Str],
        0x21 => &[U32],
        0x22 => &[U32, U32, U32],
        0x23 => &[U16, U16, U16, U16, U32, Blob, Str, Str, Blob],
        _ => return None,
    })
}

/// Sizes of heap indexes and table row counts, which together fix every
/// column width.
struct Layout {
    rows: [u32; 64],
    wide_strings: bool,
    wide_guid: bool,
    wide_blob: bool,
}

impl Layout {
    fn width(&self, column: Column) -> usize {
        match column {
            Column::U16 | Column::Pad2 => 2,
            Column::U32 => 4,
            Column::Str => self.heap(self.wide_strings),
            Column::Guid => self.heap(self.wide_guid),
            Column::Blob => self.heap(self.wide_blob),
            Column::Index(table) => {
                if self.rows[table] < 0x1_0000 {
                    2
                } else {
                    4
                }
            }
            Column::CodedIndex(kind) => {
                let largest = kind
                    .tables()
                    .iter()
                    .filter(|table| **table != NONE)
                    .map(|table| self.rows[*table])
                    .max()
                    .unwrap_or(0);
                if largest < (1 << (16 - kind.tag_bits())) {
                    2
                } else {
                    4
                }
            }
        }
    }

    fn heap(&self, wide: bool) -> usize {
        if wide { 4 } else { 2 }
    }

    fn row_size(&self, table: usize) -> Option<usize> {
        Some(
            schema(table)?
                .iter()
                .map(|column| self.width(*column))
                .sum(),
        )
    }
}

/// A located table: where its rows start and how wide one row is.
#[derive(Clone, Copy)]
struct Table {
    start: usize,
    row_size: usize,
    rows: u32,
}

struct Metadata<'a> {
    tables: &'a [u8],
    strings: &'a [u8],
    blobs: &'a [u8],
    layout: Layout,
    located: [Option<Table>; 0x24],
}

impl Metadata<'_> {
    /// Reads column `column` of 1-based row `row` of `table` as an integer.
    fn cell(&self, table: usize, row: u32, column: usize) -> Option<u32> {
        let located = self.located.get(table).copied().flatten()?;
        if row == 0 || row > located.rows.min(MAX_ROWS_READ) {
            return None;
        }
        let columns = schema(table)?;
        let mut offset = located.start + (row as usize - 1) * located.row_size;
        for kind in &columns[..column] {
            offset += self.layout.width(*kind);
        }
        match self.layout.width(columns[column]) {
            2 => read_u16(self.tables, offset, true).map(u32::from),
            _ => read_u32(self.tables, offset, true),
        }
    }

    fn string(&self, index: u32) -> Option<String> {
        read_c_string(self.strings, index as usize, MAX_NAME_BYTES)
            .filter(|value| !value.is_empty())
    }

    /// A `#Blob` heap entry; its length prefix is ECMA-335 compressed.
    fn blob(&self, index: u32) -> Option<&[u8]> {
        let start = index as usize;
        let first = *self.blobs.get(start)?;
        let (length, header) = if first & 0x80 == 0 {
            (usize::from(first), 1)
        } else if first & 0xC0 == 0x80 {
            let second = *self.blobs.get(start + 1)?;
            ((usize::from(first & 0x3F) << 8) | usize::from(second), 2)
        } else {
            let rest = self.blobs.get(start + 1..start + 4)?;
            (
                (usize::from(first & 0x1F) << 24)
                    | (usize::from(rest[0]) << 16)
                    | (usize::from(rest[1]) << 8)
                    | usize::from(rest[2]),
                4,
            )
        };
        self.blobs.get(start + header..start + header + length)
    }

    fn string_cell(&self, table: usize, row: u32, column: usize) -> Option<String> {
        self.string(self.cell(table, row, column)?)
    }

    fn rows(&self, table: usize) -> u32 {
        self.layout.rows[table]
    }

    fn version(&self, table: usize, row: u32, first: usize) -> Option<String> {
        let part = |offset| self.cell(table, row, first + offset);
        Some(format!(
            "{}.{}.{}.{}",
            part(0)?,
            part(1)?,
            part(2)?,
            part(3)?
        ))
    }

    /// `Namespace.Type` for a TypeRef row.
    fn type_ref_name(&self, row: u32) -> Option<String> {
        let name = self.string_cell(TYPE_REF, row, 1)?;
        Some(match self.string_cell(TYPE_REF, row, 2) {
            Some(namespace) => format!("{namespace}.{name}"),
            None => name,
        })
    }
}

/// Reads the CLI header at `cli_offset` and the metadata it points to, and
/// returns the report with its findings. `rva_to_offset` maps image addresses
/// to file offsets.
pub(super) fn inspect(
    bytes: &[u8],
    cli_offset: usize,
    rva_to_offset: impl Fn(u32) -> Option<usize>,
    warnings: &mut Vec<String>,
) -> Option<(DotNetReport, Vec<String>)> {
    let metadata_rva = read_u32(bytes, cli_offset + 8, true)?;
    let flags = read_u32(bytes, cli_offset + 16, true)?;
    let Some(root) = rva_to_offset(metadata_rva) else {
        warnings.push(".NET metadata cannot be mapped to file data".to_owned());
        return None;
    };
    if read_u32(bytes, root, true)? != 0x424A_5342 {
        warnings.push(".NET metadata signature is invalid".to_owned());
        return None;
    }
    let version_length = read_u32(bytes, root + 12, true)? as usize;
    if version_length > 255 {
        warnings.push(".NET metadata version string is too long".to_owned());
        return None;
    }
    let runtime_version = read_c_string(bytes, root + 16, version_length)
        .or_else(|| {
            bytes
                .get(root + 16..root + 16 + version_length)
                .map(|raw| String::from_utf8_lossy(raw).into_owned())
        })
        .unwrap_or_default();
    let after_version = root + 16 + version_length.next_multiple_of(4);
    let stream_count = read_u16(bytes, after_version + 2, true)?;

    let mut tables_stream = None;
    let mut strings_stream = None;
    let mut blob_stream = None;
    let mut cursor = after_version + 4;
    for _ in 0..stream_count.min(16) {
        let offset = read_u32(bytes, cursor, true)? as usize;
        let size = read_u32(bytes, cursor + 4, true)? as usize;
        let name = read_c_string(bytes, cursor + 8, 32)?;
        cursor += 8 + (name.len() + 1).next_multiple_of(4);
        let data =
            bytes.get(root.checked_add(offset)?..root.checked_add(offset)?.checked_add(size)?);
        match (name.as_str(), data) {
            ("#~" | "#-", Some(data)) => tables_stream = Some(data),
            ("#Strings", Some(data)) => strings_stream = Some(data),
            ("#Blob", Some(data)) => blob_stream = Some(data),
            (_, None) => warnings.push(format!(".NET stream {name} lies outside the file")),
            _ => {}
        }
    }

    let mut report = DotNetReport {
        runtime_version,
        flags: cli_flags(flags),
        module_name: None,
        assembly_name: None,
        assembly_version: None,
        type_count: 0,
        method_count: 0,
        assembly_references: Vec::new(),
        native_modules: Vec::new(),
        pinvoke_imports: Vec::new(),
        notable_references: Vec::new(),
        lists_truncated: false,
    };
    let (Some(tables), Some(strings)) = (tables_stream, strings_stream) else {
        warnings.push(".NET metadata has no table or string stream".to_owned());
        return Some((report, Vec::new()));
    };
    if let Some(metadata) =
        locate_tables(tables, strings, blob_stream.unwrap_or_default(), warnings)
    {
        read_identity(&metadata, &mut report);
    }
    let findings = findings(&report, strings);
    Some((report, findings))
}

fn cli_flags(flags: u32) -> Vec<String> {
    [
        (0x1, "IL only"),
        (0x2, "32-bit required"),
        (0x8, "strong-name signed"),
        (0x10, "native entry point"),
        (0x2_0000, "32-bit preferred"),
    ]
    .into_iter()
    .filter(|(bit, _)| flags & bit != 0)
    .map(|(_, name)| name.to_owned())
    .collect()
}

fn locate_tables<'a>(
    tables: &'a [u8],
    strings: &'a [u8],
    blobs: &'a [u8],
    warnings: &mut Vec<String>,
) -> Option<Metadata<'a>> {
    let heap_sizes = *tables.get(6)?;
    let valid = u64::from_le_bytes(tables.get(8..16)?.try_into().ok()?);
    let mut layout = Layout {
        rows: [0; 64],
        wide_strings: heap_sizes & 0x1 != 0,
        wide_guid: heap_sizes & 0x2 != 0,
        wide_blob: heap_sizes & 0x4 != 0,
    };
    let mut offset = 24;
    for table in 0..64 {
        if valid & (1 << table) != 0 {
            layout.rows[table] = read_u32(tables, offset, true)?;
            offset += 4;
        }
    }
    // Uncompressed (#-) streams may carry four extra bytes here.
    if heap_sizes & 0x40 != 0 {
        offset += 4;
    }
    let mut located = [None; 0x24];
    for (table, slot) in located.iter_mut().enumerate() {
        if valid & (1 << table) == 0 {
            continue;
        }
        let Some(row_size) = layout.row_size(table) else {
            warnings.push(format!(
                ".NET metadata table 0x{table:02X} has an unknown layout"
            ));
            return None;
        };
        let rows = layout.rows[table];
        *slot = Some(Table {
            start: offset,
            row_size,
            rows,
        });
        offset = offset.checked_add(row_size.checked_mul(rows as usize)?)?;
    }
    if offset > tables.len() {
        warnings.push(".NET metadata tables extend past their stream".to_owned());
    }
    Some(Metadata {
        tables,
        strings,
        blobs,
        layout,
        located,
    })
}

/// Notable framework members: reflection loading, decoding, process and
/// network activity, and native function pointers.
const NOTABLE: &[(&str, &str)] = &[
    ("System.Reflection.Assembly", "Load"),
    ("System.Reflection.Assembly", "LoadFile"),
    ("System.Reflection.Assembly", "LoadFrom"),
    ("System.Reflection.MethodBase", "Invoke"),
    ("System.Reflection.MethodInfo", "Invoke"),
    ("System.AppDomain", "Load"),
    ("System.Convert", "FromBase64String"),
    (
        "System.Security.Cryptography.SymmetricAlgorithm",
        "CreateDecryptor",
    ),
    ("System.Diagnostics.Process", "Start"),
    ("System.Net.WebClient", "DownloadData"),
    ("System.Net.WebClient", "DownloadFile"),
    ("System.Net.WebClient", "DownloadString"),
    ("System.Net.Http.HttpClient", "GetByteArrayAsync"),
    (
        "System.Runtime.InteropServices.Marshal",
        "GetDelegateForFunctionPointer",
    ),
    ("System.Runtime.InteropServices.Marshal", "Copy"),
    ("Microsoft.Win32.Registry", "SetValue"),
    ("Microsoft.Win32.RegistryKey", "SetValue"),
];

fn read_identity(metadata: &Metadata<'_>, report: &mut DotNetReport) {
    report.type_count = metadata.rows(TYPE_DEF);
    report.method_count = metadata.rows(METHOD_DEF);
    report.module_name = metadata.string_cell(MODULE, 1, 1);
    if metadata.rows(ASSEMBLY) > 0 {
        report.assembly_name = metadata.string_cell(ASSEMBLY, 1, 7);
        report.assembly_version = metadata.version(ASSEMBLY, 1, 1);
    }
    let push = |list: &mut Vec<String>, value: String, truncated: &mut bool| {
        if list.len() < MAX_LIST {
            if !list.contains(&value) {
                list.push(value);
            }
        } else {
            *truncated = true;
        }
    };
    let mut truncated = false;
    for row in 1..=metadata.rows(ASSEMBLY_REF).min(MAX_ROWS_READ) {
        if let Some(name) = metadata.string_cell(ASSEMBLY_REF, row, 6) {
            let version = metadata.version(ASSEMBLY_REF, row, 0).unwrap_or_default();
            push(
                &mut report.assembly_references,
                format!("{name} {version}"),
                &mut truncated,
            );
        }
    }
    for row in 1..=metadata.rows(MODULE_REF).min(MAX_ROWS_READ) {
        if let Some(name) = metadata.string_cell(MODULE_REF, row, 0) {
            push(&mut report.native_modules, name, &mut truncated);
        }
    }
    for row in 1..=metadata.rows(IMPL_MAP).min(MAX_ROWS_READ) {
        let function = metadata.string_cell(IMPL_MAP, row, 2);
        let module = metadata
            .cell(IMPL_MAP, row, 3)
            .and_then(|scope| metadata.string_cell(MODULE_REF, scope, 0));
        if let Some(function) = function {
            let module = module.unwrap_or_else(|| "?".to_owned());
            push(
                &mut report.pinvoke_imports,
                format!("{module}!{function}"),
                &mut truncated,
            );
        }
    }
    let parent_bits = Coded::MemberRefParent.tag_bits();
    for row in 1..=metadata.rows(MEMBER_REF).min(MAX_ROWS_READ) {
        let Some(parent) = metadata.cell(MEMBER_REF, row, 0) else {
            continue;
        };
        // Tag 1 is TypeRef.
        if parent & ((1 << parent_bits) - 1) != 1 {
            continue;
        }
        let (Some(type_name), Some(member)) = (
            metadata.type_ref_name(parent >> parent_bits),
            metadata.string_cell(MEMBER_REF, row, 1),
        ) else {
            continue;
        };
        if NOTABLE
            .iter()
            .any(|(known_type, known_member)| *known_type == type_name && *known_member == member)
        {
            let from_bytes = member == "Load"
                && metadata
                    .cell(MEMBER_REF, row, 2)
                    .and_then(|index| metadata.blob(index))
                    .is_some_and(takes_byte_array);
            let suffix = if from_bytes { "(byte[])" } else { "" };
            push(
                &mut report.notable_references,
                format!("{type_name}::{member}{suffix}"),
                &mut truncated,
            );
        }
    }
    report.lists_truncated = truncated;
}

/// True when a method signature takes a `byte[]` parameter: SZARRAY (0x1D)
/// of U1 (0x05) after the calling convention and parameter count.
fn takes_byte_array(signature: &[u8]) -> bool {
    signature
        .get(2..)
        .is_some_and(|rest| rest.windows(2).any(|pair| pair == [0x1D, 0x05]))
}

/// Obfuscator marker types and the product they identify.
const OBFUSCATOR_MARKERS: &[(&str, &str)] = &[
    ("ConfusedByAttribute", "ConfuserEx"),
    ("DotfuscatorAttribute", "Dotfuscator"),
    ("SmartAssembly.Attributes", "SmartAssembly"),
    ("BabelObfuscatorAttribute", "Babel"),
    ("CryptoObfuscator", "Crypto Obfuscator"),
    ("ObfuscatedByGoliath", "Goliath"),
    ("YanoAttribute", "Yano"),
    ("Xenocode.Client.Attributes", "Xenocode"),
    ("NineRays.Obfuscator", "Spices.Net"),
];

const INJECTION_APIS: &[&str] = &[
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "NtUnmapViewOfSection",
    "ZwUnmapViewOfSection",
    "SetThreadContext",
    "QueueUserAPC",
    "VirtualProtectEx",
    "NtWriteVirtualMemory",
];

/// Findings derived from the report and the raw `#Strings` heap.
fn findings(report: &DotNetReport, strings_heap: &[u8]) -> Vec<String> {
    let mut findings = Vec::new();
    for (marker, product) in OBFUSCATOR_MARKERS {
        if strings_heap
            .windows(marker.len())
            .any(|window| window == marker.as_bytes())
        {
            findings.push(format!(
                ".NET assembly carries the {product} obfuscator marker ({marker})"
            ));
        }
    }
    let injection: Vec<&str> = report
        .pinvoke_imports
        .iter()
        .filter_map(|import| import.rsplit('!').next())
        .filter(|function| INJECTION_APIS.contains(function))
        .collect();
    if !injection.is_empty() {
        findings.push(format!(
            ".NET assembly P/Invokes process-injection APIs: {}",
            injection.join(", ")
        ));
    }
    let references = |member: &str| {
        report
            .notable_references
            .iter()
            .any(|reference| reference.ends_with(member))
    };
    if (references("Assembly::Load(byte[])") || references("AppDomain::Load(byte[])"))
        && (references("::FromBase64String") || references("::CreateDecryptor"))
    {
        findings.push(
            ".NET assembly decodes data and loads an assembly from memory, a common loader pattern"
                .to_owned(),
        );
    }
    findings
}

#[cfg(test)]
mod tests {
    use super::{Coded, Column, DotNetReport, Layout, findings, takes_byte_array};

    fn layout(rows: &[(usize, u32)]) -> Layout {
        let mut layout = Layout {
            rows: [0; 64],
            wide_strings: false,
            wide_guid: false,
            wide_blob: false,
        };
        for (table, count) in rows {
            layout.rows[*table] = *count;
        }
        layout
    }

    #[test]
    fn coded_index_tag_bits_follow_ecma_335() {
        assert_eq!(Coded::TypeDefOrRef.tag_bits(), 2);
        assert_eq!(Coded::HasCustomAttribute.tag_bits(), 5);
        assert_eq!(Coded::MemberRefParent.tag_bits(), 3);
        assert_eq!(Coded::CustomAttributeType.tag_bits(), 3);
        assert_eq!(Coded::MethodDefOrRef.tag_bits(), 1);
    }

    #[test]
    fn index_widths_grow_with_row_counts() {
        let small = layout(&[(0x02, 100)]);
        assert_eq!(small.width(Column::Index(0x02)), 2);
        assert_eq!(small.width(Column::CodedIndex(Coded::TypeDefOrRef)), 2);
        // 2 tag bits leave 14 bits: 16384 rows need a four-byte index.
        let large = layout(&[(0x02, 16_384)]);
        assert_eq!(large.width(Column::CodedIndex(Coded::TypeDefOrRef)), 4);
        assert_eq!(large.width(Column::Index(0x02)), 2);
        assert_eq!(layout(&[(0x02, 70_000)]).width(Column::Index(0x02)), 4);
        // Module: Generation + Name + 3 GUIDs with two-byte heaps.
        assert_eq!(small.row_size(0x00), Some(10));
        assert_eq!(small.row_size(0x24), None);
    }

    #[test]
    fn byte_array_parameters_are_recognized() {
        // static Assembly Load(byte[]): DEFAULT, 1 param, CLASS token, SZARRAY U1.
        assert!(takes_byte_array(&[0x00, 0x01, 0x12, 0x09, 0x1D, 0x05]));
        // static Assembly Load(string): ... STRING (0x0E).
        assert!(!takes_byte_array(&[0x00, 0x01, 0x12, 0x09, 0x0E]));
        assert!(!takes_byte_array(&[0x1D, 0x05]));
    }

    fn report(pinvoke: &[&str], notable: &[&str]) -> DotNetReport {
        DotNetReport {
            runtime_version: "v4.0.30319".to_owned(),
            flags: Vec::new(),
            module_name: None,
            assembly_name: None,
            assembly_version: None,
            type_count: 0,
            method_count: 0,
            assembly_references: Vec::new(),
            native_modules: Vec::new(),
            pinvoke_imports: pinvoke.iter().map(|value| (*value).to_owned()).collect(),
            notable_references: notable.iter().map(|value| (*value).to_owned()).collect(),
            lists_truncated: false,
        }
    }

    #[test]
    fn findings_cover_obfuscators_injection_and_loaders() {
        let text = findings(
            &report(
                &["kernel32.dll!VirtualAllocEx", "kernel32.dll!GetTickCount"],
                &[
                    "System.Convert::FromBase64String",
                    "System.Reflection.Assembly::Load(byte[])",
                ],
            ),
            b"\0Program\0ConfusedByAttribute\0",
        )
        .join("\n");
        assert!(text.contains("ConfuserEx"), "{text}");
        assert!(
            text.contains("process-injection APIs: VirtualAllocEx"),
            "{text}"
        );
        assert!(!text.contains("GetTickCount"), "{text}");
        assert!(text.contains("loader pattern"), "{text}");
    }

    #[test]
    fn loading_by_name_is_not_a_loader_pattern() {
        let text = findings(
            &report(
                &[],
                &[
                    "System.Convert::FromBase64String",
                    "System.Reflection.Assembly::Load",
                ],
            ),
            b"",
        );
        assert!(text.is_empty(), "{text:?}");
    }
}
