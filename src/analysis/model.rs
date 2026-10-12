use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EncodingKind {
    Base64,
    Hex,
    UrlEncoding,
    HtmlEntity,
    UnicodeEscape,
    Gzip,
    Zlib,
    Utf16Le,
    Xor,
    CharCodes,
    HexEscape,
    StringConcat,
    FormatString,
    ReversedString,
}

impl std::fmt::Display for EncodingKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Base64 => "Base64",
            Self::Hex => "Hex",
            Self::UrlEncoding => "URL encoding",
            Self::HtmlEntity => "HTML entity",
            Self::UnicodeEscape => "Unicode escape",
            Self::Gzip => "Gzip",
            Self::Zlib => "Zlib",
            Self::Utf16Le => "UTF-16LE",
            Self::Xor => "XOR",
            Self::CharCodes => "Character codes",
            Self::HexEscape => "Hex escapes",
            Self::StringConcat => "String concatenation",
            Self::FormatString => "Format operator",
            Self::ReversedString => "Reversed string",
        };
        formatter.write_str(name)
    }
}

impl EncodingKind {
    /// Whether this layer rewrites script source rather than decoding an encoding.
    pub fn is_script_transform(self) -> bool {
        matches!(
            self,
            Self::CharCodes
                | Self::HexEscape
                | Self::StringConcat
                | Self::FormatString
                | Self::ReversedString
        )
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Layer {
    pub depth: usize,
    pub kind: EncodingKind,
    pub confidence: f32,
    pub input: String,
    pub output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Domain,
    Hash,
    Ip,
    Jwt,
    Url,
}

impl std::fmt::Display for FindingKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name = match self {
            Self::Domain => "Domain",
            Self::Hash => "Hash",
            Self::Ip => "IP",
            Self::Jwt => "JWT",
            Self::Url => "URL",
        };
        formatter.write_str(name)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub kind: FindingKind,
    pub value: String,
    pub confidence: f32,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StopReason {
    NoFurtherEncoding,
    DepthLimit,
    SizeLimit,
    RepeatedValue,
    DecodeFailed,
}

#[derive(Debug, Clone, Serialize)]
pub struct AnalysisReport {
    pub original: String,
    pub layers: Vec<Layer>,
    pub final_value: String,
    pub confidence: f32,
    pub findings: Vec<Finding>,
    pub stop_reason: StopReason,
}
