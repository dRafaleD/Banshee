//! WebAssembly exports for the browser build of Banshee.
//!
//! The page copies a file into linear memory, calls an export, and reads back
//! a UTF-8 result. Nothing here can reach the network: the module imports no
//! host functions at all, and the page's Content-Security-Policy forbids
//! connections. Results are returned as `(pointer << 32) | length`.

use banshee::report::{ReportFormat, RuleSource};

const MAX_ENTRIES: usize = 10_000;
const MAX_DEPTH: u8 = 8;
const MAX_TOKENS: usize = 10_000;
/// Browsers hold the whole sample in memory; keep it well below the CLI limit.
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;

fn layout(length: usize) -> Option<std::alloc::Layout> {
    std::alloc::Layout::array::<u8>(length.max(1)).ok()
}

/// Allocates `length` bytes for the page to fill, or returns null. Free the
/// buffer with `banshee_free` and the same length.
#[unsafe(no_mangle)]
pub extern "C" fn banshee_alloc(length: usize) -> *mut u8 {
    match layout(length) {
        // SAFETY: the layout has a non-zero size.
        Some(layout) => unsafe { std::alloc::alloc(layout) },
        None => std::ptr::null_mut(),
    }
}

/// Releases a buffer returned by `banshee_alloc` or by an analysis export.
///
/// # Safety
/// `pointer` and `length` must come from this module and be freed only once.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn banshee_free(pointer: *mut u8, length: usize) {
    if let (false, Some(layout)) = (pointer.is_null(), layout(length)) {
        // SAFETY: the caller passes a pointer allocated with this same layout.
        unsafe { std::alloc::dealloc(pointer, layout) };
    }
}

/// Builds a unified report. `format` is 0 for JSON and 1 for the offline HTML
/// page. Rule source is optional (length 0). Errors are JSON `{"error": ...}`.
///
/// # Safety
/// Each pointer must reference `length` initialized bytes in this module's memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn banshee_report(
    input: *const u8,
    input_length: usize,
    name: *const u8,
    name_length: usize,
    rules: *const u8,
    rules_length: usize,
    format: u32,
) -> u64 {
    // SAFETY: forwarded from this function's contract.
    let (input, name, rules) = unsafe {
        (
            bytes(input, input_length),
            bytes(name, name_length),
            bytes(rules, rules_length),
        )
    };
    finish(report(input, name, rules, format))
}

/// Decodes and explains a single value, like `banshee whatis --json`.
///
/// # Safety
/// `input` must reference `input_length` initialized bytes in this module's memory.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn banshee_whatis(input: *const u8, input_length: usize) -> u64 {
    // SAFETY: forwarded from this function's contract.
    let input = unsafe { bytes(input, input_length) };
    let report = banshee::analysis::Analyzer::new(MAX_DEPTH).analyze_bytes(input);
    finish(serde_json::to_string(&report).map_err(|error| error.to_string()))
}

unsafe fn bytes<'a>(pointer: *const u8, length: usize) -> &'a [u8] {
    if pointer.is_null() || length == 0 {
        return &[];
    }
    // SAFETY: the caller guarantees the range is initialized module memory.
    unsafe { std::slice::from_raw_parts(pointer, length) }
}

fn report(input: &[u8], name: &[u8], rules: &[u8], format: u32) -> Result<String, String> {
    if input.len() > MAX_INPUT_BYTES {
        return Err("the browser build accepts files up to 64 MiB".to_owned());
    }
    let name = String::from_utf8_lossy(name);
    let rules = std::str::from_utf8(rules).map_err(|_| "rules must be UTF-8 TOML".to_owned())?;
    let rule_source = (!rules.trim().is_empty()).then_some(RuleSource::Inline {
        label: "rules pasted in the browser",
        source: rules,
    });
    let report = banshee::report::generate_from_bytes(
        input,
        &name,
        rule_source,
        MAX_ENTRIES,
        MAX_DEPTH,
        MAX_TOKENS,
    )
    .map_err(|error| format!("{error:#}"))?;
    let format = match format {
        0 => ReportFormat::Json,
        1 => ReportFormat::Html,
        _ => return Err("unknown output format".to_owned()),
    };
    let mut output = Vec::new();
    banshee::report::write_to(&mut output, &report, format)
        .map_err(|error| format!("{error:#}"))?;
    String::from_utf8(output).map_err(|error| error.to_string())
}

/// Moves a result into a leaked buffer and packs its location for the page.
fn finish(result: Result<String, String>) -> u64 {
    let text = result.unwrap_or_else(|error| serde_json::json!({ "error": error }).to_string());
    let bytes = text.into_bytes();
    let length = bytes.len();
    let pointer = banshee_alloc(length);
    if pointer.is_null() {
        return 0;
    }
    // SAFETY: `pointer` has room for `length` bytes and does not overlap `bytes`.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), pointer, length) };
    ((pointer as u64) << 32) | length as u64
}
