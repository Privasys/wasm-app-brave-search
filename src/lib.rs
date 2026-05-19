// Copyright (c) Privasys. All rights reserved.
// Licensed under the GNU Affero General Public License v3.0. See LICENSE file for details.

//! # Brave Web Search — enclave-side implementation
//!
//! The Brave Search subscription token is installed at runtime via
//! the `@config-api`-decorated `set-api-key` export. Until the
//! deployer (the app owner) calls it, the host runtime freezes all
//! other exports and returns `"app is awaiting initial
//! configuration"`. After the call we persist the token to the
//! per-app sealed KV store (so it survives wasm component
//! reinstantiation between calls within the same enclave-process
//! lifetime — the host may unload the instance to reclaim memory)
//! and call `privasys:enclave-os/attestation.set-config-complete`
//! to lift the freeze. The token never crosses an untrusted
//! boundary. On enclave restart the freeze is re-armed and the key
//! must be re-injected before traffic flows again.
//!
//! Search calls go to the Brave Web Search API over attestable
//! HTTPS via `privasys:enclave-os/https.fetch`; TLS terminates
//! inside the enclave so the token never leaks to the host.
//!
//! Endpoint: `GET https://api.search.brave.com/res/v1/web/search`
//! Header:   `X-Subscription-Token: <api-key>`
//! Response shape (subset we parse):
//!   `{ "web": { "results": [ { "title", "url", "description" }, ... ] } }`

#[allow(warnings)]
mod bindings;

use bindings::{Guest, SearchHit, SearchResponse};
use bindings::privasys::enclave_os::{attestation, https};

const API_BASE: &str = "https://api.search.brave.com/res/v1/web/search";
const DEFAULT_COUNT: u32 = 10;
const MAX_COUNT: u32 = 20;
const API_KEY_KV: &str = "api_key";

struct BraveSearch;

impl Guest for BraveSearch {
    fn search(query: String, count: u32) -> SearchResponse {
        match perform_search(&query, count) {
            Ok(body) => match parse_hits(&body) {
                Ok(hits) => SearchResponse {
                    query,
                    hits,
                    error: String::new(),
                },
                Err(e) => SearchResponse {
                    query,
                    hits: Vec::new(),
                    error: format!("parse failed: {e}"),
                },
            },
            Err(e) => SearchResponse {
                query,
                hits: Vec::new(),
                error: e,
            },
        }
    }

    fn search_raw(query: String, count: u32) -> String {
        match perform_search(&query, count) {
            Ok(body) => body,
            Err(e) => format!(r#"{{"error":{}}}"#, json_escape(&e)),
        }
    }

    fn set_api_key(api_key: String) -> Result<(), String> {
        let trimmed = api_key.trim();
        if trimmed.is_empty() {
            return Err("api-key must not be empty".to_string());
        }
        // Brave subscription tokens are ASCII; reject anything else
        // early so we don't ship UTF-8 sequences in an HTTP header.
        if !trimmed.is_ascii() {
            return Err("api-key must be ASCII".to_string());
        }
        // Persist to the per-app sealed KV store so it survives
        // component instance reinstantiation between calls.
        kv::write(API_KEY_KV, trimmed)?;
        // Lift the host-enforced freeze gate so `search` /
        // `search-raw` become callable. Idempotent on the host
        // side: re-calling set-api-key after a successful unfreeze
        // simply rotates the token in-place.
        attestation::set_config_complete()
            .map_err(|e| format!("set-config-complete failed: {e}"))?;
        Ok(())
    }
}

bindings::export!(BraveSearch with_types_in bindings);

// ---------------------------------------------------------------------------
//  Core
// ---------------------------------------------------------------------------

fn perform_search(query: &str, count: u32) -> Result<String, String> {
    // Defensive: the host's freeze gate prevents search() from
    // running before set-api-key has succeeded, so this branch is
    // effectively unreachable in production.
    let api_key = kv::read(API_KEY_KV)
        .ok_or_else(|| "api-key has not been installed; call set-api-key first".to_string())?;

    let n = if count == 0 { DEFAULT_COUNT } else { count.min(MAX_COUNT).max(1) };
    let url = format!(
        "{}?q={}&count={}",
        API_BASE,
        url_encode(query),
        n,
    );

    let (status, _headers, body) = {
        let req = https::Request {
            method: https::Method::Get,
            url: url.clone(),
            headers: vec![
                ("X-Subscription-Token".into(), api_key),
                ("Accept".into(), "application/json".into()),
                ("Accept-Encoding".into(), "identity".into()),
            ],
            body: None,
            ratls: None,
            ca_roots_der: None,
        };
        let resp = https::fetch(&req).map_err(|e| format!("https fetch failed: {e}"))?;
        (resp.status, resp.headers, resp.body)
    };

    let body_str = String::from_utf8(body)
        .map_err(|_| "Brave API response was not valid UTF-8".to_string())?;

    if !(200..300).contains(&status) {
        return Err(format!("Brave API returned HTTP {status}: {}",
            truncate(&body_str, 256)));
    }
    Ok(body_str)
}

// ---------------------------------------------------------------------------
//  Minimal JSON extractor for Brave's `web.results[].{title,url,description}`
// ---------------------------------------------------------------------------
//
// We deliberately avoid pulling in `serde_json` to keep the cwasm
// tiny.  Brave's responses are well-formed and predictable, so a
// forgiving linear scan is sufficient.  If a field is missing we
// substitute an empty string rather than fail.

fn parse_hits(body: &str) -> Result<Vec<SearchHit>, String> {
    // Locate the `"web"` key, then drill into its `"results"` array.
    // Searching for `"web"` directly avoids confusion with other
    // top-level objects (`query`, `mixed`, `videos`, ...).
    let web_key = match body.find("\"web\"") {
        Some(i) => i,
        None => return Ok(Vec::new()),
    };
    // Find the opening brace of the web object.
    let web_obj_start = body[web_key..].find('{')
        .ok_or_else(|| "web has no opening brace".to_string())?
        + web_key;
    let web_obj_end = find_matching_brace(body.as_bytes(), web_obj_start)
        .ok_or_else(|| "web object is unterminated".to_string())?;
    let web_obj = &body[web_obj_start..=web_obj_end];

    let results_key = match web_obj.find("\"results\"") {
        Some(i) => i,
        None => return Ok(Vec::new()),
    };
    let bracket = web_obj[results_key..].find('[')
        .ok_or_else(|| "results has no opening bracket".to_string())?;
    let array_start = results_key + bracket + 1;

    // Walk objects inside the array, tracking brace depth and string state.
    let bytes = web_obj.as_bytes();
    let mut hits = Vec::new();
    let mut i = array_start;
    while i < bytes.len() {
        // Skip whitespace and commas
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | b'\r' | b',') {
            i += 1;
        }
        if i >= bytes.len() || bytes[i] == b']' {
            break;
        }
        if bytes[i] != b'{' {
            // Unexpected — bail rather than infinite loop.
            return Err(format!("expected '{{' at offset {i}, got byte {:?}", bytes[i]));
        }
        let obj_start = i;
        let obj_end = find_matching_brace(bytes, obj_start)
            .ok_or_else(|| "unterminated object in results".to_string())?;
        let obj = &web_obj[obj_start..=obj_end];
        hits.push(SearchHit {
            title: extract_string_field(obj, "title").unwrap_or_default(),
            url: extract_string_field(obj, "url").unwrap_or_default(),
            description: extract_string_field(obj, "description").unwrap_or_default(),
        });
        i = obj_end + 1;
    }
    Ok(hits)
}

/// Return the byte index of the matching `}` for a `{` at `start`,
/// respecting JSON string quoting and backslash escapes.
fn find_matching_brace(bytes: &[u8], start: usize) -> Option<usize> {
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut i = start;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else {
            match c {
                b'"' => in_string = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Extract `"<field>": "<value>"` (with JSON unescape) from a flat
/// JSON object string. Returns `None` if the field is missing or its
/// value is not a string.
fn extract_string_field(obj: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let mut idx = 0;
    while let Some(found) = obj[idx..].find(&needle) {
        let key_end = idx + found + needle.len();
        // Ensure we matched a key (followed by `:`), not a substring
        // inside another value.
        let after = obj[key_end..].trim_start();
        if !after.starts_with(':') {
            idx = key_end;
            continue;
        }
        let value_start = key_end + (obj[key_end..].len() - after.len()) + 1; // skip ':'
        let value_str = obj[value_start..].trim_start();
        if !value_str.starts_with('"') {
            return None;
        }
        // Walk the string with escape handling.
        let bytes = value_str.as_bytes();
        let mut j = 1;
        let mut out = String::new();
        while j < bytes.len() {
            let c = bytes[j];
            if c == b'\\' && j + 1 < bytes.len() {
                let esc = bytes[j + 1];
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'n' => out.push('\n'),
                    b't' => out.push('\t'),
                    b'r' => out.push('\r'),
                    b'b' => out.push('\u{0008}'),
                    b'f' => out.push('\u{000C}'),
                    b'u' if j + 5 < bytes.len() => {
                        let hex = std::str::from_utf8(&bytes[j + 2..j + 6]).ok()?;
                        let cp = u32::from_str_radix(hex, 16).ok()?;
                        if let Some(ch) = char::from_u32(cp) {
                            out.push(ch);
                        }
                        j += 6;
                        continue;
                    }
                    _ => out.push(esc as char),
                }
                j += 2;
            } else if c == b'"' {
                return Some(out);
            } else {
                // UTF-8 safe: append byte if ASCII; for multi-byte
                // codepoints, find the char boundary and push it.
                if c < 0x80 {
                    out.push(c as char);
                    j += 1;
                } else {
                    // Find next char boundary in the slice.
                    let s = &value_str[j..];
                    let ch = s.chars().next()?;
                    let len = ch.len_utf8();
                    out.push(ch);
                    j += len;
                }
            }
        }
        return None;
    }
    None
}

// ---------------------------------------------------------------------------
//  URL encoding (RFC 3986 unreserved set)
// ---------------------------------------------------------------------------

fn url_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for &b in input.as_bytes() {
        let safe = matches!(b,
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9'
            | b'-' | b'_' | b'.' | b'~'
        );
        if safe {
            out.push(b as char);
        } else {
            out.push('%');
            out.push(hex_digit(b >> 4));
            out.push(hex_digit(b & 0x0F));
        }
    }
    out
}

fn hex_digit(n: u8) -> char {
    match n {
        0..=9 => (b'0' + n) as char,
        10..=15 => (b'A' + (n - 10)) as char,
        _ => unreachable!(),
    }
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        let mut end = max;
        while !s.is_char_boundary(end) && end > 0 {
            end -= 1;
        }
        format!("{}…", &s[..end])
    }
}

// ─── Sealed-KV helpers ────────────────────────────────────────────
//
// The host exposes one preopened directory per app, backed by the
// per-app sealed KV store. Each "file" is a KV entry. Persisting the
// API key here means it survives wasm component instance
// reinstantiation between calls — the host is free to unload an idle
// instance to reclaim memory, and our `static Mutex<Option<String>>`
// would not survive that. See wasm-app-example for the same pattern.

mod kv {
    use crate::bindings::wasi::filesystem::{preopens, types as fs};

    pub fn write(key: &str, value: &str) -> Result<(), String> {
        let dirs = preopens::get_directories();
        if dirs.is_empty() {
            return Err("no preopened directories".into());
        }
        let root = &dirs[0].0;

        let fd = root
            .open_at(
                fs::PathFlags::empty(),
                key,
                fs::OpenFlags::CREATE | fs::OpenFlags::TRUNCATE,
                fs::DescriptorFlags::WRITE,
            )
            .map_err(|e| format!("open failed: {e:?}"))?;

        fd.write(value.as_bytes(), 0)
            .map_err(|e| format!("write failed: {e:?}"))?;

        fd.sync_data().map_err(|e| format!("sync failed: {e:?}"))?;

        Ok(())
    }

    pub fn read(key: &str) -> Option<String> {
        let dirs = preopens::get_directories();
        if dirs.is_empty() {
            return None;
        }
        let root = &dirs[0].0;

        let fd = root
            .open_at(
                fs::PathFlags::empty(),
                key,
                fs::OpenFlags::empty(),
                fs::DescriptorFlags::READ,
            )
            .ok()?;

        let stat = fd.stat().ok()?;
        let (data, _) = fd.read(stat.size, 0).ok()?;
        String::from_utf8(data).ok()
    }
}
