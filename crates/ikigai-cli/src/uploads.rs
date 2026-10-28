//! The HTTP door's uploads and its spill, read from the config home (ledger #2244).
//!
//! `ikigai serve --http` installs ikigai-fs's file-backed spill facility over a directory of its
//! own under the config home, `<config home>/spill/http-<port>` (never `TMPDIR`, never an
//! environment variable), so a body larger than memory can be written to disk while it arrives.
//! An upload route takes its body that way; `config.toml` names them:
//!
//! ```toml
//! # <path pattern> <largest body in bytes> — one line per route, the route grammar of --routes
//! http.upload = "/media/{name} 4294967296"
//! # the rate an upload must keep after its grace, in bytes a second (default 16384)
//! http.upload_min_rate = 65536
//! # how long an upload may take before that rate applies, in seconds (default 30)
//! http.upload_grace = 10
//! # the most one request may spill, in bytes (default 1073741824, 1 GiB)
//! http.spill_ceiling = 4294967296
//! # the most all uploads in flight may hold on disk at once, in bytes (default 4 GiB)
//! http.spill_total = 17179869184
//! ```
//!
//! A caller spills only when its capability holds `urn:cap:stream:spill:<bytes>` (with `--cap`,
//! grant it there); without one, an upload route takes the body into memory under `--max-body`
//! like any other route. A line that does not parse stops the door at start-up, naming it.
use std::time::Duration;

/// The route key; it repeats, one line per route.
pub const ROUTE_KEY: &str = "http.upload";
/// The minimum-rate key.
pub const RATE_KEY: &str = "http.upload_min_rate";
/// The grace key.
pub const GRACE_KEY: &str = "http.upload_grace";
/// The per-request disk ceiling key.
pub const CEILING_KEY: &str = "http.spill_ceiling";
/// The all-uploads disk bound key.
pub const TOTAL_KEY: &str = "http.spill_total";

/// What the config home says about the door's uploads and spill.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UploadConfig {
    /// `(pattern, max_body_bytes)`, in file order.
    pub routes: Vec<(String, u64)>,
    /// Bytes a second, after `grace`.
    pub min_rate: u64,
    pub grace: Duration,
    /// The most one request may spill.
    pub ceiling: u64,
    /// The most every upload in flight may hold at once.
    pub total: u64,
}

impl Default for UploadConfig {
    fn default() -> Self {
        UploadConfig {
            routes: Vec::new(),
            min_rate: ikigai_web::DEFAULT_UPLOAD_MIN_RATE,
            grace: ikigai_web::DEFAULT_UPLOAD_GRACE,
            ceiling: ikigai_core::DEFAULT_STREAM_SPILL,
            total: 4 * ikigai_core::DEFAULT_STREAM_SPILL,
        }
    }
}

/// Build the door's upload configuration from the `http.upload*` and `http.spill*` lines of
/// the config home (as `(key, value)`, in file order) over the defaults.
pub fn uploads_from(entries: &[(String, String)]) -> Result<UploadConfig, String> {
    let mut config = UploadConfig::default();
    let mut seen: Vec<&str> = Vec::new();
    for (key, value) in entries {
        let key = key.as_str();
        if key != ROUTE_KEY {
            if seen.contains(&key) {
                return Err(format!("`{key}` is set twice; set it once"));
            }
            seen.push(key);
        }
        match key {
            ROUTE_KEY => {
                let shape = || {
                    format!(
                        "`{ROUTE_KEY} = \"{value}\"` is not `<path pattern> <largest body in \
                         bytes>`, e.g. `/media/{{name}} 4294967296`"
                    )
                };
                let mut words = value.split_whitespace();
                let (Some(pattern), Some(max), None) = (words.next(), words.next(), words.next())
                else {
                    return Err(shape());
                };
                if !pattern.starts_with('/') {
                    return Err(shape());
                }
                if config.routes.iter().any(|(p, _)| p == pattern) {
                    return Err(format!(
                        "`{ROUTE_KEY}` names `{pattern}` twice; give each pattern one line"
                    ));
                }
                config
                    .routes
                    .push((pattern.to_string(), whole_number(ROUTE_KEY, max)?));
            }
            RATE_KEY => config.min_rate = whole_number(RATE_KEY, value)?,
            GRACE_KEY => config.grace = Duration::from_secs(whole_number(GRACE_KEY, value)?),
            CEILING_KEY => config.ceiling = whole_number(CEILING_KEY, value)?,
            TOTAL_KEY => config.total = whole_number(TOTAL_KEY, value)?,
            other => {
                return Err(format!(
                    "`{other}` is not an HTTP upload setting; the keys are `{ROUTE_KEY}`, \
                     `{RATE_KEY}`, `{GRACE_KEY}`, `{CEILING_KEY}` and `{TOTAL_KEY}`"
                ))
            }
        }
    }
    Ok(config)
}

/// A whole number of at least 1, with TOML's `_` separators allowed.
fn whole_number(key: &str, value: &str) -> Result<u64, String> {
    let digits: String = value.chars().filter(|c| *c != '_').collect();
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("`{key}`: `{value}` is not a whole number"));
    }
    match digits.parse::<u64>() {
        Ok(0) => Err(format!("`{key}`: `{value}`: the least it can be is 1")),
        Ok(n) => Ok(n),
        Err(_) => Err(format!("`{key}`: `{value}` is too large")),
    }
}

/// The banner's words for `config`, spilling into `dir` (or not at all).
pub fn describe(config: &UploadConfig, dir: Option<&std::path::Path>) -> String {
    match (dir, config.routes.len()) {
        (None, _) => "no spill".to_string(),
        (Some(dir), 0) => format!("spill at {}, no upload routes", dir.display()),
        (Some(dir), n) => format!(
            "{n} upload route(s), spill at {} (at most {} bytes a request)",
            dir.display(),
            config.ceiling
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entries(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn with_nothing_configured_there_are_no_routes_and_the_defaults_hold() {
        let config = uploads_from(&[]).unwrap();
        assert_eq!(config, UploadConfig::default());
        assert_eq!(config.ceiling, 1 << 30);
        assert_eq!(config.min_rate, 16 * 1024);
    }

    #[test]
    fn every_key_is_read() {
        let config = uploads_from(&entries(&[
            ("http.upload", "/media/{name} 4_294_967_296"),
            ("http.upload", "/drop 1024"),
            ("http.upload_min_rate", "65536"),
            ("http.upload_grace", "10"),
            ("http.spill_ceiling", "8589934592"),
            ("http.spill_total", "17179869184"),
        ]))
        .unwrap();
        assert_eq!(
            config.routes,
            vec![
                ("/media/{name}".to_string(), 4_294_967_296),
                ("/drop".to_string(), 1024)
            ]
        );
        assert_eq!(config.min_rate, 65536);
        assert_eq!(config.grace, Duration::from_secs(10));
        assert_eq!(config.ceiling, 8_589_934_592);
        assert_eq!(config.total, 17_179_869_184);
    }

    #[test]
    fn a_line_that_does_not_parse_is_refused_naming_it() {
        for (key, value, says) in [
            ("http.upload", "/media", "is not `<path pattern>"),
            ("http.upload", "media 10", "is not `<path pattern>"),
            ("http.upload", "/m 10 extra", "is not `<path pattern>"),
            ("http.upload", "/m ten", "is not a whole number"),
            ("http.upload", "/m 0", "the least it can be is 1"),
            ("http.upload_min_rate", "-1", "is not a whole number"),
            ("http.uploads", "/m 10", "is not an HTTP upload setting"),
        ] {
            let error = uploads_from(&entries(&[(key, value)])).unwrap_err();
            assert!(error.contains(says), "{key} = {value}: {error}");
        }
        let twice = uploads_from(&entries(&[
            ("http.spill_ceiling", "1"),
            ("http.spill_ceiling", "2"),
        ]))
        .unwrap_err();
        assert!(twice.contains("set twice"), "{twice}");
        let same = uploads_from(&entries(&[
            ("http.upload", "/m 1"),
            ("http.upload", "/m 2"),
        ]))
        .unwrap_err();
        assert!(same.contains("twice"), "{same}");
    }
}
