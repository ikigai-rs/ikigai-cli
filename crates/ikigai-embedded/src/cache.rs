//! Representation cache sizing for every host surface, from the config home.

use std::sync::{Arc, OnceLock};

use ikigai_core::{CacheBound, Kernel, Lru};

/// Validate the cache settings before any mode starts. Omitted bounds retain core's defaults.
/// Embedded callers also validate when constructing a host kernel.
pub fn configure() -> Result<(), String> {
    bound().as_ref().map(|_| ()).map_err(Clone::clone)
}

fn bound() -> &'static Result<CacheBound, String> {
    static BOUND: OnceLock<Result<CacheBound, String>> = OnceLock::new();
    BOUND.get_or_init(|| {
        let path = crate::config::config_path();
        let result = match std::fs::read_to_string(&path) {
            Ok(text) => bound_from(&text),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CacheBound::default()),
            Err(e) => Err(format!("cannot read cache settings: {e}")),
        };
        result.map_err(|e| format!("{e} (in {})", path.display()))
    })
}

pub(crate) fn apply(kernel: Kernel) -> Kernel {
    let bound = bound().as_ref().unwrap_or_else(|e| panic!("{e}"));
    kernel.with_cache_policy(Arc::new(Lru::with_bound(*bound)))
}

fn bound_from(text: &str) -> Result<CacheBound, String> {
    let mut bound = CacheBound::default();
    let mut seen = Vec::new();
    for line in text.lines() {
        // Cache values are numbers, so a comment cannot be inside a string value.
        let line = line.split('#').next().unwrap_or_default().trim();
        if !line.starts_with("cache.") {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or_else(|| format!("`{line}`: expected a cache key = whole number"))?;
        let key = key.trim();
        let value = value.trim();
        let destination = match key {
            "cache.max_entries" => &mut bound.max_entries,
            "cache.max_bytes" => &mut bound.max_bytes,
            _ => {
                return Err(format!(
                    "`{key}` is not a cache setting; use cache.max_entries or cache.max_bytes"
                ))
            }
        };
        if seen.contains(&key) {
            return Err(format!("`{key}` is set twice; set it once"));
        }
        seen.push(key);
        // Underscores separate digit groups; reject missing digits and misplaced separators.
        if value
            .split('_')
            .any(|group| group.is_empty() || !group.bytes().all(|byte| byte.is_ascii_digit()))
        {
            return Err(format!(
                "`{key} = {value}`: expected a nonnegative whole number"
            ));
        }
        *destination = value
            .replace('_', "")
            .parse::<usize>()
            .map_err(|_| format!("`{key} = {value}` is too large here"))?;
    }
    Ok(bound)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_bound_can_be_overridden_independently() {
        let defaults = CacheBound::default();
        let entries = bound_from("cache.max_entries = 10_000 # entries\n").unwrap();
        assert_eq!(entries.max_entries, 10_000);
        assert_eq!(entries.max_bytes, defaults.max_bytes);
        let bytes = bound_from("cache.max_bytes = 0").unwrap();
        assert_eq!(bytes.max_entries, defaults.max_entries);
        assert_eq!(bytes.max_bytes, 0);
    }

    #[test]
    fn malformed_values_and_keys_are_rejected() {
        for line in [
            "cache.max_entries",
            "cache.max_byte = 1",
            "cache.max_bytes = -1",
            "cache.max_entries = 1.5",
            "cache.max_entries = \"12\"",
            "cache.max_bytes =",
            "cache.max_bytes = _1",
            "cache.max_bytes = 1_",
            "cache.max_bytes = 1__2",
            "cache.max_bytes = 18446744073709551616",
            "cache.max_entries = 1\ncache.max_entries = 2",
        ] {
            assert!(bound_from(line).is_err(), "{line}");
        }
    }
}
