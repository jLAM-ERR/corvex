use crate::config::Config;
use anyhow::{bail, Context, Result};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum RouteTarget {
    Direct,
    Proxy,
}

impl std::fmt::Display for RouteTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteTarget::Direct => write!(f, "direct"),
            RouteTarget::Proxy => write!(f, "proxy"),
        }
    }
}

fn file_path(target: RouteTarget, config: &Config) -> &Path {
    match target {
        RouteTarget::Direct => &config.direct_domains,
        RouteTarget::Proxy => &config.proxy_domains,
    }
}

fn read_entries(path: &Path) -> Result<Vec<String>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let content = fs::read_to_string(path).context("Failed to read domain file")?;
    let entries: Vec<String> =
        serde_json::from_str(&content).context("Failed to parse domain file as JSON array")?;
    Ok(entries)
}

fn write_entries(path: &Path, entries: &[String]) -> Result<()> {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let json = serde_json::to_string_pretty(entries).context("Failed to serialize entries")?;
    fs::write(path, json).context("Failed to write domain file")?;
    Ok(())
}

fn validate_entry(entry: &str) -> Result<()> {
    if !entry.starts_with("domain:") && !entry.starts_with("regex:") {
        bail!("Entry must start with 'domain:' or 'regex:' prefix, got: {entry}");
    }
    Ok(())
}

pub fn list(target: RouteTarget, config: &Config) -> Result<Vec<String>> {
    read_entries(file_path(target, config))
}

pub fn add(target: RouteTarget, entry: &str, config: &Config) -> Result<()> {
    validate_entry(entry)?;
    let path = file_path(target, config);
    let mut entries = read_entries(path)?;

    if entries.iter().any(|e| e == entry) {
        bail!("Entry already exists: {entry}");
    }

    entries.push(entry.to_string());
    write_entries(path, &entries)
}

pub fn remove(target: RouteTarget, entry: &str, config: &Config) -> Result<()> {
    let path = file_path(target, config);
    let mut entries = read_entries(path)?;

    let initial_len = entries.len();
    entries.retain(|e| e != entry);

    if entries.len() == initial_len {
        bail!("Entry not found: {entry}");
    }

    write_entries(path, &entries)
}

pub fn find(target: RouteTarget, pattern: &str, config: &Config) -> Result<Vec<String>> {
    let entries = read_entries(file_path(target, config))?;
    Ok(entries
        .into_iter()
        .filter(|e| e.contains(pattern))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(dir: &Path) -> Config {
        let mut config = Config::new(None);
        config.direct_domains = dir.join("direct.json");
        config.proxy_domains = dir.join("proxy.json");
        config
    }

    #[test]
    fn add_list_remove_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        add(RouteTarget::Direct, "domain:example.com", &config).unwrap();
        add(RouteTarget::Direct, "domain:google.com", &config).unwrap();

        let entries = list(RouteTarget::Direct, &config).unwrap();
        assert_eq!(entries, vec!["domain:example.com", "domain:google.com"]);

        remove(RouteTarget::Direct, "domain:example.com", &config).unwrap();
        let entries = list(RouteTarget::Direct, &config).unwrap();
        assert_eq!(entries, vec!["domain:google.com"]);
    }

    #[test]
    fn duplicate_detection() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        add(RouteTarget::Direct, "domain:example.com", &config).unwrap();
        let err = add(RouteTarget::Direct, "domain:example.com", &config).unwrap_err();
        assert!(err.to_string().contains("already exists"));
    }

    #[test]
    fn invalid_entry_format() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let err = add(RouteTarget::Direct, "example.com", &config).unwrap_err();
        assert!(err.to_string().contains("must start with"));
    }

    #[test]
    fn find_with_partial_match() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        add(RouteTarget::Proxy, "domain:example.com", &config).unwrap();
        add(RouteTarget::Proxy, "domain:example.org", &config).unwrap();
        add(RouteTarget::Proxy, "domain:google.com", &config).unwrap();

        let results = find(RouteTarget::Proxy, "example", &config).unwrap();
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn remove_nonexistent_entry() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let err = remove(RouteTarget::Direct, "domain:nope.com", &config).unwrap_err();
        assert!(err.to_string().contains("not found"));
    }

    #[test]
    fn list_empty_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let config = test_config(dir.path());

        let entries = list(RouteTarget::Direct, &config).unwrap();
        assert!(entries.is_empty());
    }
}
