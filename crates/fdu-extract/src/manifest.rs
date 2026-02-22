//! Manifest serialization — write the extraction manifest as JSON.

use fdu_models::ExtractionManifest;
use std::path::Path;

/// Write an extraction manifest as JSON to a file.
pub fn write_manifest(manifest: &ExtractionManifest, path: &Path) -> Result<(), std::io::Error> {
    let json = serde_json::to_string_pretty(manifest)
        .map_err(std::io::Error::other)?;
    std::fs::write(path, json)
}

/// Read an extraction manifest from a JSON file.
pub fn read_manifest(path: &Path) -> Result<ExtractionManifest, std::io::Error> {
    let json = std::fs::read_to_string(path)?;
    serde_json::from_str(&json).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use fdu_models::ExtractionPolicy;
    use std::collections::HashMap;

    #[test]
    fn roundtrip() {
        let manifest = ExtractionManifest {
            files: vec![],
            quarantine_path: Path::new("/tmp/q").to_path_buf(),
            policy: ExtractionPolicy::VerifiedOnly,
            integrity_hashes: HashMap::new(),
        };

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("manifest.json");

        write_manifest(&manifest, &path).unwrap();
        let loaded = read_manifest(&path).unwrap();

        assert_eq!(loaded.policy, ExtractionPolicy::VerifiedOnly);
        assert!(loaded.files.is_empty());
    }
}
