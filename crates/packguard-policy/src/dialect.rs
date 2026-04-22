//! Version dialect abstraction — enough to let the policy engine compare
//! versions and extract `major` / `is_prerelease` without caring whether a
//! package is npm (semver) or PyPI (PEP 440).

use std::cmp::Ordering;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dialect {
    Semver,
    Pep440,
}

/// Extracted information we care about across dialects. Phase 9b adds
/// `patch` so the resolver can cascade major → minor → patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMeta {
    pub major: u64,
    pub minor: u64,
    pub patch: u64,
    pub is_prerelease: bool,
}

impl Dialect {
    pub fn meta(&self, raw: &str) -> Option<VersionMeta> {
        match self {
            Dialect::Semver => semver::Version::parse(raw).ok().map(|v| VersionMeta {
                major: v.major,
                minor: v.minor,
                patch: v.patch,
                is_prerelease: !v.pre.is_empty(),
            }),
            Dialect::Pep440 => pep440_rs::Version::from_str(raw).ok().map(|v| {
                let release = v.release();
                VersionMeta {
                    major: release.first().copied().unwrap_or(0),
                    minor: release.get(1).copied().unwrap_or(0),
                    patch: release.get(2).copied().unwrap_or(0),
                    is_prerelease: v.is_pre() || v.is_dev(),
                }
            }),
        }
    }

    pub fn compare(&self, a: &str, b: &str) -> Option<Ordering> {
        match self {
            Dialect::Semver => {
                let a = semver::Version::parse(a).ok()?;
                let b = semver::Version::parse(b).ok()?;
                Some(a.cmp(&b))
            }
            Dialect::Pep440 => {
                let a = pep440_rs::Version::from_str(a).ok()?;
                let b = pep440_rs::Version::from_str(b).ok()?;
                Some(a.cmp(&b))
            }
        }
    }

    /// For a given ecosystem id, pick the matching dialect. Keeps the
    /// mapping in one place so `packguard-core::Ecosystem::id()` remains the
    /// single source of truth.
    pub fn for_ecosystem(id: &str) -> Self {
        match id {
            "pypi" => Self::Pep440,
            _ => Self::Semver,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_meta() {
        let m = Dialect::Semver.meta("1.2.3-alpha").unwrap();
        assert_eq!(m.major, 1);
        assert_eq!(m.minor, 2);
        assert_eq!(m.patch, 3);
        assert!(m.is_prerelease);
    }

    #[test]
    fn pep440_meta() {
        let m = Dialect::Pep440.meta("2.0.0a1").unwrap();
        assert_eq!(m.major, 2);
        assert_eq!(m.patch, 0);
        assert!(m.is_prerelease);
        let m = Dialect::Pep440.meta("4.2.7").unwrap();
        assert_eq!(m.major, 4);
        assert_eq!(m.minor, 2);
        assert_eq!(m.patch, 7);
        assert!(!m.is_prerelease);
    }

    #[test]
    fn semver_compare_ordering() {
        assert_eq!(
            Dialect::Semver.compare("1.2.0", "1.2.3"),
            Some(Ordering::Less),
        );
    }

    #[test]
    fn pep440_compare_ordering() {
        assert_eq!(
            Dialect::Pep440.compare("1!0.1", "99.0.0"),
            Some(Ordering::Greater),
        );
    }

    #[test]
    fn for_ecosystem_maps() {
        assert_eq!(Dialect::for_ecosystem("pypi"), Dialect::Pep440);
        assert_eq!(Dialect::for_ecosystem("npm"), Dialect::Semver);
        assert_eq!(Dialect::for_ecosystem("cargo"), Dialect::Semver);
    }
}
