//! Semver (npm) dialect classifier. PyPI uses `crate::pypi::classify_pep440`.

use crate::model::Delta;
use semver::Version;

pub fn classify_semver(installed: Option<&str>, latest: Option<&str>) -> Delta {
    let (Some(inst), Some(lat)) = (installed, latest) else {
        return Delta::Unknown;
    };
    let (Ok(i), Ok(l)) = (Version::parse(inst), Version::parse(lat)) else {
        return Delta::Unknown;
    };
    if i >= l {
        return Delta::Current;
    }
    if i.major != l.major {
        Delta::Major
    } else if i.minor != l.minor {
        Delta::Minor
    } else {
        Delta::Patch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn current_when_equal_or_ahead() {
        assert_eq!(
            classify_semver(Some("1.2.3"), Some("1.2.3")),
            Delta::Current
        );
        assert_eq!(
            classify_semver(Some("2.0.0"), Some("1.9.9")),
            Delta::Current
        );
    }

    #[test]
    fn detects_patch_minor_major() {
        assert_eq!(classify_semver(Some("1.2.3"), Some("1.2.4")), Delta::Patch);
        assert_eq!(classify_semver(Some("1.2.3"), Some("1.3.0")), Delta::Minor);
        assert_eq!(classify_semver(Some("1.2.3"), Some("2.0.0")), Delta::Major);
    }

    #[test]
    fn unknown_when_missing_or_unparsable() {
        assert_eq!(classify_semver(None, Some("1.2.3")), Delta::Unknown);
        assert_eq!(classify_semver(Some("1.2.3"), None), Delta::Unknown);
        assert_eq!(
            classify_semver(Some("latest"), Some("1.2.3")),
            Delta::Unknown
        );
    }
}
