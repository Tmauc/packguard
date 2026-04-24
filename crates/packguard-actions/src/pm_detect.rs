//! Package-manager detection for the workspace root. The generator needs
//! to emit a `suggested_command` that actually works in the user's repo
//! — a PyPI fix rendered as `npm install` would be worse than no hint at
//! all — so we sniff the lockfile, not the ecosystem tag.
//!
//! Priority: most-specific lockfile first, then fall back to the
//! ecosystem default. The checks are cheap filesystem probes and the
//! generator calls this once per workspace.

use std::path::Path;

/// Every package manager PackGuard currently suggests a command for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageManager {
    Npm,
    Pnpm,
    Yarn,
    Pip,
    Poetry,
    Uv,
    Pdm,
}

impl PackageManager {
    pub fn as_str(self) -> &'static str {
        match self {
            PackageManager::Npm => "npm",
            PackageManager::Pnpm => "pnpm",
            PackageManager::Yarn => "yarn",
            PackageManager::Pip => "pip",
            PackageManager::Poetry => "poetry",
            PackageManager::Uv => "uv",
            PackageManager::Pdm => "pdm",
        }
    }
}

/// Probe `workspace` for the most specific lockfile we recognise. Returns
/// the ecosystem default (`Npm` for `npm`, `Pip` for PyPI, …) when
/// nothing matches so callers always get a concrete command to suggest.
pub fn detect_package_manager(workspace: &Path, ecosystem: &str) -> PackageManager {
    if ecosystem == "npm" {
        if workspace.join("pnpm-lock.yaml").exists() {
            return PackageManager::Pnpm;
        }
        if workspace.join("yarn.lock").exists() {
            return PackageManager::Yarn;
        }
        if workspace.join("package-lock.json").exists() {
            return PackageManager::Npm;
        }
        return PackageManager::Npm;
    }
    if ecosystem == "pypi" {
        if workspace.join("poetry.lock").exists() {
            return PackageManager::Poetry;
        }
        if workspace.join("uv.lock").exists() {
            return PackageManager::Uv;
        }
        if workspace.join("pdm.lock").exists() {
            return PackageManager::Pdm;
        }
        // `pip` fallback covers `requirements*.txt` + anything else — the
        // command we emit works regardless of which requirements file
        // the user is editing.
        return PackageManager::Pip;
    }
    // Unknown ecosystem — default to pip so the message still gives the
    // user something runnable; generators shouldn't be creating package
    // actions for unknown ecosystems anyway.
    PackageManager::Pip
}

/// Render the upgrade command. PackGuard's policy says "here's the
/// minimum safe version" — it doesn't pin. So JS tools get caret ranges
/// (`^x.y.z`, compatible updates) and Python tools get `>=` ranges. `uv`
/// gets an explicit `<next_major` upper bound because that's the uv
/// idiom; `pip` / `pdm` keep it open (no upper bound → user can pin
/// later if they want).
pub fn suggest_upgrade(pm: PackageManager, name: &str, version: &str) -> String {
    match pm {
        PackageManager::Npm => format!("npm install {name}@^{version}"),
        PackageManager::Pnpm => format!("pnpm add {name}@^{version}"),
        PackageManager::Yarn => format!("yarn add {name}@^{version}"),
        PackageManager::Pip => format!("pip install '{name}>={version}'"),
        PackageManager::Poetry => format!("poetry add '{name}@^{version}'"),
        PackageManager::Uv => match next_major(version) {
            Some(next) => format!("uv add '{name}>={version},<{next}'"),
            None => format!("uv add '{name}>={version}'"),
        },
        PackageManager::Pdm => format!("pdm add '{name}>={version}'"),
    }
}

/// Parse the major component of `version` and return `major + 1` for the
/// next-major upper bound used by `uv`. Handles semver (`1.2.3`), PEP
/// 440 release tuples (`3.10.5`, `10.3.0b1`), and short forms (`3.10`).
/// Returns `None` when the leading segment isn't an integer — in that
/// case the caller falls back to an open-ended `>=` range.
fn next_major(version: &str) -> Option<u64> {
    let head = version.split(['.', '-', '+']).next()?;
    // Strip any trailing non-digits (e.g. `3a`, `3rc1` before the dot).
    let digits: String = head.chars().take_while(|c| c.is_ascii_digit()).collect();
    digits.parse::<u64>().ok().map(|m| m + 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn touch(dir: &Path, name: &str) {
        std::fs::write(dir.join(name), b"").unwrap();
    }

    #[test]
    fn pm_detect_returns_pnpm_when_pnpm_lock_present() {
        let t = TempDir::new().unwrap();
        touch(t.path(), "pnpm-lock.yaml");
        touch(t.path(), "package-lock.json"); // pnpm wins
        assert_eq!(
            detect_package_manager(t.path(), "npm"),
            PackageManager::Pnpm
        );
    }

    #[test]
    fn pm_detect_returns_yarn_when_yarn_lock_present_without_pnpm() {
        let t = TempDir::new().unwrap();
        touch(t.path(), "yarn.lock");
        assert_eq!(
            detect_package_manager(t.path(), "npm"),
            PackageManager::Yarn
        );
    }

    #[test]
    fn pm_detect_returns_poetry_when_poetry_lock_present() {
        let t = TempDir::new().unwrap();
        touch(t.path(), "poetry.lock");
        assert_eq!(
            detect_package_manager(t.path(), "pypi"),
            PackageManager::Poetry
        );
    }

    #[test]
    fn pm_detect_returns_uv_when_uv_lock_present() {
        let t = TempDir::new().unwrap();
        touch(t.path(), "uv.lock");
        assert_eq!(detect_package_manager(t.path(), "pypi"), PackageManager::Uv);
    }

    #[test]
    fn pm_detect_falls_back_to_npm_without_lockfile() {
        let t = TempDir::new().unwrap();
        assert_eq!(detect_package_manager(t.path(), "npm"), PackageManager::Npm);
    }

    #[test]
    fn pm_detect_falls_back_to_pip_without_lockfile() {
        let t = TempDir::new().unwrap();
        assert_eq!(
            detect_package_manager(t.path(), "pypi"),
            PackageManager::Pip
        );
    }

    #[test]
    fn suggest_upgrade_formats_command_per_package_manager() {
        assert_eq!(
            suggest_upgrade(PackageManager::Pnpm, "lodash", "4.17.21"),
            "pnpm add lodash@^4.17.21"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Npm, "lodash", "4.17.21"),
            "npm install lodash@^4.17.21"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Yarn, "lodash", "4.17.21"),
            "yarn add lodash@^4.17.21"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Poetry, "pillow", "10.3.0"),
            "poetry add 'pillow@^10.3.0'"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Uv, "aiohttp", "3.10.5"),
            "uv add 'aiohttp>=3.10.5,<4'"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Pip, "requests", "2.32.3"),
            "pip install 'requests>=2.32.3'"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Pdm, "pydantic", "2.8.0"),
            "pdm add 'pydantic>=2.8.0'"
        );
    }

    #[test]
    fn suggest_upgrade_uv_falls_back_without_upper_bound_on_unparseable_major() {
        // A version string with no parseable leading integer → no
        // next-major bound, open-ended range.
        assert_eq!(
            suggest_upgrade(PackageManager::Uv, "weird", "latest"),
            "uv add 'weird>=latest'"
        );
    }

    #[test]
    fn next_major_parses_leading_integer() {
        assert_eq!(super::next_major("3.10.5"), Some(4));
        assert_eq!(super::next_major("10.3.0"), Some(11));
        assert_eq!(super::next_major("1.0.0-beta"), Some(2));
        assert_eq!(super::next_major("3.10"), Some(4));
        assert_eq!(super::next_major("0.1.2"), Some(1));
        assert_eq!(super::next_major("weird"), None);
    }
}
