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

/// Render the upgrade command. We keep the form as close as possible to
/// what the ecosystem's own docs advise so the string is copy-pasteable
/// into a terminal. Exact versions (no `^`, no range) so the suggestion
/// is reproducible — the dashboard renders the range elsewhere for
/// context.
pub fn suggest_upgrade(pm: PackageManager, name: &str, version: &str) -> String {
    match pm {
        PackageManager::Npm => format!("npm install {name}@{version}"),
        PackageManager::Pnpm => format!("pnpm up {name}@{version}"),
        PackageManager::Yarn => format!("yarn up {name}@{version}"),
        PackageManager::Pip => format!("pip install '{name}=={version}'"),
        PackageManager::Poetry => format!("poetry add '{name}@{version}'"),
        PackageManager::Uv => format!("uv add '{name}=={version}'"),
        PackageManager::Pdm => format!("pdm add '{name}=={version}'"),
    }
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
            "pnpm up lodash@4.17.21"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Poetry, "pillow", "10.3.0"),
            "poetry add 'pillow@10.3.0'"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Uv, "aiohttp", "3.10.5"),
            "uv add 'aiohttp==3.10.5'"
        );
        assert_eq!(
            suggest_upgrade(PackageManager::Pip, "requests", "2.32.3"),
            "pip install 'requests==2.32.3'"
        );
    }
}
