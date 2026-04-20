//! `.packguard.yml` parsing + the conservative defaults emitted by
//! `packguard init`.

use crate::model::{GroupRule, OverrideRule, Policy, Stability};
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::path::Path;

/// Baseline policy written by `packguard init` — conservative enough that
/// users can opt into more permissive rules but never unknowingly opt out of
/// the supply-chain guardrails.
pub const CONSERVATIVE_DEFAULTS_YAML: &str = include_str!("../templates/conservative.yml");

pub fn parse_policy(text: &str) -> Result<Policy> {
    if text.trim().is_empty() {
        return Ok(Policy::default());
    }
    let policy: Policy = serde_yaml::from_str(text).context("parsing .packguard.yml")?;
    validate(&policy)?;
    Ok(policy)
}

pub fn load_policy(path: &Path) -> Result<Policy> {
    let text =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse_policy(&text)
}

fn validate(policy: &Policy) -> Result<()> {
    for (i, rule) in policy.overrides.iter().enumerate() {
        validate_override(i, rule)?;
    }
    for (i, group) in policy.groups.iter().enumerate() {
        validate_group(i, group)?;
    }
    Ok(())
}

fn validate_override(i: usize, rule: &OverrideRule) -> Result<()> {
    if rule.match_glob.is_empty() {
        anyhow::bail!("override[{i}]: `match` is empty");
    }
    if let Some(pin) = &rule.pin {
        if pin.is_empty() {
            anyhow::bail!("override[{i}]: `pin` is empty");
        }
    }
    Ok(())
}

fn validate_group(i: usize, group: &GroupRule) -> Result<()> {
    if group.name.is_empty() {
        anyhow::bail!("group[{i}]: `name` is empty");
    }
    if group.match_globs.is_empty() {
        anyhow::bail!("group[{i}] ({}): `match` list is empty", group.name);
    }
    Ok(())
}

/// Accept both scalar and sequence forms for group `match`.
pub(crate) fn deserialize_match_list<'de, D>(de: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Many {
        One(String),
        Multi(Vec<String>),
    }
    Ok(match Many::deserialize(de)? {
        Many::One(s) => vec![s],
        Many::Multi(v) => v,
    })
}

/// YAML says `offset: -1` but internally we keep a positive "distance from
/// latest". `0` and positive values get mapped to `0` (you can't be ahead of
/// latest); `-N` becomes `N`.
pub(crate) fn deserialize_offset<'de, D>(de: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let raw = i64::deserialize(de)?;
    Ok(raw.unsigned_abs().min(u32::MAX as u64) as u32)
}

pub(crate) fn deserialize_offset_opt<'de, D>(de: D) -> Result<Option<u32>, D::Error>
where
    D: Deserializer<'de>,
{
    Ok(Option::<i64>::deserialize(de)?.map(|n| n.unsigned_abs().min(u32::MAX as u64) as u32))
}

impl Policy {
    /// Convenience: quick lookup of the resolved rule for a given package
    /// name. For full detail see `crate::resolve::resolve_policy`.
    pub fn resolve(&self, name: &str) -> crate::model::ResolvedPolicy {
        crate::resolve::resolve_policy(self, name)
    }
}

impl Stability {
    pub fn allows_prerelease(self) -> bool {
        matches!(self, Stability::Prerelease)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_negative_offset() {
        let p = parse_policy("defaults: { offset: -2 }").unwrap();
        assert_eq!(p.defaults.offset, 2);
    }

    #[test]
    fn match_accepts_scalar_and_list() {
        let p = parse_policy(
            r#"
groups:
  - name: a
    match: "bcrypt*"
    offset: 0
  - name: b
    match: ["foo", "bar*"]
    offset: 0
"#,
        )
        .unwrap();
        assert_eq!(p.groups[0].match_globs, vec!["bcrypt*".to_string()]);
        assert_eq!(
            p.groups[1].match_globs,
            vec!["foo".to_string(), "bar*".to_string()]
        );
    }

    #[test]
    fn rejects_empty_override_match() {
        let err = parse_policy("overrides:\n  - match: ''\n    pin: 1.0\n").unwrap_err();
        assert!(err.to_string().contains("match"));
    }

    #[test]
    fn rejects_group_without_match() {
        let err = parse_policy("groups:\n  - name: g\n    match: []\n").unwrap_err();
        assert!(err.to_string().contains("match"));
    }

    #[test]
    fn empty_input_is_ok() {
        let p = parse_policy("").unwrap();
        assert_eq!(p.overrides.len(), 0);
    }
}
