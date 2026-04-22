//! `.packguard.yml` parsing + the conservative defaults emitted by
//! `packguard init`.
//!
//! **Phase 9b breaking change** — `offset: -1` (scalar) is no longer
//! accepted. The only valid form is the three-axis object:
//!
//! ```yaml
//! offset:
//!   major: 0
//!   minor: -1
//!   patch: 0
//! ```
//!
//! Each key is optional (defaults to 0); scalar inputs produce an
//! explicit error pointing the user at the offset-policy concept doc.

use crate::model::{GroupRule, Offset, OverrideRule, Policy, Stability};
use anyhow::{Context, Result};
use serde::{Deserialize, Deserializer};
use std::path::Path;

/// Baseline policy written by `packguard init` — conservative enough that
/// users can opt into more permissive rules but never unknowingly opt out of
/// the supply-chain guardrails.
pub const CONSERVATIVE_DEFAULTS_YAML: &str = include_str!("../templates/conservative.yml");

/// Human-readable pointer used in every error message emitted by this
/// module. Keep in sync with `docs-site/content/concepts/offset-policy.mdx`.
const OFFSET_DOC_URL: &str = "https://packguard-docs.vercel.app/concepts/offset-policy";

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

/// Internal shape used by serde to parse the offset object. Each axis is
/// a signed integer because `0` and `-N` are valid; positive values are
/// rejected at validation time.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct OffsetAxes {
    #[serde(default)]
    major: Option<i64>,
    #[serde(default)]
    minor: Option<i64>,
    #[serde(default)]
    patch: Option<i64>,
}

impl OffsetAxes {
    fn into_offset(self) -> std::result::Result<Offset, String> {
        for (name, val) in [
            ("major", self.major),
            ("minor", self.minor),
            ("patch", self.patch),
        ] {
            if let Some(v) = val {
                if v > 0 {
                    return Err(format!(
                        "offset.{name} must be 0 or negative, got {v} \
                         (you can't be ahead of `latest` — see {OFFSET_DOC_URL})",
                    ));
                }
            }
        }
        Ok(Offset::from_axes(
            self.major.unwrap_or(0),
            self.minor.unwrap_or(0),
            self.patch.unwrap_or(0),
        ))
    }
}

/// Parse the object form. Rejects anything else — scalar inputs produce
/// a migration hint instead of silently mapping to `{ major: N }`.
pub(crate) fn deserialize_offset<'de, D>(de: D) -> Result<Offset, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_yaml::Value::deserialize(de)?;
    parse_offset_value(&value).map_err(D::Error::custom)
}

pub(crate) fn deserialize_offset_opt<'de, D>(de: D) -> Result<Option<Offset>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    let value = serde_yaml::Value::deserialize(de)?;
    if matches!(value, serde_yaml::Value::Null) {
        return Ok(None);
    }
    parse_offset_value(&value)
        .map(Some)
        .map_err(D::Error::custom)
}

fn parse_offset_value(value: &serde_yaml::Value) -> std::result::Result<Offset, String> {
    match value {
        serde_yaml::Value::Mapping(_) => {
            let axes: OffsetAxes = serde_yaml::from_value(value.clone()).map_err(|e| {
                format!(
                    "invalid offset object: {e}. \
                     Expected shape: offset: {{ major: 0, minor: -1, patch: 0 }}. \
                     See {OFFSET_DOC_URL}"
                )
            })?;
            axes.into_offset()
        }
        serde_yaml::Value::Number(n) => Err(format!(
            "policy `offset` must be an object with major/minor/patch keys, \
             got scalar `{n}`. \
             Rewrite as `offset: {{ major: {n}, minor: 0, patch: 0 }}` \
             (or the long form). See {OFFSET_DOC_URL}",
        )),
        serde_yaml::Value::Null => Ok(Offset::ZERO),
        other => Err(format!(
            "policy `offset` must be an object with major/minor/patch keys, \
             got {}. See {OFFSET_DOC_URL}",
            yaml_kind(other),
        )),
    }
}

fn yaml_kind(v: &serde_yaml::Value) -> &'static str {
    match v {
        serde_yaml::Value::Null => "null",
        serde_yaml::Value::Bool(_) => "boolean",
        serde_yaml::Value::Number(_) => "number",
        serde_yaml::Value::String(_) => "string",
        serde_yaml::Value::Sequence(_) => "sequence",
        serde_yaml::Value::Mapping(_) => "mapping",
        serde_yaml::Value::Tagged(_) => "tagged",
    }
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
    fn parses_object_offset_with_all_keys() {
        let p = parse_policy("defaults:\n  offset:\n    major: 0\n    minor: -1\n    patch: 0\n")
            .unwrap();
        assert_eq!(p.defaults.offset, Offset::from_axes(0, -1, 0));
    }

    #[test]
    fn parses_object_offset_with_partial_keys() {
        let p = parse_policy("defaults:\n  offset:\n    minor: -2\n").unwrap();
        assert_eq!(p.defaults.offset, Offset::from_axes(0, -2, 0));
    }

    #[test]
    fn parses_inline_object_offset() {
        let p = parse_policy("defaults: { offset: { major: -1, patch: -1 } }").unwrap();
        assert_eq!(p.defaults.offset, Offset::from_axes(-1, 0, -1));
    }

    #[test]
    fn rejects_scalar_offset_with_migration_hint() {
        let err = parse_policy("defaults:\n  offset: -1\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("major/minor/patch"),
            "missing 3-axis hint: {msg}"
        );
        assert!(
            msg.contains("offset: { major: -1"),
            "missing rewrite hint: {msg}"
        );
        assert!(msg.contains("offset-policy"), "missing doc link: {msg}");
    }

    #[test]
    fn rejects_scalar_zero_offset() {
        // Even `0` — the neutral value — must use the object form.
        let err = parse_policy("defaults:\n  offset: 0\n").unwrap_err();
        assert!(format!("{err:#}").contains("major/minor/patch"), "{err:#}");
    }

    #[test]
    fn rejects_positive_axis() {
        let err = parse_policy("defaults:\n  offset: { minor: 2 }\n").unwrap_err();
        let msg = format!("{err:#}");
        assert!(
            msg.contains("offset.minor must be 0 or negative"),
            "missing constraint: {msg}"
        );
    }

    #[test]
    fn rejects_unknown_axis_key() {
        let err = parse_policy("defaults:\n  offset:\n    macro: -1\n").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
    }

    #[test]
    fn override_rule_accepts_object_offset() {
        let p = parse_policy(
            r#"
defaults: { offset: { minor: -1 } }
overrides:
  - match: "react"
    offset: { major: -1, minor: -1, patch: -1 }
"#,
        )
        .unwrap();
        assert_eq!(p.overrides[0].offset, Some(Offset::from_axes(-1, -1, -1)));
    }

    #[test]
    fn override_rule_rejects_scalar_offset() {
        let err = parse_policy(
            r#"
defaults: { offset: { minor: -1 } }
overrides:
  - match: "react"
    offset: -1
"#,
        )
        .unwrap_err();
        assert!(format!("{err:#}").contains("major/minor/patch"), "{err:#}");
    }

    #[test]
    fn group_rule_accepts_object_offset() {
        let p = parse_policy(
            r#"
groups:
  - name: security-critical
    match: ["bcrypt*"]
    offset: { major: 0, minor: 0, patch: 0 }
"#,
        )
        .unwrap();
        assert_eq!(p.groups[0].offset, Some(Offset::ZERO));
    }

    #[test]
    fn match_accepts_scalar_and_list() {
        let p = parse_policy(
            r#"
groups:
  - name: a
    match: "bcrypt*"
    offset: { major: 0 }
  - name: b
    match: ["foo", "bar*"]
    offset: { major: 0 }
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
        assert!(p.defaults.offset.is_zero());
    }

    #[test]
    fn missing_offset_defaults_to_zero() {
        let p = parse_policy("defaults:\n  min_age_days: 7\n").unwrap();
        assert!(p.defaults.offset.is_zero());
    }
}
