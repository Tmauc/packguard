//! Typosquat heuristic.
//!
//! Compares each watched package name to the top-N list for its ecosystem:
//! - Levenshtein distance ≤ 2 → suspect (confidence depends on the kind of
//!   edit: adjacent swap > single edit > prefix/suffix addition).
//! - PEP 503 normalization is *not* applied — the user's typed name is what
//!   matters: a typosquat exploits visual similarity at the manifest level.
//!
//! Anti-false-positive filters:
//! - Skip names < 4 chars (too noisy).
//! - Skip scoped names (`@org/foo` is namespaced; the registry already
//!   prevents impersonation under `@org`).
//! - Skip names that are themselves in the top-N list (legitimate
//!   high-traffic packages don't typosquat themselves).
//! - Skip names in a small whitelist of known-confusable legitimate
//!   packages (e.g. `request` vs `requests` are both real).

pub mod embedded;
pub mod refresh;

use packguard_core::{MalwareKind, MalwareReport};
use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq)]
pub struct TyposquatHit {
    pub candidate: String,
    pub resembles: String,
    pub distance: u8,
    /// 0.0..=1.0 — higher = more confident this is a typosquat.
    pub score: f32,
    pub reason: TyposquatReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TyposquatReason {
    EditDistance(u8),
    AdjacentSwap,
    PrefixAdded(String),
    SuffixAdded(String),
}

impl TyposquatReason {
    pub fn as_str(&self) -> String {
        match self {
            TyposquatReason::EditDistance(d) => format!("edit distance {}", d),
            TyposquatReason::AdjacentSwap => "adjacent character swap".into(),
            TyposquatReason::PrefixAdded(p) => format!("prefix `{}` added", p),
            TyposquatReason::SuffixAdded(s) => format!("suffix `{}` added", s),
        }
    }
}

impl TyposquatHit {
    /// Render as the cross-source `MalwareReport` row that the store
    /// persists. Whole-package suspicion → empty version marker.
    pub fn into_malware_report(self, ecosystem: &str) -> MalwareReport {
        let evidence = serde_json::json!({
            "resembles": self.resembles,
            "distance": self.distance,
            "score": self.score,
            "reason": self.reason.as_str(),
        });
        MalwareReport {
            source: "typosquat-heuristic".into(),
            ref_id: format!("typo:{}", self.candidate),
            ecosystem: ecosystem.to_string(),
            package_name: self.candidate.clone(),
            version: String::new(),
            kind: MalwareKind::Typosquat,
            summary: Some(format!(
                "Possible typosquat of `{}` ({})",
                self.resembles,
                self.reason.as_str()
            )),
            url: None,
            evidence,
            reported_at: None,
        }
    }
}

/// Names that look typosquat-y but are legitimately distinct packages.
/// Curated based on reported false positives.
const WHITELIST: &[(&str, &str)] = &[
    // (legitimate name, looks like)
    ("request", "requests"), // npm vs pypi
    ("requests", "request"), // pypi vs npm
    ("react", "preact"),     // distinct frameworks
    ("preact", "react"),
    ("react-dom", "preact"),
    ("axios", "axes"),
    ("commander", "command"),
    ("debug", "debugger"),
    ("ms", "ns"), // sub-4-char anyway, just illustrative
];

fn whitelisted(candidate: &str, resembles: &str) -> bool {
    WHITELIST
        .iter()
        .any(|(c, r)| (*c == candidate && *r == resembles) || (*c == resembles && *r == candidate))
}

pub struct Scorer {
    top: HashSet<String>,
}

impl Scorer {
    pub fn new(top: HashSet<String>) -> Self {
        Self { top }
    }

    /// Convenience for tests / call-sites with a fixed slice.
    pub fn from_slice<I, S>(items: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self::new(items.into_iter().map(Into::into).collect())
    }

    /// Returns the highest-confidence typosquat suspicion for `name`, or
    /// `None` when none of the filters trigger.
    pub fn score(&self, name: &str) -> Option<TyposquatHit> {
        if !eligible(name) {
            return None;
        }
        if self.top.contains(name) {
            return None;
        }
        let mut best: Option<TyposquatHit> = None;
        for top in &self.top {
            if top.as_str() == name {
                continue;
            }
            if whitelisted(name, top) {
                continue;
            }
            // Prefix / suffix checks first — they routinely sit at distance
            // 4-8 (e.g. `node-axios` vs `axios`) but are still high-signal
            // typosquats. Once detected they short-circuit the distance gate.
            if let Some(reason) = prefix_or_suffix_match(top, name) {
                let hit = TyposquatHit {
                    candidate: name.to_string(),
                    resembles: top.clone(),
                    distance: strsim::levenshtein(top, name) as u8,
                    score: 0.5,
                    reason,
                };
                best = update_best(best, hit);
                continue;
            }
            // Otherwise gate on Levenshtein.
            let d = strsim::levenshtein(top, name);
            if d == 0 || d > 2 {
                continue;
            }
            let (reason, score) = classify_distance(top, name, d as u8);
            let hit = TyposquatHit {
                candidate: name.to_string(),
                resembles: top.clone(),
                distance: d as u8,
                score,
                reason,
            };
            best = update_best(best, hit);
        }
        best
    }
}

fn update_best(best: Option<TyposquatHit>, hit: TyposquatHit) -> Option<TyposquatHit> {
    match best {
        Some(prev) if prev.score >= hit.score => Some(prev),
        _ => Some(hit),
    }
}

fn eligible(name: &str) -> bool {
    if name.len() < 4 {
        return false;
    }
    // Scoped npm names (`@org/foo`) — namespacing prevents impersonation.
    if name.starts_with('@') {
        return false;
    }
    true
}

/// Recognise `node-axios` ↔ `axios`-style prefix / suffix additions
/// regardless of edit distance.
fn prefix_or_suffix_match(top: &str, candidate: &str) -> Option<TyposquatReason> {
    for prefix in ["node-", "py-", "lib-", "js-"] {
        if let Some(rest) = candidate.strip_prefix(prefix) {
            if rest == top {
                return Some(TyposquatReason::PrefixAdded(prefix.into()));
            }
        }
        if let Some(rest) = top.strip_prefix(prefix) {
            if rest == candidate {
                return Some(TyposquatReason::PrefixAdded(prefix.into()));
            }
        }
    }
    for suffix in ["-js", "-py", "-node"] {
        if let Some(rest) = candidate.strip_suffix(suffix) {
            if rest == top {
                return Some(TyposquatReason::SuffixAdded(suffix.into()));
            }
        }
        if let Some(rest) = top.strip_suffix(suffix) {
            if rest == candidate {
                return Some(TyposquatReason::SuffixAdded(suffix.into()));
            }
        }
    }
    None
}

fn classify_distance(top: &str, candidate: &str, distance: u8) -> (TyposquatReason, f32) {
    // Adjacent character swap (lodahs ↔ lodash). Two single edits look
    // distance-2 to Levenshtein but are visually one mistake.
    if distance == 2 && is_adjacent_swap(top, candidate) {
        return (TyposquatReason::AdjacentSwap, 1.0);
    }
    let score = match distance {
        1 => 0.7,
        2 => 0.5,
        _ => 0.3,
    };
    (TyposquatReason::EditDistance(distance), score)
}

fn is_adjacent_swap(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let av: Vec<char> = a.chars().collect();
    let bv: Vec<char> = b.chars().collect();
    let diffs: Vec<usize> = (0..av.len()).filter(|&i| av[i] != bv[i]).collect();
    if diffs.len() != 2 {
        return false;
    }
    diffs[1] == diffs[0] + 1 && av[diffs[0]] == bv[diffs[1]] && av[diffs[1]] == bv[diffs[0]]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn top_vec(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ---- positive cases -----------------------------------------------------

    #[test]
    fn detects_adjacent_swap_lodahs() {
        let s = Scorer::from_slice(top_vec(&["lodash"]));
        let hit = s.score("lodahs").unwrap();
        assert_eq!(hit.resembles, "lodash");
        assert_eq!(hit.reason, TyposquatReason::AdjacentSwap);
        assert!((hit.score - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn detects_single_edit_collors() {
        let s = Scorer::from_slice(top_vec(&["colors"]));
        let hit = s.score("collors").unwrap();
        assert_eq!(hit.resembles, "colors");
        assert_eq!(hit.distance, 1);
    }

    #[test]
    fn detects_prefix_addition_node_axios() {
        let s = Scorer::from_slice(top_vec(&["axios"]));
        let hit = s.score("node-axios").unwrap();
        assert_eq!(hit.resembles, "axios");
        match hit.reason {
            TyposquatReason::PrefixAdded(p) => assert_eq!(p, "node-"),
            other => panic!("expected PrefixAdded, got {other:?}"),
        }
    }

    #[test]
    fn detects_suffix_addition_discord_js() {
        // top has `discord.js`, candidate uses dash → distance 1 (`.` vs `-`).
        let s = Scorer::from_slice(top_vec(&["discord.js"]));
        let hit = s.score("discord-js").unwrap();
        assert_eq!(hit.resembles, "discord.js");
    }

    #[test]
    fn detects_distance_two_substitution() {
        // `expresss` → `express` is a 1-edit insertion; pick a real distance-2
        // candidate to prove the gate accepts d=2.
        let s = Scorer::from_slice(top_vec(&["express"]));
        let hit = s.score("xpresso").unwrap();
        assert_eq!(hit.resembles, "express");
        assert_eq!(hit.distance, 2);
    }

    #[test]
    fn detects_typo_react_dom_to_reactdom() {
        let s = Scorer::from_slice(top_vec(&["react-dom"]));
        let hit = s.score("reactdom").unwrap();
        assert_eq!(hit.resembles, "react-dom");
    }

    #[test]
    fn detects_typo_lodash_es_to_lodash_se() {
        let s = Scorer::from_slice(top_vec(&["lodash-es"]));
        let hit = s.score("lodash-se").unwrap();
        assert_eq!(hit.resembles, "lodash-es");
        assert_eq!(hit.reason, TyposquatReason::AdjacentSwap);
    }

    #[test]
    fn detects_swapped_letters_in_typescript() {
        let s = Scorer::from_slice(top_vec(&["typescript"]));
        let hit = s.score("typescirpt").unwrap();
        assert_eq!(hit.resembles, "typescript");
    }

    #[test]
    fn detects_extra_letter_in_react() {
        let s = Scorer::from_slice(top_vec(&["react"]));
        let hit = s.score("reactt").unwrap();
        assert_eq!(hit.resembles, "react");
        assert_eq!(hit.distance, 1);
    }

    #[test]
    fn detects_missing_letter_in_express() {
        let s = Scorer::from_slice(top_vec(&["express"]));
        let hit = s.score("expres").unwrap();
        assert_eq!(hit.resembles, "express");
        assert_eq!(hit.distance, 1);
    }

    // ---- negative cases -----------------------------------------------------

    #[test]
    fn skips_legitimate_top_n_member() {
        let s = Scorer::from_slice(top_vec(&["lodash", "react"]));
        assert!(s.score("lodash").is_none());
    }

    #[test]
    fn skips_short_names() {
        let s = Scorer::from_slice(top_vec(&["foo", "bar"]));
        assert!(s.score("baz").is_none(), "len < 4 always rejected");
    }

    #[test]
    fn skips_scoped_packages() {
        let s = Scorer::from_slice(top_vec(&["babel"]));
        // `@babel/core` looks similar to `babel` but the org namespace
        // prevents impersonation.
        assert!(s.score("@babel/core").is_none());
    }

    #[test]
    fn skips_distance_above_two() {
        let s = Scorer::from_slice(top_vec(&["lodash"]));
        assert!(s.score("totally-different").is_none());
    }

    #[test]
    fn skips_request_requests_pair_via_whitelist() {
        let s = Scorer::from_slice(top_vec(&["request"]));
        // `requests` (PyPI) vs `request` (npm) — both legitimate; whitelist
        // suppresses the noise for users mixing ecosystems.
        assert!(s.score("requests").is_none());
    }

    #[test]
    fn skips_react_preact_pair_via_whitelist() {
        let s = Scorer::from_slice(top_vec(&["react"]));
        assert!(s.score("preact").is_none());
    }

    #[test]
    fn skips_visually_dissimilar_short_substring() {
        let s = Scorer::from_slice(top_vec(&["express"]));
        // `compress` shares characters but distance > 2.
        assert!(s.score("compress").is_none());
    }

    #[test]
    fn skips_unrelated_substrings_in_lodash_realm() {
        let s = Scorer::from_slice(top_vec(&["lodash"]));
        assert!(s.score("redux").is_none());
        assert!(s.score("axios").is_none());
    }

    #[test]
    fn skips_self_when_in_top() {
        let s = Scorer::from_slice(top_vec(&["jquery"]));
        assert!(s.score("jquery").is_none());
    }

    #[test]
    fn skips_when_top_is_empty() {
        let s = Scorer::from_slice(top_vec(&[]));
        assert!(s.score("anything").is_none());
    }

    #[test]
    fn picks_highest_confidence_when_multiple_top_matches() {
        // `lodahs` is dist=2 from both `lodash` (swap, score 1.0) and
        // (hypothetically) `lodass` (dist 2 sub, score 0.5). Swap wins.
        let s = Scorer::from_slice(top_vec(&["lodash", "lodass"]));
        let hit = s.score("lodahs").unwrap();
        assert_eq!(hit.resembles, "lodash");
        assert_eq!(hit.reason, TyposquatReason::AdjacentSwap);
    }
}
