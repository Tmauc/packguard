//! Phase 5 graph + compatibility services.
//!
//! `build` assembles the nodes + edges consumed by `/api/graph`.
//! `contaminated_chains` runs an inverse BFS from the versions a given
//! advisory hits back to the workspace roots; results are cached in
//! `contamination_cache` and invalidated in the same transaction that
//! replaces the edge set (`save_project`). `compat` backs the new tab
//! on the package detail page.

use crate::dto::{
    CompatDependent, CompatPeerDep, CompatResponse, CompatRow, ComplianceTag, ContaminationChain,
    ContaminationHit, ContaminationResult, GraphEdge, GraphNode, GraphResponse,
    GraphVulnerabilityEntry, GraphVulnerabilityList,
};
use anyhow::Result;
use packguard_core::MalwareKind;
use packguard_intel::match_vulnerabilities;
use packguard_store::{Store, StoredEdge};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::path::Path;

/// Resolve the set of repo paths a Phase 7a scoped service should walk.
/// `Some(path)` → that single path (trust the caller to have validated
/// it through `resolve_project_filter`). `None` → every repo in the
/// store, so the endpoint's aggregate view is a strict superset of any
/// scoped call.
fn scope_paths(store: &Store, project: Option<&Path>) -> Result<Vec<std::path::PathBuf>> {
    match project {
        Some(p) => Ok(vec![p.to_path_buf()]),
        None => Ok(store.distinct_repo_paths()?),
    }
}

/// Hard cap on nodes before we signal the Cytoscape warning path.
const OVERSIZE_NODE_THRESHOLD: usize = 2000;
/// Hard cap on chains returned per contamination query.
pub const MAX_CHAINS: usize = 200;
/// Maximum BFS depth we ever explore. Protects against cycles + pathological
/// graphs; 32 is deeper than any real lockfile we've seen.
const MAX_BFS_DEPTH: u32 = 32;

pub fn build(
    store: &Store,
    project: Option<&Path>,
    workspace_filter: Option<&str>,
    max_depth: Option<u32>,
    kind_filter: Option<&str>,
) -> Result<GraphResponse> {
    // Phase 7a: `project = None` aggregates across every scanned repo so
    // `/api/graph` ⊇ `/api/graph?project=<path>` by construction. The
    // store helpers stay per-path — we just union the results here.
    let paths = scope_paths(store, project)?;
    let mut edges: Vec<StoredEdge> = Vec::new();
    let mut deps: Vec<packguard_store::StoredDependency> = Vec::new();
    let mut workspaces: Vec<(i64, Option<String>, std::path::PathBuf)> = Vec::new();
    for p in &paths {
        edges.extend(store.load_repo_edges(p)?);
        deps.extend(store.load_repo_dependencies(p)?);
        workspaces.extend(store.load_workspaces_for_repo(p)?);
    }

    let workspace_ids: BTreeSet<i64> = match workspace_filter {
        Some(w) => workspaces
            .iter()
            .filter(|(_, _, manifest)| manifest.to_string_lossy() == w)
            .map(|(id, _, _)| *id)
            .collect(),
        None => workspaces.iter().map(|(id, _, _)| *id).collect(),
    };
    let kinds = parse_kind_filter(kind_filter);
    let depth_cap = max_depth.unwrap_or(MAX_BFS_DEPTH).min(MAX_BFS_DEPTH);
    let ecosystem = deps
        .first()
        .map(|d| d.ecosystem.clone())
        .unwrap_or_else(|| "npm".to_string());

    let mut nodes: BTreeMap<String, GraphNode> = BTreeMap::new();
    let mut out_edges: Vec<GraphEdge> = Vec::new();

    // Roots: every installed direct dependency (subject to the workspace
    // filter). Also seeds the BFS traversal.
    let mut queue: VecDeque<(String, String, u32)> = VecDeque::new();
    let mut visited: HashSet<(String, String)> = HashSet::new();
    for dep in &deps {
        let Some(installed) = dep.installed.as_deref() else {
            continue;
        };
        let node = ensure_node(
            &mut nodes,
            store,
            &dep.ecosystem,
            &dep.name,
            installed,
            true,
        )?;
        let key = (node.name.clone(), node.version.clone());
        if visited.insert(key.clone()) {
            queue.push_back((node.name.clone(), node.version.clone(), 0));
        }
    }

    // Index edges by (source_name, source_version) so BFS stays O(E).
    let mut edges_by_source: HashMap<(String, String), Vec<&StoredEdge>> = HashMap::new();
    for e in &edges {
        if !workspace_ids.contains(&e.workspace_id) {
            continue;
        }
        edges_by_source
            .entry((e.source_name.clone(), e.source_version.clone()))
            .or_default()
            .push(e);
    }

    while let Some((src_name, src_version, depth)) = queue.pop_front() {
        if depth >= depth_cap {
            continue;
        }
        let Some(children) = edges_by_source.get(&(src_name.clone(), src_version.clone())) else {
            continue;
        };
        for e in children {
            if !kinds.is_empty() && !kinds.contains(&e.kind) {
                continue;
            }
            let target_name = e
                .resolved_target_name
                .clone()
                .unwrap_or_else(|| e.target_name.clone());
            let (target_version, unresolved) = match &e.resolved_version {
                Some(v) => (v.clone(), false),
                None => ("unresolved".to_string(), true),
            };
            let src_id = format!("{ecosystem}:{src_name}@{src_version}");
            let tgt_id = format!("{ecosystem}:{target_name}@{target_version}");
            out_edges.push(GraphEdge {
                source: src_id,
                target: tgt_id.clone(),
                range: e.target_range.clone(),
                kind: kind_label(e.kind).to_string(),
                unresolved,
            });
            if !unresolved {
                let node = ensure_node(
                    &mut nodes,
                    store,
                    &ecosystem,
                    &target_name,
                    &target_version,
                    false,
                )?;
                let key = (node.name.clone(), node.version.clone());
                if visited.insert(key) {
                    queue.push_back((node.name.clone(), node.version.clone(), depth + 1));
                }
            } else {
                // Placeholder node so the frontend never sees an edge whose
                // target is missing from `nodes[]`. Cytoscape crashes at
                // mount in that case — this is the backend half of the
                // Polish-bis-1 defense-in-depth fix (the frontend still
                // filters orphan edges independently).
                nodes.entry(tgt_id.clone()).or_insert_with(|| GraphNode {
                    id: tgt_id,
                    ecosystem: ecosystem.clone(),
                    name: target_name,
                    version: target_version,
                    is_root: false,
                    cve_severity: None,
                    has_malware: false,
                    has_typosquat: false,
                    compliance: None,
                    is_unresolved: true,
                });
            }
        }
    }

    let oversize_warning = if nodes.len() > OVERSIZE_NODE_THRESHOLD {
        Some(format!(
            "Graph has {} nodes — Cytoscape native renderer is slow above {}. \
             Tighten the workspace or kind filter.",
            nodes.len(),
            OVERSIZE_NODE_THRESHOLD
        ))
    } else {
        None
    };

    Ok(GraphResponse {
        nodes: nodes.into_values().collect(),
        edges: out_edges,
        oversize_warning,
    })
}

fn parse_kind_filter(filter: Option<&str>) -> BTreeSet<packguard_core::DepKind> {
    let Some(raw) = filter else {
        return BTreeSet::new();
    };
    let mut out = BTreeSet::new();
    for tok in raw.split(',') {
        match tok.trim() {
            "runtime" | "dep" => {
                out.insert(packguard_core::DepKind::Runtime);
            }
            "dev" => {
                out.insert(packguard_core::DepKind::Dev);
            }
            "peer" => {
                out.insert(packguard_core::DepKind::Peer);
            }
            "optional" | "opt" => {
                out.insert(packguard_core::DepKind::Optional);
            }
            _ => {}
        }
    }
    out
}

fn kind_label(k: packguard_core::DepKind) -> &'static str {
    match k {
        packguard_core::DepKind::Runtime => "runtime",
        packguard_core::DepKind::Dev => "dev",
        packguard_core::DepKind::Peer => "peer",
        packguard_core::DepKind::Optional => "optional",
    }
}

fn ensure_node<'a>(
    nodes: &'a mut BTreeMap<String, GraphNode>,
    store: &Store,
    ecosystem: &str,
    name: &str,
    version: &str,
    is_root: bool,
) -> Result<&'a GraphNode> {
    let id = format!("{ecosystem}:{name}@{version}");
    if let std::collections::btree_map::Entry::Vacant(entry) = nodes.entry(id.clone()) {
        // Compute cve severity + malware flags lazily per (pkg, version).
        let advisories = store.load_vulnerabilities(ecosystem, name)?;
        let core_advisories: Vec<packguard_core::Vulnerability> = advisories
            .into_iter()
            .map(|s| packguard_core::Vulnerability {
                source: s.source,
                advisory_id: s.advisory_id,
                ecosystem: s.ecosystem,
                package_name: s.package_name,
                severity: s.severity,
                cve_id: s.cve_id,
                aliases: s.aliases,
                summary: s.summary,
                url: s.url,
                affected: s.affected,
                fixed_versions: s.fixed_versions,
                published_at: s.published_at,
                modified_at: s.modified_at,
            })
            .collect();
        let matches = match_vulnerabilities(ecosystem, name, version, &core_advisories);
        let cve_severity = matches
            .iter()
            .map(|m| m.severity)
            .max()
            .filter(|s| !matches!(s, packguard_core::Severity::Unknown))
            .map(|s| s.as_str().to_string());

        let malware = store.load_malware_reports(ecosystem, name)?;
        let has_malware = malware.iter().any(|m| {
            matches!(m.kind, MalwareKind::Malware)
                && (m.version.is_none() || m.version.as_deref() == Some(version))
        });
        let has_typosquat = malware
            .iter()
            .any(|m| matches!(m.kind, MalwareKind::Typosquat));

        entry.insert(GraphNode {
            id: id.clone(),
            ecosystem: ecosystem.to_string(),
            name: name.to_string(),
            version: version.to_string(),
            is_root,
            cve_severity,
            has_malware,
            has_typosquat,
            compliance: None,
            is_unresolved: false,
        });
    } else if is_root {
        // Promote to root if any call-site flagged it as one.
        if let Some(node) = nodes.get_mut(&id) {
            node.is_root = true;
        }
    }
    Ok(nodes.get(&id).expect("just inserted"))
}

// ---- Palette: list of CVEs present in scope -------------------------------

/// Enumerate every advisory that hits a concrete (package, version) tuple
/// observable in the scoped dependency graph. The dashboard's Focus-CVE
/// command palette reads this to populate its fuzzy-search list, so the
/// user never has to know a CVE id by heart.
///
/// Shape mirrors `contaminated_chains` at a higher zoom-out: we reuse the
/// same "observed versions = direct installs ∪ resolved edge targets"
/// derivation, run `match_vulnerabilities` to filter to real hits, then
/// dedup by (advisory_id, package, version). `chains_count` is
/// deliberately absent — computing per-CVE contamination BFS at palette
/// fetch time is wasteful since selection triggers `?focus_cve=…` which
/// already renders the chains on the canvas.
pub fn vulnerabilities(store: &Store, project: Option<&Path>) -> Result<GraphVulnerabilityList> {
    let paths = scope_paths(store, project)?;
    let mut all_deps: Vec<packguard_store::StoredDependency> = Vec::new();
    let mut all_edges: Vec<StoredEdge> = Vec::new();
    for p in &paths {
        all_deps.extend(store.load_repo_dependencies(p)?);
        all_edges.extend(store.load_repo_edges(p)?);
    }

    let mut observed: BTreeSet<(String, String, String)> = BTreeSet::new();
    for dep in &all_deps {
        if let Some(v) = &dep.installed {
            observed.insert((dep.ecosystem.clone(), dep.name.clone(), v.clone()));
        }
    }
    let default_eco = all_deps
        .first()
        .map(|d| d.ecosystem.clone())
        .unwrap_or_else(|| "npm".to_string());
    for edge in &all_edges {
        let Some(resolved) = edge.resolved_version.as_deref() else {
            continue;
        };
        let name = edge
            .resolved_target_name
            .as_deref()
            .unwrap_or(&edge.target_name);
        observed.insert((default_eco.clone(), name.to_string(), resolved.to_string()));
    }

    let mut vuln_cache: HashMap<(String, String), Vec<packguard_core::Vulnerability>> =
        HashMap::new();
    let mut entries: Vec<GraphVulnerabilityEntry> = Vec::new();
    let mut seen: BTreeSet<(String, String, String, String)> = BTreeSet::new();

    for (eco, name, version) in &observed {
        let core = vuln_cache
            .entry((eco.clone(), name.clone()))
            .or_insert_with(|| {
                store
                    .load_vulnerabilities(eco, name)
                    .unwrap_or_default()
                    .into_iter()
                    .map(|v| packguard_core::Vulnerability {
                        source: v.source,
                        advisory_id: v.advisory_id,
                        ecosystem: v.ecosystem,
                        package_name: v.package_name,
                        severity: v.severity,
                        cve_id: v.cve_id,
                        aliases: v.aliases,
                        summary: v.summary,
                        url: v.url,
                        affected: v.affected,
                        fixed_versions: v.fixed_versions,
                        published_at: v.published_at,
                        modified_at: v.modified_at,
                    })
                    .collect()
            });
        if core.is_empty() {
            continue;
        }
        let matches = match_vulnerabilities(eco, name, version, core);
        for m in matches {
            let key = (
                m.advisory_id.clone(),
                eco.clone(),
                name.clone(),
                version.clone(),
            );
            if !seen.insert(key) {
                continue;
            }
            entries.push(GraphVulnerabilityEntry {
                advisory_id: m.advisory_id,
                cve_id: m.cve_id,
                ecosystem: eco.clone(),
                package_name: name.clone(),
                package_version: version.clone(),
                severity: m.severity.as_str().to_string(),
                summary: m.summary,
            });
        }
    }

    entries.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| {
                a.cve_id
                    .as_deref()
                    .unwrap_or(&a.advisory_id)
                    .cmp(b.cve_id.as_deref().unwrap_or(&b.advisory_id))
            })
            .then_with(|| a.package_name.cmp(&b.package_name))
            .then_with(|| a.package_version.cmp(&b.package_version))
    });

    Ok(GraphVulnerabilityList { entries })
}

fn severity_rank(s: &str) -> u8 {
    match s {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

// ---- Contamination BFS ----------------------------------------------------

pub fn contaminated_chains(
    store: &Store,
    project: Option<&Path>,
    advisory_id: &str,
) -> Result<ContaminationResult> {
    // Phase 7a: the contamination BFS now aggregates across every repo
    // when `project = None`, so `/api/graph/contaminated?vuln_id=X` ⊇
    // `/api/graph/contaminated?vuln_id=X&project=<path>`. When scoped,
    // the cache + BFS stay exactly as Phase 5 shipped them.
    let paths = scope_paths(store, project)?;
    let mut all_deps: Vec<packguard_store::StoredDependency> = Vec::new();
    let mut all_edges: Vec<StoredEdge> = Vec::new();
    let mut all_workspaces: Vec<(i64, Option<String>, std::path::PathBuf)> = Vec::new();
    for p in &paths {
        all_deps.extend(store.load_repo_dependencies(p)?);
        all_edges.extend(store.load_repo_edges(p)?);
        all_workspaces.extend(store.load_workspaces_for_repo(p)?);
    }

    // Which (package, version) does this advisory actually hit? We match
    // by cve_id / source+advisory_id / alias against every concrete
    // version observable in the scan: direct deps' installed versions
    // plus the resolved target of every transitive edge. `watched_packages`
    // + `load_package_versions` would miss transitive hits entirely,
    // since we only seed the version history for direct deps.
    let mut hits: Vec<ContaminationHit> = Vec::new();
    let mut observed: BTreeSet<(String, String, String)> = BTreeSet::new();
    for dep in &all_deps {
        if let Some(v) = &dep.installed {
            observed.insert((dep.ecosystem.clone(), dep.name.clone(), v.clone()));
        }
    }
    let default_eco = all_deps
        .first()
        .map(|d| d.ecosystem.clone())
        .unwrap_or_else(|| "npm".to_string());
    for edge in &all_edges {
        let Some(resolved) = edge.resolved_version.as_deref() else {
            continue;
        };
        let name = edge
            .resolved_target_name
            .as_deref()
            .unwrap_or(&edge.target_name);
        observed.insert((default_eco.clone(), name.to_string(), resolved.to_string()));
    }

    let mut advisory_cache: HashMap<(String, String), Vec<packguard_core::Vulnerability>> =
        HashMap::new();
    for (eco, name, version) in &observed {
        let core = advisory_cache
            .entry((eco.clone(), name.clone()))
            .or_insert_with(|| {
                let vulns = store.load_vulnerabilities(eco, name).unwrap_or_default();
                vulns
                    .into_iter()
                    .filter(|v| {
                        v.advisory_id == advisory_id
                            || v.cve_id.as_deref() == Some(advisory_id)
                            || v.aliases.iter().any(|a| a == advisory_id)
                    })
                    .map(|v| packguard_core::Vulnerability {
                        source: v.source,
                        advisory_id: v.advisory_id,
                        ecosystem: v.ecosystem,
                        package_name: v.package_name,
                        severity: v.severity,
                        cve_id: v.cve_id,
                        aliases: v.aliases,
                        summary: v.summary,
                        url: v.url,
                        affected: v.affected,
                        fixed_versions: v.fixed_versions,
                        published_at: v.published_at,
                        modified_at: v.modified_at,
                    })
                    .collect()
            });
        if core.is_empty() {
            continue;
        }
        let matches = match_vulnerabilities(eco, name, version, core);
        if !matches.is_empty() {
            hits.push(ContaminationHit {
                ecosystem: eco.clone(),
                name: name.clone(),
                version: version.clone(),
            });
        }
    }

    if hits.is_empty() {
        return Ok(ContaminationResult {
            hits,
            chains: Vec::new(),
            from_cache: false,
        });
    }

    // Fast path: cache keyed by (advisory_id, workspace_id). When every
    // workspace has a hit, return the union from the cache. Partial-miss
    // falls through to recomputation.
    let workspaces = &all_workspaces;
    let mut cached_chains: Vec<ContaminationChain> = Vec::new();
    let mut missing_workspace = false;
    for (ws_id, _, manifest) in workspaces {
        match store.load_contamination_cache(advisory_id, *ws_id)? {
            Some(json) => {
                let parsed: Vec<Vec<String>> = serde_json::from_str(&json).unwrap_or_default();
                for path in parsed {
                    cached_chains.push(ContaminationChain {
                        path,
                        workspace: manifest.to_string_lossy().into_owned(),
                    });
                }
            }
            None => {
                missing_workspace = true;
                break;
            }
        }
    }
    if !missing_workspace {
        cached_chains.sort_by(|a, b| a.path.len().cmp(&b.path.len()).then(a.path.cmp(&b.path)));
        cached_chains.dedup_by(|a, b| a.path == b.path && a.workspace == b.workspace);
        cached_chains.truncate(MAX_CHAINS);
        return Ok(ContaminationResult {
            hits,
            chains: cached_chains,
            from_cache: true,
        });
    }

    // Slow path — inverse BFS, per workspace.
    let edges = &all_edges;
    let deps = &all_deps;

    // Index edges by (target_name, resolved_version) for reverse traversal.
    let mut parents_by_resolved: HashMap<(String, String), Vec<&StoredEdge>> = HashMap::new();
    for e in edges.iter() {
        let Some(rv) = e.resolved_version.as_deref() else {
            continue;
        };
        parents_by_resolved
            .entry((e.target_name.clone(), rv.to_string()))
            .or_default()
            .push(e);
    }

    let mut chains_by_workspace: BTreeMap<i64, Vec<Vec<String>>> = BTreeMap::new();
    let hit_set: HashSet<(String, String, String)> = hits
        .iter()
        .map(|h| (h.ecosystem.clone(), h.name.clone(), h.version.clone()))
        .collect();

    for (ws_id, _, _) in workspaces {
        // Roots for this workspace: direct deps with an installed version.
        let workspace_roots: Vec<(String, String, String)> = deps
            .iter()
            .filter_map(|d| {
                d.installed
                    .as_deref()
                    .map(|v| (d.ecosystem.clone(), d.name.clone(), v.to_string()))
            })
            .collect();

        // Forward BFS from each root, stopping when we reach a hit.
        let ws_edges: Vec<&StoredEdge> =
            edges.iter().filter(|e| e.workspace_id == *ws_id).collect();
        let mut forward_by_source: HashMap<(String, String), Vec<&StoredEdge>> = HashMap::new();
        for e in ws_edges {
            forward_by_source
                .entry((e.source_name.clone(), e.source_version.clone()))
                .or_default()
                .push(e);
        }

        let mut ws_chains: Vec<Vec<String>> = Vec::new();
        for root in &workspace_roots {
            let start = format!("{}:{}@{}", root.0, root.1, root.2);
            let mut stack: Vec<(Vec<String>, String, String)> =
                vec![(vec![start.clone()], root.1.clone(), root.2.clone())];
            let mut seen: HashSet<(String, String)> =
                HashSet::from([(root.1.clone(), root.2.clone())]);
            while let Some((path, name, version)) = stack.pop() {
                if hit_set.contains(&(root.0.clone(), name.clone(), version.clone())) {
                    ws_chains.push(path.clone());
                    if ws_chains.len() >= MAX_CHAINS {
                        break;
                    }
                    continue;
                }
                if path.len() as u32 >= MAX_BFS_DEPTH {
                    continue;
                }
                let Some(children) = forward_by_source.get(&(name.clone(), version.clone())) else {
                    continue;
                };
                for e in children {
                    let Some(rv) = e.resolved_version.as_deref() else {
                        continue;
                    };
                    let child_name = e
                        .resolved_target_name
                        .clone()
                        .unwrap_or_else(|| e.target_name.clone());
                    if !seen.insert((child_name.clone(), rv.to_string())) {
                        continue;
                    }
                    let mut next_path = path.clone();
                    next_path.push(format!("{}:{}@{}", root.0, child_name, rv));
                    stack.push((next_path, child_name, rv.to_string()));
                }
            }
            if ws_chains.len() >= MAX_CHAINS {
                break;
            }
        }

        // Cache the raw paths for this workspace (before decoration).
        store.store_contamination_cache(
            advisory_id,
            *ws_id,
            &serde_json::to_string(&ws_chains).unwrap_or_else(|_| "[]".to_string()),
        )?;
        chains_by_workspace.insert(*ws_id, ws_chains);
    }

    let mut chains: Vec<ContaminationChain> = Vec::new();
    for (ws_id, paths) in chains_by_workspace {
        let manifest = workspaces
            .iter()
            .find(|(id, _, _)| *id == ws_id)
            .map(|(_, _, m)| m.to_string_lossy().into_owned())
            .unwrap_or_default();
        for path in paths {
            chains.push(ContaminationChain {
                path,
                workspace: manifest.clone(),
            });
        }
    }
    chains.sort_by(|a, b| a.path.len().cmp(&b.path.len()).then(a.path.cmp(&b.path)));
    chains.dedup_by(|a, b| a.path == b.path && a.workspace == b.workspace);
    chains.truncate(MAX_CHAINS);

    Ok(ContaminationResult {
        hits,
        chains,
        from_cache: false,
    })
}

// ---- Compatibility tab ----------------------------------------------------

pub fn compat(
    store: &Store,
    project: Option<&Path>,
    ecosystem: &str,
    name: &str,
) -> Result<CompatResponse> {
    let rows = store.load_compatibility(ecosystem, name)?;
    let mut compat_rows: Vec<CompatRow> = rows
        .into_iter()
        .map(|r| {
            let peer_deps: std::collections::BTreeMap<String, CompatPeerDep> = r
                .peer_deps
                .into_iter()
                .map(|(k, v)| {
                    (
                        k,
                        CompatPeerDep {
                            range: v.range,
                            optional: v.optional,
                        },
                    )
                })
                .collect();
            CompatRow {
                version: r.version,
                engines: r.engines,
                peer_deps,
            }
        })
        .collect();
    compat_rows.sort_by(|a, b| a.version.cmp(&b.version));

    // Phase 7a: aggregate across every scanned repo when `project = None`
    // so the Compat tab's "Used by" list shows every workspace that
    // depends on this package. Phase 7b tags each dependent with the repo
    // path it came from so the UI can group per-workspace without a
    // second round-trip (the header selector cross-references these
    // values against `/api/workspaces`).
    let paths = scope_paths(store, project)?;
    let mut installed: Option<String> = None;
    let mut dependents: Vec<CompatDependent> = Vec::new();
    for p in &paths {
        let workspace_key = p.display().to_string();
        if installed.is_none() {
            installed = store
                .load_repo_dependencies(p)?
                .into_iter()
                .find(|d| d.ecosystem == ecosystem && d.name == name)
                .and_then(|d| d.installed);
        }
        for e in store.load_repo_edges(p)? {
            let matches_by_resolved = e.resolved_target_name.as_deref() == Some(name);
            let matches_by_declared = e.target_name == name && e.resolved_target_name.is_none();
            if !(matches_by_resolved || matches_by_declared) {
                continue;
            }
            dependents.push(CompatDependent {
                ecosystem: ecosystem.to_string(),
                name: e.source_name,
                version: e.source_version,
                range: e.target_range,
                kind: kind_label(e.kind).to_string(),
                workspace: workspace_key.clone(),
            });
        }
    }
    dependents.sort_by(|a, b| {
        a.workspace
            .cmp(&b.workspace)
            .then(a.name.cmp(&b.name))
            .then(a.version.cmp(&b.version))
    });
    dependents
        .dedup_by(|a, b| a.workspace == b.workspace && a.name == b.name && a.version == b.version);

    Ok(CompatResponse {
        ecosystem: ecosystem.to_string(),
        name: name.to_string(),
        installed,
        rows: compat_rows,
        dependents,
    })
}

// Suppress the `ComplianceTag` use: the field is plumbed for forward
// compatibility with the compliance-colouring tier (Phase 6) but not
// written yet. Importing the type keeps the DTO contract stable.
#[allow(dead_code)]
fn _touch(_: ComplianceTag) {}
