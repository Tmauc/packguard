#!/usr/bin/env node
// Merge PackGuard's report / audit / graph JSON exports into one
// content/live/snapshot.json consumed at build time by app/live/page.tsx.
//
// Invocation (manual or from CI):
//
//   packguard scan docs-site/
//   packguard sync
//   packguard report docs-site/ --format json > /tmp/pg-report.json
//   packguard audit  docs-site/ --focus all --format json > /tmp/pg-audit.json
//   packguard graph  docs-site/ --format json > /tmp/pg-graph.json
//   node docs-site/scripts/build-snapshot.mjs \
//        --report /tmp/pg-report.json \
//        --audit  /tmp/pg-audit.json \
//        --graph  /tmp/pg-graph.json \
//        --out    docs-site/content/live/snapshot.json
//
// Fails loud on any missing/corrupt input — never writes a partial
// snapshot. The workflow relies on a non-zero exit to skip the commit
// step.

import { readFile, writeFile, mkdir } from 'node:fs/promises'
import { dirname, resolve } from 'node:path'
import { execSync } from 'node:child_process'

const MAX_GRAPH_NODES = 60

function parseArgs(argv) {
  const args = {}
  for (let i = 2; i < argv.length; i += 2) {
    const key = argv[i]?.replace(/^--/, '')
    const value = argv[i + 1]
    if (!key || value == null) continue
    args[key] = value
  }
  return args
}

function packguardVersion() {
  try {
    const raw = execSync('packguard --version', { encoding: 'utf8' }).trim()
    return raw.replace(/^packguard\s+/, '')
  } catch {
    return 'unknown'
  }
}

// Keep the graph small enough for bundling + client render:
// - every workspace root (there's usually just one here)
// - every node with a risk flag (CVE, malware, typosquat, unresolved)
// - every direct runtime/dev dep of a root
// - fill up to MAX_GRAPH_NODES with the remaining frontier
function slimGraph(graph) {
  const roots = graph.nodes.filter((n) => n.is_root)
  const risky = graph.nodes.filter(
    (n) =>
      !n.is_root &&
      (n.cve_severity || n.has_malware || n.has_typosquat || n.is_unresolved),
  )

  const directIds = new Set()
  const rootIds = new Set(roots.map((r) => r.id))
  for (const e of graph.edges) {
    if (rootIds.has(e.source)) directIds.add(e.target)
  }
  const directs = graph.nodes.filter(
    (n) => directIds.has(n.id) && !rootIds.has(n.id),
  )

  const kept = new Map()
  for (const n of [...roots, ...risky, ...directs]) {
    if (!kept.has(n.id) && kept.size < MAX_GRAPH_NODES) kept.set(n.id, n)
  }

  const keepIds = new Set(kept.keys())
  const edges = graph.edges
    .filter((e) => keepIds.has(e.source) && keepIds.has(e.target))
    .map((e) => ({
      source: e.source,
      target: e.target,
      kind: e.kind,
      unresolved: !!e.unresolved,
    }))

  return {
    nodes: [...kept.values()],
    edges,
    total_nodes: graph.nodes.length,
    total_edges: graph.edges.length,
    oversize_warning: !!graph.oversize_warning,
  }
}

function summarizeReport(report) {
  const rows = Array.isArray(report.rows) ? report.rows : []
  const counts = {
    compliant: 0,
    warning: 0,
    violation: 0,
    'cve-violation': 0,
    malware: 0,
    typosquat: 0,
    insufficient: 0,
  }
  for (const r of rows) {
    if (counts[r.status] != null) counts[r.status] += 1
  }
  return { total_packages: rows.length, by_status: counts }
}

async function main() {
  const args = parseArgs(process.argv)
  for (const k of ['report', 'audit', 'graph', 'out']) {
    if (!args[k]) {
      console.error(`[snapshot] missing required flag --${k}`)
      process.exit(2)
    }
  }

  const [report, audit, graph] = await Promise.all(
    ['report', 'audit', 'graph'].map(async (k) => {
      const path = resolve(args[k])
      const raw = await readFile(path, 'utf8')
      return JSON.parse(raw)
    }),
  )

  // Minimum sanity: a corrupt/empty report or missing keys on audit
  // means the CLI errored mid-run — refuse to commit.
  if (!Array.isArray(report.rows)) throw new Error('report.rows missing')
  if (!audit.cve || !audit.cve.summary) throw new Error('audit.cve.summary missing')
  if (!Array.isArray(graph.nodes)) throw new Error('graph.nodes missing')

  const snapshot = {
    scanned_at: new Date().toISOString(),
    packguard_version: args.version || packguardVersion(),
    target: {
      name: args.target || 'docs-site',
      ecosystems: ['npm'],
      package_manager: 'pnpm',
    },
    summary: {
      ...summarizeReport(report),
      cve_by_severity: audit.cve.summary,
      malware_confirmed: Array.isArray(audit.malware) ? audit.malware.length : 0,
      typosquat_suspects: Array.isArray(audit.typosquat) ? audit.typosquat.length : 0,
    },
    report,
    audit,
    graph: slimGraph(graph),
  }

  const outPath = resolve(args.out)
  await mkdir(dirname(outPath), { recursive: true })
  await writeFile(outPath, JSON.stringify(snapshot, null, 2) + '\n', 'utf8')
  console.log(
    `[snapshot] wrote ${outPath} — ${snapshot.summary.total_packages} pkgs, ` +
      `${snapshot.graph.nodes.length}/${snapshot.graph.total_nodes} graph nodes kept`,
  )
}

main().catch((err) => {
  console.error('[snapshot] build failed:', err.message)
  process.exit(1)
})
