import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { useSearchParams } from "react-router-dom";
import { AlertTriangleIcon, SearchIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/cn";
import { api } from "@/lib/api";
import { GraphCanvas, COLORS } from "@/components/graph/GraphCanvas";
import type { HighlightMode } from "@/components/graph/GraphCanvas";
import { NodePanel } from "@/components/graph/NodePanel";
import { CvePalette } from "@/components/graph/CvePalette";
import type { LayoutName } from "@/components/graph/register-layouts";
import { LAYOUTS } from "@/components/graph/register-layouts";
import { ScopeBadge } from "@/components/layout/ScopeBadge";
import { useScope } from "@/components/layout/workspace-scope";
import type { GraphResponse } from "@/api/types/GraphResponse";

const KINDS = ["runtime", "dev", "peer", "optional"] as const;
type Kind = (typeof KINDS)[number];

// Keys the URL `?hide=` param understands. Edge kinds live under the
// existing `?kind=` param, so the legend toggles wire those separately
// rather than double-encoding the same filter.
const HIDEABLE_KEYS = new Set([
  "eco:npm",
  "eco:pypi",
  "status:cve",
  "status:malware",
  "status:typosquat",
  "status:root",
]);

export function GraphPage() {
  const [params, setParams] = useSearchParams();
  const scope = useScope();
  const [selectedId, setSelectedId] = useState<string | null>(null);

  // URL-driven filters so the view is refreshable + linkable (the Compat
  // tab's `/graph?focus=...` deep-link relies on this).
  const kinds = useMemo<Kind[]>(() => {
    const raw = params.get("kind");
    if (!raw) return [...KINDS];
    return raw
      .split(",")
      .map((s) => s.trim())
      .filter((s): s is Kind => (KINDS as readonly string[]).includes(s));
  }, [params]);
  const maxDepth = Number(params.get("max_depth") ?? "2");
  const layout = ((params.get("layout") as LayoutName) ?? "cose-bilkent") as LayoutName;
  const focusCve = params.get("focus_cve") ?? "";
  const focusNode = params.get("focus") ?? "";
  const kindExplicit = params.get("kind") !== null;
  const hideSet = useMemo(() => {
    const raw = params.get("hide");
    if (!raw) return new Set<string>();
    return new Set(
      raw
        .split(",")
        .map((s) => s.trim())
        .filter((s) => HIDEABLE_KEYS.has(s)),
    );
  }, [params]);
  const [paletteOpen, setPaletteOpen] = useState(false);

  // Cmd+K / Ctrl+K toggle the palette while the /graph page is mounted.
  // Scoped to this effect (not a global shortcut registry) because the
  // trigger is only meaningful where the focus target lives.
  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const graphQuery = useQuery({
    queryKey: ["graph", { kinds, maxDepth }, scope ?? null],
    queryFn: () =>
      api.graph(
        {
          kind: kinds.join(","),
          max_depth: maxDepth,
        },
        scope,
      ),
  });

  const contamination = useQuery({
    queryKey: ["graph-contaminated", focusCve, scope ?? null],
    queryFn: () => api.contaminated(focusCve, scope),
    enabled: Boolean(focusCve),
  });

  const highlight: HighlightMode = useMemo(() => {
    if (!contamination.data || !focusCve) return { kind: "none" };
    const nodeIds = new Set<string>();
    const edgePairs = new Set<string>();
    for (const chain of contamination.data.chains) {
      for (let i = 0; i < chain.path.length; i += 1) {
        const nodeId = chain.path[i];
        if (typeof nodeId !== "string") continue;
        nodeIds.add(nodeId);
        if (i > 0) {
          const prev = chain.path[i - 1];
          if (typeof prev === "string") {
            edgePairs.add(`${prev}->${nodeId}`);
          }
        }
      }
    }
    return { kind: "contamination", nodeIds, edgePairs };
  }, [contamination.data, focusCve]);

  // In focus mode we narrow the canvas to just the contaminated subgraph.
  // Cytoscape runs its layout on the filtered element set, so the chain
  // gets the whole viewport instead of being hidden behind 1100+ muted
  // siblings. The `highlight` classes on top paint those chains red.
  const contaminationGraph = useMemo(() => {
    if (!graphQuery.data) return graphQuery.data;
    if (highlight.kind !== "contamination") return graphQuery.data;
    const nodes = graphQuery.data.nodes.filter((n) => highlight.nodeIds.has(n.id));
    const edges = graphQuery.data.edges.filter((e) =>
      highlight.edgePairs.has(`${e.source}->${e.target}`),
    );
    return { ...graphQuery.data, nodes, edges };
  }, [graphQuery.data, highlight]);

  // Visible node/edge counts after legend-category hide. Kept as scalars
  // rather than a full post-hide `GraphResponse` subset because filtering
  // the node array on every toggle spawns a new `elements` prop for
  // GraphCanvas, which Cytoscape treats as "graph changed → re-layout"
  // and resets every node to the origin. The canvas now gets the stable
  // pre-hide graph + a `hidden` prop and toggles a CSS class internally,
  // so positions survive the round-trip (Phase 11.4 / finding B).
  const visibleCounts = useMemo(() => {
    if (!contaminationGraph) return { nodes: 0, edges: 0 };
    if (hideSet.size === 0) {
      return {
        nodes: contaminationGraph.nodes.length,
        edges: contaminationGraph.edges.length,
      };
    }
    const kept = new Set<string>();
    for (const n of contaminationGraph.nodes) {
      if (hideSet.has(`eco:${n.ecosystem}`)) continue;
      if (hideSet.has("status:cve") && n.cve_severity) continue;
      if (hideSet.has("status:malware") && n.has_malware) continue;
      if (hideSet.has("status:typosquat") && n.has_typosquat) continue;
      if (hideSet.has("status:root") && n.is_root) continue;
      kept.add(n.id);
    }
    let edgeCount = 0;
    for (const e of contaminationGraph.edges) {
      if (kept.has(e.source) && kept.has(e.target)) edgeCount += 1;
    }
    return { nodes: kept.size, edges: edgeCount };
  }, [contaminationGraph, hideSet]);

  const selectedNode = useMemo(() => {
    if (!graphQuery.data || !selectedId) return null;
    return graphQuery.data.nodes.find((n) => n.id === selectedId) ?? null;
  }, [graphQuery.data, selectedId]);

  // React-router deep-link support: `/graph?focus=<id>` selects a node.
  useEffect(() => {
    if (focusNode && graphQuery.data?.nodes.some((n) => n.id === focusNode)) {
      setSelectedId(focusNode);
    }
  }, [focusNode, graphQuery.data]);

  function setKind(k: Kind, on: boolean) {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      const currentRaw = next.get("kind") ?? KINDS.join(",");
      const current = new Set(
        currentRaw.split(",").filter((x): x is Kind => (KINDS as readonly string[]).includes(x)),
      );
      if (on) current.add(k);
      else current.delete(k);
      if (current.size === KINDS.length) next.delete("kind");
      else next.set("kind", [...current].join(","));
      return next;
    });
  }

  function toggleHide(key: string) {
    if (!HIDEABLE_KEYS.has(key)) return;
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      const current = new Set(
        (next.get("hide") ?? "")
          .split(",")
          .map((s) => s.trim())
          .filter((s) => HIDEABLE_KEYS.has(s)),
      );
      if (current.has(key)) current.delete(key);
      else current.add(key);
      if (current.size === 0) next.delete("hide");
      else next.set("hide", [...current].sort().join(","));
      return next;
    });
  }

  function setDepth(n: number) {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (n >= 1 && n <= 32) next.set("max_depth", String(n));
      return next;
    });
  }

  function setLayout(l: LayoutName) {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("layout", l);
      return next;
    });
  }

  function selectCveFromPalette(vulnId: string) {
    setPaletteOpen(false);
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("focus_cve", vulnId);
      return next;
    });
  }

  function clearCveFilter() {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.delete("focus_cve");
      return next;
    });
  }

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col space-y-3">
      <header className="flex items-start justify-between gap-2">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-900">
            Graph
          </h1>
          <p className="text-sm text-zinc-500">
            Transitive dependency graph harvested from the last scan. Run a new
            scan to refresh.
          </p>
        </div>
        <div className="flex items-start gap-3">
          <ScopeBadge className="mt-0.5" />
          <Legend
            graph={contaminationGraph}
            hidden={hideSet}
            kinds={kinds}
            kindExplicit={kindExplicit}
            onToggleHide={toggleHide}
            onToggleKind={(k) => setKind(k, !kinds.includes(k))}
          />
        </div>
      </header>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-3 p-3">
          <div className="flex items-center gap-1.5">
            <span className="text-xs text-zinc-500">Kind:</span>
            {KINDS.map((k) => {
              const active = kinds.includes(k);
              return (
                <button
                  key={k}
                  type="button"
                  onClick={() => setKind(k, !active)}
                  className={cn(
                    "h-7 rounded-md border px-2 text-xs capitalize",
                    active
                      ? "border-zinc-900 bg-zinc-900 text-white"
                      : "border-zinc-300 bg-white text-zinc-700 hover:bg-zinc-50",
                  )}
                >
                  {k}
                </button>
              );
            })}
          </div>
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            Depth
            <input
              type="number"
              min={1}
              max={32}
              value={maxDepth}
              onChange={(e) => setDepth(Number(e.target.value))}
              className="h-7 w-14 rounded-md border border-zinc-300 px-1 text-center text-sm text-zinc-900"
            />
          </div>
          <div className="flex items-center gap-2 text-xs text-zinc-500">
            Layout
            <select
              value={layout}
              onChange={(e) => setLayout(e.target.value as LayoutName)}
              className="h-7 rounded-md border border-zinc-300 px-2 text-sm text-zinc-900"
            >
              {LAYOUTS.map((l) => (
                <option key={l} value={l}>
                  {l}
                </option>
              ))}
            </select>
          </div>
          <div className="ml-auto flex items-center gap-2">
            <Button
              size="sm"
              variant="outline"
              onClick={() => setPaletteOpen(true)}
              data-testid="open-cve-palette"
              className="gap-1.5"
            >
              <SearchIcon className="h-3.5 w-3.5 text-zinc-400" />
              <span className="text-xs text-zinc-700">
                {focusCve ? `Focus: ${focusCve}` : "Focus CVE…"}
              </span>
              <kbd className="rounded border border-zinc-200 bg-zinc-50 px-1 py-0 text-[10px] text-zinc-500">
                ⌘K
              </kbd>
            </Button>
            {focusCve && (
              <Button size="sm" variant="outline" onClick={clearCveFilter}>
                Clear
              </Button>
            )}
          </div>
        </CardContent>
      </Card>

      {graphQuery.data?.oversize_warning && (
        <div className="flex items-center gap-2 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          <AlertTriangleIcon className="h-4 w-4" />
          {graphQuery.data.oversize_warning}
        </div>
      )}

      {focusCve && contamination.data && (
        <div
          className="rounded-md border px-3 py-2 text-xs"
          style={{
            borderColor: COLORS.highlight,
            background: "#fef2f2",
            color: "#7f1d1d",
          }}
        >
          <span className="font-medium">{focusCve}</span>:{" "}
          {contamination.data.hits.length} package
          {contamination.data.hits.length === 1 ? "" : "s"} hit ·{" "}
          {contamination.data.chains.length} contamination chain
          {contamination.data.chains.length === 1 ? "" : "s"}
          {contamination.data.from_cache && " · cached"}
          {contamination.data.chains.length === 0 && (
            <>
              {" "}
              — no installed package is affected. Try one of the advisories
              listed on a Package detail page.
            </>
          )}
        </div>
      )}

      <Card className="flex flex-1 overflow-hidden p-0">
        <CardContent className="flex w-full gap-0 p-0">
          <div className="relative h-full flex-1">
            {graphQuery.isLoading && (
              <div className="p-6 text-sm text-zinc-500">Loading graph…</div>
            )}
            {graphQuery.error && (
              <div className="p-6 text-sm text-red-600">
                Failed to load graph: {String(graphQuery.error)}
              </div>
            )}
            {graphQuery.data && graphQuery.data.nodes.length === 0 && (
              <div className="p-6 text-sm text-zinc-500">
                No dependency edges in the store yet. Run{" "}
                <span className="font-mono">packguard scan</span> to populate
                the graph.
              </div>
            )}
            {contaminationGraph && contaminationGraph.nodes.length > 0 && (
              <GraphCanvas
                graph={contaminationGraph}
                layout={layout}
                highlight={highlight}
                hidden={hideSet}
                selectedId={selectedId}
                onSelect={setSelectedId}
              />
            )}
            {contaminationGraph && (
              <div className="absolute bottom-2 left-2 rounded-md bg-white/80 px-2 py-0.5 text-[10px] text-zinc-500 shadow">
                {visibleCounts.nodes} nodes · {visibleCounts.edges} edges
                {highlight.kind === "contamination" && graphQuery.data && (
                  <span className="ml-1 text-zinc-400">
                    / {graphQuery.data.nodes.length} total
                  </span>
                )}
              </div>
            )}
          </div>
          {selectedNode && (
            <NodePanel node={selectedNode} onClose={() => setSelectedId(null)} />
          )}
        </CardContent>
      </Card>
      <CvePalette
        open={paletteOpen}
        onClose={() => setPaletteOpen(false)}
        onSelect={selectCveFromPalette}
      />
    </div>
  );
}

// Inspect the currently-rendered graph to surface only the legend entries
// that map to something visible. On a 1000-node npm-only workspace the old
// static legend advertised pypi/malware/typosquat swatches the user could
// never see — pure noise. Keys are intentionally category-scoped (prefixed
// by their domain) so the click-toggle logic can route each key back to
// either the `?hide=` param (node categories) or the existing `?kind=`
// param (edge kinds).
function collectPresentCategories(graph: GraphResponse | null | undefined): Set<string> {
  const present = new Set<string>();
  if (!graph) return present;
  for (const n of graph.nodes) {
    if (n.ecosystem === "npm") present.add("eco:npm");
    else if (n.ecosystem === "pypi") present.add("eco:pypi");
    if (n.cve_severity) present.add("status:cve");
    if (n.has_malware) present.add("status:malware");
    if (n.has_typosquat) present.add("status:typosquat");
    if (n.is_root) present.add("status:root");
  }
  for (const e of graph.edges) {
    if (e.kind === "runtime") present.add("edge:runtime");
    else if (e.kind === "dev") present.add("edge:dev");
    else if (e.kind === "peer") present.add("edge:peer");
    else if (e.kind === "optional") present.add("edge:optional");
  }
  return present;
}

type NodeLegendItem = {
  key: string;
  label: string;
  color: string;
  ring?: boolean;
  dashed?: boolean;
  thick?: boolean;
};

type EdgeLegendItem = {
  kind: Kind;
  label: string;
  color: string;
  dashed?: boolean;
  dotted?: boolean;
};

const NODE_LEGEND: NodeLegendItem[] = [
  { key: "eco:npm", label: "npm", color: COLORS.ecoNpm },
  { key: "eco:pypi", label: "pypi", color: COLORS.ecoPypi },
  { key: "status:cve", label: "CVE", color: COLORS.cve, ring: true },
  { key: "status:malware", label: "malware", color: COLORS.malware },
  { key: "status:typosquat", label: "typosquat", color: COLORS.yanked, ring: true, dashed: true },
  { key: "status:root", label: "root", color: COLORS.root, ring: true, thick: true },
];

const EDGE_LEGEND: EdgeLegendItem[] = [
  { kind: "runtime", label: "runtime", color: COLORS.edgeRuntime },
  { kind: "dev", label: "dev", color: COLORS.edgeDev },
  { kind: "peer", label: "peer", color: COLORS.edgePeer, dashed: true },
  { kind: "optional", label: "optional", color: COLORS.edgeOptional, dotted: true },
];

function Legend({
  graph,
  hidden,
  kinds,
  kindExplicit,
  onToggleHide,
  onToggleKind,
}: {
  graph: GraphResponse | null | undefined;
  hidden: Set<string>;
  kinds: Kind[];
  // True when the URL has an explicit `?kind=` param — a kind not in
  // `kinds` was deliberately deselected and should stay visible in the
  // legend (desaturated) so the user can click to restore.
  kindExplicit: boolean;
  onToggleHide: (key: string) => void;
  onToggleKind: (k: Kind) => void;
}) {
  const present = useMemo(() => collectPresentCategories(graph), [graph]);
  const activeKinds = useMemo(() => new Set(kinds), [kinds]);

  const nodeItems = NODE_LEGEND.filter(
    (item) => present.has(item.key) || hidden.has(item.key),
  );
  const edgeItems = EDGE_LEGEND.filter(
    (item) =>
      present.has(`edge:${item.kind}`) || (kindExplicit && !activeKinds.has(item.kind)),
  );

  if (nodeItems.length === 0 && edgeItems.length === 0) return null;

  return (
    <div
      className="flex flex-wrap items-center gap-2 text-[11px] text-zinc-500"
      data-testid="graph-legend"
    >
      {nodeItems.map((item) => (
        <LegendSwatch
          key={item.key}
          color={item.color}
          label={item.label}
          ring={item.ring}
          dashed={item.dashed}
          thick={item.thick}
          off={hidden.has(item.key)}
          onClick={() => onToggleHide(item.key)}
          testId={`legend-${item.key}`}
        />
      ))}
      {edgeItems.length > 0 && (
        <span
          className={cn(
            "flex flex-wrap items-center gap-1.5",
            nodeItems.length > 0 && "ml-1 border-l border-zinc-200 pl-3",
          )}
        >
          <span>edges:</span>
          {edgeItems.map((item) => (
            <LegendEdgeButton
              key={item.kind}
              label={item.label}
              color={item.color}
              dashed={item.dashed}
              dotted={item.dotted}
              off={!activeKinds.has(item.kind)}
              onClick={() => onToggleKind(item.kind)}
              testId={`legend-edge-${item.kind}`}
            />
          ))}
        </span>
      )}
    </div>
  );
}

function LegendSwatch({
  color,
  label,
  ring = false,
  dashed = false,
  thick = false,
  off = false,
  onClick,
  testId,
}: {
  color: string;
  label: string;
  ring?: boolean;
  dashed?: boolean;
  thick?: boolean;
  off?: boolean;
  onClick?: () => void;
  testId?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={!off}
      data-testid={testId}
      className={cn(
        "inline-flex items-center gap-1 rounded-sm px-1 py-0.5 transition-opacity",
        "hover:bg-zinc-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-zinc-400",
        off && "text-zinc-400 line-through opacity-60",
      )}
    >
      <span
        className="inline-block h-3 w-3 rounded-full"
        style={{
          background: ring ? "#ffffff" : color,
          border: ring
            ? `${thick ? 3 : 2}px ${dashed ? "dashed" : "solid"} ${color}`
            : undefined,
          filter: off ? "grayscale(1)" : undefined,
        }}
      />
      {label}
    </button>
  );
}

function LegendEdgeButton({
  color,
  label,
  dashed = false,
  dotted = false,
  off = false,
  onClick,
  testId,
}: {
  color: string;
  label: string;
  dashed?: boolean;
  dotted?: boolean;
  off?: boolean;
  onClick?: () => void;
  testId?: string;
}) {
  const style = dashed ? "dashed" : dotted ? "dotted" : "solid";
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={!off}
      data-testid={testId}
      className={cn(
        "inline-flex items-center gap-1 rounded-sm px-1 py-0.5 transition-opacity",
        "hover:bg-zinc-100 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-zinc-400",
        off && "text-zinc-400 line-through opacity-60",
      )}
    >
      <span>{label}</span>
      <span
        className="inline-block h-0 w-6 align-middle"
        style={{
          borderBottom: `2px ${style} ${color}`,
          filter: off ? "grayscale(1)" : undefined,
        }}
      />
    </button>
  );
}
