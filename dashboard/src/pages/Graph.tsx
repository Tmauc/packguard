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
import type { LayoutName } from "@/components/graph/register-layouts";
import { LAYOUTS } from "@/components/graph/register-layouts";
import { ScopeBadge } from "@/components/layout/ScopeBadge";
import { useScope } from "@/components/layout/workspace-scope";

const KINDS = ["runtime", "dev", "peer", "optional"] as const;
type Kind = (typeof KINDS)[number];

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
  const maxDepth = Number(params.get("max_depth") ?? "4");
  const layout = ((params.get("layout") as LayoutName) ?? "dagre") as LayoutName;
  const focusCve = params.get("focus_cve") ?? "";
  const focusNode = params.get("focus") ?? "";
  const [cveInput, setCveInput] = useState(focusCve);

  useEffect(() => {
    setCveInput(focusCve);
  }, [focusCve]);

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
  const displayGraph = useMemo(() => {
    if (!graphQuery.data) return graphQuery.data;
    if (highlight.kind !== "contamination") return graphQuery.data;
    const nodes = graphQuery.data.nodes.filter((n) => highlight.nodeIds.has(n.id));
    const edges = graphQuery.data.edges.filter((e) =>
      highlight.edgePairs.has(`${e.source}->${e.target}`),
    );
    return { ...graphQuery.data, nodes, edges };
  }, [graphQuery.data, highlight]);

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

  function applyCveFilter() {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (cveInput.trim()) next.set("focus_cve", cveInput.trim());
      else next.delete("focus_cve");
      return next;
    });
  }

  function clearCveFilter() {
    setCveInput("");
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
          <Legend />
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
            <SearchIcon className="h-4 w-4 text-zinc-400" />
            <input
              type="search"
              placeholder="Focus CVE (e.g. CVE-2026-4800)"
              value={cveInput}
              onChange={(e) => setCveInput(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") applyCveFilter();
              }}
              className="h-7 w-56 rounded-md border border-zinc-300 bg-white px-2 text-sm"
            />
            <Button size="sm" variant="outline" onClick={applyCveFilter}>
              Trace
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
            {displayGraph && displayGraph.nodes.length > 0 && (
              <GraphCanvas
                graph={displayGraph}
                layout={layout}
                highlight={highlight}
                selectedId={selectedId}
                onSelect={setSelectedId}
              />
            )}
            {displayGraph && (
              <div className="absolute bottom-2 left-2 rounded-md bg-white/80 px-2 py-0.5 text-[10px] text-zinc-500 shadow">
                {displayGraph.nodes.length} nodes ·{" "}
                {displayGraph.edges.length} edges
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
    </div>
  );
}

function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-3 text-[11px] text-zinc-500">
      <LegendSwatch color={COLORS.ecoNpm} label="npm" />
      <LegendSwatch color={COLORS.ecoPypi} label="pypi" />
      <LegendSwatch color={COLORS.cve} label="CVE" ring />
      <LegendSwatch color={COLORS.malware} label="malware" />
      <LegendSwatch color={COLORS.yanked} label="typosquat" ring dashed />
      <LegendSwatch color={COLORS.root} label="root" ring thick />
      <span className="ml-1 border-l border-zinc-200 pl-3">
        edges: runtime <EdgeLabel color={COLORS.edgeRuntime} /> · dev{" "}
        <EdgeLabel color={COLORS.edgeDev} /> · peer{" "}
        <EdgeLabel color={COLORS.edgePeer} dashed /> · optional{" "}
        <EdgeLabel color={COLORS.edgeOptional} dotted />
      </span>
    </div>
  );
}

function LegendSwatch({
  color,
  label,
  ring = false,
  dashed = false,
  thick = false,
}: {
  color: string;
  label: string;
  ring?: boolean;
  dashed?: boolean;
  thick?: boolean;
}) {
  return (
    <span className="inline-flex items-center gap-1">
      <span
        className="inline-block h-3 w-3 rounded-full"
        style={{
          background: ring ? "#ffffff" : color,
          border: ring
            ? `${thick ? 3 : 2}px ${dashed ? "dashed" : "solid"} ${color}`
            : undefined,
        }}
      />
      {label}
    </span>
  );
}

function EdgeLabel({
  color,
  dashed = false,
  dotted = false,
}: {
  color: string;
  dashed?: boolean;
  dotted?: boolean;
}) {
  const style = dashed ? "dashed" : dotted ? "dotted" : "solid";
  return (
    <span
      className="inline-block h-0 w-6 align-middle"
      style={{ borderBottom: `2px ${style} ${color}` }}
    />
  );
}
