import { useEffect, useMemo, useRef } from "react";
import CytoscapeComponent from "react-cytoscapejs";
import type { Core, ElementDefinition, NodeSingular, EventObject } from "cytoscape";
import type { GraphResponse } from "@/api/types/GraphResponse";
import type { LayoutName } from "@/components/graph/register-layouts";
import "@/components/graph/register-layouts";

/// Loose cytoscape stylesheet typing — the @types/cytoscape surface for
/// selectors + style is strict in a way that fights callback-based style
/// rules. We keep our own rules statically typed below and just cast.
type CyStyleRule = { selector: string; style: Record<string, unknown> };

/// Colour palette — mirrors the CLI + dashboard's existing semantics.
/// Ecosystem fills pair with the Badge component's `muted` tone so the
/// graph feels like the same product, not a separate visualization.
export const COLORS = {
  ecoNpm: "#2563eb", // blue-600
  ecoPypi: "#16a34a", // green-600
  ecoDefault: "#71717a", // zinc-500
  cve: "#dc2626", // red-600
  malware: "#a855f7", // purple-500
  yanked: "#d946ef", // fuchsia-500
  root: "#18181b", // zinc-900
  edgeRuntime: "#18181b",
  edgeDev: "#3b82f6",
  edgePeer: "#f97316",
  edgeOptional: "#a1a1aa",
  highlight: "#dc2626",
} as const;

export type HighlightMode =
  | { kind: "none" }
  | { kind: "contamination"; nodeIds: Set<string>; edgePairs: Set<string> };

export function GraphCanvas({
  graph,
  layout,
  highlight,
  selectedId,
  onSelect,
}: {
  graph: GraphResponse;
  layout: LayoutName;
  highlight: HighlightMode;
  selectedId: string | null;
  onSelect: (id: string | null) => void;
}) {
  const cyRef = useRef<Core | null>(null);

  const elements: ElementDefinition[] = useMemo(() => {
    const out: ElementDefinition[] = [];
    for (const n of graph.nodes) {
      out.push({
        data: {
          id: n.id,
          label: n.name,
          version: n.version,
          ecosystem: n.ecosystem,
          cve_severity: n.cve_severity ?? "",
          has_malware: n.has_malware ? "1" : "",
          has_typosquat: n.has_typosquat ? "1" : "",
          is_root: n.is_root ? "1" : "",
        },
      });
    }
    for (const e of graph.edges) {
      out.push({
        data: {
          id: `${e.source}->${e.target}:${e.kind}`,
          source: e.source,
          target: e.target,
          kind: e.kind,
          unresolved: e.unresolved ? "1" : "",
        },
      });
    }
    return out;
  }, [graph]);

  const stylesheet: CyStyleRule[] = useMemo(
    () => [
      {
        selector: "node",
        style: {
          label: "data(label)",
          "font-size": 9,
          "text-valign": "bottom",
          "text-halign": "center",
          "text-margin-y": 4,
          color: "#3f3f46",
          "background-color": (ele: NodeSingular) => {
            const eco = ele.data("ecosystem");
            if (eco === "npm") return COLORS.ecoNpm;
            if (eco === "pypi") return COLORS.ecoPypi;
            return COLORS.ecoDefault;
          },
          width: 14,
          height: 14,
          "border-width": 1.5,
          "border-color": "#ffffff",
          "transition-property": "opacity, background-color, border-color",
          "transition-duration": 180,
        },
      },
      {
        selector: "node[cve_severity]",
        style: {
          "border-width": 3,
          "border-color": COLORS.cve,
        },
      },
      {
        selector: "node[has_malware = '1']",
        style: {
          "background-color": COLORS.malware,
          "border-color": COLORS.malware,
          "border-width": 3,
        },
      },
      {
        selector: "node[has_typosquat = '1']",
        style: {
          "border-color": COLORS.yanked,
          "border-width": 3,
          "border-style": "dashed",
        },
      },
      {
        selector: "node[is_root = '1']",
        style: {
          width: 22,
          height: 22,
          "border-width": 3,
          "border-color": COLORS.root,
          "font-weight": 700,
          "font-size": 11,
        },
      },
      // Edges by kind.
      {
        selector: "edge",
        style: {
          width: 1,
          "line-color": COLORS.edgeRuntime,
          "target-arrow-shape": "triangle",
          "target-arrow-color": COLORS.edgeRuntime,
          "arrow-scale": 0.6,
          "curve-style": "bezier",
          opacity: 0.55,
        },
      },
      {
        selector: "edge[kind = 'dev']",
        style: { "line-color": COLORS.edgeDev, "target-arrow-color": COLORS.edgeDev },
      },
      {
        selector: "edge[kind = 'peer']",
        style: {
          "line-color": COLORS.edgePeer,
          "target-arrow-color": COLORS.edgePeer,
          "line-style": "dashed",
        },
      },
      {
        selector: "edge[kind = 'optional']",
        style: {
          "line-color": COLORS.edgeOptional,
          "target-arrow-color": COLORS.edgeOptional,
          "line-style": "dotted",
        },
      },
      {
        selector: "edge[unresolved = '1']",
        style: { "line-style": "dashed", opacity: 0.4 },
      },
      // Selected node gets a halo so the side panel feels anchored.
      {
        selector: "node.selected",
        style: {
          "border-color": "#0f172a",
          "border-width": 4,
        },
      },
      // Contamination focus: mute everything not on the chain; highlight the
      // chain in red so the eye can follow from the root down to the hit.
      {
        selector: ".faded",
        style: { opacity: 0.08 },
      },
      {
        selector: "node.contaminated",
        style: {
          "border-color": COLORS.highlight,
          "border-width": 4,
          opacity: 1,
        },
      },
      {
        selector: "edge.contaminated",
        style: {
          "line-color": COLORS.highlight,
          "target-arrow-color": COLORS.highlight,
          opacity: 1,
          width: 2.5,
        },
      },
    ],
    [],
  );

  const layoutOptions = useMemo(() => {
    if (layout === "dagre") {
      return {
        name: "dagre",
        rankDir: "TB",
        nodeSep: 22,
        rankSep: 60,
        animate: false,
        fit: true,
        padding: 32,
      };
    }
    return {
      name: "cose-bilkent",
      animate: false,
      fit: true,
      padding: 32,
      nodeRepulsion: 4500,
      idealEdgeLength: 60,
    };
  }, [layout]);

  // Re-apply focus classes without recomputing elements. A layout run is
  // expensive; class toggles are cheap.
  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;
    cy.batch(() => {
      cy.elements().removeClass("faded contaminated selected");
      if (selectedId) {
        cy.getElementById(selectedId).addClass("selected");
      }
      if (highlight.kind === "contamination") {
        cy.nodes().forEach((n) => {
          if (!highlight.nodeIds.has(n.id())) n.addClass("faded");
          else n.addClass("contaminated");
        });
        cy.edges().forEach((e) => {
          const pair = `${e.data("source")}->${e.data("target")}`;
          if (highlight.edgePairs.has(pair)) {
            e.addClass("contaminated");
          } else {
            e.addClass("faded");
          }
        });
      }
    });
  }, [selectedId, highlight]);

  return (
    <CytoscapeComponent
      elements={elements}
      stylesheet={stylesheet}
      layout={layoutOptions}
      cy={(cy: Core) => {
        cyRef.current = cy;
        cy.removeListener("tap");
        cy.on("tap", "node", (evt: EventObject) => {
          onSelect((evt.target as NodeSingular).id());
        });
        cy.on("tap", (evt: EventObject) => {
          if (evt.target === cy) onSelect(null);
        });
      }}
      style={{ width: "100%", height: "100%" }}
      wheelSensitivity={0.2}
    />
  );
}
