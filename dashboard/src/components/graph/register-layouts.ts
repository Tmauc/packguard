/// Registers Cytoscape layout plugins once, when the graph page code first
/// imports this module. Re-importing is cheap — the `use()` calls no-op on
/// subsequent calls because Cytoscape tracks registered extensions.

import cytoscape from "cytoscape";
import dagre from "cytoscape-dagre";
import coseBilkent from "cytoscape-cose-bilkent";

type LayoutExtension = Parameters<typeof cytoscape.use>[0];

cytoscape.use(dagre as unknown as LayoutExtension);
cytoscape.use(coseBilkent as unknown as LayoutExtension);

export const LAYOUTS = ["dagre", "cose-bilkent"] as const;
export type LayoutName = (typeof LAYOUTS)[number];
