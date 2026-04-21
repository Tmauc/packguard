/// <reference types="vite/client" />

declare module "*.css";

// Cytoscape-ecosystem packages ship without types. We only touch them
// through thin wrappers in `components/graph/*`, so a blanket `any`
// declaration is enough for TS + keeps our compile surface narrow.
declare module "react-cytoscapejs" {
  import type { ComponentType } from "react";
  import type { Core, ElementDefinition } from "cytoscape";
  interface Props {
    elements: ElementDefinition[];
    stylesheet?: unknown;
    layout?: { name: string; [key: string]: unknown };
    style?: React.CSSProperties;
    cy?: (cy: Core) => void;
    wheelSensitivity?: number;
  }
  const CytoscapeComponent: ComponentType<Props>;
  export default CytoscapeComponent;
}

declare module "cytoscape-dagre";
declare module "cytoscape-cose-bilkent";
