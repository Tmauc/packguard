import { Link } from "react-router-dom";
import { ExternalLinkIcon, XIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { GraphNode } from "@/api/types/GraphNode";

/// Side drawer that opens when a node is clicked in the graph canvas.
/// Reads from the already-loaded GraphResponse so we don't re-hit the API;
/// the "Open detail →" link routes to the existing Package detail page
/// which carries CVE/malware/policy deep-dives.
export function NodePanel({
  node,
  onClose,
}: {
  node: GraphNode;
  onClose: () => void;
}) {
  const detailUrl = `/packages/${encodeURIComponent(node.ecosystem)}/${encodeURIComponent(
    node.name,
  )}`;
  return (
    <aside className="flex h-full w-80 shrink-0 flex-col border-l border-zinc-200 bg-white">
      <header className="flex items-start justify-between border-b border-zinc-200 p-3">
        <div className="min-w-0">
          <div className="truncate font-mono text-sm text-zinc-900">{node.name}</div>
          <div className="text-xs text-zinc-500">
            {node.ecosystem} · {node.version}
          </div>
        </div>
        <button
          type="button"
          onClick={onClose}
          className="text-zinc-400 hover:text-zinc-900"
          aria-label="Close"
        >
          <XIcon className="h-4 w-4" />
        </button>
      </header>
      <div className="flex-1 space-y-3 overflow-y-auto p-3 text-sm">
        <div className="flex flex-wrap gap-1">
          {node.is_root && <Badge tone="muted">root</Badge>}
          {node.cve_severity && (
            <Badge tone="cve">{node.cve_severity} CVE</Badge>
          )}
          {node.has_malware && <Badge tone="malware">malware</Badge>}
          {node.has_typosquat && <Badge tone="typosquat">typosquat</Badge>}
        </div>
        <dl className="space-y-2 text-xs">
          <div>
            <dt className="text-zinc-500">Ecosystem</dt>
            <dd className="font-mono text-zinc-900">{node.ecosystem}</dd>
          </div>
          <div>
            <dt className="text-zinc-500">Version</dt>
            <dd className="font-mono text-zinc-900">{node.version}</dd>
          </div>
          <div>
            <dt className="text-zinc-500">Graph id</dt>
            <dd className="break-all font-mono text-zinc-900">{node.id}</dd>
          </div>
        </dl>
        <Link
          to={detailUrl}
          className="inline-flex items-center gap-1 rounded-md border border-zinc-300 px-2 py-1 text-xs text-zinc-700 hover:bg-zinc-50"
        >
          Open detail <ExternalLinkIcon className="h-3 w-3" />
        </Link>
      </div>
    </aside>
  );
}
