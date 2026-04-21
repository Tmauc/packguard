import { FolderTreeIcon, LayersIcon } from "lucide-react";
import { scopeLabel, useScope } from "./workspace-scope";

/**
 * Discreet per-page indicator so a user who arrives via deep link or
 * bookmark immediately sees whether the numbers on screen are scoped
 * or aggregated. Paired with `<WorkspaceSelector />` in the header
 * (the selector is the input, this is the output sanity-check).
 */
export function ScopeBadge({ className }: { className?: string }) {
  const scope = useScope();
  if (scope) {
    return (
      <span
        className={`inline-flex items-center gap-1 rounded-md border border-zinc-300 bg-white px-2 py-0.5 text-[11px] text-zinc-700 ${className ?? ""}`}
        title={scope}
      >
        <FolderTreeIcon className="h-3 w-3 text-zinc-500" />
        Scope: <span className="font-mono text-zinc-900">{scopeLabel(scope)}</span>
      </span>
    );
  }
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border border-zinc-200 bg-zinc-50 px-2 py-0.5 text-[11px] text-zinc-500 ${className ?? ""}`}
    >
      <LayersIcon className="h-3 w-3" />
      All workspaces
    </span>
  );
}
