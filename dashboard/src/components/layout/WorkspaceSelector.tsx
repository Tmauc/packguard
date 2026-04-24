import { useQuery } from "@tanstack/react-query";
import { FolderTreeIcon } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import {
  scopeLabel,
  useRestoreScopeFromStorage,
  useScope,
  useSetScope,
} from "./workspace-scope";

const AGGREGATE_VALUE = "__aggregate__";

/**
 * Header dropdown that scopes every list-returning endpoint to a single
 * workspace via `?project=<path>`. The list comes from
 * `/api/workspaces`, already sorted by `last_scan_at DESC` on the
 * backend (Polish-2's scans_index output), so the most recently scanned
 * repo is offered right below "All workspaces".
 */
export function WorkspaceSelector() {
  const scope = useScope();
  const setScope = useSetScope();
  const query = useQuery({
    queryKey: ["workspaces"],
    queryFn: api.workspaces,
    refetchInterval: 10_000,
  });

  const workspaces = query.data?.workspaces ?? [];
  const knownPaths = workspaces.map((w) => w.path);
  useRestoreScopeFromStorage(query.data ? knownPaths : undefined, query.isLoading);

  const empty = !query.isLoading && workspaces.length === 0;

  return (
    <label
      className={cn(
        "flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400",
        empty && "opacity-60",
      )}
      title={
        empty
          ? "No scans yet — run `packguard scan <path>` to register a workspace"
          : scope
            ? scope
            : "All scanned workspaces (aggregate view)"
      }
    >
      <FolderTreeIcon className="h-4 w-4 text-zinc-400 dark:text-zinc-500" />
      <span className="font-medium text-zinc-700 dark:text-zinc-300">Workspace</span>
      <select
        value={scope ?? AGGREGATE_VALUE}
        onChange={(e) => {
          const v = e.target.value;
          setScope(v === AGGREGATE_VALUE ? undefined : v);
        }}
        disabled={empty}
        data-testid="workspace-selector"
        className="h-8 max-w-64 truncate rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-2 text-sm text-zinc-900 dark:text-zinc-100 focus:outline-2 focus:outline-zinc-900"
      >
        <option value={AGGREGATE_VALUE}>
          {empty ? "No scans yet" : "All workspaces (aggregate)"}
        </option>
        {workspaces.map((w) => (
          <option key={w.path} value={w.path} title={w.path}>
            {scopeLabel(w.path)} · {w.dependency_count} deps
          </option>
        ))}
      </select>
    </label>
  );
}
