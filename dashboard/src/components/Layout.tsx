import { useEffect, useMemo } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useMutation, useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ActivityIcon,
  GitBranchIcon,
  ListChecksIcon,
  ListTodoIcon,
  PackageIcon,
  RefreshCcwIcon,
  ScanIcon,
  ShieldCheckIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ThemeToggle } from "@/components/theme/ThemeToggle";
import { EmptyProjectGate } from "@/components/layout/EmptyProjectGate";
import { ProjectSelector } from "@/components/layout/ProjectSelector";
import { WorkspaceSelector } from "@/components/layout/WorkspaceSelector";
import {
  PROJECT_SCOPE_STORAGE_KEY,
  useLegacyProjectRedirect,
  useProjectScope,
  useRestoreProjectScopeFromStorage,
  useSetProjectScope,
  useWorkspaceScope,
} from "@/components/layout/workspace-scope";
import { api } from "@/lib/api";
import { useJobStatus } from "@/lib/useJobStatus";
import { cn } from "@/lib/cn";
import type { ActionSeverity } from "@/api/types/ActionSeverity";

const navItems = [
  { to: "/", label: "Overview", icon: ActivityIcon, end: true },
  { to: "/packages", label: "Packages", icon: PackageIcon, end: false },
  { to: "/graph", label: "Graph", icon: GitBranchIcon, end: false },
  { to: "/actions", label: "Actions", icon: ListTodoIcon, end: false },
  { to: "/policies", label: "Policies", icon: ListChecksIcon, end: false },
];

const SEVERITY_RANK: Record<ActionSeverity, number> = {
  Info: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
  // Phase 12-fix: confirmed malware outranks a critical CVE.
  Malware: 5,
};

function severityDotClass(severity: ActionSeverity): string {
  switch (severity) {
    case "Malware":
      return "bg-fuchsia-500";
    case "Critical":
      return "bg-red-500";
    case "High":
      return "bg-orange-500";
    case "Medium":
      return "bg-amber-500";
    case "Low":
      return "bg-emerald-500";
    case "Info":
      return "bg-sky-500";
  }
}

/**
 * Header-level Actions count + top-severity dot. Polls the shared
 * `/api/actions` endpoint on a slow cadence so the badge stays fresh
 * without piling on requests. Hidden when the server returns zero
 * actions — a silent badge is visual noise.
 */
function ActionsNavBadge() {
  const scope = useWorkspaceScope();
  const { data } = useQuery({
    queryKey: ["actions", scope ?? null, null],
    queryFn: () => api.actions({}, scope),
    refetchInterval: 30_000,
    // Tolerate fetch failures quietly — the badge is a hint, not a gate.
    retry: false,
  });
  const actions = data?.actions ?? [];
  if (actions.length === 0) return null;
  const topSeverity = actions.reduce<ActionSeverity>(
    (acc, a) =>
      SEVERITY_RANK[a.severity] > SEVERITY_RANK[acc] ? a.severity : acc,
    "Info",
  );
  return (
    <span
      className="ml-auto inline-flex items-center gap-1 rounded-full bg-zinc-100 dark:bg-zinc-800 px-1.5 py-0.5 text-[10px] font-medium text-zinc-700 dark:text-zinc-300"
      aria-label={`${actions.length} pending actions, highest severity ${topSeverity}`}
    >
      <span
        aria-hidden
        className={cn("h-1.5 w-1.5 rounded-full", severityDotClass(topSeverity))}
      />
      {actions.length}
    </span>
  );
}

export function Layout() {
  const { trackJob, jobs } = useJobStatus();

  // Phase 14.3a — keep v0.5 bookmarks alive: the legacy
  // `?project=<absolute path>` form gets rewritten to
  // `?project=<slug>&workspace=<path>` once the projects registry has
  // loaded. The query is shared with future selector components via
  // the cache key.
  const projectsQuery = useQuery({
    queryKey: ["projects"],
    queryFn: api.projects,
  });
  useLegacyProjectRedirect(projectsQuery.data);

  // Phase 14.3b — boot flow. Three-branch decision tree once the
  // projects list has resolved:
  //  (a) URL already carries `?project=<slug>` → noop, the selector
  //      reflects the URL.
  //  (b) URL has no slug + localStorage matches a known slug →
  //      `useRestoreProjectScopeFromStorage` writes the URL.
  //  (c) URL has no slug + no localStorage match + projects exist →
  //      auto-select the most-recently-scanned project (last_scan
  //      DESC, fallback created_at DESC) so the dashboard always
  //      lands on something concrete instead of an empty selector.
  //  (d) Projects list is empty → `EmptyProjectGate` replaces the
  //      whole layout (handled in the JSX below).
  const projects = useMemo(() => projectsQuery.data ?? [], [projectsQuery.data]);
  const knownSlugs = useMemo(() => projects.map((p) => p.slug), [projects]);
  const projectScope = useProjectScope();
  const setProjectScope = useSetProjectScope();
  useRestoreProjectScopeFromStorage(
    projectsQuery.data ? knownSlugs : undefined,
    projectsQuery.isLoading,
  );
  useEffect(() => {
    // Auto-select runs after the restore hook has had a chance to
    // populate the URL. We bail in any state where restore is the
    // right answer (loading, URL already scoped, localStorage match,
    // or no projects to pick from at all).
    if (projectsQuery.isLoading || projectScope) return;
    if (typeof window === "undefined") return;
    if (projects.length === 0) return;
    const stored = window.localStorage.getItem(PROJECT_SCOPE_STORAGE_KEY);
    if (stored && knownSlugs.includes(stored)) return;
    // last_scan can be null (never scanned) — fall back to created_at
    // so brand-new registrations still sort deterministically.
    const sorted = [...projects].sort((a, b) => {
      const aTs = a.last_scan ?? a.created_at;
      const bTs = b.last_scan ?? b.created_at;
      return bTs.localeCompare(aTs);
    });
    setProjectScope(sorted[0].slug);
  }, [
    projects,
    projectsQuery.isLoading,
    projectScope,
    knownSlugs,
    setProjectScope,
  ]);

  const scan = useMutation({
    mutationFn: () => api.startScan(),
    onSuccess: ({ id }) => {
      toast.message("Scan started", { description: `Job ${id.slice(0, 8)}…` });
      trackJob(id);
    },
    onError: (err: unknown) =>
      toast.error("Scan failed to start", { description: String(err) }),
  });
  const sync = useMutation({
    mutationFn: () => api.startSync(),
    onSuccess: ({ id }) => {
      toast.message("Sync started", { description: `Job ${id.slice(0, 8)}…` });
      trackJob(id);
    },
    onError: (err: unknown) =>
      toast.error("Sync failed to start", { description: String(err) }),
  });

  const activeJobs = jobs.filter((j) => j.status === "running" || j.status === "pending");

  // Branch (d): no projects registered → swap the whole layout for the
  // empty-state gate so dashboard pages don't render against a backend
  // that has nothing to show. Sidebar nav + header stay hidden so the
  // user sees one obvious next step.
  if (!projectsQuery.isLoading && projects.length === 0) {
    return <EmptyProjectGate />;
  }

  return (
    <div className="grid h-full grid-cols-[14rem_1fr]">
      <aside className="border-r border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-4 py-6">
        <div className="flex items-center gap-2 px-2 pb-6 text-zinc-900 dark:text-zinc-100">
          <ShieldCheckIcon className="h-5 w-5" />
          <span className="text-sm font-semibold tracking-tight">PackGuard</span>
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  "flex items-center gap-2 rounded-md px-3 py-2 text-sm",
                  isActive
                    ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                    : "text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800",
                )
              }
            >
              <item.icon className="h-4 w-4" />
              <span className="flex-1">{item.label}</span>
              {item.to === "/actions" && <ActionsNavBadge />}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="flex flex-col">
        <header className="flex items-center justify-between gap-4 border-b border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-950 px-6 py-4">
          <div className="flex items-center gap-4">
            <ProjectSelector />
            <span className="text-zinc-400 dark:text-zinc-500">/</span>
            <WorkspaceSelector />
            <span className="text-sm text-zinc-400 dark:text-zinc-500">·</span>
            <div className="text-sm text-zinc-500 dark:text-zinc-400">
              {activeJobs.length === 0
                ? "No active jobs"
                : `${activeJobs.length} job${activeJobs.length > 1 ? "s" : ""} running…`}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => scan.mutate()}
              disabled={scan.isPending}
            >
              <ScanIcon className="h-4 w-4" />
              Scan
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => sync.mutate()}
              disabled={sync.isPending}
            >
              <RefreshCcwIcon className="h-4 w-4" />
              Sync
            </Button>
            <ThemeToggle />
          </div>
        </header>
        <div className="flex-1 overflow-y-auto bg-zinc-50 dark:bg-zinc-950 p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
