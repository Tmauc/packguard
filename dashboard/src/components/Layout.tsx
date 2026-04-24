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
import { WorkspaceSelector } from "@/components/layout/WorkspaceSelector";
import { useScope } from "@/components/layout/workspace-scope";
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
  const scope = useScope();
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
      className="ml-auto inline-flex items-center gap-1 rounded-full bg-zinc-100 px-1.5 py-0.5 text-[10px] font-medium text-zinc-700"
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

  return (
    <div className="grid h-full grid-cols-[14rem_1fr]">
      <aside className="border-r border-zinc-200 bg-white px-4 py-6">
        <div className="flex items-center gap-2 px-2 pb-6 text-zinc-900">
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
                    ? "bg-zinc-900 text-white"
                    : "text-zinc-600 hover:bg-zinc-100",
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
        <header className="flex items-center justify-between gap-4 border-b border-zinc-200 bg-white px-6 py-4">
          <div className="flex items-center gap-4">
            <WorkspaceSelector />
            <span className="text-sm text-zinc-400">·</span>
            <div className="text-sm text-zinc-500">
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
          </div>
        </header>
        <div className="flex-1 overflow-y-auto bg-zinc-50 p-6">
          <Outlet />
        </div>
      </main>
    </div>
  );
}
