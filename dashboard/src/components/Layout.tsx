import { NavLink, Outlet } from "react-router-dom";
import { useMutation } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  ActivityIcon,
  GitBranchIcon,
  ListChecksIcon,
  PackageIcon,
  RefreshCcwIcon,
  ScanIcon,
  ShieldCheckIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { useJobStatus } from "@/lib/useJobStatus";
import { cn } from "@/lib/cn";

const navItems = [
  { to: "/", label: "Overview", icon: ActivityIcon, end: true },
  { to: "/packages", label: "Packages", icon: PackageIcon, end: false },
  { to: "/graph", label: "Graph", icon: GitBranchIcon, end: false },
  { to: "/policies", label: "Policies", icon: ListChecksIcon, end: false },
];

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
              {item.label}
            </NavLink>
          ))}
        </nav>
      </aside>
      <main className="flex flex-col">
        <header className="flex items-center justify-between border-b border-zinc-200 bg-white px-6 py-4">
          <div className="text-sm text-zinc-500">
            {activeJobs.length === 0
              ? "No active jobs"
              : `${activeJobs.length} job${activeJobs.length > 1 ? "s" : ""} running…`}
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
