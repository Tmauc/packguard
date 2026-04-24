import { useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import {
  CheckIcon,
  CopyIcon,
  ExternalLinkIcon,
  FolderTreeIcon,
  TriangleAlertIcon,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScopeBadge } from "@/components/layout/ScopeBadge";
import { scopeLabel, useScope } from "@/components/layout/workspace-scope";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { Action } from "@/api/types/Action";
import type { ActionKind } from "@/api/types/ActionKind";
import type { ActionSeverity } from "@/api/types/ActionSeverity";

/**
 * Severity order for the grouped render. Maps directly to the backend's
 * ActionSeverity enum — kept in one place so the "Critical first" rule
 * can't drift between the header count-dot and the list body.
 */
const SEVERITY_ORDER: ActionSeverity[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Info",
];

const SEVERITY_LABELS: Record<ActionSeverity, string> = {
  Critical: "Critical",
  High: "High",
  Medium: "Medium",
  Low: "Low",
  Info: "Info",
};

/** Marker the backend uses for workspace-agnostic actions (RefreshSync). */
const GLOBAL_WORKSPACE = "_global";

const MIN_SEVERITY_OPTIONS: { value: string; label: string }[] = [
  { value: "", label: "All" },
  { value: "info", label: "Info+" },
  { value: "low", label: "Low+" },
  { value: "medium", label: "Medium+" },
  { value: "high", label: "High+" },
  { value: "critical", label: "Critical only" },
];

export function ActionsPage() {
  const [params, setParams] = useSearchParams();
  const scope = useScope();
  const minSeverity = params.get("min_severity") ?? "";

  const query = useQuery({
    queryKey: ["actions", scope ?? null, minSeverity || null],
    queryFn: () =>
      api.actions(
        minSeverity ? { min_severity: minSeverity } : {},
        scope,
      ),
    refetchInterval: 30_000,
  });

  const setFilter = (key: string, value: string) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value) next.set(key, value);
      else next.delete(key);
      return next;
    });
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-900">
            Actions
          </h1>
          <p className="text-sm text-zinc-500">
            Prioritized to-do list distilled from the latest scan + policy +
            supply-chain intel. Do these in order.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-1 text-xs text-zinc-500">
            Min severity
            <select
              value={minSeverity}
              onChange={(e) => setFilter("min_severity", e.target.value)}
              className="h-7 rounded-md border border-zinc-300 bg-white px-2 text-xs focus:outline-2 focus:outline-zinc-900"
              aria-label="Minimum severity filter"
            >
              {MIN_SEVERITY_OPTIONS.map((o) => (
                <option key={o.value || "all"} value={o.value}>
                  {o.label}
                </option>
              ))}
            </select>
          </label>
          <ScopeBadge />
        </div>
      </header>

      {query.isLoading && <SkeletonList />}

      {query.error && (
        <Card>
          <CardContent className="flex items-center justify-between gap-3 p-4 text-sm">
            <div className="flex items-center gap-2 text-red-700">
              <TriangleAlertIcon className="h-4 w-4" />
              Failed to load actions: {String(query.error)}
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={() => void query.refetch()}
            >
              Retry
            </Button>
          </CardContent>
        </Card>
      )}

      {query.data && (
        <ActionsBody
          actions={query.data.actions}
          total={query.data.total}
          scope={scope}
        />
      )}
    </div>
  );
}

function ActionsBody({
  actions,
  total,
  scope,
}: {
  actions: Action[];
  total: number;
  scope: string | undefined;
}) {
  // Split the global banner (RefreshSync / anything attached to the
  // synthetic `_global` workspace) from the per-workspace list. The
  // banner is an attention hint; the list is the real to-do.
  const global = useMemo(
    () => actions.filter((a) => a.workspace === GLOBAL_WORKSPACE),
    [actions],
  );
  const perWorkspace = useMemo(
    () => actions.filter((a) => a.workspace !== GLOBAL_WORKSPACE),
    [actions],
  );

  const grouped = useMemo(() => {
    const map = new Map<ActionSeverity, Action[]>();
    for (const a of perWorkspace) {
      const list = map.get(a.severity) ?? [];
      list.push(a);
      map.set(a.severity, list);
    }
    return map;
  }, [perWorkspace]);

  if (actions.length === 0) {
    return <EmptyState scope={scope} filteredOut={total > 0} />;
  }

  return (
    <div className="space-y-4">
      {global.length > 0 && <GlobalBanner actions={global} />}

      {perWorkspace.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-sm text-zinc-500">
            No per-workspace actions. Advisory / scan staleness above is still
            worth addressing.
          </CardContent>
        </Card>
      ) : (
        SEVERITY_ORDER.map((severity) => {
          const group = grouped.get(severity);
          if (!group || group.length === 0) return null;
          return (
            <SeverityGroup
              key={severity}
              severity={severity}
              actions={group}
            />
          );
        })
      )}
    </div>
  );
}

function EmptyState({
  scope,
  filteredOut,
}: {
  scope: string | undefined;
  filteredOut: boolean;
}) {
  return (
    <Card>
      <CardContent className="space-y-2 p-6 text-sm text-zinc-600">
        <div className="flex items-center gap-2 text-zinc-900">
          <CheckIcon className="h-4 w-4 text-emerald-600" />
          <span className="font-medium">
            {filteredOut ? "No actions match this filter" : "You're clear"}
          </span>
        </div>
        <p>
          {filteredOut
            ? "Lower the severity filter to see the full list."
            : scope
              ? `No pending actions for ${scopeLabel(scope)}.`
              : "No pending actions across any scanned workspace."}
        </p>
      </CardContent>
    </Card>
  );
}

function GlobalBanner({ actions }: { actions: Action[] }) {
  return (
    <Card className="border-amber-300 bg-amber-50">
      <CardContent className="space-y-3 p-4">
        {actions.map((a) => (
          <div
            key={a.id}
            className="flex items-start justify-between gap-3"
          >
            <div className="flex-1">
              <div className="flex items-center gap-2">
                <TriangleAlertIcon className="h-4 w-4 text-amber-700" />
                <span className="text-sm font-medium text-amber-900">
                  {a.title}
                </span>
              </div>
              <p className="mt-1 text-xs text-amber-800">{a.explanation}</p>
            </div>
            {a.suggested_command && (
              <CopyButton command={a.suggested_command} />
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

function SeverityGroup({
  severity,
  actions,
}: {
  severity: ActionSeverity;
  actions: Action[];
}) {
  return (
    <section aria-labelledby={`sev-${severity}`}>
      <header className="mb-2 flex items-baseline gap-2 px-1">
        <SeverityDot severity={severity} />
        <h2
          id={`sev-${severity}`}
          className="text-sm font-semibold tracking-tight text-zinc-800"
        >
          {SEVERITY_LABELS[severity]}
        </h2>
        <span className="text-xs text-zinc-500">{actions.length}</span>
      </header>
      <div className="space-y-2">
        {actions.map((a) => (
          <ActionCard key={a.id} action={a} />
        ))}
      </div>
    </section>
  );
}

function ActionCard({ action }: { action: Action }) {
  return (
    <Card>
      <CardContent className="space-y-2 p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 space-y-1">
            <div className="flex flex-wrap items-center gap-2">
              <KindBadge kind={action.kind} />
              <TargetLabel action={action} />
            </div>
            <h3 className="text-sm font-medium text-zinc-900">
              {action.title}
            </h3>
            <p className="text-xs text-zinc-600">{action.explanation}</p>
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1 text-right">
            {action.workspace && action.workspace !== "_global" && (
              <span
                className="inline-flex items-center gap-1 text-[11px] text-zinc-500"
                title={action.workspace}
              >
                <FolderTreeIcon className="h-3 w-3" />
                {scopeLabel(action.workspace)}
              </span>
            )}
          </div>
        </div>

        <CommandBlock action={action} />
      </CardContent>
    </Card>
  );
}

function TargetLabel({ action }: { action: Action }) {
  if (action.target.kind === "Workspace") {
    return <span className="text-xs text-zinc-500">workspace</span>;
  }
  const { ecosystem, name, version } = action.target;
  return (
    <span className="text-xs font-mono text-zinc-700">
      {name}
      <span className="text-zinc-400">@{version}</span>
      {action.recommended_version && (
        <>
          <span className="mx-1 text-zinc-400">→</span>
          <span className="text-emerald-700">{action.recommended_version}</span>
        </>
      )}
      <span className="ml-2 text-[10px] uppercase tracking-wide text-zinc-400">
        {ecosystem}
      </span>
    </span>
  );
}

function CommandBlock({ action }: { action: Action }) {
  if (action.suggested_command) {
    return (
      <div className="flex items-stretch gap-2">
        <code className="flex-1 rounded-md border border-zinc-200 bg-zinc-50 px-3 py-2 text-xs font-mono text-zinc-800">
          {action.suggested_command}
        </code>
        <CopyButton command={action.suggested_command} />
      </div>
    );
  }
  // No command available (e.g., Insufficient with no recommended version).
  // For Package actions we still offer a deep link to the advisory tab so
  // the user can investigate without a dead end.
  if (action.target.kind === "Package") {
    const { ecosystem, name } = action.target;
    return (
      <Link
        to={`/packages/${encodeURIComponent(ecosystem)}/${encodeURIComponent(name)}`}
        className="inline-flex items-center gap-1 text-xs text-zinc-600 underline decoration-dotted hover:text-zinc-900"
      >
        View advisory <ExternalLinkIcon className="h-3 w-3" />
      </Link>
    );
  }
  return null;
}

function CopyButton({ command }: { command: string }) {
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    try {
      await navigator.clipboard.writeText(command);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 2000);
    } catch {
      // Browser denied clipboard access — surface via the page-level toast.
      const { toast } = await import("sonner");
      toast.error("Clipboard access denied");
    }
  };
  return (
    <Button
      size="sm"
      variant={copied ? "default" : "outline"}
      aria-label={copied ? "Copied" : "Copy fix"}
      onClick={onCopy}
    >
      {copied ? (
        <>
          <CheckIcon className="h-3.5 w-3.5" />
          Copied
        </>
      ) : (
        <>
          <CopyIcon className="h-3.5 w-3.5" />
          Copy fix
        </>
      )}
    </Button>
  );
}

function KindBadge({ kind }: { kind: ActionKind }) {
  const { tone, label } = kindDisplay(kind);
  return <Badge tone={tone}>{label}</Badge>;
}

function SeverityDot({ severity }: { severity: ActionSeverity }) {
  return (
    <span
      aria-hidden
      className={cn("inline-block h-2 w-2 rounded-full", dotClass(severity))}
    />
  );
}

function dotClass(severity: ActionSeverity): string {
  switch (severity) {
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

type KindDisplay = { tone: Parameters<typeof Badge>[0]["tone"]; label: string };

function kindDisplay(kind: ActionKind): KindDisplay {
  switch (kind) {
    case "FixMalware":
      return { tone: "malware", label: "Malware" };
    case "FixCveCritical":
      return { tone: "bad", label: "Fix CVE (critical)" };
    case "FixCveHigh":
      return { tone: "cve", label: "Fix CVE (high)" };
    case "ClearViolation":
      return { tone: "warn", label: "Policy violation" };
    case "ResolveInsufficient":
      return { tone: "insufficient", label: "Insufficient candidates" };
    case "WhitelistTyposquat":
      return { tone: "typosquat", label: "Typosquat" };
    case "RefreshSync":
      return { tone: "muted", label: "Refresh sync" };
    case "RescanStale":
      return { tone: "muted", label: "Rescan" };
  }
}

function SkeletonList() {
  return (
    <div className="space-y-2" aria-label="Loading actions">
      {[0, 1, 2, 3, 4].map((i) => (
        <Card key={i}>
          <CardContent className="space-y-2 p-4">
            <div className="h-3 w-24 animate-pulse rounded bg-zinc-200" />
            <div className="h-4 w-2/3 animate-pulse rounded bg-zinc-200" />
            <div className="h-8 w-full animate-pulse rounded bg-zinc-100" />
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
