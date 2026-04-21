import { useQuery } from "@tanstack/react-query";
import { ChevronRightIcon } from "lucide-react";
import { Link } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import type { Overview } from "@/api/types/Overview";
import { StatCard } from "@/components/overview/StatCard";
import { Donut } from "@/components/overview/Donut";
import { ScopeBadge } from "@/components/layout/ScopeBadge";
import { useScope } from "@/components/layout/workspace-scope";

export function OverviewPage() {
  const scope = useScope();
  const { data, isLoading, error } = useQuery({
    queryKey: ["overview", scope ?? null],
    queryFn: () => api.overview(scope),
    refetchInterval: 5_000,
  });

  if (isLoading) {
    return <div className="text-sm text-zinc-500">Loading overview…</div>;
  }
  if (error) {
    return (
      <div className="text-sm text-red-600">
        Failed to load overview: {String(error)}
      </div>
    );
  }
  if (!data) {
    return null;
  }

  if (data.packages_total === 0) {
    return <EmptyState />;
  }

  return <Loaded data={data} />;
}

function EmptyState() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>No scan yet</CardTitle>
      </CardHeader>
      <CardContent className="space-y-2 text-sm text-zinc-600">
        <p>
          The store is empty. Click <strong>Scan</strong> in the header to walk
          the current repo, then <strong>Sync</strong> to pull supply-chain
          intel from OSV / GHSA.
        </p>
      </CardContent>
    </Card>
  );
}

function Loaded({ data }: { data: Overview }) {
  const { vulnerabilities: v, malware: m, compliance: c } = data;
  const vulnTotal = v.critical + v.high + v.medium + v.low;
  const malwareTotal = m.confirmed + m.typosquat_suspects;

  const complianceData = [
    { name: "compliant", value: c.compliant, fill: "var(--color-risk-low)" },
    { name: "warnings", value: c.warnings, fill: "var(--color-risk-medium)" },
    { name: "violations", value: c.violations, fill: "var(--color-risk-critical)" },
    {
      name: "insufficient",
      value: c.insufficient,
      fill: "var(--color-risk-insufficient)",
    },
  ].filter((d) => d.value > 0);

  const vulnData = [
    { name: "critical", value: v.critical, fill: "var(--color-risk-critical)" },
    { name: "high", value: v.high, fill: "var(--color-risk-high)" },
    { name: "medium", value: v.medium, fill: "var(--color-risk-medium)" },
    { name: "low", value: v.low, fill: "var(--color-risk-low)" },
  ].filter((d) => d.value > 0);

  const malwareData = [
    { name: "confirmed", value: m.confirmed, fill: "var(--color-risk-malware)" },
    {
      name: "typosquat",
      value: m.typosquat_suspects,
      fill: "var(--color-risk-typosquat)",
    },
  ].filter((d) => d.value > 0);

  return (
    <div className="space-y-6">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-900">
            Overview
          </h1>
          <p className="text-sm text-zinc-500">
            {data.last_scan_at ? (
              <>
                Last scan: {fmtTime(data.last_scan_at)} · Last sync:{" "}
                {data.last_sync_at ? fmtTime(data.last_sync_at) : "never"}
              </>
            ) : (
              <>No scan recorded — run one from the header.</>
            )}
          </p>
        </div>
        <ScopeBadge />
      </header>

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <StatCard
          label="Health score"
          value={
            data.health_score === null ? "—" : `${data.health_score}%`
          }
          tone={
            data.health_score !== null && data.health_score >= 80
              ? "good"
              : data.health_score !== null && data.health_score >= 50
                ? "warn"
                : "bad"
          }
        />
        <StatCard
          label="Packages tracked"
          value={data.packages_total}
          sub={data.packages_by_ecosystem
            .map((e) => `${e.count} ${e.ecosystem}`)
            .join(" · ")}
        />
        <StatCard
          label="CVE matches"
          value={vulnTotal}
          tone={v.critical + v.high > 0 ? "bad" : vulnTotal > 0 ? "warn" : "good"}
          sub={
            vulnTotal === 0
              ? "no installed vuln"
              : `${v.critical} crit · ${v.high} high`
          }
        />
        <StatCard
          label="Supply chain"
          value={malwareTotal}
          tone={m.confirmed > 0 ? "bad" : malwareTotal > 0 ? "warn" : "good"}
          sub={
            malwareTotal === 0
              ? "no malware/typosquat"
              : `${m.confirmed} malware · ${m.typosquat_suspects} typo`
          }
        />
      </div>

      <div className="grid gap-4 md:grid-cols-3">
        <DonutCard title="Compliance" data={complianceData} />
        <DonutCard title="Vulnerabilities" data={vulnData} />
        <DonutCard title="Malware & typosquat" data={malwareData} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Top risks</CardTitle>
        </CardHeader>
        <CardContent>
          {data.top_risks.length === 0 ? (
            <div className="text-sm text-zinc-500">
              Nothing flagged. The active policy is happy with every scanned
              package.
            </div>
          ) : (
            <ul className="divide-y divide-zinc-200">
              {data.top_risks.map((r) => (
                <li key={`${r.ecosystem}/${r.name}`} className="py-2">
                  <Link
                    to={`/packages/${encodeURIComponent(
                      r.ecosystem,
                    )}/${encodeURIComponent(r.name)}`}
                    className="flex items-center justify-between rounded-md px-2 py-1 hover:bg-zinc-50"
                  >
                    <span className="flex items-center gap-2">
                      <Badge tone="muted">{r.ecosystem}</Badge>
                      <span className="font-mono text-sm text-zinc-900">
                        {r.name}
                      </span>
                      {r.installed && (
                        <span className="text-xs text-zinc-400">
                          @ {r.installed}
                        </span>
                      )}
                    </span>
                    <span className="flex items-center gap-3 text-xs text-zinc-500">
                      <span>{r.reason}</span>
                      <Badge tone="bad">score {r.score}</Badge>
                      <ChevronRightIcon className="h-4 w-4 text-zinc-300" />
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function DonutCard({
  title,
  data,
}: {
  title: string;
  data: { name: string; value: number; fill: string }[];
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{title}</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col items-center gap-3">
        {data.length === 0 ? (
          <div className="py-8 text-sm text-zinc-400">no data yet</div>
        ) : (
          <Donut data={data} />
        )}
        <ul className="w-full space-y-1 text-xs">
          {data.map((d) => (
            <li
              key={d.name}
              className="flex items-center justify-between text-zinc-600"
            >
              <span className="flex items-center gap-2">
                <span
                  className="inline-block h-2 w-2 rounded-full"
                  style={{ backgroundColor: d.fill }}
                />
                {d.name}
              </span>
              <span className="font-mono text-zinc-900">{d.value}</span>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function fmtTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}
