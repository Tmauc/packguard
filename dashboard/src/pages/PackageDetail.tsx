import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeftIcon, ExternalLinkIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ComplianceBadge } from "@/pages/Packages";
import { VersionTimeline } from "@/components/packages/VersionTimeline";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { MalwareEntry } from "@/api/types/MalwareEntry";
import type { PackageDetail } from "@/api/types/PackageDetail";
import type { VulnerabilityEntry } from "@/api/types/VulnerabilityEntry";

type TabKey = "versions" | "vulnerabilities" | "malware" | "policy" | "changelog";

export function PackageDetailPage() {
  const { ecosystem = "", name = "" } = useParams();
  const [tab, setTab] = useState<TabKey>("versions");

  const detail = useQuery({
    queryKey: ["package-detail", ecosystem, name],
    queryFn: () => api.packageDetail(ecosystem, name),
    enabled: Boolean(ecosystem && name),
  });

  if (detail.isLoading) {
    return <div className="text-sm text-zinc-500">Loading…</div>;
  }
  if (detail.error) {
    return (
      <div className="text-sm text-red-600">
        Failed to load {ecosystem}/{name}: {String(detail.error)}
      </div>
    );
  }
  if (!detail.data) {
    return null;
  }
  const data = detail.data;

  return (
    <div className="space-y-4">
      <Link
        to="/packages"
        className="inline-flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-900"
      >
        <ArrowLeftIcon className="h-3 w-3" />
        Back to packages
      </Link>

      <header className="flex flex-wrap items-center gap-3">
        <h1 className="font-mono text-xl text-zinc-900">{data.name}</h1>
        <Badge tone="muted">{data.ecosystem}</Badge>
        <ComplianceBadge tag={data.compliance} />
      </header>

      <MetaBar data={data} />

      <div className="flex gap-1 border-b border-zinc-200 text-sm">
        <TabButton
          label="Versions"
          count={data.versions.length}
          active={tab === "versions"}
          onClick={() => setTab("versions")}
        />
        <TabButton
          label="Vulnerabilities"
          count={data.vulnerabilities.length}
          tone={data.vulnerabilities.some((v) => v.affects_installed) ? "bad" : undefined}
          active={tab === "vulnerabilities"}
          onClick={() => setTab("vulnerabilities")}
        />
        <TabButton
          label="Malware"
          count={data.malware.length}
          tone={data.malware.length > 0 ? "malware" : undefined}
          active={tab === "malware"}
          onClick={() => setTab("malware")}
        />
        <TabButton
          label="Policy"
          active={tab === "policy"}
          onClick={() => setTab("policy")}
        />
        <TabButton
          label="Changelog"
          active={tab === "changelog"}
          onClick={() => setTab("changelog")}
        />
      </div>

      <Card>
        <CardContent className="p-4">
          {tab === "versions" && <VersionsTab detail={data} />}
          {tab === "vulnerabilities" && <VulnerabilitiesTab vulns={data.vulnerabilities} />}
          {tab === "malware" && <MalwareTab reports={data.malware} />}
          {tab === "policy" && <PolicyTab detail={data} />}
          {tab === "changelog" && <ChangelogTab />}
        </CardContent>
      </Card>
    </div>
  );
}

function MetaBar({ data }: { data: PackageDetail }) {
  const items: { label: string; value: string }[] = [
    { label: "Installed", value: data.installed ?? "—" },
    { label: "Latest", value: data.latest ?? "—" },
    { label: "Last scan", value: formatDate(data.last_scanned_at) },
    { label: "Recommended", value: data.policy_trace.recommended ?? "—" },
  ];
  return (
    <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
      {items.map((it) => (
        <div
          key={it.label}
          className="rounded-md border border-zinc-200 bg-white px-3 py-2 text-xs"
        >
          <div className="text-zinc-500">{it.label}</div>
          <div className="font-mono text-zinc-900">{it.value}</div>
        </div>
      ))}
    </div>
  );
}

function TabButton({
  label,
  count,
  tone,
  active,
  onClick,
}: {
  label: string;
  count?: number;
  tone?: "bad" | "malware";
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "-mb-px border-b-2 px-3 py-2",
        active
          ? "border-zinc-900 text-zinc-900"
          : "border-transparent text-zinc-500 hover:text-zinc-900",
      )}
    >
      <span className="inline-flex items-center gap-1.5">
        {label}
        {typeof count === "number" && (
          <span
            className={cn(
              "rounded px-1.5 py-0.5 text-[10px]",
              tone === "bad"
                ? "bg-red-100 text-red-700"
                : tone === "malware"
                  ? "bg-fuchsia-100 text-fuchsia-700"
                  : "bg-zinc-100 text-zinc-600",
            )}
          >
            {count}
          </span>
        )}
      </span>
    </button>
  );
}

function VersionsTab({ detail }: { detail: PackageDetail }) {
  return (
    <div className="space-y-4">
      <VersionTimeline
        versions={detail.versions}
        malware={detail.malware}
        installed={detail.installed ?? undefined}
        recommended={detail.policy_trace.recommended ?? undefined}
      />
      <div className="rounded-md border border-zinc-200 bg-white">
        <table className="w-full text-sm">
          <thead className="border-b border-zinc-200 text-xs uppercase tracking-wide text-zinc-500">
            <tr>
              <th className="px-3 py-2 text-left font-medium">Version</th>
              <th className="px-3 py-2 text-left font-medium">Published</th>
              <th className="px-3 py-2 text-left font-medium">Severity</th>
              <th className="px-3 py-2 text-left font-medium">Flags</th>
            </tr>
          </thead>
          <tbody>
            {[...detail.versions].reverse().slice(0, 50).map((v) => {
              const isInstalled = v.version === detail.installed;
              const isRecommended = v.version === detail.policy_trace.recommended;
              return (
                <tr key={v.version} className="border-b border-zinc-100">
                  <td className="px-3 py-1.5 font-mono">
                    <span
                      className={cn(
                        isInstalled && "rounded bg-zinc-900 px-1.5 py-0.5 text-white",
                        isRecommended && !isInstalled && "underline decoration-emerald-500 decoration-2",
                      )}
                    >
                      {v.version}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-xs text-zinc-600">
                    {formatDate(v.published_at)}
                  </td>
                  <td className="px-3 py-1.5">
                    {v.severity ? (
                      <SeverityBadge severity={v.severity} />
                    ) : (
                      <span className="text-xs text-zinc-400">—</span>
                    )}
                  </td>
                  <td className="px-3 py-1.5 text-xs">
                    {v.yanked && <Badge tone="malware">yanked</Badge>}
                    {v.deprecated && <Badge tone="warn">deprecated</Badge>}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {detail.versions.length > 50 && (
          <div className="border-t border-zinc-200 p-2 text-xs text-zinc-500">
            Showing 50 most recent of {detail.versions.length} published versions. See
            the timeline above for the full history.
          </div>
        )}
      </div>
    </div>
  );
}

function VulnerabilitiesTab({ vulns }: { vulns: VulnerabilityEntry[] }) {
  if (vulns.length === 0) {
    return (
      <div className="py-8 text-center text-sm text-zinc-500">
        No advisories on record for this package.
      </div>
    );
  }
  const [affecting, rest] = partition(vulns, (v) => v.affects_installed);
  return (
    <div className="space-y-4">
      {affecting.length > 0 && (
        <section>
          <h3 className="mb-2 text-xs uppercase tracking-wide text-red-700">
            Installed version is affected ({affecting.length})
          </h3>
          <div className="space-y-2">
            {affecting.map((v) => (
              <VulnCard key={vulnKey(v)} vuln={v} highlight />
            ))}
          </div>
        </section>
      )}
      {rest.length > 0 && (
        <section>
          <h3 className="mb-2 text-xs uppercase tracking-wide text-zinc-500">
            Other versions ({rest.length})
          </h3>
          <div className="space-y-2">
            {rest.map((v) => (
              <VulnCard key={vulnKey(v)} vuln={v} />
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

function vulnKey(v: VulnerabilityEntry) {
  return `${v.source}:${v.advisory_id}`;
}

function VulnCard({
  vuln,
  highlight = false,
}: {
  vuln: VulnerabilityEntry;
  highlight?: boolean;
}) {
  return (
    <div
      className={cn(
        "rounded-md border p-3 text-sm",
        highlight ? "border-red-300 bg-red-50" : "border-zinc-200 bg-white",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={vuln.severity} />
        <span className="font-mono text-xs text-zinc-700">
          {vuln.cve_id ?? vuln.advisory_id}
        </span>
        <span className="text-xs text-zinc-500">{vuln.source}</span>
        {vuln.url && (
          <a
            href={vuln.url}
            target="_blank"
            rel="noreferrer"
            className="ml-auto inline-flex items-center gap-1 text-xs text-zinc-600 hover:text-zinc-900"
          >
            advisory <ExternalLinkIcon className="h-3 w-3" />
          </a>
        )}
      </div>
      {vuln.summary && <p className="mt-2 text-sm text-zinc-700">{vuln.summary}</p>}
      {vuln.fixed_versions.length > 0 && (
        <p className="mt-1 text-xs text-zinc-500">
          Fixed in:{" "}
          <span className="font-mono text-zinc-700">
            {vuln.fixed_versions.join(", ")}
          </span>
        </p>
      )}
    </div>
  );
}

function MalwareTab({ reports }: { reports: MalwareEntry[] }) {
  if (reports.length === 0) {
    return (
      <div className="py-8 text-center text-sm text-zinc-500">
        No malware or typosquat signals on record.
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {reports.map((m) => (
        <div
          key={`${m.source}:${m.ref_id}`}
          className="rounded-md border border-fuchsia-200 bg-fuchsia-50 p-3 text-sm"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={m.kind === "typosquat" ? "typosquat" : "malware"}>
              {m.kind.replace("_", " ")}
            </Badge>
            <span className="font-mono text-xs text-zinc-700">{m.ref_id}</span>
            {m.version && (
              <span className="text-xs text-zinc-500">version {m.version}</span>
            )}
            {m.url && (
              <a
                href={m.url}
                target="_blank"
                rel="noreferrer"
                className="ml-auto inline-flex items-center gap-1 text-xs text-zinc-600 hover:text-zinc-900"
              >
                report <ExternalLinkIcon className="h-3 w-3" />
              </a>
            )}
          </div>
          {m.summary && <p className="mt-2 text-zinc-700">{m.summary}</p>}
          {m.reported_at && (
            <p className="mt-1 text-xs text-zinc-500">
              Reported {formatDate(m.reported_at)}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

function PolicyTab({ detail }: { detail: PackageDetail }) {
  const p = detail.policy_trace;
  const rules: { label: string; value: string }[] = [
    { label: "offset", value: String(p.offset) },
    { label: "pin", value: p.pin ?? "—" },
    { label: "stability", value: p.stability },
    { label: "min_age_days", value: String(p.min_age_days) },
  ];
  return (
    <div className="space-y-3">
      <div className="rounded-md border border-zinc-200 bg-white p-3">
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">
          Verdict
        </div>
        <div className="flex items-center gap-2">
          <ComplianceBadge tag={detail.compliance} />
          <span className="text-sm text-zinc-700">{p.reason}</span>
        </div>
      </div>
      <div className="rounded-md border border-zinc-200 bg-white p-3">
        <div className="mb-2 text-xs uppercase tracking-wide text-zinc-500">
          Resolved rules for <span className="font-mono">{detail.name}</span>
        </div>
        <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
          {rules.map((r) => (
            <div key={r.label}>
              <dt className="text-xs text-zinc-500">{r.label}</dt>
              <dd className="font-mono text-zinc-900">{r.value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}

function ChangelogTab() {
  return (
    <div className="py-8 text-center text-sm text-zinc-500">
      Inline changelog lazy-fetch lands in Phase 5. For now, inspect releases
      directly on the upstream registry (npm / PyPI / GitHub).
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const tone =
    severity === "critical"
      ? "bad"
      : severity === "high"
        ? "cve"
        : severity === "medium"
          ? "warn"
          : severity === "low"
            ? "good"
            : "muted";
  return <Badge tone={tone as never}>{severity}</Badge>;
}

function partition<T>(items: T[], pred: (t: T) => boolean): [T[], T[]] {
  const yes: T[] = [];
  const no: T[] = [];
  for (const it of items) (pred(it) ? yes : no).push(it);
  return [yes, no];
}

function formatDate(iso: string | null | undefined): string {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toISOString().slice(0, 10);
}
