import { Link, useParams, useSearchParams } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { ArrowLeftIcon, ExternalLinkIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { ComplianceBadge } from "@/pages/Packages";
import { VersionTimeline } from "@/components/packages/VersionTimeline";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { scopeLabel, useScope } from "@/components/layout/workspace-scope";
import type { CompatDependent } from "@/api/types/CompatDependent";
import type { MalwareEntry } from "@/api/types/MalwareEntry";
import type { PackageDetail } from "@/api/types/PackageDetail";
import type { VulnerabilityEntry } from "@/api/types/VulnerabilityEntry";

type TabKey =
  | "versions"
  | "vulnerabilities"
  | "malware"
  | "policy"
  | "compatibility"
  | "changelog";

const TAB_KEYS: readonly TabKey[] = [
  "versions",
  "vulnerabilities",
  "malware",
  "policy",
  "compatibility",
  "changelog",
];

function parseTab(raw: string | null): TabKey {
  if (raw && (TAB_KEYS as readonly string[]).includes(raw)) {
    return raw as TabKey;
  }
  return "versions";
}

export function PackageDetailPage() {
  const { ecosystem = "", name = "" } = useParams();
  const [params, setParams] = useSearchParams();
  const tab = parseTab(params.get("tab"));
  const setTab = (next: TabKey) => {
    setParams((prev) => {
      const p = new URLSearchParams(prev);
      if (next === "versions") p.delete("tab");
      else p.set("tab", next);
      return p;
    });
  };

  const scope = useScope();
  const detail = useQuery({
    queryKey: ["package-detail", ecosystem, name, scope ?? null],
    queryFn: () => api.packageDetail(ecosystem, name, scope),
    enabled: Boolean(ecosystem && name),
  });

  if (detail.isLoading) {
    return <div className="text-sm text-zinc-500 dark:text-zinc-400">Loading…</div>;
  }
  if (detail.error) {
    return (
      <div className="text-sm text-red-600 dark:text-red-400">
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
        className="inline-flex items-center gap-1 text-xs text-zinc-500 dark:text-zinc-400 hover:text-zinc-900"
      >
        <ArrowLeftIcon className="h-3 w-3" />
        Back to packages
      </Link>

      <header className="flex flex-wrap items-center gap-3">
        <h1 className="font-mono text-xl text-zinc-900 dark:text-zinc-100">{data.name}</h1>
        <Badge tone="muted">{data.ecosystem}</Badge>
        <ComplianceBadge tag={data.compliance} />
      </header>

      <MetaBar data={data} />

      <div className="flex gap-1 border-b border-zinc-200 dark:border-zinc-800 text-sm">
        <TabButton
          label="Versions"
          count={data.versions.length}
          active={tab === "versions"}
          onClick={() => setTab("versions")}
          title="Full published history with a zoomable timeline and per-version severity/yanked/deprecated flags."
        />
        <TabButton
          label="Vulnerabilities"
          count={data.vulnerabilities.length}
          tone={data.vulnerabilities.some((v) => v.affects_installed) ? "bad" : undefined}
          active={tab === "vulnerabilities"}
          onClick={() => setTab("vulnerabilities")}
          title="CVE advisories matched to this package. Advisories affecting the installed version are pinned to the top."
        />
        <TabButton
          label="Malware"
          count={data.malware.length}
          tone={data.malware.length > 0 ? "malware" : undefined}
          active={tab === "malware"}
          onClick={() => setTab("malware")}
          title="Malware + typosquat reports logged in the store for this package."
        />
        <TabButton
          label="Policy"
          active={tab === "policy"}
          onClick={() => setTab("policy")}
          title="Policy verdict, three-axis offset, and the full cascade trace explaining why the recommended version was picked."
        />
        <TabButton
          label="Compatibility"
          active={tab === "compatibility"}
          onClick={() => setTab("compatibility")}
          title="Peer dependencies, engine constraints, and the scoped Used-by list broken down by workspace."
        />
        <TabButton
          label="Changelog"
          active={tab === "changelog"}
          onClick={() => setTab("changelog")}
          title="Inline release notes (Phase 6 — upstream only for now)."
        />
      </div>

      <Card>
        <CardContent className="p-4">
          {tab === "versions" && <VersionsTab detail={data} />}
          {tab === "vulnerabilities" && <VulnerabilitiesTab vulns={data.vulnerabilities} />}
          {tab === "malware" && <MalwareTab reports={data.malware} />}
          {tab === "policy" && <PolicyTab detail={data} />}
          {tab === "compatibility" && (
            <CompatibilityTab
              ecosystem={data.ecosystem}
              name={data.name}
              installed={data.installed ?? undefined}
            />
          )}
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
          className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-3 py-2 text-xs"
        >
          <div className="text-zinc-500 dark:text-zinc-400">{it.label}</div>
          <div className="font-mono text-zinc-900 dark:text-zinc-100">{it.value}</div>
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
  title,
}: {
  label: string;
  count?: number;
  tone?: "bad" | "malware";
  active: boolean;
  onClick: () => void;
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      title={title}
      className={cn(
        "-mb-px border-b-2 px-3 py-2",
        active
          ? "border-zinc-900 text-zinc-900 dark:text-zinc-100"
          : "border-transparent text-zinc-500 dark:text-zinc-400 hover:text-zinc-900",
      )}
    >
      <span className="inline-flex items-center gap-1.5">
        {label}
        {typeof count === "number" && (
          <span
            className={cn(
              "rounded px-1.5 py-0.5 text-[10px]",
              tone === "bad"
                ? "bg-red-100 dark:bg-red-950/60 text-red-700 dark:text-red-300"
                : tone === "malware"
                  ? "bg-fuchsia-100 text-fuchsia-700 dark:text-fuchsia-300"
                  : "bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400",
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
      <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900">
        <table className="w-full text-sm">
          <thead className="border-b border-zinc-200 dark:border-zinc-800 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
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
                <tr key={v.version} className="border-b border-zinc-100 dark:border-zinc-800">
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
                  <td className="px-3 py-1.5 text-xs text-zinc-600 dark:text-zinc-400">
                    {formatDate(v.published_at)}
                  </td>
                  <td className="px-3 py-1.5">
                    {v.severity ? (
                      <SeverityBadge severity={v.severity} />
                    ) : (
                      <span className="text-xs text-zinc-400 dark:text-zinc-500">—</span>
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
          <div className="border-t border-zinc-200 dark:border-zinc-800 p-2 text-xs text-zinc-500 dark:text-zinc-400">
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
      <div className="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">
        No advisories on record for this package.
      </div>
    );
  }
  const [affecting, rest] = partition(vulns, (v) => v.affects_installed);
  return (
    <div className="space-y-4">
      {affecting.length > 0 && (
        <section>
          <h3 className="mb-2 text-xs uppercase tracking-wide text-red-700 dark:text-red-300">
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
          <h3 className="mb-2 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
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
        highlight ? "border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/40" : "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900",
      )}
    >
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={vuln.severity} />
        <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300">
          {vuln.cve_id ?? vuln.advisory_id}
        </span>
        <span className="text-xs text-zinc-500 dark:text-zinc-400">{vuln.source}</span>
        {vuln.url && (
          <a
            href={vuln.url}
            target="_blank"
            rel="noreferrer"
            className="ml-auto inline-flex items-center gap-1 text-xs text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
          >
            advisory <ExternalLinkIcon className="h-3 w-3" />
          </a>
        )}
      </div>
      {vuln.summary && <p className="mt-2 text-sm text-zinc-700 dark:text-zinc-300">{vuln.summary}</p>}
      {vuln.fixed_versions.length > 0 && (
        <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
          Fixed in:{" "}
          <span className="font-mono text-zinc-700 dark:text-zinc-300">
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
      <div className="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">
        No malware or typosquat signals on record.
      </div>
    );
  }
  return (
    <div className="space-y-2">
      {reports.map((m) => (
        <div
          key={`${m.source}:${m.ref_id}`}
          className="rounded-md border border-fuchsia-200 dark:border-fuchsia-900 bg-fuchsia-50 dark:bg-fuchsia-950/40 p-3 text-sm"
        >
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={m.kind === "typosquat" ? "typosquat" : "malware"}>
              {m.kind.replace("_", " ")}
            </Badge>
            <span className="font-mono text-xs text-zinc-700 dark:text-zinc-300">{m.ref_id}</span>
            {m.version && (
              <span className="text-xs text-zinc-500 dark:text-zinc-400">version {m.version}</span>
            )}
            {m.url && (
              <a
                href={m.url}
                target="_blank"
                rel="noreferrer"
                className="ml-auto inline-flex items-center gap-1 text-xs text-zinc-600 dark:text-zinc-400 hover:text-zinc-900"
              >
                report <ExternalLinkIcon className="h-3 w-3" />
              </a>
            )}
          </div>
          {m.summary && <p className="mt-2 text-zinc-700 dark:text-zinc-300">{m.summary}</p>}
          {m.reported_at && (
            <p className="mt-1 text-xs text-zinc-500 dark:text-zinc-400">
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
  // Display axes as signed integers (YAML form) — the wire shape is the
  // absolute distance, but users think in negative-deltas-from-latest.
  const signed = (n: number) => (n === 0 ? "0" : `-${n}`);
  const offsetAxes: { label: string; value: string }[] = [
    { label: "major", value: signed(p.offset.major) },
    { label: "minor", value: signed(p.offset.minor) },
    { label: "patch", value: signed(p.offset.patch) },
  ];
  const rules: { label: string; value: string }[] = [
    { label: "pin", value: p.pin ?? "—" },
    { label: "stability", value: p.stability },
    { label: "min_age_days", value: String(p.min_age_days) },
    { label: "recommended", value: p.recommended ?? "—" },
  ];
  return (
    <div className="space-y-3">
      <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3">
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          Verdict
        </div>
        <div className="flex items-center gap-2">
          <ComplianceBadge tag={detail.compliance} />
          <span className="text-sm text-zinc-700 dark:text-zinc-300">{p.reason}</span>
        </div>
      </div>
      <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3">
        <div className="mb-2 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          Offset — three-axis cascade
        </div>
        <dl className="grid grid-cols-3 gap-2 text-sm">
          {offsetAxes.map((r) => (
            <div key={r.label}>
              <dt className="text-xs text-zinc-500 dark:text-zinc-400">{r.label}</dt>
              <dd className="font-mono text-zinc-900 dark:text-zinc-100">{r.value}</dd>
            </div>
          ))}
        </dl>
      </div>
      {p.cascade.length > 0 && (
        <div
          id="cascade"
          className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3"
        >
          <div className="mb-2 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
            Cascade trace
          </div>
          <ol className="space-y-1 text-sm text-zinc-700 dark:text-zinc-300">
            {p.cascade.map((line, i) => (
              <li
                key={i}
                className="flex gap-2 font-mono text-xs leading-relaxed"
              >
                <span className="text-zinc-400 dark:text-zinc-500">{i + 1}.</span>
                <span>{line}</span>
              </li>
            ))}
          </ol>
        </div>
      )}
      {detail.policy_sources.length > 0 && (
        <PolicySourcesPanel detail={detail} />
      )}
      <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3">
        <div className="mb-2 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          Other rules for <span className="font-mono">{detail.name}</span>
        </div>
        <dl className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-4">
          {rules.map((r) => (
            <div key={r.label}>
              <dt className="text-xs text-zinc-500 dark:text-zinc-400">{r.label}</dt>
              <dd className="font-mono text-zinc-900 dark:text-zinc-100">{r.value}</dd>
            </div>
          ))}
        </dl>
      </div>
    </div>
  );
}

function ChangelogTab() {
  return (
    <div className="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">
      Inline changelog lazy-fetch lands in Phase 6. For now, inspect releases
      directly on the upstream registry (npm / PyPI / GitHub).
    </div>
  );
}

function CompatibilityTab({
  ecosystem,
  name,
  installed,
}: {
  ecosystem: string;
  name: string;
  installed?: string;
}) {
  const compat = useQuery({
    queryKey: ["compat", ecosystem, name],
    queryFn: () => api.packageCompat(ecosystem, name),
  });
  if (compat.isLoading) {
    return <div className="py-8 text-center text-sm text-zinc-500 dark:text-zinc-400">Loading…</div>;
  }
  if (compat.error) {
    return (
      <div className="py-8 text-center text-sm text-red-600 dark:text-red-400">
        Failed to load compatibility: {String(compat.error)}
      </div>
    );
  }
  if (!compat.data) return null;

  const installedRow = compat.data.rows.find((r) => r.version === installed);
  const peerRows: PeerDepRow[] = installedRow
    ? Object.entries(installedRow.peer_deps)
        .filter((entry): entry is [string, NonNullable<typeof entry[1]>] => entry[1] !== undefined)
        .map(([depName, spec]) => ({
          name: depName,
          range: spec.range,
          optional: spec.optional,
        }))
    : [];
  const engines: EngineRow[] = installedRow
    ? Object.entries(installedRow.engines)
        .filter((entry): entry is [string, string] => typeof entry[1] === "string")
        .map(([runtime, range]) => ({ runtime, range }))
    : [];

  const graphHref = `/graph?focus=${encodeURIComponent(
    `${ecosystem}:${name}@${installed ?? ""}`,
  )}`;

  // Polish-bis-4: two distinct empty cases that used to share one vague
  // banner. Disambiguate them so a user who sees empty peer/engines
  // tables knows whether to blame the scan (finding #7, now auto-resolved
  // since Polish-bis-2) or the package itself (plenty of npm entries
  // legitimately ship no `engines` / `peerDependencies`).
  const hasAnyRows = compat.data.rows.length > 0;
  const installedMissingButOthersPresent = !installedRow && hasAnyRows;
  const packageCarriesNoMetadata = !hasAnyRows;

  return (
    <div className="space-y-4">
      {installedMissingButOthersPresent && (
        <div className="rounded-md border border-amber-200 dark:border-amber-900 bg-amber-50 dark:bg-amber-950/40 px-3 py-2 text-xs text-amber-900 dark:text-amber-200">
          No compatibility metadata for the installed version
          (<span className="font-mono">{installed}</span>). Other versions do
          carry peer deps + engines — scroll through the Versions tab or
          re-scan the repo so the installed one gets populated.
        </div>
      )}
      {packageCarriesNoMetadata && (
        <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 py-2 text-xs text-zinc-600 dark:text-zinc-400">
          This package doesn&apos;t declare any peer dependencies or engine
          constraints in the scanned lockfile. That&apos;s normal — many npm
          entries ship neither — so there&apos;s nothing to show in the tables
          below. The <span className="font-medium">Used by</span> section
          still reflects who depends on it.
        </div>
      )}

      <section>
        <SectionHeader title="Peer dependencies" count={peerRows.length} />
        {peerRows.length === 0 ? (
          <EmptyRow>No peer dependencies declared for this version.</EmptyRow>
        ) : (
          <div className="overflow-hidden rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900">
            <table className="w-full text-sm">
              <thead className="border-b border-zinc-200 dark:border-zinc-800 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Peer</th>
                  <th className="px-3 py-2 text-left font-medium">Required</th>
                  <th className="px-3 py-2 text-left font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {peerRows.map((p) => (
                  <tr key={p.name} className="border-b border-zinc-100 dark:border-zinc-800">
                    <td className="px-3 py-1.5 font-mono text-xs">{p.name}</td>
                    <td className="px-3 py-1.5 font-mono text-xs text-zinc-700 dark:text-zinc-300">
                      {p.range}
                    </td>
                    <td className="px-3 py-1.5">
                      {p.optional ? (
                        <Badge
                          tone="muted"
                          title="Optional peer — npm/pnpm will skip the install warning if the consumer doesn't provide it."
                        >
                          optional
                        </Badge>
                      ) : (
                        <Badge
                          tone="warn"
                          title="Required peer — the consumer must provide a matching version. Verify the graph to make sure it is satisfied."
                        >
                          required · see graph
                        </Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section>
        <SectionHeader title="Engines" count={engines.length} />
        {engines.length === 0 ? (
          <EmptyRow>No engine constraints declared.</EmptyRow>
        ) : (
          <div className="overflow-hidden rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900">
            <table className="w-full text-sm">
              <thead className="border-b border-zinc-200 dark:border-zinc-800 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                <tr>
                  <th className="px-3 py-2 text-left font-medium">Runtime</th>
                  <th className="px-3 py-2 text-left font-medium">Required</th>
                </tr>
              </thead>
              <tbody>
                {engines.map((e) => (
                  <tr key={e.runtime} className="border-b border-zinc-100 dark:border-zinc-800">
                    <td className="px-3 py-1.5 font-mono text-xs">{e.runtime}</td>
                    <td className="px-3 py-1.5 font-mono text-xs text-zinc-700 dark:text-zinc-300">
                      {e.range}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <UsedBySection dependents={compat.data.dependents} />


      <div className="flex items-center justify-between rounded-md border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 py-2 text-xs text-zinc-600 dark:text-zinc-400">
        <span>
          Inspect upstream + transitive chains visually in the dependency graph.
        </span>
        <Link
          to={graphHref}
          className="inline-flex items-center gap-1 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-2 py-1 text-xs text-zinc-700 dark:text-zinc-300 hover:bg-white"
        >
          Open in graph <ExternalLinkIcon className="h-3 w-3" />
        </Link>
      </div>
    </div>
  );
}

type PeerDepRow = { name: string; range: string; optional: boolean };
type EngineRow = { runtime: string; range: string };

function UsedBySection({ dependents }: { dependents: CompatDependent[] }) {
  // Phase 7b: group the flat "Used by" list by workspace so the user
  // sees which repo pulls the package in — each section is independently
  // collapsible via the native <details> element (zero JS state, keeps
  // the tab light).
  const byWorkspace = new Map<string, CompatDependent[]>();
  for (const d of dependents) {
    const key = d.workspace || "(unknown workspace)";
    const list = byWorkspace.get(key) ?? [];
    list.push(d);
    byWorkspace.set(key, list);
  }
  const groups = [...byWorkspace.entries()].sort(([a], [b]) => a.localeCompare(b));
  const totalWorkspaces = groups.length;

  return (
    <section>
      <SectionHeader
        title={
          totalWorkspaces === 0
            ? "Used by"
            : `Used by · ${totalWorkspaces} workspace${totalWorkspaces === 1 ? "" : "s"}`
        }
        count={dependents.length}
      />
      {dependents.length === 0 ? (
        <EmptyRow>
          Nothing in the scanned repos depends on this package.
        </EmptyRow>
      ) : (
        <div className="space-y-2">
          {groups.map(([workspace, items], groupIdx) => (
            <details
              key={workspace}
              open={groupIdx === 0}
              className="overflow-hidden rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900"
              data-testid={`used-by-group-${workspace}`}
            >
              <summary
                className="flex cursor-pointer items-center justify-between gap-3 border-b border-zinc-100 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-3 py-2 text-xs"
                title="Workspace consuming this package. Click to collapse/expand the parents that pull it in."
              >
                <span className="flex items-center gap-2">
                  <Badge tone="muted">{scopeLabel(workspace)}</Badge>
                  <span className="font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
                    {workspace}
                  </span>
                </span>
                <span className="text-zinc-500 dark:text-zinc-400">
                  {items.length} parent{items.length === 1 ? "" : "s"}
                </span>
              </summary>
              <table className="w-full text-sm">
                <thead className="border-b border-zinc-200 dark:border-zinc-800 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                  <tr>
                    <th className="px-3 py-2 text-left font-medium">Parent</th>
                    <th className="px-3 py-2 text-left font-medium">Version</th>
                    <th className="px-3 py-2 text-left font-medium">Range asked</th>
                    <th className="px-3 py-2 text-left font-medium">Kind</th>
                  </tr>
                </thead>
                <tbody>
                  {items.slice(0, 50).map((d, i) => (
                    <tr
                      key={`${d.name}@${d.version}-${i}`}
                      className="border-b border-zinc-100 dark:border-zinc-800"
                    >
                      <td className="px-3 py-1.5">
                        <Link
                          to={`/packages/${encodeURIComponent(d.ecosystem)}/${encodeURIComponent(d.name)}`}
                          className="font-mono text-xs text-zinc-900 dark:text-zinc-100 hover:underline"
                        >
                          {d.name}
                        </Link>
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs text-zinc-700 dark:text-zinc-300">
                        {d.version}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-xs text-zinc-700 dark:text-zinc-300">
                        {d.range}
                      </td>
                      <td className="px-3 py-1.5">
                        <Badge
                          tone="muted"
                          title="Edge kind declared by the parent: runtime/dev/peer/optional. Drives which production bundles pull this package in."
                        >
                          {d.kind}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {items.length > 50 && (
                <div className="border-t border-zinc-200 dark:border-zinc-800 p-2 text-xs text-zinc-500 dark:text-zinc-400">
                  Showing 50 of {items.length} dependents in this workspace.
                </div>
              )}
            </details>
          ))}
        </div>
      )}
    </section>
  );
}

function SectionHeader({ title, count }: { title: string; count: number }) {
  return (
    <h3 className="mb-2 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
      {title} <span className="text-zinc-400 dark:text-zinc-500">({count})</span>
    </h3>
  );
}

function EmptyRow({ children }: { children: React.ReactNode }) {
  return (
    <div className="rounded-md border border-dashed border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 px-3 py-3 text-xs text-zinc-500 dark:text-zinc-400">
      {children}
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
  const title =
    severity === "critical"
      ? "Critical severity — exploit trivial / widespread impact. Treat as release-blocking."
      : severity === "high"
        ? "High severity — significant impact, patch ASAP."
        : severity === "medium"
          ? "Medium severity — patch in the next maintenance window."
          : severity === "low"
            ? "Low severity — informational, patch on the next upgrade cycle."
            : "Severity not classified by the advisory source.";
  return (
    <Badge tone={tone as never} title={title}>
      {severity}
    </Badge>
  );
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

function PolicySourcesPanel({ detail }: { detail: PackageDetail }) {
  const provByKey = new Map<string, { sourceIndex: number; line: number | null }>();
  for (const p of detail.policy_provenance) {
    provByKey.set(p.key, { sourceIndex: p.source_index, line: p.line });
  }
  // Key rows we surface with their effective value + provenance badge.
  const keyRows: { key: string; label: string; value: string }[] = [
    {
      key: "defaults.offset.major",
      label: "offset.major",
      value: signedAxis(detail.policy_trace.offset.major),
    },
    {
      key: "defaults.offset.minor",
      label: "offset.minor",
      value: signedAxis(detail.policy_trace.offset.minor),
    },
    {
      key: "defaults.offset.patch",
      label: "offset.patch",
      value: signedAxis(detail.policy_trace.offset.patch),
    },
    {
      key: "defaults.stability",
      label: "stability",
      value: detail.policy_trace.stability,
    },
    {
      key: "defaults.min_age_days",
      label: "min_age_days",
      value: String(detail.policy_trace.min_age_days),
    },
  ];
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-3">
      <div className="mb-2 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
        Policy sources
      </div>
      <div className="mb-3 text-xs text-zinc-500 dark:text-zinc-400">
        Merge order — later wins. Effective policy deep-merges the layers
        below on every key.
      </div>
      <ol className="mb-3 space-y-1 text-xs">
        {detail.policy_sources.map((src, i) => (
          <li key={i} className="flex items-start gap-2">
            <span className="font-mono text-zinc-400 dark:text-zinc-500">[{i}]</span>
            <span className="font-mono text-zinc-800">{src.label}</span>
            <span className="ml-auto text-zinc-400 dark:text-zinc-500">{src.kind}</span>
          </li>
        ))}
      </ol>
      <dl className="grid gap-y-1 text-xs sm:grid-cols-[max-content_max-content_1fr] sm:gap-x-3">
        {keyRows.map((row) => {
          const prov = provByKey.get(row.key);
          const source =
            prov !== undefined ? detail.policy_sources[prov.sourceIndex] : undefined;
          const origin = source
            ? prov?.line != null
              ? `from ${source.label}:L${prov.line}`
              : `from ${source.label}`
            : "unset (falls through to downstream default)";
          return (
            <div
              key={row.key}
              className="contents text-zinc-700 dark:text-zinc-300"
              title={origin}
            >
              <dt className="font-mono text-zinc-500 dark:text-zinc-400">{row.label}</dt>
              <dd className="font-mono text-zinc-900 dark:text-zinc-100">{row.value}</dd>
              <dd className="text-zinc-400 dark:text-zinc-500">{origin}</dd>
            </div>
          );
        })}
      </dl>
    </div>
  );
}

function signedAxis(n: number): string {
  return n === 0 ? "0" : `-${n}`;
}
