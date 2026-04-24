import { useEffect, useMemo, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowDownIcon, ArrowUpIcon, SearchIcon } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { ScopeBadge } from "@/components/layout/ScopeBadge";
import { useScope } from "@/components/layout/workspace-scope";
import type { ComplianceTag } from "@/api/types/ComplianceTag";
import type { PackageRow } from "@/api/types/PackageRow";
import type { PackageRisk } from "@/api/types/PackageRisk";
import type { PackagesQuery } from "@/api/types/PackagesQuery";

const STATUS_OPTIONS: { value: ComplianceTag; label: string }[] = [
  { value: "compliant", label: "Compliant" },
  { value: "warning", label: "Warning" },
  { value: "violation", label: "Violation" },
  { value: "cve-violation", label: "CVE violation" },
  { value: "malware", label: "Malware" },
  { value: "typosquat", label: "Typosquat" },
  { value: "insufficient", label: "Insufficient" },
];

const SEVERITY_OPTIONS = ["low", "medium", "high", "critical"] as const;
const ECOSYSTEMS = ["npm", "pypi"] as const;

export function PackagesPage() {
  const [params, setParams] = useSearchParams();
  const scope = useScope();
  const queryFromUrl = useMemo<Partial<PackagesQuery>>(
    () => ({
      ecosystem: params.get("ecosystem") ?? undefined,
      status: params.get("status") ?? undefined,
      min_severity: params.get("min_severity") ?? undefined,
      has_malware: params.get("has_malware") === "1" ? true : undefined,
      has_typosquat: params.get("has_typosquat") === "1" ? true : undefined,
      q: params.get("q") ?? undefined,
      sort: params.get("sort") ?? undefined,
      dir: params.get("dir") ?? undefined,
      page: params.get("page") ? Number(params.get("page")) : undefined,
      per_page: params.get("per_page") ? Number(params.get("per_page")) : 50,
    }),
    [params],
  );

  // Debounced search box that pushes into the URL.
  const [search, setSearch] = useState(queryFromUrl.q ?? "");
  useEffect(() => {
    const handle = setTimeout(() => {
      setParams((prev) => {
        const next = new URLSearchParams(prev);
        if (search) next.set("q", search);
        else next.delete("q");
        next.set("page", "1");
        return next;
      });
    }, 300);
    return () => clearTimeout(handle);
    // setParams is stable enough for this loop; including it would re-fire on every URL update.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search]);

  const list = useQuery({
    queryKey: ["packages", queryFromUrl, scope ?? null],
    queryFn: () => api.packages(queryFromUrl, scope),
  });

  const setFilter = (key: string, value: string | undefined) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (value === undefined || value === "" || value === "all") {
        next.delete(key);
      } else {
        next.set(key, value);
      }
      next.set("page", "1");
      return next;
    });
  };

  const toggle = (key: string) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      if (next.get(key) === "1") next.delete(key);
      else next.set(key, "1");
      next.set("page", "1");
      return next;
    });
  };

  const setSort = (column: string) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      const currentSort = next.get("sort") ?? "name";
      const currentDir = next.get("dir") ?? "asc";
      if (currentSort === column) {
        next.set("dir", currentDir === "asc" ? "desc" : "asc");
      } else {
        next.set("sort", column);
        next.set("dir", "asc");
      }
      return next;
    });
  };

  const setPage = (page: number) => {
    setParams((prev) => {
      const next = new URLSearchParams(prev);
      next.set("page", String(page));
      return next;
    });
  };

  return (
    <div className="space-y-4">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
            Packages
          </h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            Every dependency the latest scan persisted, evaluated against the
            active policy.
          </p>
        </div>
        <ScopeBadge />
      </header>

      <Card>
        <CardContent className="flex flex-wrap items-center gap-2 p-3">
          <SelectInput
            label="Ecosystem"
            value={queryFromUrl.ecosystem}
            options={[
              { value: "all", label: "All" },
              ...ECOSYSTEMS.map((e) => ({ value: e, label: e })),
            ]}
            onChange={(v) => setFilter("ecosystem", v)}
          />
          <SelectInput
            label="Status"
            value={queryFromUrl.status}
            options={[
              { value: "all", label: "All" },
              ...STATUS_OPTIONS.map((s) => ({ value: s.value, label: s.label })),
            ]}
            onChange={(v) => setFilter("status", v)}
          />
          <SelectInput
            label="Min severity"
            value={queryFromUrl.min_severity}
            options={[
              { value: "all", label: "Any" },
              ...SEVERITY_OPTIONS.map((s) => ({ value: s, label: s })),
            ]}
            onChange={(v) => setFilter("min_severity", v)}
          />
          <ToggleChip
            label="Has malware"
            on={Boolean(queryFromUrl.has_malware)}
            onClick={() => toggle("has_malware")}
          />
          <ToggleChip
            label="Has typosquat"
            on={Boolean(queryFromUrl.has_typosquat)}
            onClick={() => toggle("has_typosquat")}
          />
          <div className="ml-auto flex items-center gap-2">
            <SearchIcon className="h-4 w-4 text-zinc-400 dark:text-zinc-500" />
            <input
              type="search"
              placeholder="Search package…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 w-56 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-2 text-sm focus:outline-2 focus:outline-zinc-900"
            />
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="p-0">
          {list.isLoading ? (
            <div className="p-6 text-sm text-zinc-500 dark:text-zinc-400">Loading…</div>
          ) : list.error ? (
            <div className="p-6 text-sm text-red-600 dark:text-red-400">
              Failed to load packages: {String(list.error)}
            </div>
          ) : !list.data || list.data.rows.length === 0 ? (
            <div className="p-6 text-sm text-zinc-500 dark:text-zinc-400">
              No packages match the current filters.
            </div>
          ) : (
            <>
              <table className="w-full text-sm">
                <thead className="border-b border-zinc-200 dark:border-zinc-800 text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
                  <tr>
                    <SortHeader
                      label="Package"
                      column="name"
                      query={queryFromUrl}
                      onSort={setSort}
                    />
                    <SortHeader
                      label="Eco"
                      column="ecosystem"
                      query={queryFromUrl}
                      onSort={setSort}
                      title="Ecosystem (npm / pypi)."
                    />
                    <th
                      className="px-3 py-2 text-left font-medium"
                      title="Version currently pinned by the lockfile."
                    >
                      Installed
                    </th>
                    <th
                      className="px-3 py-2 text-left font-medium"
                      title="Latest stable release known to the registry."
                    >
                      Latest
                    </th>
                    <SortHeader
                      label="Compliance"
                      column="compliance"
                      query={queryFromUrl}
                      onSort={setSort}
                      title="Verdict: compliant / warning / violation / cve-violation / malware / typosquat / insufficient. Click an insufficient badge to jump to the Policy eval cascade trace."
                    />
                    <SortHeader
                      label="Risk"
                      column="risk"
                      query={queryFromUrl}
                      onSort={setSort}
                      title="CVE severity counts + supply-chain flags. 🔴 critical · 🟠 high · 🟡 medium · 🟢 low · 🏴‍☠️ malware · ⚠ typosquat."
                    />
                  </tr>
                </thead>
                <tbody>
                  {list.data.rows.map((row) => (
                    <Row key={`${row.ecosystem}/${row.name}`} row={row} />
                  ))}
                </tbody>
              </table>
              <Pagination
                total={list.data.total}
                page={list.data.page}
                perPage={list.data.per_page}
                onChange={setPage}
              />
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

function Row({ row }: { row: PackageRow }) {
  const detailHref = `/packages/${encodeURIComponent(row.ecosystem)}/${encodeURIComponent(row.name)}`;
  // Insufficient rows deep-link into the Policy eval tab so the user lands
  // directly on the cascade trace that explains the verdict.
  const complianceHref =
    row.compliance === "insufficient" ? `${detailHref}?tab=policy#cascade` : detailHref;
  return (
    <tr className="border-b border-zinc-100 dark:border-zinc-800 hover:bg-zinc-50 dark:hover:bg-zinc-800">
      <td className="px-3 py-2">
        <Link to={detailHref} className="font-mono text-zinc-900 dark:text-zinc-100 hover:underline">
          {row.name}
        </Link>
      </td>
      <td className="px-3 py-2">
        <Badge tone="muted">{row.ecosystem}</Badge>
      </td>
      <td className="px-3 py-2 font-mono text-xs text-zinc-700 dark:text-zinc-300">
        {row.installed ?? "—"}
      </td>
      <td className="px-3 py-2 font-mono text-xs text-zinc-700 dark:text-zinc-300">
        {row.latest ?? "—"}
      </td>
      <td className="px-3 py-2">
        <Link
          to={complianceHref}
          className="hover:underline"
          aria-label={
            row.compliance === "insufficient"
              ? `Open Policy eval cascade for ${row.name}`
              : undefined
          }
        >
          <ComplianceBadge tag={row.compliance} />
        </Link>
      </td>
      <td className="px-3 py-2">
        <RiskBadges risk={row.risk} />
      </td>
    </tr>
  );
}

function SortHeader({
  label,
  column,
  query,
  onSort,
  title,
}: {
  label: string;
  column: string;
  query: Partial<PackagesQuery>;
  onSort: (col: string) => void;
  title?: string;
}) {
  const active = (query.sort ?? "name") === column;
  const asc = (query.dir ?? "asc") === "asc";
  return (
    <th
      className={cn(
        "cursor-pointer select-none px-3 py-2 text-left font-medium",
        active && "text-zinc-900 dark:text-zinc-100",
      )}
      onClick={() => onSort(column)}
      title={title}
    >
      <span className="inline-flex items-center gap-1">
        {label}
        {active &&
          (asc ? (
            <ArrowUpIcon className="h-3 w-3" />
          ) : (
            <ArrowDownIcon className="h-3 w-3" />
          ))}
      </span>
    </th>
  );
}

function SelectInput({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string | null | undefined;
  options: { value: string; label: string }[];
  onChange: (v: string | undefined) => void;
}) {
  return (
    <label className="flex items-center gap-2 text-xs text-zinc-500 dark:text-zinc-400">
      {label}
      <select
        value={value ?? "all"}
        onChange={(e) =>
          onChange(e.target.value === "all" ? undefined : e.target.value)
        }
        className="h-8 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-2 text-sm text-zinc-900 dark:text-zinc-100 focus:outline-2 focus:outline-zinc-900"
      >
        {options.map((o) => (
          <option key={o.value} value={o.value}>
            {o.label}
          </option>
        ))}
      </select>
    </label>
  );
}

function ToggleChip({
  label,
  on,
  onClick,
}: {
  label: string;
  on: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "h-8 rounded-md border px-3 text-xs",
        on
          ? "border-zinc-900 bg-zinc-900 text-white"
          : "border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-50 dark:hover:bg-zinc-800",
      )}
    >
      {label}
    </button>
  );
}

function Pagination({
  total,
  page,
  perPage,
  onChange,
}: {
  total: number;
  page: number;
  perPage: number;
  onChange: (page: number) => void;
}) {
  const lastPage = Math.max(1, Math.ceil(total / perPage));
  return (
    <div className="flex items-center justify-between border-t border-zinc-200 dark:border-zinc-800 px-3 py-2 text-xs text-zinc-500 dark:text-zinc-400">
      <span>
        {total === 0
          ? "0 packages"
          : `Page ${page} of ${lastPage} · ${total} packages`}
      </span>
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="sm"
          disabled={page <= 1}
          onClick={() => onChange(page - 1)}
        >
          Prev
        </Button>
        <Button
          variant="outline"
          size="sm"
          disabled={page >= lastPage}
          onClick={() => onChange(page + 1)}
        >
          Next
        </Button>
      </div>
    </div>
  );
}

export function ComplianceBadge({ tag }: { tag: ComplianceTag }) {
  const tone =
    tag === "compliant"
      ? "good"
      : tag === "warning"
        ? "warn"
        : tag === "violation" || tag === "cve-violation"
          ? "bad"
          : tag === "malware"
            ? "malware"
            : tag === "typosquat"
              ? "typosquat"
              : tag === "insufficient"
                ? "insufficient"
                : "muted";
  const title =
    tag === "compliant"
      ? "Compliant: installed version satisfies the active policy."
      : tag === "warning"
        ? "Warning: installed version drifts past the policy's soft bound but still passes."
        : tag === "violation"
          ? "Violation: installed version is outside the policy's hard bound."
          : tag === "cve-violation"
            ? "CVE violation: installed version matches an advisory blocked by the policy."
            : tag === "malware"
              ? "Malware: installed version is flagged in malware_reports — replace immediately."
              : tag === "typosquat"
                ? "Typosquat: package name is flagged as a likely typo of a popular one."
                : tag === "insufficient"
                  ? "Insufficient: no release satisfies the resolver's offset bound. Open the Policy eval tab to see the cascade trace, then loosen offset or pin explicitly."
                  : undefined;
  return (
    <Badge tone={tone} title={title}>
      {tag}
    </Badge>
  );
}

export function RiskBadges({ risk }: { risk: PackageRisk }) {
  const parts: { label: string; tone: Parameters<typeof Badge>[0]["tone"] }[] = [];
  if (risk.critical > 0) parts.push({ label: `${risk.critical}🔴`, tone: "bad" });
  if (risk.high > 0) parts.push({ label: `${risk.high}🟠`, tone: "cve" });
  if (risk.medium > 0) parts.push({ label: `${risk.medium}🟡`, tone: "warn" });
  if (risk.low > 0) parts.push({ label: `${risk.low}🟢`, tone: "good" });
  if (risk.malware_confirmed > 0)
    parts.push({ label: `${risk.malware_confirmed}🏴‍☠️`, tone: "malware" });
  if (risk.typosquat_suspects > 0)
    parts.push({ label: `${risk.typosquat_suspects}⚠`, tone: "typosquat" });
  if (parts.length === 0) {
    return <span className="text-xs text-zinc-400 dark:text-zinc-500">—</span>;
  }
  return (
    <span className="flex flex-wrap gap-1">
      {parts.map((p, i) => (
        <Badge key={i} tone={p.tone}>
          {p.label}
        </Badge>
      ))}
    </span>
  );
}
