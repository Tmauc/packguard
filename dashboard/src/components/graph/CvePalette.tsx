import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { SearchIcon } from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import type { GraphVulnerabilityEntry } from "@/api/types/GraphVulnerabilityEntry";
import { useWorkspaceScope } from "@/components/layout/workspace-scope";

// Phase 11.3: command palette for picking a CVE to focus the graph on.
// Replaces the free-text `Focus CVE` input — users don't know CVE ids
// by heart, so we surface the list of advisories actually hitting the
// current workspace and let them pick by package name, severity, or
// CVE id via a loose `includes` match that covers every visible field.

function matches(entry: GraphVulnerabilityEntry, query: string): boolean {
  if (!query) return true;
  const haystack = [
    entry.cve_id ?? "",
    entry.advisory_id,
    entry.package_name,
    entry.package_version,
    entry.severity,
    entry.summary ?? "",
  ]
    .join(" ")
    .toLowerCase();
  return query
    .toLowerCase()
    .split(/\s+/)
    .filter(Boolean)
    .every((tok) => haystack.includes(tok));
}

function severityClasses(severity: string): string {
  switch (severity) {
    case "critical":
      return "bg-red-100 dark:bg-red-950/60 text-red-800 border-red-300 dark:border-red-800";
    case "high":
      return "bg-orange-100 text-orange-800 border-orange-300";
    case "medium":
      return "bg-yellow-100 text-yellow-800 border-yellow-300";
    case "low":
      return "bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300 border-zinc-300 dark:border-zinc-700";
    default:
      return "bg-zinc-50 dark:bg-zinc-900 text-zinc-600 dark:text-zinc-400 border-zinc-200 dark:border-zinc-800";
  }
}

export function CvePalette({
  open,
  onClose,
  onSelect,
}: {
  open: boolean;
  onClose: () => void;
  onSelect: (vulnId: string) => void;
}) {
  const scope = useWorkspaceScope();
  const [query, setQuery] = useState("");
  const [highlight, setHighlight] = useState(0);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const listRef = useRef<HTMLUListElement | null>(null);

  const vulns = useQuery({
    queryKey: ["graph-vulnerabilities", scope ?? null],
    queryFn: () => api.graphVulnerabilities(scope),
    enabled: open,
  });

  const filtered = useMemo(() => {
    const entries = vulns.data?.entries ?? [];
    return entries.filter((e) => matches(e, query));
  }, [vulns.data, query]);

  // Re-seat the highlight whenever the filtered set changes so arrow
  // keys always land on a visible row.
  useEffect(() => {
    setHighlight(0);
  }, [query, vulns.data]);

  // Reset input + highlight when the palette reopens; keep nothing
  // leaking between sessions.
  useEffect(() => {
    if (open) {
      setQuery("");
      setHighlight(0);
      // Defer focus so the portal is mounted and the input is actually
      // reachable by the user-agent's focus manager.
      requestAnimationFrame(() => inputRef.current?.focus());
    }
  }, [open]);

  // Keep the highlighted row scrolled into view during arrow navigation.
  useEffect(() => {
    if (!open || !listRef.current) return;
    const row = listRef.current.querySelector<HTMLElement>(
      `[data-row="${highlight}"]`,
    );
    row?.scrollIntoView({ block: "nearest" });
  }, [highlight, open]);

  function commit(entry: GraphVulnerabilityEntry) {
    onSelect(entry.cve_id ?? entry.advisory_id);
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLDivElement>) {
    if (e.key === "Escape") {
      e.preventDefault();
      onClose();
      return;
    }
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setHighlight((h) => Math.min(h + 1, Math.max(0, filtered.length - 1)));
      return;
    }
    if (e.key === "ArrowUp") {
      e.preventDefault();
      setHighlight((h) => Math.max(0, h - 1));
      return;
    }
    if (e.key === "Enter") {
      e.preventDefault();
      const pick = filtered[highlight];
      if (pick) commit(pick);
    }
  }

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-zinc-900/40 pt-[15vh]"
      onClick={onClose}
      data-testid="cve-palette-overlay"
    >
      <div
        role="dialog"
        aria-label="Focus CVE palette"
        aria-modal="true"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={handleKeyDown}
        className="w-full max-w-xl overflow-hidden rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-2xl"
        data-testid="cve-palette"
      >
        <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 px-3 py-2">
          <SearchIcon className="h-4 w-4 text-zinc-400 dark:text-zinc-500" />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search CVE id, package, severity…"
            className="w-full border-0 bg-transparent text-sm text-zinc-900 dark:text-zinc-100 focus:outline-none"
            role="combobox"
            aria-expanded="true"
            aria-controls="cve-palette-list"
            aria-autocomplete="list"
            data-testid="cve-palette-input"
          />
          <kbd className="rounded border border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-900 px-1.5 py-0.5 text-[10px] text-zinc-500 dark:text-zinc-400">
            Esc
          </kbd>
        </div>
        <ul
          id="cve-palette-list"
          ref={listRef}
          role="listbox"
          className="max-h-80 overflow-y-auto"
          data-testid="cve-palette-list"
        >
          {vulns.isLoading && (
            <li className="px-3 py-6 text-center text-xs text-zinc-500 dark:text-zinc-400">Loading…</li>
          )}
          {vulns.error && (
            <li className="px-3 py-6 text-center text-xs text-red-600 dark:text-red-400">
              Failed to load CVEs: {String(vulns.error)}
            </li>
          )}
          {!vulns.isLoading &&
            !vulns.error &&
            filtered.length === 0 &&
            (vulns.data?.entries ?? []).length === 0 && (
              <li
                className="px-3 py-6 text-center text-xs text-zinc-500 dark:text-zinc-400"
                data-testid="cve-palette-empty"
              >
                No CVE in scope. Run <span className="font-mono">packguard sync</span>{" "}
                to fetch the advisory database, then re-scan.
              </li>
            )}
          {!vulns.isLoading &&
            !vulns.error &&
            filtered.length === 0 &&
            (vulns.data?.entries ?? []).length > 0 && (
              <li className="px-3 py-6 text-center text-xs text-zinc-500 dark:text-zinc-400">
                No match for <span className="font-mono">{query}</span>.
              </li>
            )}
          {filtered.map((entry, i) => {
            const id = entry.cve_id ?? entry.advisory_id;
            const active = i === highlight;
            return (
              <li
                key={`${entry.advisory_id}:${entry.ecosystem}:${entry.package_name}:${entry.package_version}`}
                data-row={i}
              >
                <button
                  type="button"
                  role="option"
                  aria-selected={active}
                  onMouseEnter={() => setHighlight(i)}
                  onClick={() => commit(entry)}
                  className={cn(
                    "flex w-full items-center gap-3 px-3 py-2 text-left text-sm",
                    active ? "bg-zinc-100 dark:bg-zinc-800" : "bg-white dark:bg-zinc-900 hover:bg-zinc-50 dark:hover:bg-zinc-800",
                  )}
                  data-testid={`cve-palette-row-${id}`}
                >
                  <span className="font-mono text-xs text-zinc-900 dark:text-zinc-100">{id}</span>
                  <span className="truncate text-zinc-700 dark:text-zinc-300">
                    {entry.package_name}
                    <span className="text-zinc-400 dark:text-zinc-500">@{entry.package_version}</span>
                  </span>
                  <span
                    className={cn(
                      "ml-auto rounded-sm border px-1.5 py-0.5 text-[10px] uppercase tracking-wide",
                      severityClasses(entry.severity),
                    )}
                  >
                    {entry.severity}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
