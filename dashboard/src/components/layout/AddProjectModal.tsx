import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  ChevronRightIcon,
  FolderGitIcon,
  FolderIcon,
  HomeIcon,
  PackageIcon,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useJobStatus } from "@/lib/useJobStatus";
import { useSetProjectScope } from "@/components/layout/workspace-scope";
import type { ProjectDto } from "@/api/types/ProjectDto";

type Mode = "browse" | "type";

/// Phase 14.5c — directory-picker modal for registering a new project.
///
/// Two modes share the same submit pipeline:
///
/// - **Browse** (default, the UX Thomas asked for in 14.5 dogfood): the
///   user navigates the filesystem from `$HOME` via a breadcrumb +
///   subdir list. Quick-roots ($HOME / Repo / Projects / …) come from
///   `/api/fs/roots`; each directory level comes from
///   `/api/fs/browse?path=<abs>`. `Select this folder` submits the
///   *current directory*, not a child entry — Thomas can navigate to
///   the folder he wants to register, then commit. Entries that match
///   an already-registered project surface an "✓ Registered" badge so
///   the user doesn't accidentally re-add the same path; if the
///   *current* directory is itself registered, the primary button
///   flips to "Switch to existing project" and short-circuits the
///   POST in favour of `setProjectScope(slug)`.
///
/// - **Type path** (legacy fallback for power users who copy-paste
///   absolute paths): the v0.5 flow — text input + client-side
///   "must be absolute" guard + POST.
///
/// The job-completion + scope-switch wiring (job poll → outcome.slug
/// → setProjectScope) is unchanged from 14.3c. Only the path-picking
/// surface in front of it changed.
export function AddProjectModal({
  open,
  onClose,
  onStarted,
}: {
  open: boolean;
  onClose: () => void;
  onStarted?: (jobId: string, path: string) => void;
}) {
  const [mode, setMode] = useState<Mode>("browse");
  const [currentPath, setCurrentPath] = useState<string | undefined>(undefined);
  const [typedPath, setTypedPath] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pendingJob, setPendingJob] = useState<
    { id: string; path: string } | null
  >(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const setProjectScope = useSetProjectScope();
  const qc = useQueryClient();
  const { trackJob, jobs } = useJobStatus();

  // The projects list powers the already-registered hint. Reuse the
  // shared queryKey so the cache is hot whenever Layout has rendered
  // (which it always has by the time this modal opens).
  const projectsQuery = useQuery({
    queryKey: ["projects"],
    queryFn: api.projects,
  });
  const registeredByPath = useMemo(() => {
    const map = new Map<string, string /* slug */>();
    for (const p of projectsQuery.data ?? []) {
      map.set(p.path, p.slug);
    }
    return map;
  }, [projectsQuery.data]);

  const rootsQuery = useQuery({
    queryKey: ["fs-roots"],
    queryFn: api.fsRoots,
    enabled: open && mode === "browse",
  });

  const browseQuery = useQuery({
    queryKey: ["fs-browse", currentPath ?? ""],
    queryFn: () => api.fsBrowse(currentPath),
    enabled: open && mode === "browse" && !!currentPath,
  });

  // Once roots resolve, jump the browser to $HOME so the user has
  // something concrete on screen. We don't reset `currentPath` if the
  // user has already navigated — only the first-mount transition.
  useEffect(() => {
    if (mode !== "browse") return;
    if (currentPath) return;
    if (!rootsQuery.data) return;
    setCurrentPath(rootsQuery.data.home);
  }, [mode, currentPath, rootsQuery.data]);

  // Reset modal state on every open so a previous submission doesn't
  // linger. We keep `mode` sticky across opens so a power user who
  // chose "Type path" once doesn't get yanked back to "Browse".
  useEffect(() => {
    if (open) {
      setError(null);
      setPendingJob(null);
      setTypedPath("");
      setCurrentPath(undefined);
      if (mode === "type") {
        requestAnimationFrame(() => inputRef.current?.focus());
      }
    }
    // mode is intentionally not in the dep list — switching mode while
    // open is handled by the toggle handler, not this open-side reset.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [open, onClose]);

  const register = useMutation({
    mutationFn: (abs: string) => api.startAddProject(abs),
    onSuccess: ({ id }, abs) => {
      trackJob(id);
      onStarted?.(id, abs);
      setPendingJob({ id, path: abs });
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 400) {
        setError(err.message);
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      toast.error("Couldn't register project", { description: msg });
      setError(msg);
    },
  });

  // Watch the queued job for completion. Outcome shape is
  // `{ project: ProjectDto, scan: ... }` per
  // crates/packguard-server/src/jobs.rs:139-142.
  useEffect(() => {
    if (!pendingJob) return;
    const job = jobs.find((j) => j.id === pendingJob.id);
    if (!job) return;
    if (job.status === "succeeded") {
      const outcome = job.result as
        | { project?: ProjectDto; scan?: unknown }
        | null;
      const newSlug = outcome?.project?.slug;
      const displayName =
        outcome?.project?.name ?? pendingJob.path.split("/").pop() ?? "Project";
      void qc.invalidateQueries({ queryKey: ["projects"] });
      void qc.invalidateQueries({ queryKey: ["workspaces"] });
      if (newSlug) {
        setProjectScope(newSlug);
      }
      toast.success("Project registered", {
        description: `${displayName} is now active.`,
      });
      setPendingJob(null);
      onClose();
    } else if (job.status === "failed") {
      const msg =
        job.error ?? "Project registration failed. Check the server logs.";
      setError(msg);
      setPendingJob(null);
    }
  }, [jobs, pendingJob, setProjectScope, qc, onClose]);

  // Pre-compute the breadcrumb before the early return so the hook
  // call order stays stable across `open` toggles. (eslint
  // react-hooks/rules-of-hooks would otherwise complain because the
  // helper's name starts with `use*`.)
  const home = rootsQuery.data?.home;
  const breadcrumb = useMemoBreadcrumb(home, currentPath);

  if (!open) return null;

  const busy = register.isPending || pendingJob !== null;

  // ---- submit dispatch ------------------------------------------------

  const submitTyped = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const trimmed = typedPath.trim();
    if (trimmed.length === 0) {
      setError("Path is required.");
      return;
    }
    if (!/^(\/|[A-Za-z]:[/\\])/.test(trimmed)) {
      setError("Path must be absolute (start with / or a drive letter).");
      return;
    }
    register.mutate(trimmed);
  };

  const currentSlug = currentPath ? registeredByPath.get(currentPath) : undefined;
  const submitBrowse = () => {
    setError(null);
    if (!currentPath) {
      setError("Pick a folder before submitting.");
      return;
    }
    if (currentSlug) {
      // Already registered → switch instead of double-registering.
      setProjectScope(currentSlug);
      toast.message("Switched to existing project", {
        description: currentPath,
      });
      onClose();
      return;
    }
    register.mutate(currentPath);
  };

  // ---- render ---------------------------------------------------------

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-zinc-950/40 p-8 backdrop-blur-sm"
      data-testid="add-project-modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Register a new project"
        data-testid="add-project-modal"
        className={cn(
          "mt-12 flex w-full max-w-2xl flex-col overflow-hidden rounded-lg border shadow-xl",
          "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900",
        )}
      >
        <header className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 px-4 py-3">
          <FolderGitIcon className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
          <h2 className="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
            Register a new project
          </h2>
          <div className="ml-auto flex items-center gap-1 rounded-md border border-zinc-200 dark:border-zinc-800 p-0.5 text-xs">
            <ModeToggle
              active={mode === "browse"}
              label="Browse"
              testId="add-project-mode-browse"
              onClick={() => {
                setMode("browse");
                setError(null);
              }}
            />
            <ModeToggle
              active={mode === "type"}
              label="Type path"
              testId="add-project-mode-type"
              onClick={() => {
                setMode("type");
                setError(null);
                setTypedPath("");
                requestAnimationFrame(() => inputRef.current?.focus());
              }}
            />
          </div>
        </header>

        {mode === "browse" ? (
          <BrowsePane
            home={home}
            currentPath={currentPath}
            roots={rootsQuery.data?.entries ?? []}
            rootsLoading={rootsQuery.isLoading}
            entries={browseQuery.data?.entries ?? []}
            parent={browseQuery.data?.parent ?? null}
            truncated={browseQuery.data?.truncated ?? false}
            entriesLoading={browseQuery.isLoading}
            entriesError={browseQuery.error as Error | null}
            registeredByPath={registeredByPath}
            breadcrumb={breadcrumb}
            onNavigate={(p) => {
              setError(null);
              setCurrentPath(p);
            }}
          />
        ) : (
          <TypePane
            inputRef={inputRef}
            value={typedPath}
            onChange={(v) => setTypedPath(v)}
            disabled={busy}
            onSubmit={submitTyped}
          />
        )}

        {error && (
          <div
            role="alert"
            data-testid="add-project-error"
            className="border-t border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 px-4 py-2 text-xs text-red-700 dark:text-red-300"
          >
            {error}
          </div>
        )}

        <footer className="flex items-center justify-between gap-2 border-t border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-4 py-3">
          <span
            className="truncate font-mono text-[11px] text-zinc-500 dark:text-zinc-400"
            data-testid="add-project-selected"
          >
            {mode === "browse" && currentPath
              ? `Selected: ${currentPath}`
              : mode === "type"
                ? "Type an absolute path"
                : "—"}
          </span>
          <div className="flex items-center gap-2">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              onClick={onClose}
              disabled={busy}
              data-testid="add-project-cancel"
            >
              Cancel
            </Button>
            {mode === "browse" ? (
              <Button
                type="button"
                size="sm"
                onClick={submitBrowse}
                disabled={busy || !currentPath || currentPath === home}
                title={
                  currentPath === home
                    ? "Pick a project folder under $HOME"
                    : currentSlug
                      ? "This folder is already registered — clicking switches scope to it"
                      : undefined
                }
                data-testid="add-project-submit"
              >
                {pendingJob
                  ? "Registering…"
                  : register.isPending
                    ? "Submitting…"
                    : currentSlug
                      ? "Switch to existing project"
                      : "Select this folder"}
              </Button>
            ) : (
              <Button
                type="submit"
                form="add-project-type-form"
                size="sm"
                disabled={busy}
                data-testid="add-project-submit"
              >
                {pendingJob
                  ? "Registering…"
                  : register.isPending
                    ? "Submitting…"
                    : "Register project"}
              </Button>
            )}
          </div>
        </footer>
      </div>
    </div>
  );
}

// ---- subcomponents ----------------------------------------------------

function ModeToggle({
  active,
  label,
  testId,
  onClick,
}: {
  active: boolean;
  label: string;
  testId: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      data-testid={testId}
      data-active={active}
      className={cn(
        "rounded px-2 py-1 text-xs",
        active
          ? "bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
          : "text-zinc-600 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800",
      )}
    >
      {label}
    </button>
  );
}

type BreadcrumbSegment = { label: string; path: string };

function useMemoBreadcrumb(
  home: string | undefined,
  currentPath: string | undefined,
): BreadcrumbSegment[] {
  return useMemo(() => {
    if (!home || !currentPath) return [];
    if (!currentPath.startsWith(home)) {
      // Defensive — should never happen because the backend sandbox
      // rejects paths outside $HOME, but if it does we render the
      // current path as a single segment so the user isn't stuck.
      return [{ label: currentPath, path: currentPath }];
    }
    const segments: BreadcrumbSegment[] = [
      { label: "$HOME", path: home },
    ];
    if (currentPath === home) return segments;
    const rel = currentPath.slice(home.length).replace(/^\/+/, "");
    if (rel.length === 0) return segments;
    let acc = home;
    for (const seg of rel.split("/")) {
      acc = `${acc}/${seg}`;
      segments.push({ label: seg, path: acc });
    }
    return segments;
  }, [home, currentPath]);
}

function BrowsePane({
  home,
  currentPath,
  roots,
  rootsLoading,
  entries,
  parent,
  truncated,
  entriesLoading,
  entriesError,
  registeredByPath,
  breadcrumb,
  onNavigate,
}: {
  home: string | undefined;
  currentPath: string | undefined;
  roots: Array<{ label: string; path: string }>;
  rootsLoading: boolean;
  entries: Array<{
    name: string;
    path: string;
    has_git: boolean;
    has_manifest: boolean;
  }>;
  parent: string | null;
  truncated: boolean;
  entriesLoading: boolean;
  entriesError: Error | null;
  registeredByPath: Map<string, string>;
  breadcrumb: BreadcrumbSegment[];
  onNavigate: (path: string) => void;
}) {
  return (
    <div className="flex flex-col gap-3 px-4 py-3">
      {/* Quick roots */}
      <div
        className="flex flex-wrap items-center gap-1"
        data-testid="add-project-roots"
      >
        <span className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          Quick roots
        </span>
        {rootsLoading && (
          <span className="text-xs text-zinc-400 dark:text-zinc-500">Loading…</span>
        )}
        {roots.map((r) => (
          <button
            key={r.path}
            type="button"
            onClick={() => onNavigate(r.path)}
            data-testid={`add-project-root-${r.label}`}
            data-active={currentPath === r.path}
            className={cn(
              "rounded-md border px-2 py-1 text-xs",
              currentPath === r.path
                ? "border-zinc-900 dark:border-zinc-100 bg-zinc-900 text-white dark:bg-zinc-100 dark:text-zinc-900"
                : "border-zinc-200 dark:border-zinc-800 text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800",
            )}
          >
            {r.label === "$HOME" ? (
              <span className="inline-flex items-center gap-1">
                <HomeIcon className="h-3 w-3" />
                {r.label}
              </span>
            ) : (
              r.label
            )}
          </button>
        ))}
      </div>

      {/* Breadcrumb */}
      <nav
        className="flex flex-wrap items-center gap-0.5 font-mono text-xs text-zinc-700 dark:text-zinc-300"
        data-testid="add-project-breadcrumb"
        aria-label="Current path"
      >
        {breadcrumb.map((seg, i) => (
          <span key={seg.path} className="inline-flex items-center gap-0.5">
            <button
              type="button"
              onClick={() => onNavigate(seg.path)}
              data-testid={`add-project-crumb-${i}`}
              className="rounded px-1 py-0.5 hover:bg-zinc-100 dark:hover:bg-zinc-800"
            >
              {seg.label}
            </button>
            {i < breadcrumb.length - 1 && (
              <ChevronRightIcon className="h-3 w-3 text-zinc-400 dark:text-zinc-500" />
            )}
          </span>
        ))}
      </nav>

      {/* Entries list */}
      <div
        className={cn(
          "max-h-80 overflow-y-auto rounded-md border",
          "border-zinc-200 dark:border-zinc-800",
        )}
      >
        {parent && currentPath !== home && (
          <button
            type="button"
            onClick={() => onNavigate(parent)}
            data-testid="add-project-up"
            className="flex w-full items-center gap-2 border-b border-zinc-100 dark:border-zinc-900 px-3 py-1.5 text-left text-xs text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-900/50"
          >
            <FolderIcon className="h-3.5 w-3.5" />
            <span className="font-mono">..</span>
          </button>
        )}
        {entriesLoading && (
          <div className="px-3 py-4 text-center text-xs text-zinc-500 dark:text-zinc-400">
            Loading…
          </div>
        )}
        {entriesError && (
          <div
            data-testid="add-project-entries-error"
            className="px-3 py-4 text-center text-xs text-red-600 dark:text-red-400"
          >
            {entriesError.message}
          </div>
        )}
        {!entriesLoading && !entriesError && entries.length === 0 && (
          <div className="px-3 py-4 text-center text-xs text-zinc-500 dark:text-zinc-400">
            No subdirectories.
          </div>
        )}
        {entries.map((entry) => {
          const registeredSlug = registeredByPath.get(entry.path);
          return (
            <button
              key={entry.path}
              type="button"
              onClick={() => onNavigate(entry.path)}
              data-testid={`add-project-entry-${entry.name}`}
              className="flex w-full items-center gap-2 border-b border-zinc-100 dark:border-zinc-900 px-3 py-1.5 text-left text-sm hover:bg-zinc-50 dark:hover:bg-zinc-900/50"
            >
              <FolderIcon className="h-4 w-4 text-zinc-400 dark:text-zinc-500" />
              <span className="flex-1 truncate font-mono text-xs">
                {entry.name}
              </span>
              {entry.has_git && (
                <span
                  className="rounded bg-emerald-100 px-1.5 py-0.5 text-[10px] font-medium text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300"
                  title="Contains a .git/ directory"
                  data-testid={`add-project-entry-git-${entry.name}`}
                >
                  git
                </span>
              )}
              {entry.has_manifest && (
                <span
                  className="inline-flex items-center gap-0.5 rounded bg-sky-100 px-1.5 py-0.5 text-[10px] font-medium text-sky-700 dark:bg-sky-950/60 dark:text-sky-300"
                  title="Contains a supported manifest (package.json, pyproject.toml, …)"
                  data-testid={`add-project-entry-manifest-${entry.name}`}
                >
                  <PackageIcon className="h-2.5 w-2.5" />
                  manifest
                </span>
              )}
              {registeredSlug && (
                <span
                  className="rounded bg-zinc-200 px-1.5 py-0.5 text-[10px] font-medium text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300"
                  title="Already registered as a project — click to navigate inside, or select this folder to switch scope"
                  data-testid={`add-project-entry-registered-${entry.name}`}
                >
                  ✓ Registered
                </span>
              )}
            </button>
          );
        })}
        {truncated && (
          <div
            className="px-3 py-2 text-center text-[11px] text-zinc-500 dark:text-zinc-400"
            data-testid="add-project-truncated"
          >
            Showing first 500 entries — refine via the breadcrumb.
          </div>
        )}
      </div>
    </div>
  );
}

function TypePane({
  inputRef,
  value,
  onChange,
  disabled,
  onSubmit,
}: {
  inputRef: React.RefObject<HTMLInputElement | null>;
  value: string;
  onChange: (v: string) => void;
  disabled: boolean;
  onSubmit: (e: React.FormEvent) => void;
}) {
  return (
    <form
      id="add-project-type-form"
      onSubmit={onSubmit}
      className="space-y-3 px-4 py-3"
    >
      <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300">
        Absolute path to the project root
        <input
          ref={inputRef}
          type="text"
          value={value}
          onChange={(e) => onChange(e.target.value)}
          placeholder="/Users/you/Repo/your-project"
          data-testid="add-project-path-input"
          spellCheck={false}
          autoCapitalize="off"
          autoCorrect="off"
          disabled={disabled}
          className={cn(
            "mt-1 h-9 w-full rounded-md border px-2 font-mono text-sm",
            "border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900",
            "text-zinc-900 dark:text-zinc-100 focus:outline-2 focus:outline-zinc-900",
            "disabled:opacity-60",
          )}
        />
      </label>
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        PackGuard scopes scans, policies, and actions to a project — typically
        a directory containing a <span className="font-mono">.git/</span>{" "}
        root. Submit the absolute path; PackGuard walks up to find the git
        root, registers it, and recursively scans every workspace inside.
      </p>
    </form>
  );
}
