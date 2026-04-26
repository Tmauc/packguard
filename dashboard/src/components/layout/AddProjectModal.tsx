import { useEffect, useRef, useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FolderGitIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";
import { useJobStatus } from "@/lib/useJobStatus";
import { useSetProjectScope } from "@/components/layout/workspace-scope";
import type { ProjectDto } from "@/api/types/ProjectDto";

/// Phase 14.3c — modal for registering a new project from the UI.
///
/// Lifecycle (mirrors AddWorkspaceModal but with one extra step: we
/// wait for the `add_project` job to complete before closing, because
/// we need the new slug from `outcome.project.slug` to switch scope):
///   1. Client-side check rejects empty / non-absolute input.
///   2. POST /api/projects → 202 + JobAccepted{id}. Inline-surface
///      a 400 (path doesn't exist / not a git repo / relative). Stash
///      the job id; the modal stays open with a "Registering…" footer.
///   3. The shared useJobStatus tracker polls the job. We watch the
///      jobs[] array for our id:
///        - succeeded → decode `result.project.slug`, invalidate
///          ["projects"] + ["workspaces"], set the project scope to
///          the new slug, toast, close.
///        - failed → surface job.error inline (typically a UNIQUE
///          violation when the path is already registered) and
///          reset the pending job so the user can edit + retry.
export function AddProjectModal({
  open,
  onClose,
  onStarted,
}: {
  open: boolean;
  onClose: () => void;
  onStarted?: (jobId: string, path: string) => void;
}) {
  const [path, setPath] = useState("");
  const [error, setError] = useState<string | null>(null);
  // Once the user submits successfully, we hold the job id here and
  // delegate completion handling to the effect below. `path` is
  // retained as a tooltip for the toast.
  const [pendingJob, setPendingJob] = useState<
    { id: string; path: string } | null
  >(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const setProjectScope = useSetProjectScope();
  const qc = useQueryClient();
  const { trackJob, jobs } = useJobStatus();

  // Reset on every open so a previous submission doesn't linger.
  useEffect(() => {
    if (open) {
      setPath("");
      setError(null);
      setPendingJob(null);
      requestAnimationFrame(() => inputRef.current?.focus());
    }
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
      // Don't close yet — wait for the job to reach `succeeded` so
      // we can read the slug from the outcome.
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError && err.status === 400) {
        // 400 means the synchronous validation in projects_create
        // rejected the path (relative, not a directory, no .git/).
        // Inline so the user can edit + retry.
        setError(err.message);
        return;
      }
      const msg = err instanceof Error ? err.message : String(err);
      toast.error("Couldn't register project", { description: msg });
      setError(msg);
    },
  });

  // Watch the job we just queued. The shared tracker handles the
  // generic "${kind} ${status}" toast; we add the project-specific
  // scope-switch + close on top of it.
  useEffect(() => {
    if (!pendingJob) return;
    const job = jobs.find((j) => j.id === pendingJob.id);
    if (!job) return;
    if (job.status === "succeeded") {
      // Outcome shape from run_add_project_job: { project, scan }.
      // The cast keeps the modal hermetic — JsonValue is `unknown` at
      // the type level, but the backend contract is documented in
      // crates/packguard-server/src/jobs.rs:139-142.
      const outcome = job.result as
        | { project?: ProjectDto; scan?: unknown }
        | null;
      const newSlug = outcome?.project?.slug;
      const displayName =
        outcome?.project?.name ?? pendingJob.path.split("/").pop() ?? "Project";
      // Invalidate before scope-switch so the new project surfaces in
      // the next render's projects list.
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
      // Most common failure: SQLite UNIQUE constraint when the user
      // re-submits an already-registered path. Surface the message
      // verbatim so the cause is visible without devtools.
      const msg =
        job.error ?? "Project registration failed. Check the server logs.";
      setError(msg);
      setPendingJob(null);
    }
  }, [jobs, pendingJob, setProjectScope, qc, onClose]);

  if (!open) return null;

  const trimmed = path.trim();
  const busy = register.isPending || pendingJob !== null;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
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
          "mt-24 w-full max-w-lg overflow-hidden rounded-lg border shadow-xl",
          "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900",
        )}
      >
        <form onSubmit={handleSubmit}>
          <header className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 px-4 py-3">
            <FolderGitIcon className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            <h2 className="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
              Register a new project
            </h2>
          </header>
          <div className="space-y-3 px-4 py-4">
            <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300">
              Absolute path to the project root
              <input
                ref={inputRef}
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/Users/you/Repo/your-project"
                data-testid="add-project-path-input"
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                disabled={busy}
                className={cn(
                  "mt-1 h-9 w-full rounded-md border px-2 font-mono text-sm",
                  "border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900",
                  "text-zinc-900 dark:text-zinc-100 focus:outline-2 focus:outline-zinc-900",
                  "disabled:opacity-60",
                )}
              />
            </label>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              PackGuard scopes scans, policies, and actions to a project —
              typically a directory containing a{" "}
              <span className="font-mono">.git/</span> root. Submit the
              absolute path; PackGuard walks up to the git root, registers
              it, and recursively scans every workspace inside.
            </p>
            {error && (
              <div
                role="alert"
                data-testid="add-project-error"
                className="rounded-md border border-red-200 dark:border-red-900 bg-red-50 dark:bg-red-950/40 px-3 py-2 text-xs text-red-700 dark:text-red-300"
              >
                {error}
              </div>
            )}
          </div>
          <footer className="flex items-center justify-end gap-2 border-t border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-4 py-3">
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
            <Button
              type="submit"
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
          </footer>
        </form>
      </div>
    </div>
  );
}
