import { useEffect, useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { FolderPlusIcon } from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/cn";

/// Absolute-path-only modal for scanning a new workspace from the UI.
///
/// Flow:
///  1. Client-side check rejects empty / non-absolute input before the
///     round-trip (cheap guard, but the server double-checks anyway).
///  2. POST /api/scan?path=<abs>. The server canonicalises + asserts
///     directory existence; a 400 arrives with a human-readable message
///     that we surface inline without closing the modal.
///  3. On 202 we fire a Sonner toast, hand the job id back to the
///     caller (which wires it into useJobStatus + invalidates the
///     workspaces query), and close.
export function AddWorkspaceModal({
  open,
  onClose,
  onStarted,
}: {
  open: boolean;
  onClose: () => void;
  onStarted: (jobId: string, path: string) => void;
}) {
  const [path, setPath] = useState("");
  const [error, setError] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Reset on every open so a previous typo doesn't linger in the input
  // next time the user fires it up.
  useEffect(() => {
    if (open) {
      setPath("");
      setError(null);
      // Focus after a microtask so the layout settles before we grab
      // the caret (happy-dom ignores layout but browsers care).
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

  const scan = useMutation({
    mutationFn: (abs: string) => api.startScan(abs),
    onSuccess: ({ id }, abs) => {
      toast.message("Scan started", {
        description: `${abs} — job ${id.slice(0, 8)}…`,
      });
      onStarted(id, abs);
      onClose();
    },
    onError: (err: unknown) => {
      if (err instanceof ApiError) {
        // 400 → inline validation feedback; anything else falls through
        // as a toast since the modal can't usefully retry it (e.g. 500).
        if (err.status === 400) {
          setError(err.message);
          return;
        }
      }
      const msg = err instanceof Error ? err.message : String(err);
      toast.error("Couldn't start scan", { description: msg });
      setError(msg);
    },
  });

  if (!open) return null;

  const trimmed = path.trim();

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (trimmed.length === 0) {
      setError("Path is required.");
      return;
    }
    // Windows paths (C:\…) are accepted by the regex below but the Rust
    // server canonicalize() will reject them on non-Windows runs — the
    // 400 from the server then surfaces here just like any other.
    if (!/^(\/|[A-Za-z]:[/\\])/.test(trimmed)) {
      setError("Path must be absolute (start with / or a drive letter).");
      return;
    }
    scan.mutate(trimmed);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center bg-zinc-950/40 p-8 backdrop-blur-sm"
      data-testid="add-workspace-modal-backdrop"
      onClick={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Add workspace"
        data-testid="add-workspace-modal"
        className={cn(
          "mt-24 w-full max-w-lg overflow-hidden rounded-lg border shadow-xl",
          "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900",
        )}
      >
        <form onSubmit={handleSubmit}>
          <header className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 px-4 py-3">
            <FolderPlusIcon className="h-4 w-4 text-zinc-500 dark:text-zinc-400" />
            <h2 className="text-sm font-semibold tracking-tight text-zinc-900 dark:text-zinc-100">
              Scan a new workspace
            </h2>
          </header>
          <div className="space-y-3 px-4 py-4">
            <label className="block text-xs font-medium text-zinc-700 dark:text-zinc-300">
              Absolute path to scan
              <input
                ref={inputRef}
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="/Users/you/repo/project"
                data-testid="add-workspace-path-input"
                spellCheck={false}
                autoCapitalize="off"
                autoCorrect="off"
                className={cn(
                  "mt-1 h-9 w-full rounded-md border px-2 font-mono text-sm",
                  "border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900",
                  "text-zinc-900 dark:text-zinc-100 focus:outline-2 focus:outline-zinc-900",
                )}
              />
            </label>
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              PackGuard walks the path for supported manifests
              (package.json, pyproject.toml, requirements.txt, …) and
              records every workspace it finds. The scan runs server-
              side — same code path as{" "}
              <span className="font-mono">packguard scan &lt;path&gt;</span>.
            </p>
            {error && (
              <div
                role="alert"
                data-testid="add-workspace-error"
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
              disabled={scan.isPending}
              data-testid="add-workspace-cancel"
            >
              Cancel
            </Button>
            <Button
              type="submit"
              size="sm"
              disabled={scan.isPending}
              data-testid="add-workspace-submit"
            >
              {scan.isPending ? "Starting…" : "Start scan"}
            </Button>
          </footer>
        </form>
      </div>
    </div>
  );
}
