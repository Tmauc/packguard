import { ShieldCheckIcon } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * Full-screen empty state shown when `/api/projects` returns an empty
 * list — that is, the user has booted `packguard ui` without ever
 * running a scan. Replaces the sidebar nav + header so dashboard
 * pages don't render in a degenerate "no project" state where every
 * query 404s or returns nothing.
 *
 * 14.3b: the "Add your first project" button is a disabled placeholder
 * for the AddProjectModal landing in 14.3c. Until then the user has
 * to fall back to the CLI (`packguard scan <path>`), which we surface
 * as a hint below the button.
 */
export function EmptyProjectGate() {
  return (
    <div
      data-testid="empty-project-gate"
      className="grid h-full place-items-center bg-zinc-50 dark:bg-zinc-950 p-12"
    >
      <div className="max-w-md text-center">
        <ShieldCheckIcon className="mx-auto h-12 w-12 text-zinc-400 dark:text-zinc-500" />
        <h1 className="mt-4 text-xl font-semibold text-zinc-900 dark:text-zinc-100">
          Welcome to PackGuard
        </h1>
        <p className="mt-2 text-sm text-zinc-600 dark:text-zinc-400">
          You haven{"’"}t registered any projects yet. PackGuard scopes
          scans, policies, and actions to a project — a directory containing a{" "}
          <code className="rounded bg-zinc-100 px-1 py-0.5 text-xs dark:bg-zinc-800">
            .git/
          </code>{" "}
          root.
        </p>
        <Button
          className="mt-6"
          disabled
          data-testid="empty-project-add-cta"
          title="Available in v0.6.0 — Phase 14.3c (AddProjectModal)"
        >
          + Add your first project
        </Button>
        <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400">
          Or run{" "}
          <code className="rounded bg-zinc-100 px-1 py-0.5 text-xs dark:bg-zinc-800">
            packguard scan &lt;path&gt;
          </code>{" "}
          from a terminal.
        </p>
      </div>
    </div>
  );
}
