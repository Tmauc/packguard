import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  ChevronDownIcon,
  FolderGitIcon,
  FolderPlusIcon,
  SearchIcon,
} from "lucide-react";
import { api } from "@/lib/api";
import { cn } from "@/lib/cn";
import { formatRelativeTime } from "@/lib/relativeTime";
import { Button } from "@/components/ui/button";
import {
  useProjectScope,
  useSetProjectScope,
} from "./workspace-scope";
import type { ProjectDto } from "@/api/types/ProjectDto";

/**
 * Header dropdown that picks the active project (the slug that scopes
 * every read endpoint via `?project=<slug>`).
 *
 * Unlike the WorkspaceSelector, the projects list is naturally flat:
 * each row is a git repo root, identified by its slug. So the
 * dropdown is a vertical list, not a tree.
 *
 * Layout decisions:
 *  - Trigger surfaces the active project's `name` (truncated to 28ch)
 *    with the full path as `title=`.
 *  - Each row shows `name` + monospaced path tail + the relative
 *    "last_scan" formatted by `formatRelativeTime`. The active row
 *    gets the same `bg-zinc-100 / dark:bg-zinc-800` highlight
 *    WorkspaceSelector uses for its active leaf.
 *  - Footer slot: an "Add new project" button, currently disabled —
 *    the AddProjectModal arrives in 14.3c and will own this slot.
 *  - Switching project scope does NOT also clear the workspace scope:
 *    if the new project owns the current workspace path, the backend
 *    keeps it; if not, the next workspace fetch + a 404 will surface
 *    the mismatch and the user clears via the WorkspaceSelector.
 */
export function ProjectSelector({
  onAddProject,
}: {
  /// Phase 14.3c — invoked when the user clicks the footer
  /// "+ Add new project" button. The modal lives in Layout (so the
  /// EmptyProjectGate can share it), so the selector only needs to
  /// signal the open intent.
  onAddProject?: () => void;
} = {}) {
  const projectScope = useProjectScope();
  const setProjectScope = useSetProjectScope();
  const query = useQuery({
    queryKey: ["projects"],
    queryFn: api.projects,
    refetchInterval: 30_000,
  });

  const projects = useMemo(() => query.data ?? [], [query.data]);
  const active = useMemo(
    () => projects.find((p) => p.slug === projectScope),
    [projects, projectScope],
  );

  const [open, setOpen] = useState(false);
  const [search, setSearch] = useState("");
  const popoverRef = useRef<HTMLDivElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  // Click-outside + Escape close the popover. Same wiring as
  // WorkspaceSelector — only attached while open so we don't pay the
  // listener cost for an idle picker.
  useEffect(() => {
    if (!open) return;
    function onDown(e: MouseEvent) {
      if (popoverRef.current && !popoverRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  // Autofocus the search box on open so the user can just start typing.
  useEffect(() => {
    if (open) {
      searchRef.current?.focus();
      setSearch("");
    }
  }, [open]);

  const lowered = search.trim().toLowerCase();
  const filtered = useMemo(() => {
    if (lowered === "") return projects;
    return projects.filter(
      (p) =>
        p.name.toLowerCase().includes(lowered) ||
        p.slug.toLowerCase().includes(lowered) ||
        p.path.toLowerCase().includes(lowered),
    );
  }, [projects, lowered]);

  const triggerLabel = active
    ? active.name
    : projects.length === 0
      ? "No project"
      : "Select project";

  const pick = (slug: string) => {
    setProjectScope(slug);
    setOpen(false);
  };

  return (
    <div className="relative" ref={popoverRef}>
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        data-testid="project-selector"
        aria-haspopup="dialog"
        aria-expanded={open}
        title={active?.path ?? "No project selected"}
        className={cn(
          "inline-flex h-8 max-w-72 items-center gap-2 rounded-md border px-2 text-sm",
          "border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900",
          "text-zinc-900 dark:text-zinc-100",
          "hover:bg-zinc-50 dark:hover:bg-zinc-800 focus:outline-2 focus:outline-zinc-900",
        )}
      >
        <FolderGitIcon className="h-4 w-4 text-zinc-400 dark:text-zinc-500" />
        <span className="font-medium text-zinc-700 dark:text-zinc-300">Project</span>
        <span className="truncate text-zinc-500 dark:text-zinc-400">
          {triggerLabel}
        </span>
        <ChevronDownIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
      </button>

      {open && (
        <div
          role="dialog"
          aria-label="Project picker"
          data-testid="project-picker"
          className={cn(
            "absolute left-0 top-10 z-50 w-96 overflow-hidden rounded-md border shadow-lg",
            "border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900",
          )}
        >
          <div className="flex items-center gap-2 border-b border-zinc-200 dark:border-zinc-800 px-2 py-1.5">
            <SearchIcon className="h-3.5 w-3.5 text-zinc-400 dark:text-zinc-500" />
            <input
              ref={searchRef}
              type="search"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter projects…"
              data-testid="project-search"
              className={cn(
                "h-7 w-full bg-transparent text-sm outline-none",
                "text-zinc-900 dark:text-zinc-100 placeholder:text-zinc-400 dark:placeholder:text-zinc-600",
              )}
            />
          </div>
          <div className="max-h-96 overflow-y-auto p-1">
            {projects.length === 0 ? (
              <div
                data-testid="project-empty"
                className="px-3 py-6 text-center text-xs text-zinc-500 dark:text-zinc-400"
              >
                No projects registered yet.
              </div>
            ) : filtered.length === 0 ? (
              <div
                data-testid="project-no-match"
                className="px-3 py-4 text-center text-xs text-zinc-500 dark:text-zinc-400"
              >
                No projects match {JSON.stringify(search)}.
              </div>
            ) : (
              filtered.map((project) => (
                <ProjectRow
                  key={project.slug}
                  project={project}
                  active={project.slug === projectScope}
                  onPick={() => pick(project.slug)}
                />
              ))
            )}
          </div>
          <div className="flex items-center justify-end border-t border-zinc-200 dark:border-zinc-800 bg-zinc-50 dark:bg-zinc-950 px-2 py-1.5">
            <Button
              type="button"
              variant="ghost"
              size="sm"
              data-testid="project-add-cta"
              disabled={!onAddProject}
              onClick={() => {
                if (!onAddProject) return;
                // Close popover before opening the modal so the two
                // overlays don't stack — both eat outside-click events
                // and the picker would visually leak under the modal
                // backdrop.
                setOpen(false);
                onAddProject();
              }}
            >
              <FolderPlusIcon className="h-3.5 w-3.5" />
              Add new project
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

function ProjectRow({
  project,
  active,
  onPick,
}: {
  project: ProjectDto;
  active: boolean;
  onPick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onPick}
      data-testid={`project-row-${project.slug}`}
      data-active={active}
      title={project.path}
      className={cn(
        "flex w-full flex-col items-start gap-0.5 rounded px-2 py-1.5 text-left text-sm",
        active
          ? "bg-zinc-100 dark:bg-zinc-800 text-zinc-900 dark:text-zinc-100"
          : "text-zinc-700 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800",
      )}
    >
      <div className="flex w-full items-center gap-2">
        <FolderGitIcon
          className={cn(
            "h-3.5 w-3.5",
            active ? "text-zinc-700 dark:text-zinc-300" : "text-zinc-400 dark:text-zinc-500",
          )}
        />
        <span className="flex-1 truncate font-medium">{project.name}</span>
        <span className="shrink-0 text-[10px] text-zinc-500 dark:text-zinc-400">
          {formatRelativeTime(project.last_scan)}
        </span>
      </div>
      <span className="ml-5 truncate font-mono text-[11px] text-zinc-500 dark:text-zinc-400">
        {project.path}
      </span>
    </button>
  );
}
