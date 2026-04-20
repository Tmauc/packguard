/// In-memory job tracker. Polls /api/jobs/:id every second until the job
/// reaches a terminal state, then surfaces a toast and invalidates the
/// queries that depend on the underlying data.
///
/// Lives in a module-scoped cache (not a global store) so any component
/// can subscribe via the hook without prop drilling. Phase 4b will likely
/// replace this with SSE if the polling cost ever shows up.

import { useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";
import { api } from "@/lib/api";
import type { JobView } from "@/api/types/JobView";

type Tracker = {
  jobs: Map<string, JobView>;
  listeners: Set<() => void>;
};

const tracker: Tracker = { jobs: new Map(), listeners: new Set() };

function notify() {
  for (const fn of tracker.listeners) fn();
}

async function poll(id: string, queryClient: ReturnType<typeof useQueryClient>) {
  while (true) {
    let view: JobView;
    try {
      view = await api.job(id);
    } catch (err) {
      tracker.jobs.delete(id);
      notify();
      toast.error("Job lookup failed", { description: String(err) });
      return;
    }
    tracker.jobs.set(id, view);
    notify();
    if (view.status === "succeeded") {
      toast.success(`${view.kind} succeeded`, {
        description: `${view.id.slice(0, 8)}…`,
      });
      queryClient.invalidateQueries();
      return;
    }
    if (view.status === "failed") {
      toast.error(`${view.kind} failed`, { description: view.error ?? undefined });
      queryClient.invalidateQueries();
      return;
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
}

export function useJobStatus() {
  const queryClient = useQueryClient();
  const [, force] = useState(0);

  useEffect(() => {
    const fn = () => force((n) => n + 1);
    tracker.listeners.add(fn);
    return () => {
      tracker.listeners.delete(fn);
    };
  }, []);

  const trackJob = useCallback(
    (id: string) => {
      if (tracker.jobs.has(id)) return;
      tracker.jobs.set(id, {
        id,
        kind: "scan",
        status: "pending",
        started_at: new Date().toISOString(),
        finished_at: null,
        result: null,
        error: null,
      });
      notify();
      void poll(id, queryClient);
    },
    [queryClient],
  );

  return {
    trackJob,
    jobs: Array.from(tracker.jobs.values()),
  };
}
