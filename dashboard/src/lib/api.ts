/// Single typed `fetch` shim that every page uses. Keeps the URL prefix,
/// JSON parsing, and the error envelope decoded in one place.

import type { Overview } from "@/api/types/Overview";
import type { PackagesPage } from "@/api/types/PackagesPage";
import type { PackagesQuery } from "@/api/types/PackagesQuery";
import type { PackageDetail } from "@/api/types/PackageDetail";
import type { PolicyDocument } from "@/api/types/PolicyDocument";
import type { PolicyDryRunResult } from "@/api/types/PolicyDryRunResult";
import type { JobAccepted } from "@/api/types/JobAccepted";
import type { JobView } from "@/api/types/JobView";
import type { GraphResponse } from "@/api/types/GraphResponse";
import type { ContaminationResult } from "@/api/types/ContaminationResult";
import type { GraphVulnerabilityList } from "@/api/types/GraphVulnerabilityList";
import type { CompatResponse } from "@/api/types/CompatResponse";
import type { WorkspacesResponse } from "@/api/types/WorkspacesResponse";
import type { ActionsResponse } from "@/api/types/ActionsResponse";
import type { ActionDismissResponse } from "@/api/types/ActionDismissResponse";
import type { ActionDeferResponse } from "@/api/types/ActionDeferResponse";

/**
 * Phase 7b scope hint. `undefined` (or empty) = aggregate view across
 * every scanned repo. Any non-empty string is forwarded as-is to the
 * backend's `?project=<path>` filter, which canonicalizes + validates
 * it (404 with the known-workspace list on a miss).
 */
export type ProjectScope = string | undefined;

function withProject(
  params: URLSearchParams,
  project: ProjectScope,
): URLSearchParams {
  if (project && project.length > 0) {
    params.set("project", project);
  }
  return params;
}

export class ApiError extends Error {
  constructor(
    public code: string,
    message: string,
    public status: number,
    public detail?: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function handle<T>(res: Response): Promise<T> {
  if (res.ok) {
    return (await res.json()) as T;
  }
  let payload: { error?: { code?: string; message?: string; detail?: string } } = {};
  try {
    payload = await res.json();
  } catch {
    // server returned a non-JSON error body — fall through to generic
  }
  const code = payload.error?.code ?? "http_error";
  const message = payload.error?.message ?? `HTTP ${res.status}`;
  throw new ApiError(code, message, res.status, payload.error?.detail);
}

export const api = {
  overview: (project?: ProjectScope) => {
    const qs = withProject(new URLSearchParams(), project).toString();
    return fetch(`/api/overview${qs ? `?${qs}` : ""}`).then(handle<Overview>);
  },

  packages: (q: Partial<PackagesQuery> = {}, project?: ProjectScope) => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) {
      if (k === "project") continue;
      if (v !== undefined && v !== null && v !== "") {
        params.set(k, String(v));
      }
    }
    withProject(params, project);
    const qs = params.toString();
    return fetch(`/api/packages${qs ? `?${qs}` : ""}`).then(handle<PackagesPage>);
  },

  packageDetail: (eco: string, name: string, project?: ProjectScope) => {
    const qs = withProject(new URLSearchParams(), project).toString();
    return fetch(
      `/api/packages/${encodeURIComponent(eco)}/${encodeURIComponent(name)}${qs ? `?${qs}` : ""}`,
    ).then(handle<PackageDetail>);
  },

  policies: (project?: ProjectScope) => {
    const qs = withProject(new URLSearchParams(), project).toString();
    return fetch(`/api/policies${qs ? `?${qs}` : ""}`).then(handle<PolicyDocument>);
  },

  savePolicy: (yaml: string, project?: ProjectScope) => {
    const qs = withProject(new URLSearchParams(), project).toString();
    return fetch(`/api/policies${qs ? `?${qs}` : ""}`, {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ yaml }),
    }).then(handle<PolicyDocument>);
  },

  dryRunPolicy: (yaml: string, project?: ProjectScope) => {
    const qs = withProject(new URLSearchParams(), project).toString();
    return fetch(`/api/policies/dry-run${qs ? `?${qs}` : ""}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ yaml }),
    }).then(handle<PolicyDryRunResult>);
  },

  startScan: () =>
    fetch("/api/scan", { method: "POST" }).then(handle<JobAccepted>),

  startSync: () =>
    fetch("/api/sync", { method: "POST" }).then(handle<JobAccepted>),

  job: (id: string) => fetch(`/api/jobs/${encodeURIComponent(id)}`).then(handle<JobView>),

  graph: (
    q: {
      workspace?: string;
      max_depth?: number;
      kind?: string;
    } = {},
    project?: ProjectScope,
  ) => {
    const params = new URLSearchParams();
    if (q.workspace) params.set("workspace", q.workspace);
    if (q.max_depth !== undefined) params.set("max_depth", String(q.max_depth));
    if (q.kind) params.set("kind", q.kind);
    withProject(params, project);
    const qs = params.toString();
    return fetch(`/api/graph${qs ? `?${qs}` : ""}`).then(handle<GraphResponse>);
  },

  contaminated: (vuln_id: string, project?: ProjectScope) => {
    const params = new URLSearchParams();
    params.set("vuln_id", vuln_id);
    withProject(params, project);
    return fetch(`/api/graph/contaminated?${params.toString()}`).then(
      handle<ContaminationResult>,
    );
  },

  graphVulnerabilities: (project?: ProjectScope) => {
    const qs = withProject(new URLSearchParams(), project).toString();
    return fetch(`/api/graph/vulnerabilities${qs ? `?${qs}` : ""}`).then(
      handle<GraphVulnerabilityList>,
    );
  },

  packageCompat: (eco: string, name: string, project?: ProjectScope) => {
    const qs = withProject(new URLSearchParams(), project).toString();
    return fetch(
      `/api/packages/${encodeURIComponent(eco)}/${encodeURIComponent(name)}/compat${qs ? `?${qs}` : ""}`,
    ).then(handle<CompatResponse>);
  },

  workspaces: () => fetch("/api/workspaces").then(handle<WorkspacesResponse>),

  actions: (
    q: { min_severity?: string } = {},
    project?: ProjectScope,
  ) => {
    const params = new URLSearchParams();
    if (q.min_severity) params.set("min_severity", q.min_severity);
    withProject(params, project);
    const qs = params.toString();
    return fetch(`/api/actions${qs ? `?${qs}` : ""}`).then(
      handle<ActionsResponse>,
    );
  },

  dismissAction: (id: string, reason?: string) =>
    fetch(`/api/actions/${encodeURIComponent(id)}/dismiss`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ reason: reason ?? null }),
    }).then(handle<ActionDismissResponse>),

  deferAction: (id: string, days: number, reason?: string) =>
    fetch(`/api/actions/${encodeURIComponent(id)}/defer`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ days, reason: reason ?? null }),
    }).then(handle<ActionDeferResponse>),

  restoreAction: (id: string) =>
    fetch(`/api/actions/${encodeURIComponent(id)}`, {
      method: "DELETE",
    }).then(async (res) => {
      if (!res.ok && res.status !== 204) {
        // Reuse the generic JSON error path so the caller surfaces the
        // same error envelope as every other mutation.
        await handle<unknown>(res);
      }
    }),
};
