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
import type { CompatResponse } from "@/api/types/CompatResponse";

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
  overview: () => fetch("/api/overview").then(handle<Overview>),

  packages: (q: Partial<PackagesQuery> = {}) => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(q)) {
      if (v !== undefined && v !== null && v !== "") {
        params.set(k, String(v));
      }
    }
    const qs = params.toString();
    return fetch(`/api/packages${qs ? `?${qs}` : ""}`).then(handle<PackagesPage>);
  },

  packageDetail: (eco: string, name: string) =>
    fetch(`/api/packages/${encodeURIComponent(eco)}/${encodeURIComponent(name)}`).then(
      handle<PackageDetail>,
    ),

  policies: () => fetch("/api/policies").then(handle<PolicyDocument>),

  savePolicy: (yaml: string) =>
    fetch("/api/policies", {
      method: "PUT",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ yaml }),
    }).then(handle<PolicyDocument>),

  dryRunPolicy: (yaml: string) =>
    fetch("/api/policies/dry-run", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ yaml }),
    }).then(handle<PolicyDryRunResult>),

  startScan: () =>
    fetch("/api/scan", { method: "POST" }).then(handle<JobAccepted>),

  startSync: () =>
    fetch("/api/sync", { method: "POST" }).then(handle<JobAccepted>),

  job: (id: string) => fetch(`/api/jobs/${encodeURIComponent(id)}`).then(handle<JobView>),

  graph: (q: {
    workspace?: string;
    max_depth?: number;
    kind?: string;
  } = {}) => {
    const params = new URLSearchParams();
    if (q.workspace) params.set("workspace", q.workspace);
    if (q.max_depth !== undefined) params.set("max_depth", String(q.max_depth));
    if (q.kind) params.set("kind", q.kind);
    const qs = params.toString();
    return fetch(`/api/graph${qs ? `?${qs}` : ""}`).then(handle<GraphResponse>);
  },

  contaminated: (vuln_id: string) =>
    fetch(`/api/graph/contaminated?vuln_id=${encodeURIComponent(vuln_id)}`).then(
      handle<ContaminationResult>,
    ),

  packageCompat: (eco: string, name: string) =>
    fetch(
      `/api/packages/${encodeURIComponent(eco)}/${encodeURIComponent(name)}/compat`,
    ).then(handle<CompatResponse>),
};
