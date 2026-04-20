/// Single typed `fetch` shim that every page uses. Keeps the URL prefix,
/// JSON parsing, and the error envelope decoded in one place.

import type { Overview } from "@/api/types/Overview";
import type { PackagesPage } from "@/api/types/PackagesPage";
import type { PackagesQuery } from "@/api/types/PackagesQuery";
import type { PackageDetail } from "@/api/types/PackageDetail";
import type { PolicyDocument } from "@/api/types/PolicyDocument";
import type { JobAccepted } from "@/api/types/JobAccepted";
import type { JobView } from "@/api/types/JobView";

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

  startScan: () =>
    fetch("/api/scan", { method: "POST" }).then(handle<JobAccepted>),

  startSync: () =>
    fetch("/api/sync", { method: "POST" }).then(handle<JobAccepted>),

  job: (id: string) => fetch(`/api/jobs/${encodeURIComponent(id)}`).then(handle<JobView>),
};
