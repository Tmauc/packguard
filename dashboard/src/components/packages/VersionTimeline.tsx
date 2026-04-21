import type { VersionRow } from "@/api/types/VersionRow";

/// Minimal placeholder — 4.6 swaps this for the visx-based timeline with
/// virtualization, density clusters, and hover-zoom. The shape of the props
/// stays stable so the detail page doesn't change when we upgrade.
export function VersionTimeline({
  versions,
}: {
  versions: VersionRow[];
  installed?: string;
  recommended?: string;
}) {
  return (
    <div className="rounded-md border border-dashed border-zinc-300 bg-zinc-50 p-3 text-xs text-zinc-500">
      Timeline placeholder — visualisation arrives with the visx upgrade in
      Phase 4.6. {versions.length} version{versions.length === 1 ? "" : "s"} on
      record.
    </div>
  );
}
