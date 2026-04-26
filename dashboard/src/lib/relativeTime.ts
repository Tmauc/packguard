/**
 * Compact relative-time formatter for the ProjectSelector dropdown
 * (and any other surface that wants "2h ago" / "3d ago" / "never
 * scanned" without pulling in date-fns).
 *
 * Why a hand-rolled helper: PackGuard's house rule is zero new deps in
 * the dashboard — the ~30 LoC of buckets here is cheaper than the
 * 70KB date-fns brings to the bundle.
 *
 * Buckets, in order:
 *  - `null` / undefined → `"never scanned"`
 *  - 0 ≤ Δ < 60s        → `"<1m ago"`
 *  - 1m ≤ Δ < 60m       → `"Nm ago"`
 *  - 1h ≤ Δ < 24h       → `"Nh ago"`
 *  - 1d ≤ Δ < 30d       → `"Nd ago"`
 *  - older              → ISO date short (YYYY-MM-DD)
 *  - future timestamps  → `"just now"` (clock skew tolerance — server
 *    last_scan can land a couple of seconds ahead of the browser).
 */
export function formatRelativeTime(
  iso: string | null | undefined,
  now: Date = new Date(),
): string {
  if (iso === null || iso === undefined || iso === "") return "never scanned";
  const ts = Date.parse(iso);
  if (Number.isNaN(ts)) return "never scanned";
  const deltaMs = now.getTime() - ts;
  if (deltaMs < 0) return "just now";
  const seconds = Math.floor(deltaMs / 1000);
  if (seconds < 60) return "<1m ago";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  // Older than a month — drop to a stable absolute date so the user
  // doesn't have to do mental math on "127d ago".
  return new Date(ts).toISOString().slice(0, 10);
}
