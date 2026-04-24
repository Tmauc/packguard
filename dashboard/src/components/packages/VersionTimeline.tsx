import { useMemo, useRef, useState } from "react";
import { AxisBottom } from "@visx/axis";
import { Group } from "@visx/group";
import { scaleTime } from "@visx/scale";
import { localPoint } from "@visx/event";
import { useTooltip, TooltipWithBounds, defaultStyles } from "@visx/tooltip";
import { useTheme } from "@/components/theme/useTheme";
import type { MalwareEntry } from "@/api/types/MalwareEntry";
import type { VersionRow } from "@/api/types/VersionRow";

/// Virtualization threshold. Above this count we switch to density clusters —
/// the user's briefing pins this at 200 (CONTEXT.md §14.8 suggested 500, but
/// 200 is what keeps individual markers legibly non-overlapping at typical
/// dashboard widths).
const CLUSTER_THRESHOLD = 200;
/// Number of time-buckets when clustering is active. Tuned so dense
/// npm packages (sentry-sdk ~329 versions, pillow ~108) still read cleanly.
const CLUSTER_BUCKETS = 60;

const HEIGHT = 140;
const AXIS_HEIGHT = 28;
const MARGIN = { top: 16, right: 16, bottom: AXIS_HEIGHT, left: 16 };
const MARKER_RADIUS = 4;

type Kind = "normal" | "critical" | "high" | "medium" | "yanked" | "malware";

type Marker = {
  version: string;
  time: number;
  kind: Kind;
  published_at: string | null;
};

type Cluster = {
  /// Center of the bucket's time range — where we anchor the density marker.
  time: number;
  /// Range start / end so clicking zooms exactly to this window.
  range: [number, number];
  markers: Marker[];
  /// Worst kind across the bucket — drives the colour.
  kind: Kind;
};

const COLORS: Record<Kind, string> = {
  normal: "#d4d4d8", // zinc-300
  medium: "#facc15", // yellow-400
  high: "#f97316", // orange-500
  critical: "#dc2626", // red-600
  yanked: "#e879f9", // fuchsia-400
  malware: "#a855f7", // purple-500
};

const KIND_RANK: Record<Kind, number> = {
  normal: 0,
  medium: 1,
  high: 2,
  critical: 3,
  yanked: 4,
  malware: 5,
};

function worstKind(markers: Marker[]): Kind {
  let worst: Kind = "normal";
  for (const m of markers) {
    if (KIND_RANK[m.kind] > KIND_RANK[worst]) worst = m.kind;
  }
  return worst;
}

function classifyVersion(v: VersionRow, malwareVersions: Set<string>): Kind {
  if (malwareVersions.has(v.version)) return "malware";
  if (v.yanked) return "yanked";
  if (v.severity === "critical") return "critical";
  if (v.severity === "high") return "high";
  if (v.severity === "medium") return "medium";
  return "normal";
}

/// Parse an ISO timestamp, returning `null` if it's missing or malformed.
/// We drop versions without a published_at from the timeline (they still
/// show up in the table) rather than collapsing them all onto the epoch.
function parseTime(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isNaN(t) ? null : t;
}

type TooltipPayload = {
  title: string;
  lines: string[];
  kind: Kind;
};

export function VersionTimeline({
  versions,
  malware = [],
  installed,
  recommended,
}: {
  versions: VersionRow[];
  malware?: MalwareEntry[];
  installed?: string;
  recommended?: string;
}) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);
  const [focus, setFocus] = useState<[number, number] | null>(null);
  const { resolved } = useTheme();
  const isDark = resolved === "dark";
  // Axis / baseline palette. Light uses zinc-200/500; dark drops the
  // baseline two shades and pushes tick labels one shade lighter so
  // they stay legible on the zinc-900 panel backdrop.
  const baselineStroke = isDark ? "#3f3f46" : "#e4e4e7"; // zinc-700 / zinc-200
  const axisTickStroke = baselineStroke;
  const axisLabelFill = isDark ? "#a1a1aa" : "#71717a"; // zinc-400 / zinc-500
  const installedStroke = isDark ? "#fafafa" : "#18181b"; // zinc-50 / zinc-900
  const markerRing = isDark ? "#18181b" : "#ffffff"; // zinc-900 / white

  // ResizeObserver keeps the SVG in sync with the container width. Happy-dom
  // lacks it; we guard so tests don't explode.
  useResizeObserver(containerRef, (w) => setWidth(w));

  const malwareVersions = useMemo(
    () =>
      new Set(
        malware
          .filter((m) => m.kind === "malware" && m.version)
          .map((m) => m.version as string),
      ),
    [malware],
  );

  const markers: Marker[] = useMemo(
    () =>
      versions
        .map((v) => {
          const t = parseTime(v.published_at);
          if (t === null) return null;
          return {
            version: v.version,
            time: t,
            published_at: v.published_at,
            kind: classifyVersion(v, malwareVersions),
          };
        })
        .filter((m): m is Marker => m !== null)
        .sort((a, b) => a.time - b.time),
    [versions, malwareVersions],
  );

  const [tMin, tMax] = useMemo(() => {
    if (markers.length === 0) return [Date.now() - 86_400_000, Date.now()];
    return [markers[0].time, markers[markers.length - 1].time];
  }, [markers]);

  const innerWidth = Math.max(100, width - MARGIN.left - MARGIN.right);
  const innerHeight = HEIGHT - MARGIN.top - MARGIN.bottom;
  const rowY = innerHeight / 2;

  const xScale = useMemo(() => {
    const domain: [Date, Date] = focus
      ? [new Date(focus[0]), new Date(focus[1])]
      : [new Date(tMin), new Date(tMax)];
    return scaleTime({ domain, range: [0, innerWidth] });
  }, [focus, tMin, tMax, innerWidth]);

  const visibleMarkers = useMemo(() => {
    if (!focus) return markers;
    return markers.filter((m) => m.time >= focus[0] && m.time <= focus[1]);
  }, [markers, focus]);

  const clusters: Cluster[] = useMemo(() => {
    if (visibleMarkers.length <= CLUSTER_THRESHOLD) return [];
    if (visibleMarkers.length === 0) return [];
    const lo = visibleMarkers[0].time;
    const hi = visibleMarkers[visibleMarkers.length - 1].time;
    if (hi === lo) return [];
    const step = (hi - lo) / CLUSTER_BUCKETS;
    const buckets: Marker[][] = Array.from({ length: CLUSTER_BUCKETS }, () => []);
    for (const m of visibleMarkers) {
      const idx = Math.min(
        CLUSTER_BUCKETS - 1,
        Math.floor((m.time - lo) / step),
      );
      buckets[idx].push(m);
    }
    return buckets
      .map((bucket, i): Cluster | null => {
        if (bucket.length === 0) return null;
        const rangeStart = lo + i * step;
        const rangeEnd = rangeStart + step;
        const sumTime = bucket.reduce((acc, b) => acc + b.time, 0);
        return {
          time: sumTime / bucket.length,
          range: [rangeStart, rangeEnd],
          markers: bucket,
          kind: worstKind(bucket),
        };
      })
      .filter((c): c is Cluster => c !== null);
  }, [visibleMarkers]);

  const clustered = clusters.length > 0;

  const tooltip = useTooltip<TooltipPayload>();

  function showMarkerTooltip(event: React.MouseEvent<SVGElement>, m: Marker) {
    const point = localPoint(event) ?? { x: 0, y: 0 };
    tooltip.showTooltip({
      tooltipData: {
        title: m.version,
        lines: [formatDate(m.published_at), markerLabel(m.kind)],
        kind: m.kind,
      },
      tooltipLeft: point.x,
      tooltipTop: point.y,
    });
  }

  function showClusterTooltip(event: React.MouseEvent<SVGElement>, c: Cluster) {
    const point = localPoint(event) ?? { x: 0, y: 0 };
    const sample = [...c.markers]
      .slice(-4)
      .reverse()
      .map((m) => `${m.version} · ${formatDate(m.published_at)}`);
    tooltip.showTooltip({
      tooltipData: {
        title: `${c.markers.length} versions`,
        lines: [
          `${formatDate(new Date(c.range[0]).toISOString())} → ${formatDate(
            new Date(c.range[1]).toISOString(),
          )}`,
          ...sample,
          c.markers.length > sample.length ? "click to zoom in" : "click to zoom",
        ],
        kind: c.kind,
      },
      tooltipLeft: point.x,
      tooltipTop: point.y,
    });
  }

  const installedMarker =
    installed !== undefined
      ? markers.find((m) => m.version === installed)
      : undefined;
  const recommendedMarker =
    recommended !== undefined
      ? markers.find((m) => m.version === recommended)
      : undefined;

  // Screen-reader text. The SVG gets an aria-label; tests pick this up to
  // verify virtualization kicked in without having to inspect coordinates.
  const ariaLabel = clustered
    ? `Version timeline: ${markers.length} versions grouped into ${clusters.length} clusters`
    : `Version timeline: ${markers.length} versions`;

  if (markers.length === 0) {
    return (
      <div className="rounded-md border border-dashed border-zinc-300 dark:border-zinc-700 bg-zinc-50 dark:bg-zinc-900 p-3 text-xs text-zinc-500 dark:text-zinc-400">
        No published dates on file — nothing to plot on a time axis.
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <Legend />
      <div
        ref={containerRef}
        className="relative rounded-md border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900"
      >
        <svg
          width={width}
          height={HEIGHT}
          role="img"
          aria-label={ariaLabel}
          data-testid="version-timeline"
          data-mode={clustered ? "clustered" : "full"}
        >
          <Group left={MARGIN.left} top={MARGIN.top}>
            {/* Baseline. */}
            <line
              x1={0}
              x2={innerWidth}
              y1={rowY}
              y2={rowY}
              stroke={baselineStroke}
              strokeWidth={1}
            />

            {/* Markers (either individual or clustered). */}
            {clustered
              ? clusters.map((c) => (
                  <ClusterMarker
                    key={`${c.range[0]}-${c.range[1]}`}
                    c={c}
                    x={xScale(new Date(c.time)) ?? 0}
                    y={rowY}
                    onHover={(e) => showClusterTooltip(e, c)}
                    onLeave={tooltip.hideTooltip}
                    onClick={() => setFocus([c.range[0], c.range[1]])}
                  />
                ))
              : visibleMarkers.map((m) => {
                  const x = xScale(new Date(m.time)) ?? 0;
                  const isInstalled = m.version === installed;
                  const isRecommended = m.version === recommended;
                  return (
                    <g key={m.version}>
                      <circle
                        cx={x}
                        cy={rowY}
                        r={isInstalled ? MARKER_RADIUS + 2 : MARKER_RADIUS}
                        fill={COLORS[m.kind]}
                        stroke={isInstalled ? installedStroke : markerRing}
                        strokeWidth={isInstalled ? 2 : 1}
                        onMouseMove={(e) => showMarkerTooltip(e, m)}
                        onMouseLeave={tooltip.hideTooltip}
                        style={{ cursor: "pointer" }}
                      />
                      {isRecommended && (
                        <line
                          x1={x}
                          x2={x}
                          y1={rowY + MARKER_RADIUS + 2}
                          y2={rowY + MARKER_RADIUS + 10}
                          stroke="#16a34a"
                          strokeWidth={2}
                        />
                      )}
                    </g>
                  );
                })}

            {/* Installed / recommended anchors always visible even when
                clustered — they are the versions the user came here to
                reason about. */}
            {clustered && installedMarker && (
              <AnchorLine
                x={xScale(new Date(installedMarker.time)) ?? 0}
                rowY={rowY}
                label="installed"
                color={installedStroke}
              />
            )}
            {clustered && recommendedMarker && (
              <AnchorLine
                x={xScale(new Date(recommendedMarker.time)) ?? 0}
                rowY={rowY}
                label="recommended"
                color="#16a34a"
              />
            )}

            <AxisBottom
              top={innerHeight}
              scale={xScale}
              numTicks={Math.max(3, Math.floor(innerWidth / 110))}
              tickLabelProps={() => ({
                fill: axisLabelFill,
                fontSize: 10,
                textAnchor: "middle",
              })}
              stroke={baselineStroke}
              tickStroke={axisTickStroke}
            />
          </Group>
        </svg>
        {tooltip.tooltipOpen && tooltip.tooltipData && (
          <TooltipWithBounds
            top={tooltip.tooltipTop}
            left={tooltip.tooltipLeft}
            style={{
              ...defaultStyles,
              background: "#18181b",
              color: "white",
              padding: "6px 8px",
              borderRadius: 4,
              fontSize: 11,
              lineHeight: 1.4,
            }}
          >
            <div style={{ fontWeight: 600 }}>{tooltip.tooltipData.title}</div>
            {tooltip.tooltipData.lines.map((l, i) => (
              <div key={i} style={{ color: "#d4d4d8" }}>
                {l}
              </div>
            ))}
          </TooltipWithBounds>
        )}
        {focus && (
          <button
            type="button"
            onClick={() => setFocus(null)}
            title="Clear the zoom selection and show every published version again."
            className="absolute right-2 top-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 px-2 py-0.5 text-[10px] text-zinc-600 dark:text-zinc-400 hover:bg-zinc-50 dark:hover:bg-zinc-800"
          >
            Reset zoom
          </button>
        )}
      </div>
    </div>
  );
}

function ClusterMarker({
  c,
  x,
  y,
  onHover,
  onLeave,
  onClick,
}: {
  c: Cluster;
  x: number;
  y: number;
  onHover: (e: React.MouseEvent<SVGElement>) => void;
  onLeave: () => void;
  onClick: () => void;
}) {
  const { resolved } = useTheme();
  const ring = resolved === "dark" ? "#18181b" : "#ffffff"; // zinc-900 / white
  const labelFill = resolved === "dark" ? "#a1a1aa" : "#52525b"; // zinc-400 / zinc-600
  const r = Math.min(9, 3 + Math.log2(c.markers.length + 1) * 1.4);
  return (
    <g style={{ cursor: "pointer" }} onClick={onClick}>
      <circle
        cx={x}
        cy={y}
        r={r}
        fill={COLORS[c.kind]}
        stroke={ring}
        strokeWidth={1}
        onMouseMove={onHover}
        onMouseLeave={onLeave}
      />
      <text
        x={x}
        y={y - r - 2}
        textAnchor="middle"
        fontSize={9}
        fill={labelFill}
      >
        +{c.markers.length}
      </text>
    </g>
  );
}

function AnchorLine({
  x,
  rowY,
  label,
  color,
}: {
  x: number;
  rowY: number;
  label: string;
  color: string;
}) {
  return (
    <g>
      <line
        x1={x}
        x2={x}
        y1={rowY - 18}
        y2={rowY + 18}
        stroke={color}
        strokeDasharray="3 2"
        strokeWidth={1}
      />
      <text x={x + 4} y={rowY - 22} fontSize={9} fill={color}>
        {label}
      </text>
    </g>
  );
}

function Legend() {
  const items: { kind: Kind; label: string; title: string }[] = [
    {
      kind: "normal",
      label: "normal",
      title: "Published release with no known CVE, malware, or yank signal.",
    },
    {
      kind: "medium",
      label: "medium CVE",
      title: "Version affected by a medium-severity advisory.",
    },
    {
      kind: "high",
      label: "high CVE",
      title: "Version affected by a high-severity advisory.",
    },
    {
      kind: "critical",
      label: "critical CVE",
      title: "Version affected by a critical-severity advisory.",
    },
    {
      kind: "yanked",
      label: "yanked",
      title: "Version withdrawn by the maintainer after publication.",
    },
    {
      kind: "malware",
      label: "malware",
      title: "Version flagged in malware_reports — do not install.",
    },
  ];
  return (
    <div className="flex flex-wrap items-center gap-3 text-[11px] text-zinc-500 dark:text-zinc-400">
      {items.map((it) => (
        <span
          key={it.kind}
          className="inline-flex items-center gap-1"
          title={it.title}
        >
          <span
            className="inline-block h-2.5 w-2.5 rounded-full"
            style={{ backgroundColor: COLORS[it.kind] }}
          />
          {it.label}
        </span>
      ))}
      <span
        className="ml-auto"
        title="The installed version has a black outline; the policy-recommended version has a green tick underneath."
      >
        installed: outlined · recommended: green tick
      </span>
    </div>
  );
}

function markerLabel(k: Kind): string {
  return k === "normal" ? "published" : k.replace("_", " ");
}

function formatDate(iso: string | null): string {
  if (!iso) return "—";
  return iso.slice(0, 10);
}

function useResizeObserver(
  ref: React.RefObject<HTMLDivElement | null>,
  onWidth: (w: number) => void,
) {
  // Measured once synchronously so SSR / tests get a usable initial width,
  // then subscribed to live changes in browsers that support it.
  useMemo(() => {
    if (!ref.current) return;
    onWidth(ref.current.getBoundingClientRect().width || 800);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ref.current]);
  useMemo(() => {
    if (typeof window === "undefined" || !ref.current) return;
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width ?? 800;
      onWidth(w);
    });
    ro.observe(ref.current);
    return () => ro.disconnect();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ref.current]);
}
