import { useEffect, useRef, useState } from "react";
import { Cell, Pie, PieChart, Tooltip } from "recharts";

/// recharts wrapper so the Overview's three breakdowns share one component.
/// We measure the parent width ourselves instead of leaning on recharts'
/// `ResponsiveContainer` — headless Chrome + happy-dom don't reliably
/// tick `ResizeObserver` before the first paint, so the chart would render
/// at 0×0 and leave the cards visibly empty (both in tests and in release
/// screenshots). The measurement falls back to 320px.
export function Donut({
  data,
}: {
  data: { name: string; value: number; fill: string }[];
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(320);
  useEffect(() => {
    if (!ref.current) return;
    const measure = () => {
      const w = ref.current?.getBoundingClientRect().width ?? 320;
      if (w > 0) setWidth(w);
    };
    measure();
    if (typeof ResizeObserver !== "undefined") {
      const ro = new ResizeObserver(measure);
      ro.observe(ref.current);
      return () => ro.disconnect();
    }
  }, []);
  const height = 160;
  return (
    <div ref={ref} className="h-40 w-full">
      <PieChart width={width} height={height}>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          cx={width / 2}
          cy={height / 2}
          innerRadius={36}
          outerRadius={64}
          paddingAngle={1}
          stroke="white"
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.fill} />
          ))}
        </Pie>
        <Tooltip />
      </PieChart>
    </div>
  );
}
