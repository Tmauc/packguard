import { Cell, Pie, PieChart, ResponsiveContainer, Tooltip } from "recharts";

/// recharts wrapper so the Overview's three breakdowns share one component.
/// Wraps in ResponsiveContainer with a fixed height — the parent card
/// constrains the width, no additional layout work needed.
export function Donut({
  data,
}: {
  data: { name: string; value: number; fill: string }[];
}) {
  return (
    <div className="h-40 w-full">
      <ResponsiveContainer>
        <PieChart>
          <Pie
            data={data}
            dataKey="value"
            nameKey="name"
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
      </ResponsiveContainer>
    </div>
  );
}
