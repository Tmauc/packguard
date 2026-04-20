import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { cn } from "@/lib/cn";

type Tone = "good" | "warn" | "bad" | "neutral";

const toneClasses: Record<Tone, string> = {
  good: "text-emerald-700",
  warn: "text-amber-700",
  bad: "text-red-700",
  neutral: "text-zinc-900",
};

export function StatCard({
  label,
  value,
  sub,
  tone = "neutral",
}: {
  label: string;
  value: number | string;
  sub?: string;
  tone?: Tone;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>{label}</CardTitle>
      </CardHeader>
      <CardContent className="space-y-1">
        <div
          data-testid="stat-value"
          className={cn(
            "text-3xl font-semibold tabular-nums",
            toneClasses[tone],
          )}
        >
          {value}
        </div>
        {sub && <div className="text-xs text-zinc-500">{sub}</div>}
      </CardContent>
    </Card>
  );
}
