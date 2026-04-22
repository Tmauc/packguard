import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const badgeVariants = cva(
  "inline-flex items-center rounded px-2 py-0.5 text-xs font-medium",
  {
    variants: {
      tone: {
        neutral: "bg-zinc-100 text-zinc-700",
        good: "bg-emerald-100 text-emerald-700",
        warn: "bg-amber-100 text-amber-700",
        bad: "bg-red-100 text-red-700",
        cve: "bg-orange-100 text-orange-700",
        malware: "bg-fuchsia-100 text-fuchsia-700",
        typosquat: "bg-violet-100 text-violet-700",
        insufficient: "bg-purple-100 text-purple-700",
        muted: "bg-zinc-50 text-zinc-500 border border-zinc-200",
      },
    },
    defaultVariants: { tone: "neutral" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLSpanElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, tone, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ tone, className }))} {...props} />;
}
