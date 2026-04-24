import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/cn";

const badgeVariants = cva(
  "inline-flex items-center rounded px-2 py-0.5 text-xs font-medium",
  {
    variants: {
      tone: {
        neutral: "bg-zinc-100 dark:bg-zinc-800 text-zinc-700 dark:text-zinc-300",
        good: "bg-emerald-100 dark:bg-emerald-950/60 text-emerald-700 dark:text-emerald-300",
        warn: "bg-amber-100 dark:bg-amber-950/60 text-amber-700 dark:text-amber-300",
        bad: "bg-red-100 dark:bg-red-950/60 text-red-700 dark:text-red-300",
        cve: "bg-orange-100 dark:bg-orange-950/60 text-orange-700 dark:text-orange-300",
        malware: "bg-fuchsia-100 dark:bg-fuchsia-950/60 text-fuchsia-700 dark:text-fuchsia-300",
        typosquat: "bg-violet-100 dark:bg-violet-950/60 text-violet-700 dark:text-violet-300",
        insufficient: "bg-purple-100 dark:bg-purple-950/60 text-purple-700 dark:text-purple-300",
        muted: "bg-zinc-50 dark:bg-zinc-900 text-zinc-500 dark:text-zinc-400 border border-zinc-200 dark:border-zinc-800",
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
