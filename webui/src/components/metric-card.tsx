import { Link } from "react-router-dom";
import type { ReactNode } from "react";
import { cn } from "@/lib/utils";

export function MetricCard({
  label,
  value,
  hint,
  icon,
  to,
  className,
  accent,
}: {
  label: string;
  value: ReactNode;
  hint?: ReactNode;
  icon?: ReactNode;
  to?: string;
  className?: string;
  accent?: "default" | "critical" | "warning" | "success";
}) {
  const accentClass =
    accent === "critical"
      ? "text-red-400"
      : accent === "warning"
        ? "text-amber-400"
        : accent === "success"
          ? "text-emerald-400"
          : "text-foreground";

  const body = (
    <div
      className={cn(
        "group rounded-md border border-border bg-card p-5 transition-colors card-hover",
        to && "cursor-pointer",
        className,
      )}
    >
      <div className="flex items-start justify-between gap-2">
        <p className="text-xs uppercase tracking-wide text-muted-foreground">
          {label}
        </p>
        {icon && <span className="text-muted-foreground">{icon}</span>}
      </div>
      <div className={cn("mt-3 text-3xl font-semibold tabular-nums", accentClass)}>
        {value}
      </div>
      {hint != null && (
        <div className="mt-2 text-xs text-muted-foreground">{hint}</div>
      )}
    </div>
  );
  return to ? (
    <Link to={to} className="block focus:outline-none focus:ring-1 focus:ring-ring rounded-md">
      {body}
    </Link>
  ) : (
    body
  );
}
