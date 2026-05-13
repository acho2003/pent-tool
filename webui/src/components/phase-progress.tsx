import { cn } from "@/lib/utils";

// Xalgorix methodology phases (mirrors the legacy dashboard's 10-phase model).
export const PHASES: { id: number; name: string }[] = [
  { id: 1, name: "Recon" },
  { id: 2, name: "Mapping" },
  { id: 3, name: "Discovery" },
  { id: 4, name: "Auth" },
  { id: 5, name: "Injection" },
  { id: 6, name: "Logic" },
  { id: 7, name: "Server" },
  { id: 8, name: "Client" },
  { id: 9, name: "Chaining" },
  { id: 10, name: "Reporting" },
];

export function PhaseProgress({
  current,
  selected,
  status,
  className,
}: {
  current?: number;
  selected?: number[];
  status?: string;
  className?: string;
}) {
  const isRunning = (status || "").toLowerCase() === "running";
  const selectedSet = new Set(selected && selected.length ? selected : PHASES.map((p) => p.id));
  return (
    <div className={cn("flex items-center gap-1.5", className)}>
      {PHASES.map((p) => {
        const isSelected = selectedSet.has(p.id);
        const isCurrent = isRunning && current === p.id;
        const isPassed = current ? p.id < current : false;
        return (
          <div
            key={p.id}
            title={`${p.id}. ${p.name}`}
            className={cn(
              "h-1.5 flex-1 rounded-sm transition-colors",
              !isSelected && "bg-muted/40",
              isSelected && !isPassed && !isCurrent && "bg-muted",
              isPassed && "bg-emerald-500/70",
              isCurrent && "bg-amber-400 pulse-dot",
            )}
          />
        );
      })}
    </div>
  );
}
