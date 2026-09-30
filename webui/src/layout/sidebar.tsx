import { NavLink } from "react-router-dom";
import {
  Activity,
  CircleAlert,
  Clock,
  FileText,
  LayoutGrid,
  Plug,
  Plus,
  Radio,
  Server,
  Settings,
  Target,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useVersion } from "@/api/queries";

const NAV = [
  { label: "Workspace", items: [
    { to: "/", label: "Overview", icon: LayoutGrid, end: true },
    { to: "/scans", label: "Assessments", icon: Target },
    { to: "/findings", label: "Findings", icon: CircleAlert },
    { to: "/reports", label: "Reports", icon: FileText },
  ]},
  { label: "Operations", items: [
    { to: "/scans/new", label: "New assessment", icon: Plus },
    { to: "/live", label: "Live feed", icon: Radio },
    { to: "/instances", label: "Instances", icon: Server },
    { to: "/schedules", label: "Schedules", icon: Clock },
  ]},
  { label: "Configure", items: [
    { to: "/integrations", label: "Integrations", icon: Plug },
    { to: "/settings", label: "Settings", icon: Settings },
  ]},
];

export function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const { data: version } = useVersion();
  return (
    <aside className="flex h-full w-60 shrink-0 flex-col border-r border-border bg-card">
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <div className="flex h-8 w-8 items-center justify-center overflow-hidden">
          <img src="/logo.svg" alt="" className="h-full w-full object-contain p-0.5" aria-hidden />
        </div>
        <div className="flex flex-col">
          <span className="text-sm font-semibold tracking-tight">Xalgorix</span>
          <span className="text-[10px] text-muted-foreground mono">
            {version?.version ? `v${version.version}` : "security scanner"}
          </span>
        </div>
      </div>
      <nav className="flex-1 overflow-y-auto py-3" aria-label="Primary">
        <ul className="space-y-0.5 px-2">
          {NAV.map((section) => <li key={section.label} className="mb-4">
            <p className="px-2.5 pb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground/70">{section.label}</p>
            <ul className="space-y-0.5">
            {section.items.map((item) => {
              const Icon = item.icon;
              return <li key={item.to}>
                <NavLink to={item.to} end={item.end}
                  onClick={onNavigate}
                  className={({ isActive }) =>
                    cn(
                      "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                      isActive
                        ? "border border-primary/45 bg-primary/10 text-primary"
                        : "text-muted-foreground hover:bg-accent/40 hover:text-foreground",
                    )
                  }
                >
                  <Icon className="h-3.5 w-3.5" aria-hidden />
                  <span>{item.label}</span>
                </NavLink></li>;
            })}
            </ul>
          </li>)}
        </ul>
      </nav>
      <div className="border-t border-border px-4 py-3 text-[10px] text-muted-foreground mono">
        <div className="flex items-center gap-1.5">
          <Activity className="h-3 w-3" aria-hidden />
          <span>Local scanner</span>
        </div>
        <div className="mt-1 flex items-center gap-1.5 opacity-70">
          <CircleAlert className="h-3 w-3" aria-hidden />
          <span>Ctrl+K for actions</span>
        </div>
      </div>
    </aside>
  );
}
