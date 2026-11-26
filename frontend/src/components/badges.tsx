import { Ban, BadgeCheck, CheckCheck, CircleDot, EyeOff, Fish, Search, Sprout, Layers, Loader2, ShieldAlert, Clock, CircleCheck, CircleAlert, CircleX } from "lucide-react"
import { cn } from "@/lib/utils"
import type { Decision, FindingStage, RiskLevel, ScanStatus } from "@/lib/api"
import { RISK_RANK, SCAN_STATUS_HELP, SCAN_STATUS_LABELS, moduleLabel, MODULE_SHORT } from "@/lib/constants"
import type { ModuleName } from "@/lib/api"

const RISK_VAR: Record<RiskLevel, string> = {
  Critical: "critical",
  High: "high",
  Medium: "medium",
  Low: "low",
}

/**
 * Four-segment severity meter: the number of lit segments encodes the level,
 * so risk never relies on colour alone.
 */
export function RiskMeter({ level, className }: { level: RiskLevel; className?: string }) {
  const lit = RISK_RANK[level]
  const v = RISK_VAR[level]
  return (
    <span aria-hidden className={cn("inline-flex items-end gap-[2px]", className)}>
      {[1, 2, 3, 4].map((i) => (
        <span
          key={i}
          className="w-[3px] rounded-[1px]"
          style={{
            height: `${4 + i * 2}px`,
            background: i <= lit ? `var(--risk-${v})` : "var(--meter-track)",
          }}
        />
      ))}
    </span>
  )
}

export function RiskBadge({
  level,
  score,
  className,
  size = "default",
}: {
  level: RiskLevel
  score?: number
  className?: string
  size?: "default" | "lg"
}) {
  const v = RISK_VAR[level]
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md font-medium whitespace-nowrap",
        size === "lg" ? "px-2.5 py-1 text-sm" : "px-1.5 py-0.5 text-xs",
        className,
      )}
      style={{ background: `var(--risk-${v}-wash)`, color: `var(--risk-${v}-ink)` }}
    >
      <RiskMeter level={level} />
      <span>{level}</span>
      {score !== undefined && <span className="tnum opacity-80 font-normal">{score}</span>}
    </span>
  )
}

const STATUS_STYLE: Record<Decision, { icon: typeof CircleDot; className: string }> = {
  New: { icon: CircleDot, className: "text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/50 ring-sky-200 dark:ring-sky-900" },
  Investigating: {
    icon: Search,
    className: "text-violet-700 dark:text-violet-300 bg-violet-50 dark:bg-violet-950/40 ring-violet-200 dark:ring-violet-900",
  },
  "Confirmed Threat": {
    icon: ShieldAlert,
    className: "text-rose-800 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 ring-rose-200 dark:ring-rose-900",
  },
  "False Positive": {
    icon: Ban,
    className: "text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-slate-800/60 ring-slate-200 dark:ring-slate-700",
  },
  Legitimate: {
    icon: BadgeCheck,
    className: "text-teal-800 dark:text-teal-300 bg-teal-50 dark:bg-teal-950/40 ring-teal-200 dark:ring-teal-900",
  },
  Ignored: {
    icon: EyeOff,
    className: "text-zinc-500 dark:text-zinc-400 bg-zinc-50 dark:bg-zinc-900/60 ring-zinc-200 dark:ring-zinc-800",
  },
  Resolved: {
    icon: CheckCheck,
    className: "text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 ring-emerald-200 dark:ring-emerald-900",
  },
}

/** Badge for an analyst decision (the finding's status). */
export function StatusBadge({ status, className }: { status: Decision; className?: string }) {
  const s = STATUS_STYLE[status] ?? STATUS_STYLE.New
  const Icon = s.icon
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        s.className,
        className,
      )}
    >
      <Icon className="size-3" aria-hidden />
      {status}
    </span>
  )
}

export function StageBadge({ stage, className }: { stage: FindingStage; className?: string }) {
  const candidate = stage === "Candidate"
  const Icon = candidate ? Sprout : Layers
  return (
    <span
      title={candidate ? "Discovered but not yet analysed" : "Analysed finding"}
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        candidate
          ? "text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 ring-amber-200 dark:ring-amber-900"
          : "text-muted-foreground bg-muted ring-border",
        className,
      )}
    >
      <Icon className="size-3" aria-hidden />
      {stage}
    </span>
  )
}

export function PhishingBadge({ className }: { className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-semibold whitespace-nowrap",
        className,
      )}
      style={{ background: "var(--risk-critical)", color: "#fff" }}
    >
      <Fish className="size-3" aria-hidden />
      Suspected phishing
    </span>
  )
}

const SCAN_STYLE: Record<ScanStatus, { icon: typeof Clock; className: string; spin?: boolean }> = {
  queued: { icon: Clock, className: "text-muted-foreground bg-muted ring-border" },
  running: {
    icon: Loader2,
    spin: true,
    className: "text-sky-700 dark:text-sky-300 bg-sky-50 dark:bg-sky-950/50 ring-sky-200 dark:ring-sky-900",
  },
  completed: {
    icon: CircleCheck,
    className: "text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 ring-emerald-200 dark:ring-emerald-900",
  },
  partially_completed: {
    icon: CircleAlert,
    className: "text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 ring-amber-200 dark:ring-amber-900",
  },
  completed_with_errors: {
    icon: CircleAlert,
    className: "text-orange-800 dark:text-orange-300 bg-orange-50 dark:bg-orange-950/40 ring-orange-200 dark:ring-orange-900",
  },
  failed: {
    icon: CircleX,
    className: "text-rose-800 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 ring-rose-200 dark:ring-rose-900",
  },
  cancelled: { icon: CircleX, className: "text-muted-foreground bg-muted ring-border" },
}

export function ScanStatusBadge({ status }: { status: ScanStatus }) {
  const s = SCAN_STYLE[status] ?? SCAN_STYLE.queued
  const Icon = s.icon
  return (
    <span
      title={SCAN_STATUS_HELP[status]}
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        s.className,
      )}
    >
      <Icon className={cn("size-3", s.spin && "animate-spin")} aria-hidden />
      {SCAN_STATUS_LABELS[status] ?? status}
    </span>
  )
}

export function ModuleLabel({ module, short }: { module: ModuleName | string; short?: boolean }) {
  return (
    <span className="whitespace-nowrap text-foreground/85" title={moduleLabel(module)}>
      {short ? (MODULE_SHORT[module as ModuleName] ?? module) : moduleLabel(module)}
    </span>
  )
}
