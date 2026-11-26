import { CircleAlert, CircleCheck, CircleMinus, CircleX } from "lucide-react"
import type { ComponentStatus, ScanComponent } from "@/lib/api"
import { COMPONENT_STATUS_LABELS } from "@/lib/constants"
import { cn } from "@/lib/utils"

const STYLE: Record<ComponentStatus, { icon: typeof CircleCheck; className: string }> = {
  ok: { icon: CircleCheck, className: "text-emerald-700 dark:text-emerald-400" },
  skipped: { icon: CircleMinus, className: "text-muted-foreground" },
  not_configured: { icon: CircleAlert, className: "text-amber-700 dark:text-amber-400" },
  unavailable: { icon: CircleAlert, className: "text-amber-700 dark:text-amber-400" },
  failed: { icon: CircleX, className: "text-rose-700 dark:text-rose-400" },
}

export function ComponentStatusIcon({ status, className }: { status: ComponentStatus; className?: string }) {
  const s = STYLE[status] ?? STYLE.failed
  const Icon = s.icon
  return <Icon className={cn("size-4 shrink-0", s.className, className)} aria-hidden />
}

/** Which parts of a scan ran and which did not (D-31), e.g. "Telegram API — Not configured". */
export function ScanComponents({ components }: { components: ScanComponent[] }) {
  if (!components?.length) return null
  return (
    <ul className="divide-y rounded-md border bg-card text-sm" aria-label="Scan components">
      {components.map((c) => (
        <li key={c.name} className="flex flex-wrap items-start gap-x-3 gap-y-0.5 px-3 py-2">
          <ComponentStatusIcon status={c.status} className="mt-0.5" />
          <span className="min-w-[12rem] flex-1 font-medium">{c.name}</span>
          <span className={cn("text-xs font-medium", STYLE[c.status]?.className)}>
            {COMPONENT_STATUS_LABELS[c.status] ?? c.status}
            {c.fatal && c.status !== "ok" && " — nothing could be checked"}
          </span>
          {Object.keys(c.counts ?? {}).length > 0 && (
            <span className="tnum w-full pl-7 text-xs text-muted-foreground">
              {Object.entries(c.counts)
                .map(([k, v]) => `${k.replace(/_/g, " ")}: ${v}`)
                .join(" · ")}
            </span>
          )}
          {c.message && <span className="w-full pl-7 text-xs break-words text-muted-foreground">{c.message}</span>}
        </li>
      ))}
    </ul>
  )
}
