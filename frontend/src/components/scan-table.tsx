"use client"

import { Fragment, useState } from "react"
import Link from "next/link"
import { ChevronRight, Radar } from "lucide-react"
import { ScanStatusBadge } from "@/components/badges"
import { ErrorPanel } from "@/components/query-state"
import { ScanComponents } from "@/components/scan-components"
import { EmptyState } from "@/components/widgets"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import type { Scan } from "@/lib/api"
import { MODULE_LABELS } from "@/lib/constants"
import { fmtDateTime, fmtDuration, fmtRelative } from "@/lib/format"
import { cn } from "@/lib/utils"

const RUNNER_LABELS: Record<string, string> = {
  domains: "Domains: typosquat, MX, phishing",
  apk: MODULE_LABELS.apk,
  rogue_app: MODULE_LABELS.rogue_app,
  social: MODULE_LABELS.social,
  documents: MODULE_LABELS.documents,
  logo: MODULE_LABELS.logo,
  email_posture: "Brand email security (SPF/DMARC)",
}

export function runnerLabel(scan: Scan): string {
  const runner = typeof scan.stats?.runner === "string" ? scan.stats.runner : null
  return (runner && RUNNER_LABELS[runner]) || MODULE_LABELS[scan.module] || scan.module
}

export const isActiveScan = (s: Scan) => s.status === "queued" || s.status === "running"

const STAT_KEYS = ["findings", "created", "updated", "errors"] as const

function num(v: unknown): number | null {
  return typeof v === "number" ? v : null
}

export function ScanTable({
  scans,
  loading,
  error,
  onRetry,
  showBrand = true,
  emptyText = "No scans have run yet.",
}: {
  scans?: Scan[]
  loading?: boolean
  error?: unknown
  onRetry?: () => void
  showBrand?: boolean
  emptyText?: string
}) {
  const [open, setOpen] = useState<Set<string>>(new Set())
  const toggle = (id: string) =>
    setOpen((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  const cols = showBrand ? 8 : 7
  if (error) return <ErrorPanel error={error} onRetry={onRetry} title="Couldn't load scans" />

  return (
    <div className="overflow-hidden rounded-lg border bg-card">
      <Table>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-8" />
            <TableHead className="text-xs text-muted-foreground">Status</TableHead>
            <TableHead className="text-xs text-muted-foreground">Module</TableHead>
            {showBrand && <TableHead className="hidden text-xs text-muted-foreground sm:table-cell">Brand</TableHead>}
            <TableHead className="hidden text-xs text-muted-foreground md:table-cell">Trigger</TableHead>
            <TableHead className="text-xs text-muted-foreground">Started</TableHead>
            <TableHead className="hidden text-xs text-muted-foreground lg:table-cell">Duration</TableHead>
            <TableHead className="text-right text-xs text-muted-foreground">
              <span className="hidden sm:inline">Findings / new / updated / errors</span>
              <span className="sm:hidden">Findings</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {loading &&
            Array.from({ length: 4 }).map((_, i) => (
              <TableRow key={i}>
                <TableCell colSpan={cols}>
                  <Skeleton className="h-5 w-full" />
                </TableCell>
              </TableRow>
            ))}
          {scans?.map((s) => {
            const expandable = !!s.error || (s.components?.length ?? 0) > 0 || Object.keys(s.stats ?? {}).length > 0
            const isOpen = open.has(s.id)
            return (
              <Fragment key={s.id}>
                <TableRow
                  className={cn(expandable && "cursor-pointer", isOpen && "border-b-0 bg-muted/40")}
                  onClick={() => expandable && toggle(s.id)}
                >
                  <TableCell className="pr-0">
                    {expandable && (
                      <button
                        type="button"
                        aria-expanded={isOpen}
                        aria-label={isOpen ? "Hide scan details" : "Show scan details"}
                        onClick={(e) => {
                          e.stopPropagation()
                          toggle(s.id)
                        }}
                        className="rounded p-0.5 text-muted-foreground outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
                      >
                        <ChevronRight className={cn("size-4 transition-transform", isOpen && "rotate-90")} />
                      </button>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <ScanStatusBadge status={s.status} />
                      {s.error && !isOpen && <span className="hidden max-w-[16rem] truncate text-xs text-destructive xl:inline">{s.error}</span>}
                    </div>
                  </TableCell>
                  <TableCell className="text-sm">
                    {runnerLabel(s)}
                  </TableCell>
                  {showBrand && (
                    <TableCell className="hidden sm:table-cell">
                      <Link href={`/brands/${s.brand_id}`} onClick={(e) => e.stopPropagation()} className="hover:underline">
                        {s.brand_name ?? "—"}
                      </Link>
                    </TableCell>
                  )}
                  <TableCell className="hidden text-sm text-muted-foreground md:table-cell">
                    <span className="capitalize">{s.trigger}</span>
                    {(typeof s.stats?.date_from === "string" || typeof s.stats?.date_to === "string") && (
                      <span className="block text-xs whitespace-nowrap">
                        {String(s.stats?.date_from ?? "…")} → {String(s.stats?.date_to ?? "today")}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="text-sm whitespace-nowrap" title={fmtDateTime(s.started_at ?? s.created_at)}>
                    {fmtRelative(s.started_at ?? s.created_at)}
                  </TableCell>
                  <TableCell className="tnum hidden text-sm text-muted-foreground lg:table-cell">
                    {s.started_at ? fmtDuration(s.started_at, s.finished_at) : "—"}
                  </TableCell>
                  <TableCell className="tnum text-right text-sm whitespace-nowrap">
                    <span className="font-medium">{num(s.stats?.findings) ?? "—"}</span>
                    <span className="hidden text-muted-foreground sm:inline">
                      {" / "}
                      {num(s.stats?.created) ?? "—"} / {num(s.stats?.updated) ?? "—"} /{" "}
                      <span className={cn((num(s.stats?.errors) ?? 0) > 0 && "font-medium text-destructive")}>{num(s.stats?.errors) ?? "—"}</span>
                    </span>
                  </TableCell>
                </TableRow>
                {isOpen && (
                  <TableRow className="bg-muted/40 hover:bg-muted/40">
                    <TableCell />
                    <TableCell colSpan={cols - 1} className="pb-3 whitespace-normal">
                      {(s.components?.length ?? 0) > 0 && (
                        <div className="mb-3">
                          <div className="mb-1 text-xs font-medium text-muted-foreground">What this scan checked</div>
                          <ScanComponents components={s.components} />
                        </div>
                      )}
                      {s.error && (
                        <div className="mb-2">
                          <div className="text-xs font-medium text-destructive">Error</div>
                          <pre className="mt-1 max-h-60 overflow-auto rounded bg-card p-2 font-mono text-xs whitespace-pre-wrap break-all">{s.error}</pre>
                        </div>
                      )}
                      <dl className="grid grid-cols-2 gap-x-6 gap-y-1 text-xs sm:grid-cols-4">
                        {STAT_KEYS.map((k) => (
                          <div key={k} className="flex gap-2">
                            <dt className="text-muted-foreground capitalize">{k}</dt>
                            <dd className="tnum font-medium">{num(s.stats?.[k]) ?? "—"}</dd>
                          </div>
                        ))}
                        {Object.entries(s.stats ?? {})
                          .filter(([k]) => !(STAT_KEYS as readonly string[]).includes(k) && k !== "runner" && k !== "data_source")
                          .map(([k, v]) => (
                            <div key={k} className="flex gap-2">
                              <dt className="text-muted-foreground">{k.replace(/_/g, " ")}</dt>
                              <dd className="tnum font-medium break-all">{typeof v === "object" ? JSON.stringify(v) : String(v)}</dd>
                            </div>
                          ))}
                      </dl>
                      <div className="mt-2 text-xs text-muted-foreground">
                        Queued {fmtDateTime(s.created_at)}
                        {s.finished_at && `, finished ${fmtDateTime(s.finished_at)}`}
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
            )
          })}
        </TableBody>
      </Table>
      {!loading && scans?.length === 0 && (
        <EmptyState icon={Radar} title="No scans yet" className="py-8">
          {emptyText}
        </EmptyState>
      )}
    </div>
  )
}
