"use client"

import Link from "next/link"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { CalendarClock, Loader2, Lock, TriangleAlert } from "lucide-react"
import { ErrorPanel } from "@/components/query-state"
import { Panel } from "@/components/widgets"
import { Skeleton } from "@/components/ui/skeleton"
import { Switch } from "@/components/ui/switch"
import { api, type AutoScanSettings } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { fmtDateTime, fmtNumber } from "@/lib/format"
import { keys } from "@/lib/queries"
import { cn } from "@/lib/utils"

export function useAutoScan() {
  return useQuery({ queryKey: keys.autoScan, queryFn: api.autoScan, staleTime: 30_000 })
}

/** Master switch for scheduled scans (D-39). Admins can toggle; analysts see it read-only. */
export function AutoScanCard() {
  const { isAdmin } = useAuth()
  const qc = useQueryClient()
  const settings = useAutoScan()
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.setAutoScan(enabled),
    onSuccess: (s: AutoScanSettings) => {
      qc.setQueryData(keys.autoScan, s)
      toast.success(s.enabled ? "Automatic scans switched on" : "Automatic scans switched off")
    },
    onError: (e) => toast.error(e.message),
  })
  const s = settings.data

  return (
    <Panel
      title={
        <span className="inline-flex items-center gap-1.5">
          <CalendarClock className="size-4" aria-hidden />
          Automatic scans
        </span>
      }
      description="Scheduled scans for every brand that has automatic scanning on"
    >
      {settings.error ? (
        <ErrorPanel error={settings.error} onRetry={() => settings.refetch()} title="Couldn't load the automatic-scan setting" />
      ) : !s ? (
        <Skeleton className="h-24 w-full" />
      ) : (
        <div className="space-y-3">
          <label
            className={cn(
              "flex items-center justify-between gap-4 rounded-lg border p-4",
              isAdmin ? "cursor-pointer" : "cursor-default",
              s.enabled
                ? "border-emerald-300/60 bg-emerald-50/60 dark:border-emerald-900 dark:bg-emerald-950/30"
                : "border-amber-300/60 bg-amber-50/60 dark:border-amber-900 dark:bg-amber-950/30",
            )}
          >
            <span>
              <span className="block text-lg font-semibold">{s.enabled ? "ON" : "OFF"}</span>
              <span className="block text-sm text-muted-foreground">
                When OFF nothing runs on a schedule — Run scan now still works. Social media scans use YouTube API quota
                (~750 units per brand per scan) and, when APIFY_TOKEN is set, paid Apify results (capped per run).
              </span>
            </span>
            <span className="flex shrink-0 items-center gap-2">
              {toggle.isPending && <Loader2 className="size-4 animate-spin" aria-hidden />}
              {!isAdmin && <Lock className="size-3.5 text-muted-foreground" aria-label="Only admins can change this" />}
              <Switch
                checked={s.enabled}
                onCheckedChange={(c) => toggle.mutate(!!c)}
                disabled={!isAdmin || toggle.isPending}
                aria-label="Automatic scans"
                className="scale-125"
              />
            </span>
          </label>
          <p className="text-sm">
            <span className="tnum font-medium">
              {fmtNumber(s.brands_enabled)} of {fmtNumber(s.brands_total)}
            </span>{" "}
            {s.brands_total === 1 ? "brand has" : "brands have"} automatic scanning on.{" "}
            <Link href="/brands" className="underline underline-offset-2">
              Set it per brand
            </Link>
            .
          </p>
          <p className="text-xs text-muted-foreground">Schedule (UTC): {s.schedule_utc}</p>
          {s.updated_at && <p className="text-xs text-muted-foreground">Last changed {fmtDateTime(s.updated_at)}</p>}
          {!isAdmin && <p className="text-xs text-muted-foreground">Only admins can change this setting.</p>}
        </div>
      )}
    </Panel>
  )
}

/** Shown on the Scans page when nothing will run on a schedule. */
export function AutoScanBanner() {
  const settings = useAutoScan()
  const s = settings.data
  if (!s || (s.enabled && s.brands_enabled > 0)) return null
  return (
    <div
      role="status"
      className="mb-3 flex items-start gap-3 rounded-lg border border-amber-300/60 bg-amber-50/60 p-4 text-sm dark:border-amber-900 dark:bg-amber-950/30"
    >
      <TriangleAlert className="mt-0.5 size-4 shrink-0 text-amber-700 dark:text-amber-300" aria-hidden />
      <p>
        {!s.enabled
          ? "Automatic scans are switched off — only manual scans run."
          : "No brand has automatic scanning on — only manual scans run."}{" "}
        <Link href={!s.enabled ? "/settings" : "/brands"} className="font-medium underline underline-offset-2">
          {!s.enabled ? "Open Settings" : "Choose brands"}
        </Link>
      </p>
    </div>
  )
}
