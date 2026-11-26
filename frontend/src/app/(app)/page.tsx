"use client"

import { Suspense } from "react"
import Link from "next/link"
import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { useQuery } from "@tanstack/react-query"
import {
  AppWindow,
  CircleAlert,
  FileWarning,
  Layers,
  Sprout,
  Fish,
  Inbox,
  Mail,
  MailWarning,
  Radar,
  ShieldCheck,
  Siren,
  UserRoundX,
  ChevronRight,
} from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { RiskMeter } from "@/components/badges"
import { BarList, RiskLegend, TrendChart } from "@/components/charts"
import { ErrorPanel } from "@/components/query-state"
import { Panel, SimpleSelect } from "@/components/widgets"
import { Skeleton } from "@/components/ui/skeleton"
import { api, toSearch, type ExecutiveStats, type ModuleName, type RiskLevel } from "@/lib/api"
import { ALERT_MODULES, MODULE_SHORT, OPEN_STATUSES, RISK_LEVELS, STATUSES } from "@/lib/constants"
import { fmtDate, fmtDateTime, fmtNumber, fmtRelative } from "@/lib/format"
import { keys, useBrands } from "@/lib/queries"
import { cn } from "@/lib/utils"

type Q = Record<string, string | string[] | undefined>

function alertsLink(q: Q, brandId: string | null): string {
  return `/alerts${toSearch({ ...q, brand_id: brandId ?? undefined })}`
}

function findingsLink(q: Q, brandId: string | null): string {
  return `/findings${toSearch({ ...q, brand_id: brandId ?? undefined })}`
}

function Tile({
  href,
  label,
  value,
  note,
  icon: Icon,
}: {
  href: string
  label: string
  value: number | undefined
  note: string
  icon: React.ComponentType<{ className?: string }>
}) {
  return (
    <Link
      href={href}
      className="group flex flex-col justify-between gap-3 rounded-lg border bg-card p-3 sm:p-4 outline-none transition-colors hover:border-primary/40 focus-visible:ring-2 focus-visible:ring-ring"
    >
      <div className="flex items-start justify-between gap-2">
        <span className="text-sm leading-snug text-muted-foreground">{label}</span>
        <Icon className="size-4 shrink-0 text-muted-foreground/70" />
      </div>
      <div>
        {value === undefined ? (
          <Skeleton className="h-8 w-12" />
        ) : (
          <div className={cn("tnum text-2xl font-semibold tracking-tight sm:text-3xl", value === 0 && "text-muted-foreground/70")}>
            {fmtNumber(value)}
          </div>
        )}
        <div className="mt-0.5 flex items-center justify-between text-xs text-muted-foreground">
          <span>{note}</span>
          <ChevronRight className="size-3.5 opacity-0 transition-opacity group-hover:opacity-100" />
        </div>
      </div>
    </Link>
  )
}

/**
 * What the numbers below mean (RDA-02): "No threats detected." only when a scan has actually completed, and
 * always with how much of the scan could not run. Never claimed when nothing was scanned.
 */
function CoverageBanner({ stats }: { stats: ExecutiveStats }) {
  const gaps = stats.components_unavailable
  const failed = stats.scans_failed
  const gapNote =
    gaps > 0 || failed > 0 ? (
      <>
        {" "}
        {failed > 0 && (
          <>
            {failed} {failed === 1 ? "scanner's" : "scanners'"} latest scan failed or was cancelled and checked nothing.{" "}
          </>
        )}
        {gaps > 0 && (
          <>
            {gaps} scan {gaps === 1 ? "part" : "parts"} could not run in the latest scans, so coverage is reduced.{" "}
          </>
        )}
        See{" "}
        <Link href="/scans" className="underline underline-offset-2">
          Scans
        </Link>{" "}
        and{" "}
        <Link href="/integrations" className="underline underline-offset-2">
          Integrations
        </Link>
        .
      </>
    ) : null
  if (!stats.last_completed_scan_at) {
    return (
      <div role="status" className="mb-3 flex items-start gap-3 rounded-lg border bg-card p-4">
        <Radar className="mt-0.5 size-5 shrink-0 text-muted-foreground" aria-hidden />
        <div>
          <p className="font-medium">No scans have run yet</p>
          <p className="text-sm text-muted-foreground">
            Nothing has been checked, so there is no result yet — this is not the same as &ldquo;no threats&rdquo;. Add a brand under{" "}
            <Link href="/brands" className="underline underline-offset-2">
              Brands
            </Link>{" "}
            and press Run scan now.
          </p>
        </div>
      </div>
    )
  }
  const last = (
    <span title={fmtDateTime(stats.last_completed_scan_at)}>Last completed scan {fmtRelative(stats.last_completed_scan_at)}.</span>
  )
  if (stats.open_alerts === 0 && failed === 0) {
    return (
      <div role="status" className="mb-3 flex items-start gap-3 rounded-lg border border-emerald-300/60 bg-emerald-50/60 p-4 dark:border-emerald-900 dark:bg-emerald-950/30">
        <ShieldCheck className="mt-0.5 size-5 shrink-0 text-emerald-700 dark:text-emerald-400" aria-hidden />
        <div>
          <p className="font-medium">No threats detected.</p>
          <p className="text-sm text-muted-foreground">
            {last}
            {gapNote}
          </p>
        </div>
      </div>
    )
  }
  if (gaps > 0 || failed > 0) {
    return (
      <div role="status" className="mb-3 flex items-start gap-3 rounded-lg border border-amber-300/60 bg-amber-50/60 p-4 text-sm dark:border-amber-900 dark:bg-amber-950/30">
        <CircleAlert className="mt-0.5 size-5 shrink-0 text-amber-700 dark:text-amber-400" aria-hidden />
        <p className="text-muted-foreground">
          {stats.open_alerts === 0 && <strong className="text-foreground">No threats found, but coverage is incomplete. </strong>}
          {last}
          {gapNote}
        </p>
      </div>
    )
  }
  return null
}

/** The lead figure: open High/Critical alerts with today's delta and the open-risk mix. */
function HighCriticalHero({ stats, brandId, today }: { stats?: ExecutiveStats; brandId: string | null; today: string }) {
  const open = stats?.by_risk ?? {}
  const totalOpen = RISK_LEVELS.reduce((a, l) => a + (open[l] ?? 0), 0)
  return (
    <section className="flex flex-col justify-between gap-5 rounded-lg border bg-card p-5 col-span-2 lg:row-span-2">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-medium">High and Critical alerts open</h2>
          <p className="text-xs text-muted-foreground">New, investigating or confirmed threat</p>
        </div>
        <Siren className="size-5 text-[var(--risk-critical)]" aria-hidden />
      </div>
      <div className="flex flex-wrap items-end gap-x-4 gap-y-1">
        {stats ? (
          <Link
            href={alertsLink({ risk_level: ["Critical", "High"], status: OPEN_STATUSES, sort: "risk" }, brandId)}
            className="tnum text-6xl leading-none font-semibold tracking-tight outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
          >
            {fmtNumber(stats.high_critical_alerts)}
          </Link>
        ) : (
          <Skeleton className="h-14 w-24" />
        )}
        {stats && (
          <Link
            href={alertsLink({ risk_level: ["Critical", "High"], date_from: today, date_to: today }, brandId)}
            className={cn(
              "mb-1 rounded-md px-2 py-0.5 text-sm font-medium outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring",
              stats.high_critical_today > 0 ? "bg-[var(--risk-critical-wash)] text-[var(--risk-critical-ink)]" : "bg-muted text-muted-foreground",
            )}
          >
            +{fmtNumber(stats.high_critical_today)} today
          </Link>
        )}
      </div>
      <div>
        <div className="mb-2 flex items-center justify-between text-xs text-muted-foreground">
          <span>All open alerts by risk</span>
          <span className="tnum">{fmtNumber(totalOpen)} open</span>
        </div>
        <div className="flex h-2.5 w-full gap-[2px] overflow-hidden rounded-full bg-[var(--meter-track)]" role="img" aria-label={RISK_LEVELS.map((l) => `${l} ${open[l] ?? 0}`).join(", ")}>
          {totalOpen > 0 &&
            RISK_LEVELS.map((l) =>
              (open[l] ?? 0) > 0 ? (
                <span key={l} style={{ flexGrow: open[l], background: `var(--risk-${l.toLowerCase()})` }} />
              ) : null,
            )}
        </div>
        <ul className="mt-3 grid grid-cols-2 gap-x-4 gap-y-1.5 sm:grid-cols-4">
          {RISK_LEVELS.map((l) => (
            <li key={l}>
              <Link
                href={alertsLink({ risk_level: l, status: OPEN_STATUSES }, brandId)}
                className="flex items-center gap-2 rounded text-sm outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
              >
                <RiskMeter level={l} />
                <span className="text-muted-foreground">{l}</span>
                <span className="tnum ml-auto font-medium sm:ml-0">{fmtNumber(open[l] ?? 0)}</span>
              </Link>
            </li>
          ))}
        </ul>
      </div>
    </section>
  )
}

function Dashboard() {
  const params = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()
  const brandId = params.get("brand")
  const brandIds = brandId ? [brandId] : []
  const brands = useBrands()
  const stats = useQuery({ queryKey: keys.executive(brandIds), queryFn: () => api.executive(brandIds), refetchInterval: 60_000 })
  const trends = useQuery({ queryKey: keys.trends(30, brandIds), queryFn: () => api.trends(30, brandIds) })

  const s = stats.data
  const today = s?.date ?? new Date().toISOString().slice(0, 10)
  const todayQ = { date_from: today, date_to: today }
  const brandName = brands.data?.find((b) => b.id === brandId)?.name

  const tiles: {
    label: string
    value?: number
    note: string
    q: Q
    href?: string
    icon: React.ComponentType<{ className?: string }>
  }[] = [
    { label: "Total alerts today", value: s?.total_alerts_today, note: "All modules", q: todayQ, icon: Inbox },
    {
      label: "New phishing domains",
      value: s?.new_phishing_domains,
      note: "Typosquat, MX, phishing",
      q: { ...todayQ, module: ["typosquat", "mx", "phishing"] },
      icon: Fish,
    },
    {
      label: "New impersonation accounts",
      value: s?.new_impersonation_accounts,
      note: "Social media",
      q: { ...todayQ, module: "social" },
      icon: UserRoundX,
    },
    {
      label: "New rogue apps",
      value: s?.new_rogue_apps,
      note: "Fake APKs and store apps",
      q: { ...todayQ, module: ["apk", "rogue_app"] },
      icon: AppWindow,
    },
    {
      label: "Sensitive document exposures",
      value: s?.sensitive_document_exposures,
      note: "Found today",
      q: { ...todayQ, module: "documents" },
      icon: FileWarning,
    },
    {
      label: "Phishing emails today",
      value: s?.phishing_emails_today,
      note: "Reported or uploaded",
      q: { ...todayQ, module: "email" },
      icon: Mail,
    },
    {
      label: "Spoofed-sender attempts",
      value: s?.spoofed_sender_attempts,
      note: "High/Critical email & domain spoofing",
      q: { module: ["email", "email_posture", "dmarc"], risk_level: ["High", "Critical"], status: OPEN_STATUSES },
      icon: MailWarning,
    },
    { label: "Open alerts", value: s?.open_alerts, note: "Awaiting a decision", q: { status: OPEN_STATUSES }, icon: Inbox },
    {
      label: "Candidates",
      value: s?.candidates,
      note: "Discovered, not yet analysed",
      q: {},
      href: findingsLink({ stage: "Candidate" }, brandId),
      icon: Sprout,
    },
    {
      label: "Findings below alert level",
      value: s?.findings_below_alert_level,
      note: "Analysed, held back by the brand's alert level",
      q: {},
      href: findingsLink({ stage: "Finding", alerted: "false" }, brandId),
      icon: Layers,
    },
  ]

  const brandOptions = [{ value: "all", label: "All brands" }, ...(brands.data ?? []).map((b) => ({ value: b.id, label: b.name }))]

  return (
    <>
      <PageHeader
        title="Brand exposure today"
        description={
          <>
            {s ? fmtDate(`${s.date}T12:00:00Z`) : "Loading…"} (UTC day), {brandName ?? "all monitored brands"}
          </>
        }
        actions={
          <SimpleSelect
            ariaLabel="Brand"
            value={brandId ?? "all"}
            onChange={(v) => router.replace(v === "all" ? pathname : `${pathname}?brand=${v}`, { scroll: false })}
            options={brandOptions}
            className="w-56"
          />
        }
      />

      {stats.error ? (
        <ErrorPanel error={stats.error} onRetry={() => stats.refetch()} title="Couldn't load the dashboard" />
      ) : (
      <>
      {s && <CoverageBanner stats={s} />}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-5">
        <HighCriticalHero stats={s} brandId={brandId} today={today} />
        {tiles.map((t) => (
          <Tile key={t.label} href={t.href ?? alertsLink(t.q, brandId)} label={t.label} value={t.value} note={t.note} icon={t.icon} />
        ))}
      </div>

      <div className="mt-3 grid grid-cols-1 gap-3 xl:grid-cols-3">
        <Panel
          className="xl:col-span-2"
          title="New alerts, last 30 days"
          description="By risk level. Select a day to open its alerts."
          actions={<RiskLegend />}
        >
          {trends.error ? (
            <ErrorPanel error={trends.error} onRetry={() => trends.refetch()} title="Couldn't load the trend" />
          ) : trends.data ? (
            <TrendChart data={trends.data} alertsHref={(day) => alertsLink({ date_from: day, date_to: day }, brandId)} />
          ) : (
            <Skeleton className="h-64 w-full" />
          )}
        </Panel>
        <Panel title="Open alerts by risk" description="New, investigating or confirmed threat">
          {s ? (
            <BarList
              rows={RISK_LEVELS.map((l: RiskLevel) => ({
                key: l,
                label: l,
                value: s.by_risk[l] ?? 0,
                href: alertsLink({ risk_level: l, status: OPEN_STATUSES }, brandId),
                color: `var(--risk-${l.toLowerCase()})`,
                marker: <RiskMeter level={l} />,
              }))}
            />
          ) : (
            <Skeleton className="h-40 w-full" />
          )}
        </Panel>
        <Panel title="Open alerts by module" description="Where the open work comes from" className="xl:col-span-2">
          {s ? (
            <BarList
              rows={ALERT_MODULES.map((m: ModuleName) => ({
                key: m,
                label: MODULE_SHORT[m],
                value: s.by_module[m] ?? 0,
                href: alertsLink({ module: m, status: OPEN_STATUSES }, brandId),
              }))}
            />
          ) : (
            <Skeleton className="h-56 w-full" />
          )}
        </Panel>
        <Panel title="Alerted findings by decision" description="Every alerted finding, open or closed">
          {s ? (
            <BarList
              emptyText="No alerts yet"
              rows={STATUSES.map((st) => ({
                key: st,
                label: st,
                value: s.by_status[st] ?? 0,
                href: alertsLink({ status: st }, brandId),
              }))}
            />
          ) : (
            <Skeleton className="h-40 w-full" />
          )}
        </Panel>
      </div>
      </>
      )}
    </>
  )
}

export default function DashboardPage() {
  return (
    <Suspense>
      <Dashboard />
    </Suspense>
  )
}
