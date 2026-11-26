"use client"

import { Suspense, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useUrlFilters } from "@/lib/url-filters"
import { keepPreviousData, useQuery } from "@tanstack/react-query"
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table"
import { toast } from "sonner"
import {
  ArrowDown,
  ArrowUp,
  ChevronLeft,
  ChevronRight,
  Download,
  FileText,
  Fish,
  ImageOff,
  Loader2,
  Search,
  SearchX,
  X,
} from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { ModuleLabel, RiskBadge, RiskMeter, StatusBadge } from "@/components/badges"
import { ErrorPanel } from "@/components/query-state"
import { triggerLabel } from "@/components/finding-detail"
import { EmptyState, MultiFilter, SimpleSelect } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Alert } from "@/lib/api"
import { ALERT_MODULES, MODULE_LABELS, RISK_LEVELS, STATUSES } from "@/lib/constants"
import { fmtDate, fmtDateTime, fmtNumber, fmtRelative, fmtTime } from "@/lib/format"
import { keys, useBrands } from "@/lib/queries"
import { cn } from "@/lib/utils"

const FILTER_KEYS = ["brand_id", "module", "risk_level", "status", "date_from", "date_to", "q", "suspected_phishing", "sort"]
const SORT_OPTIONS = [
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "risk", label: "Highest risk" },
  { value: "confidence", label: "Most certain" },
  { value: "last_seen", label: "Recently seen" },
]
const PAGE_SIZES = ["25", "50", "100"]

const features = tableFeatures({})
const helper = createColumnHelper<typeof features, Alert>()

function Thumb({ alert }: { alert: Alert }) {
  const [broken, setBroken] = useState(false)
  if (!alert.thumbnail_url || broken) {
    return (
      <div className="flex h-10 w-16 items-center justify-center rounded border border-dashed bg-muted/40 text-muted-foreground/60">
        <ImageOff className="size-3.5" aria-hidden />
      </div>
    )
  }
  return (
    <img
      src={alert.thumbnail_url}
      alt=""
      loading="lazy"
      referrerPolicy="no-referrer"
      onError={() => setBroken(true)}
      className="h-10 w-16 rounded border object-cover object-top"
    />
  )
}

function SortHeader({
  label,
  active,
  dir,
  onClick,
}: {
  label: string
  active: boolean
  dir?: "asc" | "desc"
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "-mx-1 inline-flex items-center gap-1 rounded px-1 outline-none hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring",
        active && "text-foreground",
      )}
    >
      {label}
      {active && <span className="sr-only">{dir === "asc" ? "(sorted oldest first)" : "(sorted descending)"}</span>}
      {active && (dir === "asc" ? <ArrowUp className="size-3" /> : <ArrowDown className="size-3" />)}
    </button>
  )
}

function ExportButtons({ query }: { query: URLSearchParams }) {
  const [busy, setBusy] = useState<"csv" | "pdf" | null>(null)
  const [simple, setSimple] = useState(false)
  const run = async (format: "csv" | "pdf") => {
    setBusy(format)
    try {
      const q = new URLSearchParams(query)
      if (simple) q.set("simple", "true")
      const name = await api.exportAlerts(format, q)
      toast.success(`Downloaded ${name}`)
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Export failed")
    } finally {
      setBusy(null)
    }
  }
  return (
    <>
      <label
        className="flex h-8 cursor-pointer items-center gap-2 rounded-lg border px-2.5 text-sm"
        title="Only brand, module, title, risk, score, status, alert time and link — no extra details"
      >
        <Checkbox checked={simple} onCheckedChange={(c) => setSimple(c === true)} disabled={busy !== null} />
        Simple format
      </label>
      <Button variant="outline" size="sm" onClick={() => run("csv")} disabled={busy !== null}>
        {busy === "csv" ? <Loader2 className="animate-spin" /> : <Download />}
        Export CSV
      </Button>
      <Button variant="outline" size="sm" onClick={() => run("pdf")} disabled={busy !== null}>
        {busy === "pdf" ? <Loader2 className="animate-spin" /> : <FileText />}
        Export PDF
      </Button>
    </>
  )
}

function AlertQueue() {
  const { params, update, toggle } = useUrlFilters()
  const router = useRouter()
  const brands = useBrands()

  const page = Math.max(1, Number(params.get("page") ?? 1) || 1)
  const pageSize = PAGE_SIZES.includes(params.get("page_size") ?? "") ? Number(params.get("page_size")) : 25
  const sort = params.get("sort") ?? "newest"
  const get = (k: string) => params.getAll(k)

  // Only forward known keys to the API
  const filterQuery = useMemo(() => {
    const q = new URLSearchParams()
    for (const k of FILTER_KEYS) for (const v of params.getAll(k)) if (v) q.append(k, v)
    return q
  }, [params])
  const listQuery = useMemo(() => {
    const q = new URLSearchParams(filterQuery)
    q.set("page", String(page))
    q.set("page_size", String(pageSize))
    return q
  }, [filterQuery, page, pageSize])

  // whether any scan has completed — "No threats detected." is only claimed after one has (RDA-22)
  const coverage = useQuery({ queryKey: keys.executive([]), queryFn: () => api.executive([]) })
  const alerts = useQuery({
    queryKey: keys.alerts(listQuery.toString()),
    queryFn: () => api.alerts(listQuery),
    placeholderData: keepPreviousData,
  })

  // Debounced free-text search → URL
  const urlQ = params.get("q") ?? ""
  const [q, setQ] = useState(urlQ)
  const [syncedQ, setSyncedQ] = useState(urlQ)
  if (urlQ !== syncedQ) {
    setSyncedQ(urlQ)
    setQ(urlQ)
  }
  useEffect(() => {
    if (q === urlQ) return
    const t = setTimeout(() => update({ q: q.trim() || null }), 350)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q])

  const columns = useMemo(
    () =>
      helper.columns([
        helper.display({
          id: "risk",
          header: () => (
            <SortHeader label="Risk" active={sort === "risk"} dir="desc" onClick={() => update({ sort: "risk" })} />
          ),
          cell: ({ row }) => <RiskBadge level={row.original.risk_level} score={row.original.score} />,
        }),
        helper.display({
          id: "thumb",
          header: () => <span className="sr-only">Screenshot</span>,
          cell: ({ row }) => <Thumb alert={row.original} />,
        }),
        helper.display({
          id: "title",
          header: () => "Finding",
          cell: ({ row }) => {
            const a = row.original
            return (
              <div className="min-w-[10rem] max-w-[24rem] whitespace-normal sm:min-w-[14rem]">
                <Link
                  href={`/alerts/${a.id}`}
                  className="line-clamp-2 font-medium [overflow-wrap:anywhere] outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
                  onClick={(e) => e.stopPropagation()}
                >
                  {a.title}
                </Link>
                <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
                  {a.suspected_phishing && (
                    <span className="inline-flex items-center gap-0.5 font-medium text-[var(--risk-critical-ink)]">
                      <Fish className="size-3" aria-hidden />
                      Phishing
                    </span>
                  )}
                  <span className="truncate font-mono">{a.entity_key}</span>
                </div>
                {a.reason && (
                  <div className="mt-0.5 line-clamp-2 text-xs text-muted-foreground" title={`${triggerLabel(a.trigger)}, ${fmtDateTime(a.alerted_at)}`}>
                    <span className="font-medium text-foreground/70">{triggerLabel(a.trigger)}:</span> {a.reason}
                  </div>
                )}
                <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs md:hidden">
                  <StatusBadge status={a.status} />
                  <span className="text-muted-foreground sm:hidden">
                    <ModuleLabel module={a.module} short />
                  </span>
                </div>
              </div>
            )
          },
        }),
        helper.display({
          id: "module",
          header: () => "Module",
          cell: ({ row }) => <ModuleLabel module={row.original.module} short />,
        }),
        helper.display({
          id: "brand",
          header: () => "Brand",
          cell: ({ row }) => <span className="whitespace-nowrap">{row.original.brand_name}</span>,
        }),
        helper.display({
          id: "status",
          header: () => "Decision",
          cell: ({ row }) => <StatusBadge status={row.original.status} />,
        }),
        helper.display({
          id: "first_seen",
          header: () => (
            <SortHeader
              label="First seen"
              active={sort === "newest" || sort === "oldest"}
              dir={sort === "oldest" ? "asc" : "desc"}
              onClick={() => update({ sort: sort === "newest" ? "oldest" : "newest" })}
            />
          ),
          cell: ({ row }) => (
            <span className="tnum block text-sm whitespace-nowrap" title={fmtDateTime(row.original.first_seen)}>
              {fmtDate(row.original.first_seen)}
              <span className="block text-xs text-muted-foreground">{fmtTime(row.original.first_seen)}</span>
            </span>
          ),
        }),
        helper.display({
          id: "last_seen",
          header: () => (
            <SortHeader label="Last seen" active={sort === "last_seen"} dir="desc" onClick={() => update({ sort: "last_seen" })} />
          ),
          cell: ({ row }) => (
            <span className="whitespace-nowrap text-muted-foreground" title={fmtDateTime(row.original.last_seen)}>
              {fmtRelative(row.original.last_seen)}
            </span>
          ),
        }),
      ]),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sort, params],
  )

  const EMPTY: Alert[] = useMemo(() => [], [])
  const table = useTable({ features, columns, data: alerts.data?.items ?? EMPTY })

  const total = alerts.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)
  const activeFilters = FILTER_KEYS.filter((k) => k !== "sort" && params.getAll(k).some(Boolean)).length
  const cellClass: Record<string, string> = {
    thumb: "hidden md:table-cell w-[4.5rem]",
    brand: "hidden lg:table-cell",
    last_seen: "hidden xl:table-cell text-xs",
    module: "hidden sm:table-cell",
    status: "hidden md:table-cell",
    first_seen: "hidden sm:table-cell",
  }

  return (
    <>
      <PageHeader
        title="Alert queue"
        description="Findings that crossed their brand's alert level, newest alert per finding. Select a row to review evidence and record a decision."
        actions={<ExportButtons query={filterQuery} />}
      />

      <div className="mb-3 flex flex-col gap-2 rounded-lg border bg-card p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search title, domain, app, handle…"
              aria-label="Search alerts"
              className="h-8 pl-8"
            />
          </div>
          <MultiFilter
            label="Brand"
            value={get("brand_id")}
            onChange={toggle("brand_id")}
            options={(brands.data ?? []).map((b) => ({ value: b.id, label: b.name, text: b.name }))}
          />
          <MultiFilter
            label="Module"
            value={get("module")}
            onChange={toggle("module")}
            options={ALERT_MODULES.map((m) => ({ value: m, label: MODULE_LABELS[m], text: MODULE_LABELS[m] }))}
          />
          <MultiFilter
            label="Risk"
            value={get("risk_level")}
            onChange={toggle("risk_level")}
            options={RISK_LEVELS.map((r) => ({
              value: r,
              text: r,
              label: (
                <span className="flex items-center gap-2">
                  <RiskMeter level={r} />
                  {r}
                </span>
              ),
            }))}
          />
          <MultiFilter
            label="Decision"
            value={get("status")}
            onChange={toggle("status")}
            options={STATUSES.map((s) => ({ value: s, text: s, label: <StatusBadge status={s} /> }))}
          />
          <div className="flex items-center gap-1.5">
            <label className="sr-only" htmlFor="date_from">
              First seen from
            </label>
            <Input
              id="date_from"
              type="date"
              value={params.get("date_from") ?? ""}
              max={params.get("date_to") ?? undefined}
              onChange={(e) => update({ date_from: e.target.value || null })}
              className="h-8 w-[9.5rem] text-sm"
              title="First seen from"
            />
            <span className="text-xs text-muted-foreground">to</span>
            <label className="sr-only" htmlFor="date_to">
              First seen to
            </label>
            <Input
              id="date_to"
              type="date"
              value={params.get("date_to") ?? ""}
              min={params.get("date_from") ?? undefined}
              onChange={(e) => update({ date_to: e.target.value || null })}
              className="h-8 w-[9.5rem] text-sm"
              title="First seen to"
            />
          </div>
          <label className="flex h-8 cursor-pointer items-center gap-2 rounded-lg border px-2.5 text-sm">
            <Checkbox
              checked={params.get("suspected_phishing") === "true"}
              onCheckedChange={(c) => update({ suspected_phishing: c ? "true" : null })}
            />
            Suspected phishing only
          </label>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <div className="flex items-center gap-2 text-muted-foreground">
            <span className="tnum" aria-live="polite">
              {alerts.isLoading
                ? "Loading…"
                : alerts.error
                  ? "Alerts could not be loaded"
                  : `${fmtNumber(total)} ${total === 1 ? "alert" : "alerts"}`}
            </span>
            {alerts.isFetching && !alerts.isLoading && <Loader2 className="size-3.5 animate-spin" aria-label="Refreshing" />}
            {activeFilters > 0 && (
              <Button
                variant="ghost"
                size="xs"
                onClick={() => update(Object.fromEntries(FILTER_KEYS.filter((k) => k !== "sort").map((k) => [k, null])))}
              >
                <X />
                Clear {activeFilters} {activeFilters === 1 ? "filter" : "filters"}
              </Button>
            )}
          </div>
          <SimpleSelect
            ariaLabel="Sort"
            size="sm"
            value={sort}
            onChange={(v) => update({ sort: v })}
            options={SORT_OPTIONS}
            className="w-40"
          />
        </div>
      </div>

      <div className="overflow-hidden rounded-lg border bg-card">
        <Table>
          <TableHeader>
            {table.getHeaderGroups().map((group) => (
              <TableRow key={group.id} className="hover:bg-transparent">
                {group.headers.map((header) => (
                  <TableHead key={header.id} className={cn("h-9 text-xs text-muted-foreground", cellClass[header.column.id])}>
                    {header.isPlaceholder ? null : <table.FlexRender header={header} />}
                  </TableHead>
                ))}
              </TableRow>
            ))}
          </TableHeader>
          <TableBody>
            {alerts.isLoading &&
              Array.from({ length: 8 }).map((_, i) => (
                <TableRow key={i}>
                  {columns.map((c, j) => (
                    <TableCell key={j} className={cellClass[c.id ?? ""]}>
                      <Skeleton className="h-5 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            {!alerts.isLoading &&
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  onClick={() => router.push(`/alerts/${row.original.id}`)}
                  className="cursor-pointer"
                  style={{ boxShadow: `inset 3px 0 0 var(--risk-${row.original.risk_level.toLowerCase()})` }}
                >
                  {row.getAllCells().map((cell) => (
                    <TableCell key={cell.id} className={cn("py-2", cellClass[cell.column.id])}>
                      <table.FlexRender cell={cell} />
                    </TableCell>
                  ))}
                </TableRow>
              ))}
          </TableBody>
        </Table>
        {alerts.error && (
          <ErrorPanel error={alerts.error} onRetry={() => alerts.refetch()} title="Couldn't load alerts" className="m-3" />
        )}
        {!alerts.isLoading && !alerts.error && total === 0 && (
          <EmptyState
            icon={SearchX}
            title={
              activeFilters
                ? "No alerts match these filters"
                : coverage.data?.last_completed_scan_at
                  ? "No threats detected."
                  : "No scans have run yet"
            }
          >
            {activeFilters ? (
              "Widen the date range or clear a filter to see more."
            ) : (
              <>
                The scans that have run found nothing to flag. If no scan has run yet, start one from a brand&apos;s page, and
                check <Link href="/scans" className="underline underline-offset-2">Scans</Link> for parts that could not run.
              </>
            )}
          </EmptyState>
        )}
        {total > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t px-3 py-2 text-sm">
            <span className="tnum text-muted-foreground">
              {fmtNumber(from)}–{fmtNumber(to)} of {fmtNumber(total)}
            </span>
            <div className="flex items-center gap-2">
              <span className="hidden text-xs text-muted-foreground sm:inline">Rows</span>
              <SimpleSelect
                ariaLabel="Rows per page"
                size="sm"
                value={String(pageSize)}
                onChange={(v) => update({ page_size: v })}
                options={PAGE_SIZES.map((s) => ({ value: s, label: s }))}
                className="w-[4.5rem]"
              />
              <Button
                variant="outline"
                size="icon-sm"
                aria-label="Previous page"
                disabled={page <= 1}
                onClick={() => update({ page: page - 1 > 1 ? String(page - 1) : null }, false)}
              >
                <ChevronLeft />
              </Button>
              <span className="tnum text-xs">
                Page {page} of {pages}
              </span>
              <Button
                variant="outline"
                size="icon-sm"
                aria-label="Next page"
                disabled={page >= pages}
                onClick={() => update({ page: String(page + 1) }, false)}
              >
                <ChevronRight />
              </Button>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

export default function AlertsPage() {
  return (
    <Suspense>
      <AlertQueue />
    </Suspense>
  )
}

