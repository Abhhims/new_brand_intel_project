"use client"

import { Suspense, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ChevronLeft, ChevronRight, Fish, ImageOff, Loader2, Search, SearchX, X } from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { ModuleLabel, RiskBadge, RiskMeter, StageBadge, StatusBadge } from "@/components/badges"
import { ErrorPanel } from "@/components/query-state"
import { EmptyState, MultiFilter, SimpleSelect } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { Textarea } from "@/components/ui/textarea"
import { api, type Decision, type Finding } from "@/lib/api"
import { ALERT_MODULES, MODULE_LABELS, NOTE_REQUIRED, RISK_LEVELS, STAGES, STATUSES } from "@/lib/constants"
import { fmtDate, fmtDateTime, fmtNumber, fmtRelative } from "@/lib/format"
import { keys, useBrands } from "@/lib/queries"
import { useUrlFilters } from "@/lib/url-filters"

const FILTER_KEYS = ["brand_id", "module", "stage", "decision", "risk_level", "alerted", "q", "sort"]
const SORT_OPTIONS = [
  { value: "newest", label: "Newest first" },
  { value: "oldest", label: "Oldest first" },
  { value: "risk", label: "Highest risk" },
  { value: "confidence", label: "Most certain" },
  { value: "last_seen", label: "Recently seen" },
]
const ALERTED_OPTIONS = [
  { value: "any", label: "Alerted or not" },
  { value: "true", label: "Alerted" },
  { value: "false", label: "Not alerted" },
]
const PAGE_SIZES = ["25", "50", "100"]

function Thumb({ url }: { url: string | null }) {
  const [broken, setBroken] = useState(false)
  if (!url || broken) {
    return (
      <div className="flex h-10 w-16 items-center justify-center rounded border border-dashed bg-muted/40 text-muted-foreground/60">
        <ImageOff className="size-3.5" aria-hidden />
      </div>
    )
  }
  return (
    <img
      src={url}
      alt=""
      loading="lazy"
      referrerPolicy="no-referrer"
      onError={() => setBroken(true)}
      className="h-10 w-16 rounded border object-cover object-top"
    />
  )
}

/** Same decision and note for every selected finding; the backend applies all or none (D-35). */
function BulkDecision({ ids, onDone }: { ids: string[]; onDone: () => void }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const [decision, setDecision] = useState<Decision | null>(null)
  const [note, setNote] = useState("")
  const required = decision ? NOTE_REQUIRED.has(decision) : false
  const mutation = useMutation({
    mutationFn: () => api.bulkDecide(ids, decision!, note),
    onSuccess: (rows) => {
      toast.success(`${rows.length} ${rows.length === 1 ? "finding" : "findings"} marked as ${decision}`)
      qc.invalidateQueries({ queryKey: ["findings"] })
      qc.invalidateQueries({ queryKey: ["alerts"] })
      qc.invalidateQueries({ queryKey: ["stats"] })
      setOpen(false)
      setDecision(null)
      setNote("")
      onDone()
    },
  })
  return (
    <>
      <Button size="sm" onClick={() => setOpen(true)} disabled={!ids.length}>
        Set decision…
      </Button>
      <Dialog open={open} onOpenChange={(o) => !mutation.isPending && setOpen(o)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              Decide {ids.length} {ids.length === 1 ? "finding" : "findings"}
            </DialogTitle>
            <DialogDescription>
              The same decision and note are applied to every selected finding. If any of them cannot move to this decision,
              nothing is changed.
            </DialogDescription>
          </DialogHeader>
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault()
              if (decision && (!required || note.trim())) mutation.mutate()
            }}
          >
            <div className="space-y-1.5">
              <Label>Decision</Label>
              <SimpleSelect
                ariaLabel="Decision"
                value={decision}
                onChange={(v) => setDecision(v as Decision)}
                options={STATUSES.map((s) => ({ value: s, label: s }))}
                placeholder="Choose a decision"
                className="w-full"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="bulk-note">Note{required ? "" : " (optional)"}</Label>
              <Textarea
                id="bulk-note"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                maxLength={2000}
                rows={3}
                required={required}
                placeholder="What did you check? Why this decision?"
              />
              {required && <p className="text-xs text-muted-foreground">A note is required for {decision}.</p>}
            </div>
            {mutation.error && <p className="text-xs text-destructive">{mutation.error.message}</p>}
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setOpen(false)} disabled={mutation.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={!decision || mutation.isPending || (required && !note.trim())}>
                {mutation.isPending && <Loader2 className="animate-spin" />}
                Apply to {ids.length}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </>
  )
}

function FindingsList() {
  const { params, update, toggle } = useUrlFilters()
  const router = useRouter()
  const brands = useBrands()

  const page = Math.max(1, Number(params.get("page") ?? 1) || 1)
  const pageSize = PAGE_SIZES.includes(params.get("page_size") ?? "") ? Number(params.get("page_size")) : 25
  const sort = params.get("sort") ?? "newest"
  const get = (k: string) => params.getAll(k)

  const listQuery = useMemo(() => {
    const q = new URLSearchParams()
    for (const k of FILTER_KEYS) for (const v of params.getAll(k)) if (v) q.append(k, v)
    q.set("page", String(page))
    q.set("page_size", String(pageSize))
    return q
  }, [params, page, pageSize])

  const findings = useQuery({
    queryKey: keys.findings(listQuery.toString()),
    queryFn: () => api.findings(listQuery),
    placeholderData: keepPreviousData,
  })

  // Selection is per page view: changing filters or page clears it
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [selectionKey, setSelectionKey] = useState(listQuery.toString())
  if (selectionKey !== listQuery.toString()) {
    setSelectionKey(listQuery.toString())
    setSelected(new Set())
  }

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

  const rows: Finding[] = findings.data?.items ?? []
  const total = findings.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / pageSize))
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1
  const to = Math.min(total, page * pageSize)
  const activeFilters = FILTER_KEYS.filter((k) => k !== "sort" && params.getAll(k).some(Boolean)).length
  const allChecked = rows.length > 0 && rows.every((r) => selected.has(r.id))
  const someChecked = rows.some((r) => selected.has(r.id))
  const toggleRow = (id: string, checked: boolean) =>
    setSelected((prev) => {
      const next = new Set(prev)
      if (checked) next.add(id)
      else next.delete(id)
      return next
    })

  return (
    <>
      <PageHeader
        title="Findings"
        description="Every entity the scanners have found, including candidates not yet analysed and findings below the alert level."
      />

      <div className="mb-3 flex flex-col gap-2 rounded-lg border bg-card p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search title, domain, app, handle…"
              aria-label="Search findings"
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
            label="Stage"
            value={get("stage")}
            onChange={toggle("stage")}
            options={STAGES.map((s) => ({ value: s, text: s, label: <StageBadge stage={s} /> }))}
          />
          <MultiFilter
            label="Decision"
            value={get("decision")}
            onChange={toggle("decision")}
            options={STATUSES.map((s) => ({ value: s, text: s, label: <StatusBadge status={s} /> }))}
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
          <SimpleSelect
            ariaLabel="Alerted"
            size="sm"
            value={params.get("alerted") ?? "any"}
            onChange={(v) => update({ alerted: v === "any" ? null : v })}
            options={ALERTED_OPTIONS}
            className="w-36"
          />
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <div className="flex items-center gap-2 text-muted-foreground">
            <span className="tnum" aria-live="polite">
              {findings.isLoading
                ? "Loading…"
                : findings.error
                  ? "Findings could not be loaded"
                  : `${fmtNumber(total)} ${total === 1 ? "finding" : "findings"}`}
            </span>
            {findings.isFetching && !findings.isLoading && <Loader2 className="size-3.5 animate-spin" aria-label="Refreshing" />}
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

      {selected.size > 0 && (
        <div className="mb-3 flex flex-wrap items-center justify-between gap-2 rounded-lg border border-primary/30 bg-primary/5 px-3 py-2 text-sm">
          <span className="tnum">
            {selected.size} {selected.size === 1 ? "finding" : "findings"} selected
          </span>
          <div className="flex items-center gap-2">
            <Button variant="ghost" size="sm" onClick={() => setSelected(new Set())}>
              Clear selection
            </Button>
            <BulkDecision ids={[...selected]} onDone={() => setSelected(new Set())} />
          </div>
        </div>
      )}

      <div className="overflow-hidden rounded-lg border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="h-9 w-8">
                <Checkbox
                  aria-label="Select all on this page"
                  checked={allChecked}
                  indeterminate={someChecked && !allChecked}
                  onCheckedChange={(c) => setSelected(c ? new Set(rows.map((r) => r.id)) : new Set())}
                  disabled={!rows.length}
                />
              </TableHead>
              <TableHead className="h-9 text-xs text-muted-foreground">Risk</TableHead>
              <TableHead className="hidden h-9 w-[4.5rem] text-xs text-muted-foreground md:table-cell">
                <span className="sr-only">Screenshot</span>
              </TableHead>
              <TableHead className="h-9 text-xs text-muted-foreground">Finding</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground sm:table-cell">Module</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground lg:table-cell">Brand</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground md:table-cell">Stage</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground md:table-cell">Decision</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground xl:table-cell">Alerts</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground sm:table-cell">First seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {findings.isLoading &&
              Array.from({ length: 8 }).map((_, i) => (
                <TableRow key={i}>
                  {Array.from({ length: 10 }).map((__, j) => (
                    <TableCell key={j}>
                      <Skeleton className="h-5 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            {!findings.isLoading &&
              rows.map((f) => (
                <TableRow
                  key={f.id}
                  onClick={() => router.push(`/findings/${f.id}`)}
                  className="cursor-pointer"
                  data-state={selected.has(f.id) ? "selected" : undefined}
                  style={{ boxShadow: `inset 3px 0 0 var(--risk-${f.risk_level.toLowerCase()})` }}
                >
                  <TableCell className="py-2" onClick={(e) => e.stopPropagation()}>
                    <Checkbox
                      aria-label={`Select ${f.title}`}
                      checked={selected.has(f.id)}
                      onCheckedChange={(c) => toggleRow(f.id, !!c)}
                    />
                  </TableCell>
                  <TableCell className="py-2">
                    <RiskBadge level={f.risk_level} score={f.score} />
                  </TableCell>
                  <TableCell className="hidden py-2 md:table-cell">
                    <Thumb url={f.thumbnail_url} />
                  </TableCell>
                  <TableCell className="py-2">
                    <div className="min-w-[10rem] max-w-[24rem] whitespace-normal sm:min-w-[14rem]">
                      <Link
                        href={`/findings/${f.id}`}
                        className="line-clamp-2 font-medium [overflow-wrap:anywhere] outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {f.title}
                      </Link>
                      <div className="mt-0.5 flex items-center gap-1.5 text-xs text-muted-foreground">
                        {f.suspected_phishing && (
                          <span className="inline-flex items-center gap-0.5 font-medium text-[var(--risk-critical-ink)]">
                            <Fish className="size-3" aria-hidden />
                            Phishing
                          </span>
                        )}
                        <span className="truncate font-mono">{f.entity_key}</span>
                      </div>
                      <div className="mt-1 flex flex-wrap items-center gap-1.5 text-xs md:hidden">
                        <StageBadge stage={f.stage} />
                        <StatusBadge status={f.decision} />
                      </div>
                    </div>
                  </TableCell>
                  <TableCell className="hidden py-2 sm:table-cell">
                    <ModuleLabel module={f.module} short />
                  </TableCell>
                  <TableCell className="hidden py-2 lg:table-cell">
                    <span className="whitespace-nowrap">{f.brand_name}</span>
                  </TableCell>
                  <TableCell className="hidden py-2 md:table-cell">
                    <StageBadge stage={f.stage} />
                  </TableCell>
                  <TableCell className="hidden py-2 md:table-cell">
                    <StatusBadge status={f.decision} />
                  </TableCell>
                  <TableCell className="hidden py-2 text-xs xl:table-cell">
                    {f.last_alert_at ? (
                      <span className="whitespace-nowrap" title={`Last alert ${fmtDateTime(f.last_alert_at)}`}>
                        <span className="tnum">{f.alert_count}</span>
                        <span className="text-muted-foreground">, {fmtRelative(f.last_alert_at)}</span>
                      </span>
                    ) : (
                      <span className="text-muted-foreground">Not alerted</span>
                    )}
                  </TableCell>
                  <TableCell className="hidden py-2 sm:table-cell">
                    <span className="tnum text-sm whitespace-nowrap" title={fmtDateTime(f.first_seen)}>
                      {fmtDate(f.first_seen)}
                    </span>
                  </TableCell>
                </TableRow>
              ))}
          </TableBody>
        </Table>
        {findings.error && (
          <ErrorPanel error={findings.error} onRetry={() => findings.refetch()} title="Couldn't load findings" className="m-3" />
        )}
        {!findings.isLoading && !findings.error && total === 0 && (
          <EmptyState icon={SearchX} title={activeFilters ? "No findings match these filters" : "No findings yet"}>
            {activeFilters ? (
              "Clear a filter to see more."
            ) : (
              <>
                Findings appear here once a scan has run. Start one from a brand&apos;s page, and check{" "}
                <Link href="/scans" className="underline underline-offset-2">
                  Scans
                </Link>{" "}
                for parts that could not run.
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

export default function FindingsPage() {
  return (
    <Suspense>
      <FindingsList />
    </Suspense>
  )
}
