"use client"

import { Suspense, useEffect, useMemo, useState } from "react"
import Link from "next/link"
import { keepPreviousData, useQuery } from "@tanstack/react-query"
import {
  ChevronLeft,
  ChevronRight,
  Download,
  ExternalLink,
  Eye,
  FileText,
  Heart,
  ImageOff,
  Loader2,
  Search,
  SearchX,
  X,
} from "lucide-react"
import { toast } from "sonner"
import { PageHeader } from "@/components/app-shell"
import { ModuleLabel, RiskBadge, RiskMeter, StageBadge, StatusBadge } from "@/components/badges"
import { ErrorPanel } from "@/components/query-state"
import { EmptyState, MultiFilter, SimpleSelect } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { api, type Finding } from "@/lib/api"
import { RISK_LEVELS, SOCIAL_PLATFORMS, STAGES, STATUSES } from "@/lib/constants"
import { fmtDate, fmtDateTime, fmtNumber } from "@/lib/format"
import { keys } from "@/lib/queries"
import { useUrlFilters } from "@/lib/url-filters"
import { cn } from "@/lib/utils"

const SOCIAL_MODULES = ["social_media", "social"]
/** URL filter keys forwarded to GET /findings (modules are fixed for this page). */
const FILTER_KEYS = ["platform", "content_type", "stage", "decision", "risk_level", "q", "sort"]
const TYPE_OPTIONS = [
  { value: "all", label: "All types", types: [] as string[] },
  { value: "Video", label: "Videos", types: ["Video"] },
  { value: "Post", label: "Posts", types: ["Post"] },
  { value: "Ad", label: "Ads", types: ["Ad"] },
  { value: "Channel", label: "Channels and accounts", types: ["Channel", "Account"] },
]
const SORT_OPTIONS = [
  { value: "newest", label: "Newest first" },
  { value: "risk", label: "Highest risk" },
  { value: "last_seen", label: "Recently seen" },
  { value: "oldest", label: "Oldest first" },
]
const PAGE_SIZE = 24

const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v : null)
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null)
const list = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && !!x.trim()) : [])

function compact(n: number): string {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(n)
}

function Chip({ children, className }: { children: React.ReactNode; className?: string }) {
  return <span className={cn("inline-flex items-center rounded-md px-1.5 py-0.5 text-xs whitespace-nowrap", className)}>{children}</span>
}

function CardImage({ finding, platform }: { finding: Finding; platform: string | null }) {
  const [broken, setBroken] = useState(false)
  if (!finding.thumbnail_url || broken) {
    return (
      <div className="flex aspect-video w-full flex-col items-center justify-center gap-1 border-b bg-muted/40 text-muted-foreground/70">
        <ImageOff className="size-5" aria-hidden />
        <span className="text-xs">{platform ?? "No screenshot"}</span>
      </div>
    )
  }
  return (
    <img
      src={finding.thumbnail_url}
      alt={`Screenshot of ${finding.title}`}
      loading="lazy"
      referrerPolicy="no-referrer"
      onError={() => setBroken(true)}
      className="aspect-video w-full border-b bg-white object-cover object-top"
    />
  )
}

function SocialCard({ f }: { f: Finding }) {
  const d = f.details ?? {}
  const platform = str(d["Platform"])
  const type = str(d["Content Type"])
  const title = str(d["Title"]) ?? str(d["Display Name"]) ?? f.title
  const author = str(d["Author"]) ?? str(d["Username"])
  const published = str(d["Published"])
  const views = num(d["Views"])
  const likes = num(d["Likes"])
  const followers = num(d["Followers"]) ?? num(d["Subscribers"])
  const contacts = list(d["Scam Contacts"])
  const phrases = list(d["Scam Phrases"])
  const logo = d["Logo Match"] === true
  return (
    <article
      className="flex flex-col overflow-hidden rounded-lg border bg-card"
      style={{ boxShadow: `inset 0 3px 0 var(--risk-${f.risk_level.toLowerCase()})` }}
    >
      <Link href={`/findings/${f.id}`} className="block outline-none focus-visible:ring-2 focus-visible:ring-ring" tabIndex={-1}>
        <CardImage finding={f} platform={platform} />
      </Link>
      <div className="flex flex-1 flex-col gap-2 p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {platform && <Chip className="bg-foreground/10 font-medium">{platform}</Chip>}
          {type ? <Chip className="bg-muted">{type}</Chip> : f.module === "social" && <Chip className="bg-muted">Account</Chip>}
          <RiskBadge level={f.risk_level} score={f.score} />
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          <StageBadge stage={f.stage} />
          <StatusBadge status={f.decision} />
        </div>
        <Link
          href={`/findings/${f.id}`}
          className="line-clamp-2 text-sm font-medium [overflow-wrap:anywhere] outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring"
          title={title}
        >
          {title}
        </Link>
        <div className="flex flex-wrap items-center gap-x-2 gap-y-0.5 text-xs text-muted-foreground">
          {author && <span className="max-w-full truncate">{author}</span>}
          {published && <span title={published}>{fmtDate(published) || published}</span>}
          {views !== null && (
            <span className="tnum inline-flex items-center gap-0.5" title={`${fmtNumber(views)} views`}>
              <Eye className="size-3" aria-hidden />
              {compact(views)}
            </span>
          )}
          {likes !== null && (
            <span className="tnum inline-flex items-center gap-0.5" title={`${fmtNumber(likes)} likes`}>
              <Heart className="size-3" aria-hidden />
              {compact(likes)}
            </span>
          )}
          {followers !== null && <span className="tnum">{compact(followers)} followers</span>}
        </div>
        {contacts.length > 0 && (
          <div>
            <div className="mb-0.5 text-[11px] font-medium text-[var(--risk-critical-ink)]">Fake contact details</div>
            <ul className="flex flex-wrap gap-1">
              {contacts.slice(0, 4).map((c) => (
                <li
                  key={c}
                  className="rounded-md bg-[var(--risk-critical-wash)] px-1.5 py-0.5 font-mono text-[11px] break-all text-[var(--risk-critical-ink)]"
                >
                  {c}
                </li>
              ))}
              {contacts.length > 4 && <li className="text-[11px] text-muted-foreground">+{contacts.length - 4} more</li>}
            </ul>
          </div>
        )}
        {(phrases.length > 0 || logo) && (
          <div className="flex flex-wrap gap-1">
            {logo && <Chip className="bg-foreground/10 font-medium">Logo used</Chip>}
            {phrases.slice(0, 3).map((p) => (
              <Chip key={p} className="bg-[var(--risk-high-wash)] text-[var(--risk-high-ink)]">
                {p}
              </Chip>
            ))}
            {phrases.length > 3 && <span className="text-[11px] text-muted-foreground">+{phrases.length - 3} more</span>}
          </div>
        )}
        <div className="mt-auto flex flex-wrap gap-2 pt-1">
          {f.source_url && (
            <Button
              variant="outline"
              size="xs"
              render={<a href={f.source_url} target="_blank" rel="noopener noreferrer nofollow" referrerPolicy="no-referrer" />}
              nativeButton={false}
            >
              <ExternalLink />
              Open on {platform ?? "platform"}
            </Button>
          )}
          <Button size="xs" render={<Link href={`/findings/${f.id}`} />} nativeButton={false}>
            Details
          </Button>
        </div>
        <div className="text-[11px] text-muted-foreground" title={fmtDateTime(f.first_seen)}>
          <ModuleLabel module={f.module} short /> · first seen {fmtDate(f.first_seen)}
        </div>
      </div>
    </article>
  )
}

function ExportButtons({ query, disabled }: { query: URLSearchParams; disabled: boolean }) {
  const [busy, setBusy] = useState<"csv" | "pdf" | null>(null)
  const [linksOnly, setLinksOnly] = useState(false)
  const run = async (format: "csv" | "pdf") => {
    setBusy(format)
    try {
      const q = new URLSearchParams(query)
      if (linksOnly) q.set("links_only", "true")
      const name = await api.exportFindings(format, q)
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
        title="Export only the links, without any other details"
      >
        <Checkbox checked={linksOnly} onCheckedChange={(c) => setLinksOnly(c === true)} disabled={busy !== null} />
        Links only
      </label>
      <Button variant="outline" size="sm" onClick={() => run("csv")} disabled={disabled || busy !== null}>
        {busy === "csv" ? <Loader2 className="animate-spin" /> : <Download />}
        Export CSV
      </Button>
      <Button variant="outline" size="sm" onClick={() => run("pdf")} disabled={disabled || busy !== null}>
        {busy === "pdf" ? <Loader2 className="animate-spin" /> : <FileText />}
        Export PDF
      </Button>
    </>
  )
}

function SocialMedia() {
  const { params, update, toggle } = useUrlFilters()
  const page = Math.max(1, Number(params.get("page") ?? 1) || 1)
  const platform = params.get("platform") ?? "all"
  const typeValue = TYPE_OPTIONS.find((t) => t.types.length && t.types.every((x) => params.getAll("content_type").includes(x)))?.value ?? "all"
  const sort = params.get("sort") ?? "newest"
  const get = (k: string) => params.getAll(k)

  const listQuery = useMemo(() => {
    const q = new URLSearchParams()
    SOCIAL_MODULES.forEach((m) => q.append("module", m))
    for (const k of FILTER_KEYS) for (const v of params.getAll(k)) if (v) q.append(k, v)
    q.set("page", String(page))
    q.set("page_size", String(PAGE_SIZE))
    return q
  }, [params, page])

  /** Same filters as the grid, without paging — the export covers every matching item. */
  const exportQuery = useMemo(() => {
    const q = new URLSearchParams(listQuery)
    q.delete("page")
    q.delete("page_size")
    return q
  }, [listQuery])

  const findings = useQuery({
    queryKey: keys.findings(listQuery.toString()),
    queryFn: () => api.findings(listQuery),
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

  const rows = findings.data?.items ?? []
  const total = findings.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const activeFilters = FILTER_KEYS.filter((k) => k !== "sort" && params.getAll(k).some(Boolean)).length

  return (
    <>
      <PageHeader
        title="Social Media"
        description="Posts, videos, ads and accounts that use the brand on social platforms: fake customer-care numbers, scam offers, logo misuse and impersonation accounts."
        actions={<ExportButtons query={exportQuery} disabled={findings.isLoading || total === 0} />}
      />

      <Tabs value={platform} onValueChange={(v) => update({ platform: v === "all" ? null : String(v) })} className="mb-3">
        <div className="-mx-1 overflow-x-auto px-1 pb-1">
          <TabsList aria-label="Platform">
            <TabsTrigger value="all">All</TabsTrigger>
            {SOCIAL_PLATFORMS.map((p) => (
              <TabsTrigger key={p} value={p}>
                {p}
              </TabsTrigger>
            ))}
          </TabsList>
        </div>
      </Tabs>

      <div className="mb-3 flex flex-col gap-2 rounded-lg border bg-card p-3">
        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search title, author, phone number…"
              aria-label="Search social media findings"
              className="h-8 pl-8"
            />
          </div>
          <SimpleSelect
            ariaLabel="Content type"
            size="sm"
            value={typeValue}
            onChange={(v) => update({ content_type: TYPE_OPTIONS.find((t) => t.value === v)?.types ?? null })}
            options={TYPE_OPTIONS.map(({ value, label }) => ({ value, label }))}
            className="w-48"
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
        </div>
        <div className="flex flex-wrap items-center justify-between gap-2 text-sm">
          <div className="flex items-center gap-2 text-muted-foreground">
            <span className="tnum" aria-live="polite">
              {findings.isLoading
                ? "Loading…"
                : findings.error
                  ? "Findings could not be loaded"
                  : `${fmtNumber(total)} ${total === 1 ? "item" : "items"}${platform !== "all" ? ` on ${platform}` : " across all platforms"}`}
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

      {findings.error ? (
        <ErrorPanel error={findings.error} onRetry={() => findings.refetch()} title="Couldn't load social media findings" />
      ) : findings.isLoading ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <Skeleton key={i} className="h-80 w-full rounded-lg" />
          ))}
        </div>
      ) : total === 0 ? (
        <div className="rounded-lg border bg-card">
          {activeFilters ? (
            <EmptyState icon={SearchX} title="Nothing matches these filters">
              Choose another platform or clear a filter to see more.
            </EmptyState>
          ) : (
            <EmptyState icon={SearchX} title="No brand misuse found on social media yet">
              Run a scan from a brand&apos;s page, or add API keys on the{" "}
              <Link href="/integrations" className="underline underline-offset-2">
                Integrations
              </Link>{" "}
              page so more platforms can be searched.
            </EmptyState>
          )}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-4">
            {rows.map((f) => (
              <SocialCard key={f.id} f={f} />
            ))}
          </div>
          <div className="mt-3 flex items-center justify-end gap-2 text-sm">
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
        </>
      )}
    </>
  )
}

export default function SocialMediaPage() {
  return (
    <Suspense>
      <SocialMedia />
    </Suspense>
  )
}
