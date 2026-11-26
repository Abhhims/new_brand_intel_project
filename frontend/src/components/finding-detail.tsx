"use client"

/**
 * Building blocks shared by the alert detail and finding detail pages (SP2 finding model):
 * module output, score explanation, evidence, decision buttons, timeline, observations and alert history.
 */

import { useState } from "react"
import Link from "next/link"
import { useMutation, useQuery } from "@tanstack/react-query"
import { toast } from "sonner"
import { ArrowRight, Download, ExternalLink, FileQuestion, Loader2, Maximize2, TriangleAlert } from "lucide-react"
import { RiskBadge, StageBadge, StatusBadge } from "@/components/badges"
import { EmptyState, Panel } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api } from "@/lib/api"
import type { AlertEvent, AlertRecord, AlertSignals, Decision, Evidence, ModuleName, Observation } from "@/lib/api"
import {
  ALLOWLIST_MODULES,
  MONO_FIELDS,
  NOTE_REQUIRED,
  OUTPUT_FIELDS,
  RULE_LABELS,
  STATUSES,
  TRANSITIONS,
  TRIGGER_LABELS,
  decisionAction,
} from "@/lib/constants"
import { fmtBytes, fmtDateTime, fmtRelative, fmtValue, isEmptyValue } from "@/lib/format"
import { cn } from "@/lib/utils"

const IMAGE_KINDS = new Set(["screenshot", "image", "favicon"])
const EVIDENCE_LABELS: Record<string, string> = {
  screenshot: "Screenshot",
  favicon: "Favicon",
  html: "Page HTML",
  metadata: "Metadata",
  file: "File",
  ssl: "TLS certificate",
  whois: "WHOIS record",
  dns: "DNS records",
  image: "Image",
}
const SKIP_FIELDS = new Set(["Screenshot"])

export function shortId(id: string | null | undefined): string {
  return id ? id.slice(0, 8) : "—"
}

export function triggerLabel(trigger: string): string {
  return TRIGGER_LABELS[trigger] ?? trigger.replace(/_/g, " ")
}

/** Readable name of an entity-state fact, e.g. `login_form` → "Login form". */
function factLabel(key: string): string {
  const s = key.replace(/_/g, " ")
  return s.charAt(0).toUpperCase() + s.slice(1)
}

// ------------------------------------------------------------------ module output fields
function FieldValue({ label, value }: { label: string; value: unknown }) {
  if (typeof value === "boolean") {
    return (
      <span className={cn("font-medium", value ? "text-foreground" : "text-muted-foreground")}>{value ? "Yes" : "No"}</span>
    )
  }
  if (Array.isArray(value) && value.every((v) => typeof v !== "object")) {
    return (
      <ul className="flex flex-wrap gap-1">
        {value.map((v, i) => (
          <li key={i} className={cn("rounded bg-muted px-1.5 py-0.5 text-xs break-all", MONO_FIELDS.has(label) && "font-mono")}>
            {fmtValue(v)}
          </li>
        ))}
      </ul>
    )
  }
  return <span className={cn("break-words", MONO_FIELDS.has(label) && "font-mono text-[13px] break-all")}>{fmtValue(value)}</span>
}

export function ModuleFields({ module, details }: { module: ModuleName; details: Record<string, unknown> }) {
  const ordered = OUTPUT_FIELDS[module] ?? []
  const extra = Object.keys(details).filter((k) => !ordered.includes(k))
  const rows = [...ordered, ...extra].filter((k) => !SKIP_FIELDS.has(k) && !isEmptyValue(details[k]))
  if (!rows.length) return <p className="text-sm text-muted-foreground">This module reported no output fields.</p>
  return (
    <dl className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
      {rows.map((k) => (
        <div key={k} className="grid grid-cols-[minmax(8rem,40%)_1fr] gap-3 border-b border-dashed py-2 text-sm last:border-0">
          <dt className="text-muted-foreground">{k}</dt>
          <dd className="min-w-0">
            <FieldValue label={k} value={details[k]} />
          </dd>
        </div>
      ))}
    </dl>
  )
}

// ------------------------------------------------------------------ score explanation
const BANDS = [
  { from: 0, to: 29, level: "low" },
  { from: 30, to: 59, level: "medium" },
  { from: 60, to: 79, level: "high" },
  { from: 80, to: 100, level: "critical" },
]

export function ScorePanel({ score, signals }: { score: number; signals: AlertSignals }) {
  const rules = Object.entries(signals?.rules ?? {})
  const raw = signals?.raw_score
  return (
    <Panel title="Why this score" description="Points from the scoring rules that fired">
      <div className="mb-1 flex items-baseline justify-between">
        <span className="tnum text-3xl font-semibold">{score}</span>
        <span className="text-xs text-muted-foreground">out of 100</span>
      </div>
      <div className="relative mb-5">
        <div className="flex h-2 gap-[2px]">
          {BANDS.map((b) => (
            <span
              key={b.level}
              className="rounded-[2px]"
              style={{ flexGrow: b.to - b.from + 1, background: `var(--risk-${b.level})`, opacity: 0.35 }}
            />
          ))}
        </div>
        <span
          className="absolute -top-1 h-4 w-[3px] rounded-full bg-foreground ring-2 ring-card"
          style={{ left: `calc(${Math.min(100, Math.max(0, score))}% - 1.5px)` }}
          aria-hidden
        />
        <div className="tnum mt-1 flex justify-between text-[11px] text-muted-foreground">
          <span>0</span>
          <span>30</span>
          <span>60</span>
          <span>80</span>
          <span>100</span>
        </div>
      </div>
      {rules.length ? (
        <ul className="divide-y text-sm">
          {rules.map(([name, points]) => (
            <li key={name} className="flex items-start justify-between gap-3 py-1.5">
              <span>{RULE_LABELS[name] ?? name}</span>
              <span className="tnum shrink-0 font-medium">+{points}</span>
            </li>
          ))}
          <li className="flex justify-between gap-3 py-1.5 font-medium">
            <span>Rule total{raw !== undefined && raw >= 100 ? " (capped at 100)" : ""}</span>
            <span className="tnum">{raw ?? rules.reduce((a, [, p]) => a + Number(p), 0)}</span>
          </li>
        </ul>
      ) : (
        <p className="text-sm text-muted-foreground">No scoring rules fired.</p>
      )}
      {raw !== undefined && raw !== score && (
        <p className="mt-3 rounded-md bg-muted px-3 py-2 text-xs text-muted-foreground">
          Adjusted from {raw} to {score} to stay within the risk range this module can report.
        </p>
      )}
      {signals?.confidence && (
        <div className="mt-5 border-t pt-4">
          <div className="mb-2 flex items-baseline justify-between">
            <span className="text-sm font-medium">Confidence: {signals.confidence.level}</span>
            <span className="tnum text-xs text-muted-foreground">{signals.confidence.score} / 100</span>
          </div>
          <p className="mb-2 text-xs text-muted-foreground">
            How sure we are that this is a real brand threat (evidence quality), separate from the risk above.
          </p>
          <ul className="divide-y text-sm">
            {signals.confidence.factors.map((f) => (
              <li key={f.factor} className="flex items-start justify-between gap-3 py-1.5">
                <span>{f.why}</span>
                <span className="tnum shrink-0 font-medium">
                  {f.points > 0 ? "+" : ""}
                  {f.points}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </Panel>
  )
}

// ------------------------------------------------------------------ related findings (SP4)
export function RelatedPanel({ findingId }: { findingId: string }) {
  const related = useQuery({ queryKey: ["findings", "related", findingId], queryFn: () => api.related(findingId) })
  const rows = related.data ?? []
  if (related.isLoading || (!related.isError && rows.length === 0)) return null
  return (
    <Panel
      title="Related findings"
      description="Findings that share an identifier with this one. Strong links suggest the same operator; weak links (shared hosting, favicon) are not proof."
    >
      {related.isError ? (
        <p className="text-sm text-muted-foreground">Related findings could not be loaded.</p>
      ) : (
        <ul className="divide-y text-sm">
          {rows.map((r) => (
            <li key={`${r.finding_id}-${r.kind}-${r.value}`} className="py-2">
              <div className="flex items-start justify-between gap-3">
                <Link href={`/findings/${r.finding_id}`} className="min-w-0 truncate font-medium hover:underline">
                  {r.entity_key}
                </Link>
                <RiskBadge level={r.risk_level} score={r.score} />
              </div>
              <p className="mt-0.5 text-xs text-muted-foreground">
                {r.strong ? "Strong" : "Weak"} · {r.label}: <span className="font-mono">{r.value}</span>
              </p>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

// ------------------------------------------------------------------ evidence
export function EvidenceGallery({ evidence }: { evidence: Evidence[] }) {
  const [open, setOpen] = useState<Evidence | null>(null)
  const images = evidence.filter((e) => IMAGE_KINDS.has(e.kind) && e.url)
  const files = evidence.filter((e) => !(IMAGE_KINDS.has(e.kind) && e.url))
  if (!evidence.length) {
    return <EmptyState icon={FileQuestion} title="No evidence captured" className="py-8" />
  }
  return (
    <div className="space-y-4">
      {images.length > 0 && (
        <div className="grid grid-cols-1 items-start gap-3 md:grid-cols-2">
          {images.map((e, i) => (
            <figure key={e.id} className={cn("overflow-hidden rounded-md border bg-muted/30", i === 0 && e.kind === "screenshot" && "md:col-span-2")}>
              <button
                type="button"
                onClick={() => setOpen(e)}
                className="group relative block w-full outline-none focus-visible:ring-2 focus-visible:ring-ring"
                aria-label={`Enlarge ${EVIDENCE_LABELS[e.kind] ?? e.kind}`}
              >
                <img
                  src={e.url!}
                  alt={`${EVIDENCE_LABELS[e.kind] ?? e.kind} captured ${fmtDateTime(e.captured_at)}`}
                  referrerPolicy="no-referrer"
                  className={cn(
                    "w-full bg-white object-contain object-top",
                    e.kind === "favicon" ? "h-24 p-4" : i === 0 ? "max-h-[28rem]" : "max-h-64",
                  )}
                />
                <span className="absolute top-2 right-2 rounded-md bg-background/85 p-1.5 opacity-0 shadow-sm transition-opacity group-hover:opacity-100 group-focus-visible:opacity-100">
                  <Maximize2 className="size-3.5" />
                </span>
              </button>
              <figcaption className="flex items-center justify-between gap-2 border-t px-3 py-1.5 text-xs text-muted-foreground">
                <span>{EVIDENCE_LABELS[e.kind] ?? e.kind}</span>
                <span className="tnum">{fmtDateTime(e.captured_at)}</span>
              </figcaption>
            </figure>
          ))}
        </div>
      )}
      {files.length > 0 && (
        <ul className="divide-y rounded-md border">
          {files.map((e) => (
            <li key={e.id} className="px-3 py-2 text-sm">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="min-w-0">
                  <span className="font-medium">{EVIDENCE_LABELS[e.kind] ?? e.kind}</span>
                  <span className="ml-2 text-xs text-muted-foreground">
                    {[e.content_type, e.size != null ? fmtBytes(e.size) : null, fmtDateTime(e.captured_at)].filter(Boolean).join(", ")}
                  </span>
                  {e.sha256 && <div className="truncate font-mono text-[11px] text-muted-foreground">sha256 {e.sha256}</div>}
                </div>
                {e.url && (
                  <Button
                    variant="outline"
                    size="xs"
                    render={<a href={e.url} target="_blank" rel="noopener noreferrer" download />}
                    nativeButton={false}
                  >
                    <Download />
                    Download
                  </Button>
                )}
              </div>
              {Object.keys(e.meta ?? {}).length > 0 && (
                <details className="mt-1.5">
                  <summary className="cursor-pointer text-xs text-muted-foreground hover:text-foreground">Details</summary>
                  <pre className="mt-1.5 max-h-72 overflow-auto rounded bg-muted p-2.5 font-mono text-[11px] leading-relaxed whitespace-pre-wrap break-all">
                    {JSON.stringify(e.meta, null, 2)}
                  </pre>
                </details>
              )}
            </li>
          ))}
        </ul>
      )}
      <Dialog open={!!open} onOpenChange={(o) => !o && setOpen(null)}>
        <DialogContent className="max-h-[92vh] w-[min(96vw,1200px)] max-w-none overflow-auto p-3 sm:max-w-none">
          <DialogTitle className="text-sm">{open ? (EVIDENCE_LABELS[open.kind] ?? open.kind) : ""}</DialogTitle>
          <DialogDescription className="text-xs">{open ? `Captured ${fmtDateTime(open.captured_at)}` : ""}</DialogDescription>
          {open?.url && <img src={open.url} alt="" referrerPolicy="no-referrer" className="w-full rounded border bg-white" />}
        </DialogContent>
      </Dialog>
    </div>
  )
}

/** Warning strip with the suspicious source URL; opening it is the analyst's explicit choice. */
export function SourceWarning({ url }: { url: string }) {
  return (
    <div className="mt-4 flex flex-col gap-2 rounded-md border border-[var(--risk-high)]/40 bg-[var(--risk-high-wash)] p-3 text-sm sm:flex-row sm:items-center sm:justify-between">
      <div className="flex min-w-0 items-start gap-2 text-[var(--risk-high-ink)]">
        <TriangleAlert className="mt-0.5 size-4 shrink-0" aria-hidden />
        <div className="min-w-0">
          <div className="font-medium">Suspicious source. Open only in an isolated browser and never enter credentials.</div>
          <div className="font-mono text-xs break-all opacity-90">{url}</div>
        </div>
      </div>
      <Button
        variant="outline"
        size="sm"
        className="shrink-0"
        render={<a href={url} target="_blank" rel="noopener noreferrer nofollow" referrerPolicy="no-referrer" />}
        nativeButton={false}
      >
        <ExternalLink />
        Open source
      </Button>
    </div>
  )
}

// ------------------------------------------------------------------ decision workflow
export interface DecisionVars {
  decision: Decision
  note: string
  addToAllowlist: boolean
}

/**
 * One button per allowed transition (D-35). Decisions that need a reason (False Positive, Legitimate, Ignored)
 * open a note dialog; Legitimate can also add the entity to the brand allowlist for the modules that support it.
 */
export function DecisionControl({
  current,
  module,
  note,
  decidedBy,
  decidedAt,
  onDecide,
  onDone,
}: {
  current: Decision
  module: ModuleName
  note?: string | null
  decidedBy?: string | null
  decidedAt?: string | null
  onDecide: (vars: DecisionVars) => Promise<unknown>
  onDone?: (decision: Decision) => void
}) {
  const options = TRANSITIONS[current] ?? []
  const [dialog, setDialog] = useState<Decision | null>(null)
  const [text, setText] = useState("")
  const [allow, setAllow] = useState(false)
  const mutation = useMutation({
    mutationFn: onDecide,
    onSuccess: (_, vars) => {
      toast.success(`Decision recorded: ${vars.decision}`)
      setDialog(null)
      setText("")
      setAllow(false)
      onDone?.(vars.decision)
    },
  })
  const choose = (d: Decision) => {
    if (NOTE_REQUIRED.has(d)) {
      setDialog(d)
      setText("")
      setAllow(false)
    } else {
      mutation.mutate({ decision: d, note: "", addToAllowlist: false })
    }
  }
  const required = dialog ? NOTE_REQUIRED.has(dialog) : false
  const offerAllow = dialog === "Legitimate" && ALLOWLIST_MODULES.has(module)

  return (
    <Panel title="Decision" description="Record what this finding is">
      <div className="mb-3 flex flex-wrap items-center gap-2 text-sm">
        <span className="text-muted-foreground">Current</span>
        <StatusBadge status={current} />
      </div>
      {note && (
        <p className="mb-3 rounded-md bg-muted px-2.5 py-1.5 text-sm whitespace-pre-wrap break-words">
          {note}
          {(decidedBy || decidedAt) && (
            <span className="mt-1 block text-[11px] text-muted-foreground">
              {[decidedBy, decidedAt ? fmtDateTime(decidedAt) : null].filter(Boolean).join(", ")}
            </span>
          )}
        </p>
      )}
      {options.length === 0 ? (
        <p className="text-sm text-muted-foreground">No further decisions are possible from here.</p>
      ) : (
        <div className="grid grid-cols-2 gap-2">
          {options.map((d) => (
            <Button
              key={d}
              variant={d === "Confirmed Threat" ? "destructive" : "outline"}
              size="sm"
              disabled={mutation.isPending}
              onClick={() => choose(d)}
              title={`Set the decision to ${d}${NOTE_REQUIRED.has(d) ? " (needs a note)" : ""}`}
            >
              {mutation.isPending && mutation.variables?.decision === d && <Loader2 className="animate-spin" />}
              {decisionAction(current, d)}
            </Button>
          ))}
        </div>
      )}
      {mutation.error && !dialog && <p className="mt-2 text-xs text-destructive">{mutation.error.message}</p>}

      <Dialog open={!!dialog} onOpenChange={(o) => !o && !mutation.isPending && setDialog(null)}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Mark as {dialog}</DialogTitle>
            <DialogDescription>
              {required ? "A note is required so other analysts know why." : "Add a note for other analysts (optional)."}
            </DialogDescription>
          </DialogHeader>
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault()
              if (dialog && (!required || text.trim())) mutation.mutate({ decision: dialog, note: text, addToAllowlist: offerAllow && allow })
            }}
          >
            <div className="space-y-1.5">
              <Label htmlFor="decision-note">Note{required ? "" : " (optional)"}</Label>
              <Textarea
                id="decision-note"
                value={text}
                onChange={(e) => setText(e.target.value)}
                maxLength={2000}
                rows={4}
                required={required}
                placeholder="What did you check? Why this decision?"
              />
            </div>
            {offerAllow && (
              <label className="flex cursor-pointer items-start gap-2 text-sm">
                <Checkbox checked={allow} onCheckedChange={(c) => setAllow(!!c)} className="mt-0.5" />
                <span>
                  Also add to the brand allowlist
                  <span className="block text-xs text-muted-foreground">Future scans will not report this entity again</span>
                </span>
              </label>
            )}
            {mutation.error && <p className="text-xs text-destructive">{mutation.error.message}</p>}
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => setDialog(null)} disabled={mutation.isPending}>
                Cancel
              </Button>
              <Button type="submit" disabled={mutation.isPending || (required && !text.trim())}>
                {mutation.isPending && <Loader2 className="animate-spin" />}
                Mark as {dialog}
              </Button>
            </DialogFooter>
          </form>
        </DialogContent>
      </Dialog>
    </Panel>
  )
}

// ------------------------------------------------------------------ timeline
const EVENT_LABELS: Record<string, string> = {
  discovered: "Discovered",
  promoted: "Promoted to finding",
  changed: "Changed",
  rescored: "Risk rescored",
  stage: "Stage changed",
  alerted: "Alert raised",
  decision: "Decision",
  reopened: "Reopened",
  app_status: "App status changed",
  status: "Status changed",
}

function TransitionValue({ value }: { value: string }) {
  if ((STATUSES as string[]).includes(value)) return <StatusBadge status={value as Decision} />
  return <span className="rounded bg-muted px-1.5 py-0.5 text-xs">{value}</span>
}

export function Timeline({ events }: { events: AlertEvent[] }) {
  return (
    <Panel title="Timeline" description="Everything that happened to this finding, newest first">
      {events.length === 0 ? (
        <p className="text-sm text-muted-foreground">No activity recorded yet.</p>
      ) : (
        <ol className="relative space-y-4 border-l pl-4">
          {events.map((ev) => (
            <li key={ev.id} className="relative text-sm">
              <span
                className={cn(
                  "absolute top-1.5 -left-[21px] size-2.5 rounded-full border-2 border-card",
                  ev.kind === "alerted" ? "bg-[var(--risk-high)]" : "bg-muted-foreground/60",
                )}
                aria-hidden
              />
              <div className="flex flex-wrap items-baseline justify-between gap-x-2">
                <span className="font-medium">{EVENT_LABELS[ev.kind] ?? factLabel(ev.kind)}</span>
                <time className="text-xs text-muted-foreground" dateTime={ev.at} title={fmtDateTime(ev.at)}>
                  {fmtRelative(ev.at)}
                </time>
              </div>
              {(ev.from_status || ev.to_status) && (
                <div className="mt-1 flex flex-wrap items-center gap-1.5">
                  {ev.from_status && <TransitionValue value={ev.from_status} />}
                  {ev.from_status && ev.to_status && <ArrowRight className="size-3 text-muted-foreground" aria-label="to" />}
                  {ev.to_status && <TransitionValue value={ev.to_status} />}
                </div>
              )}
              {ev.note && <p className="mt-1.5 rounded-md bg-muted px-2.5 py-1.5 whitespace-pre-wrap break-words">{ev.note}</p>}
              <div className="mt-0.5 text-[11px] text-muted-foreground">
                {ev.user_name ?? "System"}, {fmtDateTime(ev.at)}
              </div>
            </li>
          ))}
        </ol>
      )}
    </Panel>
  )
}

// ------------------------------------------------------------------ observations
function StateFacts({ state }: { state: Record<string, unknown> }) {
  const entries = Object.entries(state ?? {}).filter(([, v]) => v !== null && v !== undefined && typeof v !== "object")
  if (!entries.length) return <span className="text-muted-foreground">—</span>
  return (
    <ul className="flex flex-wrap gap-1">
      {entries.slice(0, 6).map(([k, v]) => (
        <li
          key={k}
          className={cn(
            "rounded px-1.5 py-0.5 text-xs whitespace-nowrap",
            v === true ? "bg-foreground/10 font-medium" : "bg-muted text-muted-foreground",
          )}
        >
          {factLabel(k)}: {typeof v === "boolean" ? (v ? "yes" : "no") : String(v)}
        </li>
      ))}
    </ul>
  )
}

export function ObservationsTable({ observations }: { observations: Observation[] }) {
  return (
    <Panel title="Observations" description="Each time a scan saw this entity" bodyClassName="p-0">
      {observations.length === 0 ? (
        <p className="p-4 text-sm text-muted-foreground">No observations recorded.</p>
      ) : (
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="h-9 text-xs text-muted-foreground">Observed</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground sm:table-cell">Scan</TableHead>
              <TableHead className="h-9 text-xs text-muted-foreground">Stage</TableHead>
              <TableHead className="h-9 text-xs text-muted-foreground">Risk</TableHead>
              <TableHead className="hidden h-9 text-xs text-muted-foreground md:table-cell">State</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {observations.map((o) => (
              <TableRow key={o.id}>
                <TableCell className="tnum py-2 text-sm whitespace-nowrap" title={fmtDateTime(o.observed_at)}>
                  {fmtDateTime(o.observed_at)}
                  <span className="block text-xs text-muted-foreground">{o.channel}</span>
                </TableCell>
                <TableCell className="hidden py-2 font-mono text-xs text-muted-foreground sm:table-cell" title={o.scan_id ?? undefined}>
                  {shortId(o.scan_id)}
                </TableCell>
                <TableCell className="py-2">
                  <StageBadge stage={o.stage} />
                </TableCell>
                <TableCell className="py-2">
                  <RiskBadge level={o.risk_level} score={o.score} />
                </TableCell>
                <TableCell className="hidden py-2 whitespace-normal md:table-cell">
                  <StateFacts state={o.state} />
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </Panel>
  )
}

// ------------------------------------------------------------------ alert history
export function AlertHistory({ alerts, currentId }: { alerts: AlertRecord[]; currentId?: string }) {
  const sorted = [...alerts].sort((a, b) => b.created_at.localeCompare(a.created_at))
  return (
    <Panel title="Alert history" description="Every alert raised for this finding">
      {sorted.length === 0 ? (
        <p className="text-sm text-muted-foreground">No alert has been raised. The finding is below the brand&apos;s alert level or still a candidate.</p>
      ) : (
        <ul className="divide-y text-sm">
          {sorted.map((a) => (
            <li key={a.id} className="py-2 first:pt-0 last:pb-0">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <RiskBadge level={a.risk_level} score={a.score} />
                <time className="tnum text-xs text-muted-foreground" dateTime={a.created_at}>
                  {fmtDateTime(a.created_at)}
                </time>
              </div>
              <p className="mt-1 break-words">{a.reason}</p>
              <div className="mt-0.5 flex flex-wrap items-center gap-x-2 text-xs text-muted-foreground">
                <span>{triggerLabel(a.trigger)}</span>
                {a.id === currentId ? (
                  <span className="font-medium text-foreground">This alert</span>
                ) : (
                  <Link href={`/alerts/${a.id}`} className="underline underline-offset-2 hover:text-foreground">
                    Open alert
                  </Link>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

// ------------------------------------------------------------------ social media brand misuse
function strList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && x.trim() !== "") : []
}

/** Fake contact details and scam wording from a social_media finding, shown before the generic module output. */
export function SocialMisusePanel({
  details,
  sourceUrl,
}: {
  details: Record<string, unknown>
  sourceUrl: string | null
}) {
  const contacts = strList(details["Scam Contacts"])
  const phrases = strList(details["Scam Phrases"])
  const terms = strList(details["Brand Terms"])
  const platform = typeof details["Platform"] === "string" ? (details["Platform"] as string) : "the platform"
  const excerpt = typeof details["Text Excerpt"] === "string" ? (details["Text Excerpt"] as string) : ""
  return (
    <Panel
      title="Brand misuse"
      description={[details["Platform"], details["Content Type"]].filter(Boolean).join(" · ") || undefined}
      actions={
        sourceUrl ? (
          <Button
            variant="outline"
            size="sm"
            render={<a href={sourceUrl} target="_blank" rel="noopener noreferrer nofollow" referrerPolicy="no-referrer" />}
            nativeButton={false}
          >
            <ExternalLink />
            Open on {platform}
          </Button>
        ) : undefined
      }
    >
      <div className="space-y-3 text-sm">
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">Fake contact details</div>
          {contacts.length ? (
            <ul className="flex flex-wrap gap-1.5">
              {contacts.map((c) => (
                <li
                  key={c}
                  className="rounded-md bg-[var(--risk-critical-wash)] px-2 py-0.5 font-mono text-xs break-all text-[var(--risk-critical-ink)] ring-1 ring-[var(--risk-critical)]/30 ring-inset"
                >
                  {c}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted-foreground">None found.</p>
          )}
        </div>
        <div>
          <div className="mb-1 text-xs font-medium text-muted-foreground">Scam wording</div>
          {phrases.length ? (
            <ul className="flex flex-wrap gap-1.5">
              {phrases.map((p) => (
                <li key={p} className="rounded-md bg-[var(--risk-high-wash)] px-2 py-0.5 text-xs text-[var(--risk-high-ink)]">
                  {p}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-muted-foreground">None found.</p>
          )}
        </div>
        {(terms.length > 0 || details["Logo Match"] === true) && (
          <div className="flex flex-wrap items-center gap-1.5">
            {details["Logo Match"] === true && (
              <span className="rounded-md bg-foreground/10 px-2 py-0.5 text-xs font-medium">Official logo used</span>
            )}
            {terms.map((t) => (
              <span key={t} className="rounded-md bg-muted px-2 py-0.5 text-xs">
                {t}
              </span>
            ))}
          </div>
        )}
        {excerpt && (
          <blockquote className="rounded-md border-l-2 bg-muted/50 px-3 py-2 text-[13px] whitespace-pre-wrap break-words text-muted-foreground">
            {excerpt}
          </blockquote>
        )}
      </div>
    </Panel>
  )
}
