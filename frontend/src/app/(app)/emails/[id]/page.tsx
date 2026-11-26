"use client"

import { useState } from "react"
import Link from "next/link"
import { useParams } from "next/navigation"
import { useQuery } from "@tanstack/react-query"
import { ArrowLeft, Download, FileQuestion, Maximize2 } from "lucide-react"
import { ModuleLabel, PhishingBadge, RiskBadge, StatusBadge } from "@/components/badges"
import {
  AttachmentTable,
  AuthPanel,
  NotCheckedNotice,
  SanitisedPreview,
  UrlTable,
} from "@/components/email-sections"
import { ScorePanel } from "@/components/finding-detail"
import { EmptyState, Panel } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type Evidence } from "@/lib/api"
import { channelLabelFor } from "@/lib/email"
import { fmtBytes, fmtDateTime } from "@/lib/format"
import { keys } from "@/lib/queries"

const IMAGE_KINDS = new Set(["screenshot", "image", "favicon"])
const EVIDENCE_LABELS: Record<string, string> = {
  screenshot: "Linked page screenshot",
  favicon: "Favicon",
  html: "Page HTML",
  metadata: "Email metadata",
  file: "Attachment",
  image: "Image",
}

// ------------------------------------------------------------------ evidence (raw .eml, attachments, screenshots)
function EvidenceGallery({ evidence }: { evidence: Evidence[] }) {
  const [open, setOpen] = useState<Evidence | null>(null)
  const images = evidence.filter((e) => IMAGE_KINDS.has(e.kind) && e.url)
  const files = evidence.filter((e) => !(IMAGE_KINDS.has(e.kind) && e.url))
  if (!evidence.length) return <EmptyState icon={FileQuestion} title="No evidence captured" className="py-8" />
  return (
    <div className="space-y-4">
      {images.length > 0 && (
        <div className="grid grid-cols-1 items-start gap-3 md:grid-cols-2">
          {images.map((e) => (
            <figure key={e.id} className="overflow-hidden rounded-md border bg-muted/30">
              <button
                type="button"
                onClick={() => setOpen(e)}
                className="group relative block w-full outline-none focus-visible:ring-2 focus-visible:ring-ring"
                aria-label={`Enlarge ${EVIDENCE_LABELS[e.kind] ?? e.kind}`}
              >
                {/* Screenshot of a linked page, captured server-side in an isolated browser — not remote email content. */}
                <img
                  src={e.url!}
                  alt={`${EVIDENCE_LABELS[e.kind] ?? e.kind} captured ${fmtDateTime(e.captured_at)}`}
                  referrerPolicy="no-referrer"
                  className="w-full bg-white object-contain object-top max-h-72"
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
                    {[e.content_type, e.size != null ? fmtBytes(e.size) : null, fmtDateTime(e.captured_at)]
                      .filter(Boolean)
                      .join(", ")}
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

// ------------------------------------------------------------------ header
function HeaderTable({ rows }: { rows: { label: string; value: string | null; mono?: boolean }[] }) {
  return (
    <dl className="grid grid-cols-1 gap-x-6 sm:grid-cols-2">
      {rows.map((r) => (
        <div key={r.label} className="grid grid-cols-[minmax(6rem,34%)_1fr] gap-3 border-b border-dashed py-2 text-sm last:border-0 sm:[&:nth-last-child(2)]:border-0">
          <dt className="text-muted-foreground">{r.label}</dt>
          <dd className="min-w-0 break-words">
            {r.value ? (
              <span className={r.mono ? "font-mono text-[13px] break-all" : undefined}>{r.value}</span>
            ) : (
              <span className="text-muted-foreground">—</span>
            )}
          </dd>
        </div>
      ))}
    </dl>
  )
}

export default function EmailDetailPage() {
  const { id } = useParams<{ id: string }>()
  const email = useQuery({ queryKey: keys.email(id), queryFn: () => api.email(id) })
  const e = email.data

  if (email.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-9 w-2/3" />
        <Skeleton className="h-80 w-full" />
      </div>
    )
  }
  if (!e) {
    return (
      <EmptyState
        icon={FileQuestion}
        title="Email not found"
        action={
          <Button render={<Link href="/emails" />} nativeButton={false}>
            Back to emails
          </Button>
        }
      >
        It may have been removed, or the link is incomplete.
      </EmptyState>
    )
  }

  const finding = e.finding
  const details = finding?.details ?? {}
  const str = (v: unknown): string | null => (v === null || v === undefined || v === "" ? null : String(v))
  const headerRows = [
    { label: "From", value: e.from_addr, mono: true },
    { label: "Reply-To", value: str(details["Reply-To"]), mono: true },
    { label: "Return-Path", value: str(details["Return-Path"]), mono: true },
    { label: "Sender IP", value: e.sender_ip, mono: true },
    { label: "Channel", value: channelLabelFor(e.channel) },
    { label: "Received", value: fmtDateTime(e.received_at) },
  ]

  return (
    <>
      <Link href="/emails" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-3.5" />
        Phishing emails
      </Link>

      <header
        className="mb-4 rounded-lg border bg-card p-4 sm:p-5"
        style={e.risk_level ? { boxShadow: `inset 4px 0 0 var(--risk-${e.risk_level.toLowerCase()})` } : undefined}
      >
        <div className="flex flex-wrap items-center gap-2">
          {e.risk_level && <RiskBadge level={e.risk_level} score={e.score ?? undefined} size="lg" />}
          {finding && <StatusBadge status={finding.decision} />}
          {finding?.suspected_phishing && <PhishingBadge />}
          {e.verdict && <span className="text-sm text-muted-foreground">{e.verdict}</span>}
        </div>
        <h1 className="mt-3 text-xl font-semibold tracking-tight [overflow-wrap:anywhere] sm:text-2xl">
          {e.subject || "(no subject)"}
        </h1>
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-sm text-muted-foreground">
          <span className="inline-flex items-center gap-1.5">
            <ModuleLabel module="email" />
          </span>
          {finding && (
            <Link href={`/brands/${finding.brand_id}`} className="hover:underline">
              {finding.brand_name}
            </Link>
          )}
          {finding && (
            <Link href={`/findings/${finding.id}`} className="font-medium text-foreground hover:underline">
              Open finding
            </Link>
          )}
        </div>
        <div className="mt-4">
          <HeaderTable rows={headerRows} />
        </div>
      </header>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          <NotCheckedNotice items={e.not_checked} />
          <AuthPanel details={details} />
          <UrlTable indicators={e.indicators} />
          <AttachmentTable indicators={e.indicators} />
          <SanitisedPreview email={e} />
          {finding && (
            <Panel title="Evidence" description={`${finding.evidence.length} ${finding.evidence.length === 1 ? "item" : "items"} captured`}>
              <EvidenceGallery evidence={finding.evidence} />
            </Panel>
          )}
        </div>
        <div className="space-y-4">
          {finding ? (
            <ScorePanel score={finding.score} signals={finding.signals} />
          ) : (
            <Panel title="Why this score">
              <p className="text-sm text-muted-foreground">This email has not produced a finding yet.</p>
            </Panel>
          )}
        </div>
      </div>
    </>
  )
}
