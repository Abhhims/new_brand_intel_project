"use client"

/**
 * Shared, safe renderers for analysed phishing emails (D-28, spec §6).
 *
 * SECURITY: every value here (subject, sender, URLs, attachment names, tool details)
 * is hostile, untrusted email content. It is only ever placed as React text — React
 * escapes it. We NEVER use dangerouslySetInnerHTML, never render email HTML, never load
 * remote images from the email, and never turn an email link into a live <a href>.
 */

import { CircleCheck, CircleX, Link2, MinusCircle, Paperclip, ShieldQuestion } from "lucide-react"
import { Panel } from "@/components/widgets"
import type { EmailDetail, EmailIndicator, EmailVerdict, NotCheckedItem } from "@/lib/api"
import { cn } from "@/lib/utils"

// ------------------------------------------------------------------ tool labels
const TOOL_LABELS: Record<string, string> = {
  clamav: "ClamAV",
  yara: "YARA",
  urlhaus: "URLhaus",
  urlhaus_hash: "URLhaus hash",
  openphish: "OpenPhish",
  urlscan: "urlscan.io",
  abuseipdb: "AbuseIPDB",
  rspamd: "Rspamd",
}
function toolLabel(tool: string): string {
  return TOOL_LABELS[tool] ?? tool
}

// ------------------------------------------------------------------ tone helpers
type Tone = "ok" | "bad" | "warn" | "muted"

const TONE_CLASS: Record<Tone, string> = {
  ok: "text-emerald-800 dark:text-emerald-300 bg-emerald-50 dark:bg-emerald-950/40 ring-emerald-200 dark:ring-emerald-900",
  bad: "text-rose-800 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/40 ring-rose-200 dark:ring-rose-900",
  warn: "text-amber-800 dark:text-amber-300 bg-amber-50 dark:bg-amber-950/40 ring-amber-200 dark:ring-amber-900",
  muted: "text-muted-foreground bg-muted ring-border",
}

function Chip({ tone, children, className }: { tone: Tone; children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md px-1.5 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        TONE_CLASS[tone],
        className,
      )}
    >
      {children}
    </span>
  )
}

/** First token of an auth value, e.g. "fail (independent: fail)" → "fail". */
function authTone(value: string): Tone {
  const t = value.trim().toLowerCase().split(/[\s(]/)[0]
  if (["pass", "no action", "no_action"].includes(t)) return "ok"
  if (["fail", "softfail", "permerror", "reject"].includes(t)) return "bad"
  if (["none", "neutral", "temperror", "add"].includes(t)) return "warn"
  return "muted"
}

// ------------------------------------------------------------------ authentication panel
function asText(v: unknown): string {
  if (v === null || v === undefined || v === "") return "—"
  return String(v)
}

export function AuthPanel({ details }: { details: Record<string, unknown> }) {
  const rows: { label: string; value: string }[] = [
    { label: "SPF", value: asText(details["SPF"]) },
    { label: "DKIM", value: asText(details["DKIM"]) },
    { label: "DMARC", value: asText(details["DMARC"]) },
    { label: "Rspamd", value: asText(details["Rspamd"]) },
  ]
  return (
    <Panel title="Authentication" description="Header result and our independent re-check">
      <dl className="flex flex-wrap gap-x-6 gap-y-3">
        {rows.map((r) => (
          <div key={r.label} className="min-w-[7rem]">
            <dt className="mb-1 text-xs text-muted-foreground">{r.label}</dt>
            <dd>
              {r.value === "—" ? (
                <Chip tone="muted">not checked</Chip>
              ) : (
                <Chip tone={authTone(r.value)} className="[overflow-wrap:anywhere] whitespace-normal">
                  {r.value}
                </Chip>
              )}
            </dd>
          </div>
        ))}
      </dl>
      <p className="mt-3 text-xs text-muted-foreground">
        DMARC shows the receiving server&apos;s result and, in brackets, our own independent evaluation.
      </p>
    </Panel>
  )
}

// ------------------------------------------------------------------ verdict cell
function VerdictChip({ v }: { v: EmailVerdict }) {
  const label = toolLabel(v.tool)
  if (v.status === "not_checked") {
    return (
      <Chip tone="muted">
        <MinusCircle className="size-3" aria-hidden />
        {label}: not checked
      </Chip>
    )
  }
  if (v.status === "error") {
    return (
      <Chip tone="warn">
        <ShieldQuestion className="size-3" aria-hidden />
        {label}: error
      </Chip>
    )
  }
  if (v.malicious) {
    return (
      <Chip tone="bad">
        <CircleX className="size-3" aria-hidden />
        {label}: malicious
      </Chip>
    )
  }
  return (
    <Chip tone="ok">
      <CircleCheck className="size-3" aria-hidden />
      {label}: clean
    </Chip>
  )
}

function SourcesBadge({ n }: { n: number }) {
  if (n >= 2) return <Chip tone="bad">known malicious ({n} sources)</Chip>
  if (n === 1) return <Chip tone="warn">1 source</Chip>
  return null
}

// ------------------------------------------------------------------ URLs
export function UrlTable({ indicators }: { indicators: EmailIndicator[] }) {
  const urls = indicators.filter((i) => i.kind === "url")
  return (
    <Panel title="Links" description={`${urls.length} ${urls.length === 1 ? "link" : "links"} found in the email`}>
      {urls.length === 0 ? (
        <p className="text-sm text-muted-foreground">No links were found in this email.</p>
      ) : (
        <ul className="divide-y">
          {urls.map((u, i) => (
            <li key={i} className="py-3 first:pt-0 last:pb-0">
              <div className="flex items-start gap-2">
                <Link2 className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                {/* Plain text on purpose — a phishing URL is never a clickable link. */}
                <span className="font-mono text-[13px] break-all select-all" title="Shown as plain text; not clickable">
                  {u.value}
                </span>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 pl-5">
                {u.verdicts.length ? (
                  u.verdicts.map((v, j) => <VerdictChip key={j} v={v} />)
                ) : (
                  <Chip tone="muted">not checked</Chip>
                )}
                <SourcesBadge n={u.malicious_sources} />
              </div>
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

// ------------------------------------------------------------------ attachments
export function AttachmentTable({ indicators }: { indicators: EmailIndicator[] }) {
  const atts = indicators.filter((i) => i.kind === "attachment")
  return (
    <Panel title="Attachments" description={`${atts.length} ${atts.length === 1 ? "attachment" : "attachments"}`}>
      {atts.length === 0 ? (
        <p className="text-sm text-muted-foreground">This email has no attachments.</p>
      ) : (
        <ul className="divide-y">
          {atts.map((a, i) => (
            <li key={i} className="py-3 first:pt-0 last:pb-0">
              <div className="flex items-start gap-2">
                <Paperclip className="mt-0.5 size-3.5 shrink-0 text-muted-foreground" aria-hidden />
                <span className="font-mono text-[13px] break-all">{a.value}</span>
              </div>
              <div className="mt-2 flex flex-wrap items-center gap-1.5 pl-5">
                {a.verdicts.length ? (
                  a.verdicts.map((v, j) => <VerdictChip key={j} v={v} />)
                ) : (
                  <Chip tone="muted">not scanned</Chip>
                )}
                <SourcesBadge n={a.malicious_sources} />
              </div>
            </li>
          ))}
        </ul>
      )}
      <p className="mt-3 text-xs text-muted-foreground">
        Attachments are only scanned and read as text. They are never opened or executed.
      </p>
    </Panel>
  )
}

// ------------------------------------------------------------------ not-checked coverage notice
export function NotCheckedNotice({ items }: { items: NotCheckedItem[] }) {
  if (!items.length) return null
  const tools = Array.from(new Set(items.map((i) => toolLabel(i.tool)))).sort()
  return (
    <div
      role="note"
      className="rounded-lg border border-amber-300 bg-amber-50 p-3 text-sm text-amber-950 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100"
    >
      <div className="font-medium">Coverage gaps — some tools could not run</div>
      <p className="mt-1 text-xs opacity-90">
        These checks were unreachable or unconfigured, so they contributed no score. Absence here is not a clean
        verdict.
      </p>
      <ul className="mt-2 flex flex-wrap gap-1.5">
        {tools.map((t) => (
          <li key={t}>
            <Chip tone="warn">{t}: not checked</Chip>
          </li>
        ))}
      </ul>
    </div>
  )
}

// ------------------------------------------------------------------ sanitised text preview
/**
 * Plain-text preview only. The API does not return the email body, so we fall back to a
 * `text_excerpt` on the metadata evidence if present, and otherwise render nothing.
 * No HTML, no remote images — ever.
 */
export function SanitisedPreview({ email }: { email: EmailDetail }) {
  let excerpt: string | null = null
  for (const ev of email.finding?.evidence ?? []) {
    if (ev.kind === "metadata" && ev.meta && typeof ev.meta["text_excerpt"] === "string") {
      excerpt = ev.meta["text_excerpt"] as string
      break
    }
  }
  if (!excerpt) return null
  return (
    <Panel title="Text preview" description="Plain text only — no HTML rendering, no remote images">
      <pre className="max-h-96 overflow-auto rounded-md border bg-muted/40 p-3 font-sans text-[13px] leading-relaxed whitespace-pre-wrap break-words">
        {excerpt}
      </pre>
    </Panel>
  )
}
