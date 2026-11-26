const dateTime = new Intl.DateTimeFormat(undefined, {
  year: "numeric",
  month: "short",
  day: "2-digit",
  hour: "2-digit",
  minute: "2-digit",
})
const dateOnly = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "2-digit" })
const shortDay = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" })
const timeOnly = new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" })
const rel = new Intl.RelativeTimeFormat(undefined, { numeric: "auto", style: "short" })

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return ""
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? "" : timeOnly.format(d)
}

export function fmtDateTime(iso: string | null | undefined): string {
  if (!iso) return "—"
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : dateTime.format(d)
}

export function fmtDate(iso: string | null | undefined): string {
  if (!iso) return "—"
  const d = new Date(iso)
  return Number.isNaN(d.getTime()) ? iso : dateOnly.format(d)
}

/** "2026-10-06" (a calendar day, no time zone shift) → "Oct 6" */
export function fmtDay(isoDay: string): string {
  const [y, m, d] = isoDay.split("-").map(Number)
  return shortDay.format(new Date(y, m - 1, d))
}

export function fmtRelative(iso: string | null | undefined): string {
  if (!iso) return "—"
  const diff = (new Date(iso).getTime() - Date.now()) / 1000
  const abs = Math.abs(diff)
  if (abs < 60) return rel.format(Math.round(diff), "second")
  if (abs < 3600) return rel.format(Math.round(diff / 60), "minute")
  if (abs < 86400) return rel.format(Math.round(diff / 3600), "hour")
  if (abs < 86400 * 30) return rel.format(Math.round(diff / 86400), "day")
  return fmtDate(iso)
}

export function fmtDuration(start: string | null, end: string | null): string {
  if (!start) return "—"
  const ms = (end ? new Date(end).getTime() : Date.now()) - new Date(start).getTime()
  if (ms < 1000) return "<1s"
  const s = Math.round(ms / 1000)
  if (s < 60) return `${s}s`
  const m = Math.floor(s / 60)
  return `${m}m ${s % 60}s`
}

export function fmtBytes(n: number | null | undefined): string {
  if (n == null) return "—"
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export const fmtNumber = (n: number) => new Intl.NumberFormat().format(n)

/** Render any API value as display text. Booleans → Yes/No, arrays joined, objects as key: value. */
export function fmtValue(value: unknown): string {
  if (value === null || value === undefined) return ""
  if (typeof value === "boolean") return value ? "Yes" : "No"
  if (Array.isArray(value)) return value.map(fmtValue).filter(Boolean).join(", ")
  if (typeof value === "object") {
    return Object.entries(value as Record<string, unknown>)
      .map(([k, v]) => `${k}: ${fmtValue(v)}`)
      .join("; ")
  }
  return String(value)
}

export function isEmptyValue(value: unknown): boolean {
  return (
    value === null ||
    value === undefined ||
    value === "" ||
    (Array.isArray(value) && value.length === 0) ||
    (typeof value === "object" && !Array.isArray(value) && Object.keys(value as object).length === 0)
  )
}

/** Today as YYYY-MM-DD in the browser's time zone. */
export function todayIso(): string {
  const d = new Date()
  const pad = (n: number) => String(n).padStart(2, "0")
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`
}
