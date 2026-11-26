/**
 * Typed client for the Beyond Cloud Brand Intelligence REST API (docs/api/openapi.json).
 * All requests go to `${NEXT_PUBLIC_API_URL}/api/v1` with the bearer token from localStorage.
 */

export const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8010").replace(/\/$/, "")
const BASE = `${API_URL}/api/v1`

// ------------------------------------------------------------------ enums
export type Role = "admin" | "analyst"
export type ModuleName =
  | "typosquat"
  | "mx"
  | "phishing"
  | "apk"
  | "rogue_app"
  | "social"
  | "social_media"
  | "documents"
  | "logo"
  | "email"
  | "email_posture"
  | "dmarc"
export type RiskLevel = "Low" | "Medium" | "High" | "Critical"
/** Analyst decision on a finding (backend D-35). Alerts show their finding's decision as `status`. */
export type Decision =
  | "New"
  | "Investigating"
  | "Confirmed Threat"
  | "False Positive"
  | "Legitimate"
  | "Ignored"
  | "Resolved"
export type AlertStatus = Decision
/** Candidate = discovered but not yet analysed; Finding = analysed (D-33). */
export type FindingStage = "Candidate" | "Finding"
export type AlertTrigger = "first_crossing" | "change" | "reopen" | "migrated"
/** How often a brand is scanned automatically (D-39). */
export type AutoScanFrequency = "daily" | "every_3_days" | "weekly"
/** Scanners a brand can pick for automatic scans; none picked = every scanner. */
export type AutoRunner =
  | "domains"
  | "apk"
  | "rogue_app"
  | "social"
  | "social_media"
  | "documents"
  | "logo"
  | "email_posture"
export type AssetKind = "logo" | "favicon" | "app_icon"
export type AllowKind = "domain" | "package" | "publisher" | "social_handle" | "email_domain" | "signing_cert"
export type ScanStatus =
  | "queued"
  | "running"
  | "completed"
  | "partially_completed"
  | "completed_with_errors"
  | "failed"
  | "cancelled"

/** One part of a scan run (backend D-31): whether it ran, and why not. */
export type ComponentStatus = "ok" | "skipped" | "not_configured" | "unavailable" | "failed"

export interface ScanComponent {
  name: string
  status: ComponentStatus
  message: string
  counts: Record<string, number>
  fatal?: boolean
}

export interface Integration {
  id: string
  name: string
  category: string
  modules: string[]
  configured: boolean
  how_to_configure: string
  last_status: ComponentStatus | null
  last_message: string | null
  last_checked_at: string | null
}

// ------------------------------------------------------------------ models
export interface User {
  id: string
  email: string
  name: string
  role: Role
  is_active: boolean
  created_at: string
}

export interface TokenOut {
  access_token: string
  token_type: string
  user: User
}

export interface Asset {
  id: string
  kind: AssetKind
  filename: string
  content_type: string
  sha256: string
  phash: string | null
  mmh3: number | null
  created_at: string
  url: string | null
}

export interface AllowEntry {
  id: string
  kind: AllowKind
  value: string
}

export interface Brand {
  id: string
  name: string
  description: string | null
  keywords: string[]
  product_terms: string[]
  is_active: boolean
  alert_min_level: RiskLevel
  auto_scan_enabled: boolean
  auto_scan_frequency: AutoScanFrequency
  auto_scan_runners: AutoRunner[]
  last_auto_scan_at: string | null
  next_auto_scan_at: string | null
  created_at: string
  assets: Asset[]
  allowlist: AllowEntry[]
  open_alerts: number
}

export interface BrandInput {
  name: string
  description?: string | null
  keywords: string[]
  product_terms: string[]
  is_active: boolean
  alert_min_level?: RiskLevel
  auto_scan_enabled?: boolean
  auto_scan_frequency?: AutoScanFrequency
  auto_scan_runners?: AutoRunner[]
  allowlist?: { kind: AllowKind; value: string }[]
}

/** Master switch for scheduled scans (D-39). */
export interface AutoScanSettings {
  enabled: boolean
  updated_at: string | null
  brands_enabled: number
  brands_total: number
  schedule_utc: string
}

export interface Scan {
  id: string
  brand_id: string
  brand_name: string | null
  module: ModuleName
  trigger: string
  status: ScanStatus
  started_at: string | null
  finished_at: string | null
  stats: Record<string, unknown>
  components: ScanComponent[]
  error: string | null
  created_at: string
}

export interface Evidence {
  id: string
  kind: string
  content_type: string | null
  sha256: string | null
  size: number | null
  meta: Record<string, unknown>
  captured_at: string
  url: string | null
}

export interface AlertEvent {
  id: string
  kind: string
  from_status: string | null
  to_status: string | null
  note: string | null
  at: string
  user_name: string | null
}

export interface AlertSignals {
  score?: number
  level?: string
  raw_score?: number
  rules?: Record<string, number>
  confidence?: {
    score: number
    level: string
    policy?: string
    factors: { factor: string; points: number; why: string }[]
  }
  [key: string]: unknown
}

export interface RelatedFinding {
  finding_id: string
  module: ModuleName
  entity_key: string
  title: string
  risk_level: RiskLevel
  score: number
  decision: string
  kind: string
  label: string
  value: string
  strong: boolean
  seen_in: string
}

export interface Observation {
  id: string
  scan_id: string | null
  channel: string
  observed_at: string
  stage: FindingStage
  module: ModuleName
  score: number
  risk_level: RiskLevel
  state: Record<string, unknown>
}

export interface AlertRecord {
  id: string
  finding_id: string
  scan_id: string | null
  trigger: AlertTrigger | string
  reason: string
  score: number
  risk_level: RiskLevel
  reasons: Record<string, unknown>
  created_at: string
}

export interface Finding {
  id: string
  brand_id: string
  brand_name: string
  module: ModuleName
  entity_key: string
  stage: FindingStage
  title: string
  similarity: number | null
  score: number
  risk_level: RiskLevel
  decision: Decision
  decision_note: string | null
  decided_at: string | null
  suspected_phishing: boolean
  details: Record<string, unknown>
  signals: AlertSignals
  state: Record<string, unknown>
  source_url: string | null
  first_seen: string
  last_seen: string
  last_alert_at: string | null
  updated_at: string
  thumbnail_url: string | null
  alert_count: number
}

export interface FindingDetail extends Finding {
  decided_by_name: string | null
  evidence: Evidence[]
  events: AlertEvent[]
  observations: Observation[]
  alerts: AlertRecord[]
}

export interface FindingPage {
  items: Finding[]
  total: number
  page: number
  page_size: number
}

export interface Alert {
  id: string
  finding_id: string
  brand_id: string
  brand_name: string
  module: ModuleName
  entity_key: string
  stage: FindingStage
  title: string
  similarity: number | null
  score: number
  risk_level: RiskLevel
  status: Decision
  suspected_phishing: boolean
  details: Record<string, unknown>
  signals: AlertSignals
  source_url: string | null
  first_seen: string
  last_seen: string
  updated_at: string
  alerted_at: string
  trigger: AlertTrigger | string
  /** Human-readable reason the alert was raised */
  reason: string
  scan_id: string | null
  thumbnail_url: string | null
}

export interface AlertDetail extends Alert {
  evidence: Evidence[]
  events: AlertEvent[]
  observations: Observation[]
  alerts: AlertRecord[]
  decision_note: string | null
}

export interface AlertPage {
  items: Alert[]
  total: number
  page: number
  page_size: number
}

export interface ExecutiveStats {
  date: string
  total_alerts_today: number
  high_critical_alerts: number
  high_critical_today: number
  new_phishing_domains: number
  new_impersonation_accounts: number
  new_rogue_apps: number
  sensitive_document_exposures: number
  phishing_emails_today: number
  spoofed_sender_attempts: number
  open_alerts: number
  by_module: Record<string, number>
  by_risk: Record<string, number>
  /** keyed by analyst decision */
  by_status: Record<string, number>
  /** candidates not yet analysed into findings */
  candidates: number
  /** analysed findings held back by the brand's "Alert from" level */
  findings_below_alert_level: number
  /** null = no scan has completed yet, so "no threats" cannot be claimed */
  last_completed_scan_at: string | null
  /** scan components that could not run in the latest run of each scanner */
  components_unavailable: number
  /** brand/scanner pairs whose latest run failed or was cancelled — those checked nothing */
  scans_failed: number
}

export interface TrendPoint {
  date: string
  total: number
  low: number
  medium: number
  high: number
  critical: number
}

// ------------------------------------------------------------------ phishing email (D-28)
/** One tool's opinion on a URL or attachment. Treat `details` as untrusted. */
export interface EmailVerdict {
  tool: string
  status: "ok" | "not_checked" | "error" | string
  malicious: boolean
  score: number | null
  details: Record<string, unknown>
  checked_at?: string | null
}

export interface EmailIndicator {
  kind: "url" | "attachment"
  /** The raw URL or attachment name — hostile, untrusted content. Never render as a live link. */
  value: string
  verdicts: EmailVerdict[]
  malicious_sources: number
}

export interface NotCheckedItem {
  tool: string
  target: string
  status: string
}

export interface EmailOut {
  id: string
  brand_id: string
  subject: string | null
  from_addr: string | null
  sender_ip: string | null
  channel: string
  status: string
  received_at: string
  risk_level: RiskLevel | null
  score: number | null
  finding_id: string | null
  verdict: string | null
}

export interface EmailDetail extends EmailOut {
  indicators: EmailIndicator[]
  not_checked: NotCheckedItem[]
  finding: FindingDetail | null
}

export interface EmailPage {
  items: EmailOut[]
  total: number
  page: number
  page_size: number
}

// ------------------------------------------------------------------ token storage
const TOKEN_KEY = "bc.token"
const USER_KEY = "bc.user"

export const session = {
  token(): string | null {
    try {
      return localStorage.getItem(TOKEN_KEY)
    } catch {
      return null
    }
  },
  user(): User | null {
    try {
      const raw = localStorage.getItem(USER_KEY)
      return raw ? (JSON.parse(raw) as User) : null
    } catch {
      return null
    }
  },
  save(token: string, user: User) {
    localStorage.setItem(TOKEN_KEY, token)
    localStorage.setItem(USER_KEY, JSON.stringify(user))
  },
  clear() {
    try {
      localStorage.removeItem(TOKEN_KEY)
      localStorage.removeItem(USER_KEY)
    } catch {
      /* storage unavailable */
    }
  },
}

// ------------------------------------------------------------------ errors
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
    this.name = "ApiError"
  }
}

type FastApiDetail = string | { msg?: string; loc?: (string | number)[] }[] | undefined

function detailMessage(detail: FastApiDetail, fallback: string): string {
  if (typeof detail === "string") return detail
  if (Array.isArray(detail) && detail.length) {
    return detail
      .map((d) => {
        const field = d.loc?.filter((p) => p !== "body" && p !== "query").join(".")
        return field ? `${field}: ${d.msg}` : (d.msg ?? "")
      })
      .join("; ")
  }
  return fallback
}

function onUnauthorized() {
  session.clear()
  if (typeof window !== "undefined" && !window.location.pathname.startsWith("/login")) {
    const next = encodeURIComponent(window.location.pathname + window.location.search)
    // Full reload on purpose: drops every cached query belonging to the expired session
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination
    window.location.assign(`/login?next=${next}`)
  }
}

// ------------------------------------------------------------------ core request
export type Query = Record<string, string | number | boolean | null | undefined | (string | number)[]>

export function toSearch(query?: Query | URLSearchParams): string {
  if (!query) return ""
  const params = query instanceof URLSearchParams ? new URLSearchParams(query) : new URLSearchParams()
  if (!(query instanceof URLSearchParams)) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === "") continue
      if (Array.isArray(value)) value.forEach((v) => params.append(key, String(v)))
      else params.append(key, String(value))
    }
  }
  const s = params.toString()
  return s ? `?${s}` : ""
}

async function raw(path: string, init: RequestInit = {}, query?: Query | URLSearchParams): Promise<Response> {
  const headers = new Headers(init.headers)
  const token = session.token()
  if (token) headers.set("Authorization", `Bearer ${token}`)
  if (init.body && !(init.body instanceof FormData) && !headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json")
  }
  let res: Response
  try {
    res = await fetch(`${BASE}${path}${toSearch(query)}`, { ...init, headers })
  } catch {
    throw new ApiError(0, `Cannot reach the API at ${API_URL}. Check that the backend is running.`)
  }
  if (res.status === 401 && !path.startsWith("/auth/login")) {
    onUnauthorized()
    throw new ApiError(401, "Your session has expired. Sign in again.")
  }
  if (!res.ok) {
    let message = `Request failed (${res.status})`
    try {
      const body = (await res.json()) as { detail?: FastApiDetail }
      message = detailMessage(body.detail, message)
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, message)
  }
  return res
}

async function json<T>(path: string, init: RequestInit = {}, query?: Query | URLSearchParams): Promise<T> {
  const res = await raw(path, init, query)
  if (res.status === 204) return undefined as T
  return (await res.json()) as T
}

/** Download an authenticated file and save it with the server-provided filename. */
async function download(path: string, query: URLSearchParams | Query, fallbackName: string) {
  const res = await raw(path, {}, query)
  const blob = await res.blob()
  const disposition = res.headers.get("Content-Disposition") ?? ""
  const match = /filename\*?=(?:UTF-8'')?"?([^";]+)"?/i.exec(disposition)
  const filename = match ? decodeURIComponent(match[1]) : fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
  return filename
}

// ------------------------------------------------------------------ endpoints
export const api = {
  login: (email: string, password: string) =>
    json<TokenOut>("/auth/login", { method: "POST", body: JSON.stringify({ email, password }) }),
  me: () => json<User>("/auth/me"),

  users: () => json<User[]>("/users"),
  createUser: (body: { email: string; name: string; password: string; role: Role }) =>
    json<User>("/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (id: string, body: Partial<{ name: string; password: string; role: Role; is_active: boolean }>) =>
    json<User>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),

  brands: () => json<Brand[]>("/brands"),
  brand: (id: string) => json<Brand>(`/brands/${id}`),
  createBrand: (body: BrandInput) => json<Brand>("/brands", { method: "POST", body: JSON.stringify(body) }),
  updateBrand: (id: string, body: Partial<BrandInput>) =>
    json<Brand>(`/brands/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteBrand: (id: string) => json<void>(`/brands/${id}`, { method: "DELETE" }),
  uploadAsset: (brandId: string, kind: AssetKind, file: File) => {
    const form = new FormData()
    form.append("kind", kind)
    form.append("file", file)
    return json<Asset>(`/brands/${brandId}/assets`, { method: "POST", body: form })
  },
  deleteAsset: (brandId: string, assetId: string) =>
    json<void>(`/brands/${brandId}/assets/${assetId}`, { method: "DELETE" }),
  addAllow: (brandId: string, kind: AllowKind, value: string) =>
    json<AllowEntry>(`/brands/${brandId}/allowlist`, { method: "POST", body: JSON.stringify({ kind, value }) }),
  deleteAllow: (brandId: string, allowId: string) =>
    json<void>(`/brands/${brandId}/allowlist/${allowId}`, { method: "DELETE" }),

  scans: (query?: { brand_id?: string[]; limit?: number }) => json<Scan[]>("/scans", {}, query),
  autoScan: () => json<AutoScanSettings>("/settings/auto-scan"),
  setAutoScan: (enabled: boolean) =>
    json<AutoScanSettings>("/settings/auto-scan", { method: "PUT", body: JSON.stringify({ enabled }) }),
  integrations: () => json<Integration[]>("/integrations"),
  startScan: (brand_id: string, modules: ModuleName[] | null, range?: { date_from?: string | null; date_to?: string | null }) =>
    json<Scan[]>("/scans", {
      method: "POST",
      body: JSON.stringify({ brand_id, modules, date_from: range?.date_from || null, date_to: range?.date_to || null }),
    }),

  alerts: (query: URLSearchParams) => json<AlertPage>("/alerts", {}, query),
  alert: (id: string) => json<AlertDetail>(`/alerts/${id}`),
  setStatus: (id: string, status: Decision, note?: string, addToAllowlist = false) =>
    json<AlertDetail>(`/alerts/${id}/status`, {
      method: "POST",
      body: JSON.stringify({ status, note: note?.trim() ? note.trim() : null, add_to_allowlist: addToAllowlist }),
    }),

  findings: (query: URLSearchParams) => json<FindingPage>("/findings", {}, query),
  finding: (id: string) => json<FindingDetail>(`/findings/${id}`),
  related: (id: string) => json<RelatedFinding[]>(`/findings/${id}/related`),
  decide: (id: string, decision: Decision, note?: string, addToAllowlist = false) =>
    json<FindingDetail>(`/findings/${id}/decision`, {
      method: "POST",
      body: JSON.stringify({ decision, note: note?.trim() ? note.trim() : null, add_to_allowlist: addToAllowlist }),
    }),
  bulkDecide: (findingIds: string[], decision: Decision, note?: string) =>
    json<Finding[]>("/findings/decision", {
      method: "POST",
      body: JSON.stringify({ finding_ids: findingIds, decision, note: note?.trim() ? note.trim() : null }),
    }),

  executive: (brandIds: string[]) => json<ExecutiveStats>("/stats/executive", {}, { brand_id: brandIds }),
  trends: (days: number, brandIds: string[]) => json<TrendPoint[]>("/stats/trends", {}, { days, brand_id: brandIds }),

  exportAlerts: (format: "csv" | "pdf", query: URLSearchParams) =>
    download(`/exports/alerts.${format}`, query, `alerts.${format}`),
  exportFindings: (format: "csv" | "pdf", query: URLSearchParams) =>
    download(`/exports/findings.${format}`, query, `findings.${format}`),

  emails: (query?: Query) => json<EmailPage>("/emails", {}, query),
  email: (id: string) => json<EmailDetail>(`/emails/${id}`),
  uploadEmail: (brandId: string, file: File) => {
    const form = new FormData()
    form.append("brand_id", brandId)
    form.append("file", file)
    return json<EmailDetail>("/emails", { method: "POST", body: form })
  },
}
