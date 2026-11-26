"use client"

import { ErrorPanel, isNotFound } from "@/components/query-state"
import { useRef, useState } from "react"
import Link from "next/link"
import { useParams, useRouter } from "next/navigation"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { ArrowLeft, Building2, ImagePlus, Loader2, Play, Plus, Trash2, Upload, X } from "lucide-react"
import { BrandForm } from "@/components/brand-form"
import { ScanTable, isActiveScan } from "@/components/scan-table"
import { RiskBadge } from "@/components/badges"
import { EmptyState, Panel, SimpleSelect } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type AllowKind, type AssetKind, type Brand, type ModuleName } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { ALLOW_KINDS, ASSET_KINDS, MODULES, MODULE_LABELS } from "@/lib/constants"
import { fmtDate, fmtNumber } from "@/lib/format"
import { keys } from "@/lib/queries"
import { cn } from "@/lib/utils"

// ------------------------------------------------------------------ run scan
function RunScanDialog({ brand, open, onOpenChange }: { brand: Brand; open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const [mode, setMode] = useState<"all" | "some">("all")
  const [chosen, setChosen] = useState<ModuleName[]>([])
  const [dateFrom, setDateFrom] = useState("")
  const [dateTo, setDateTo] = useState("")
  const rangeInvalid = !!dateFrom && !!dateTo && dateFrom > dateTo
  const start = useMutation({
    mutationFn: () => api.startScan(brand.id, mode === "all" ? null : chosen, { date_from: dateFrom, date_to: dateTo }),
    onSuccess: (runs) => {
      qc.invalidateQueries({ queryKey: ["scans"] })
      const failed = runs.filter((r) => r.status === "failed")
      if (failed.length) toast.error(`${failed.length} of ${runs.length} scans could not be queued. See the scan list for details.`)
      else toast.success(`${runs.length} ${runs.length === 1 ? "scan" : "scans"} queued for ${brand.name}`)
      onOpenChange(false)
    },
  })
  const canStart = (mode === "all" || chosen.length > 0) && !rangeInvalid
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle>Run a scan for {brand.name}</DialogTitle>
          <DialogDescription>Scans run in the background. Progress shows under Recent scans.</DialogDescription>
        </DialogHeader>
        <div className="space-y-2">
          <label className={cn("flex cursor-pointer items-start gap-3 rounded-lg border p-3", mode === "all" && "border-primary/60 bg-accent/50")}>
            <input type="radio" name="scan-mode" className="mt-1 accent-[var(--primary)]" checked={mode === "all"} onChange={() => setMode("all")} />
            <span>
              <span className="block text-sm font-medium">All modules</span>
              <span className="block text-xs text-muted-foreground">Every detection module, as the daily schedule does</span>
            </span>
          </label>
          <label className={cn("flex cursor-pointer items-start gap-3 rounded-lg border p-3", mode === "some" && "border-primary/60 bg-accent/50")}>
            <input type="radio" name="scan-mode" className="mt-1 accent-[var(--primary)]" checked={mode === "some"} onChange={() => setMode("some")} />
            <span className="block text-sm font-medium">Chosen modules</span>
          </label>
          {mode === "some" && (
            <div className="grid grid-cols-1 gap-1 pl-2 sm:grid-cols-2">
              {MODULES.map((m) => (
                <label key={m} className="flex cursor-pointer items-center gap-2 rounded-md px-2 py-1.5 text-sm hover:bg-accent">
                  <Checkbox
                    checked={chosen.includes(m)}
                    onCheckedChange={(c) => setChosen((prev) => (c ? [...prev, m] : prev.filter((x) => x !== m)))}
                  />
                  {MODULE_LABELS[m]}
                </label>
              ))}
              <p className="col-span-full px-2 text-xs text-muted-foreground">
                Typosquat, MX and phishing share one domain scan, so choosing any of them runs all three.
              </p>
            </div>
          )}
        </div>
        <div className="space-y-2 rounded-lg border p-3">
          <div>
            <span className="block text-sm font-medium">Date range (optional)</span>
            <span className="block text-xs text-muted-foreground">
              Only content published in this range (social media, web search, documents) and domains registered or certificates issued in it.
              Items without a known date are always kept. Leave empty to check everything.
            </span>
          </div>
          <div className="grid grid-cols-2 gap-2">
            <label className="space-y-1 text-xs text-muted-foreground">
              From
              <Input type="date" value={dateFrom} max={dateTo || undefined} onChange={(e) => setDateFrom(e.target.value)} />
            </label>
            <label className="space-y-1 text-xs text-muted-foreground">
              To
              <Input type="date" value={dateTo} min={dateFrom || undefined} onChange={(e) => setDateTo(e.target.value)} />
            </label>
          </div>
          {rangeInvalid && <p className="text-xs text-destructive">&apos;From&apos; must be on or before &apos;To&apos;.</p>}
          {(dateFrom || dateTo) && (
            <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => { setDateFrom(""); setDateTo("") }}>
              Clear dates
            </Button>
          )}
        </div>
        <DialogFooter>
          <Button variant="ghost" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button onClick={() => start.mutate()} disabled={!canStart || start.isPending}>
            {start.isPending ? <Loader2 className="animate-spin" /> : <Play />}
            Start scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ------------------------------------------------------------------ official assets (FND-05)
function Assets({ brand, isAdmin }: { brand: Brand; isAdmin: boolean }) {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const [kind, setKind] = useState<AssetKind>("logo")
  const [file, setFile] = useState<File | null>(null)
  const refresh = () => qc.invalidateQueries({ queryKey: keys.brands })
  const upload = useMutation({
    mutationFn: () => api.uploadAsset(brand.id, kind, file!),
    onSuccess: (a) => {
      toast.success(`Uploaded ${a.filename}`)
      setFile(null)
      if (fileRef.current) fileRef.current.value = ""
      refresh()
    },
  })
  const remove = useMutation({
    mutationFn: (assetId: string) => api.deleteAsset(brand.id, assetId),
    onSuccess: () => {
      toast.success("Asset removed")
      refresh()
    },
  })

  return (
    <Panel title="Official assets" description="Logos and icons that detections compare against">
      {brand.assets.length === 0 ? (
        <EmptyState icon={ImagePlus} title="No official assets" className="py-6">
          Upload the logo, favicon and app icon so logo-matching and favicon checks can work.
        </EmptyState>
      ) : (
        <ul className="grid grid-cols-2 gap-3 sm:grid-cols-3">
          {brand.assets.map((a) => (
            <li key={a.id} className="group overflow-hidden rounded-md border">
              <div className="flex h-28 items-center justify-center bg-white p-3 bg-[linear-gradient(45deg,#f1f3f5_25%,transparent_25%,transparent_75%,#f1f3f5_75%),linear-gradient(45deg,#f1f3f5_25%,transparent_25%,transparent_75%,#f1f3f5_75%)] bg-[length:12px_12px] bg-[position:0_0,6px_6px]">
                {a.url ? <img src={a.url} alt={`${a.kind} ${a.filename}`} className="max-h-full max-w-full object-contain" /> : <span className="text-xs text-muted-foreground">No preview</span>}
              </div>
              <div className="flex items-start justify-between gap-1 border-t px-2.5 py-1.5">
                <div className="min-w-0">
                  <div className="text-xs font-medium">{ASSET_KINDS.find((k) => k.value === a.kind)?.label ?? a.kind}</div>
                  <div className="truncate text-[11px] text-muted-foreground" title={a.filename}>
                    {a.filename}
                  </div>
                </div>
                {isAdmin && (
                  <Button
                    variant="ghost"
                    size="icon-xs"
                    aria-label={`Delete ${a.filename}`}
                    disabled={remove.isPending}
                    onClick={() => {
                      if (window.confirm(`Delete ${a.filename}? Logo matching will stop using it.`)) remove.mutate(a.id)
                    }}
                  >
                    <Trash2 />
                  </Button>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
      {isAdmin && (
        <form
          className="mt-4 flex flex-col gap-2 border-t pt-4 sm:flex-row sm:items-center"
          onSubmit={(e) => {
            e.preventDefault()
            if (file) upload.mutate()
          }}
        >
          <SimpleSelect
            ariaLabel="Asset type"
            value={kind}
            onChange={(v) => setKind(v as AssetKind)}
            options={ASSET_KINDS.map((k) => ({ value: k.value, label: k.label }))}
            className="sm:w-32"
          />
          <Input
            ref={fileRef}
            type="file"
            accept="image/png,image/jpeg,image/gif,image/webp,image/x-icon,image/vnd.microsoft.icon,image/bmp,.ico"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
            aria-label="Image file"
            className="min-w-0 flex-1 text-sm file:mr-2"
          />
          <Button type="submit" disabled={!file || upload.isPending}>
            {upload.isPending ? <Loader2 className="animate-spin" /> : <Upload />}
            Upload
          </Button>
        </form>
      )}
      {isAdmin && <p className="mt-2 text-xs text-muted-foreground">{ASSET_KINDS.find((k) => k.value === kind)?.hint}. PNG, JPG, GIF, WEBP, ICO or BMP up to 5 MB.</p>}
    </Panel>
  )
}

// ------------------------------------------------------------------ allowlists (FND-06)
function AllowGroup({ brand, kind, isAdmin }: { brand: Brand; kind: (typeof ALLOW_KINDS)[number]; isAdmin: boolean }) {
  const qc = useQueryClient()
  const [value, setValue] = useState("")
  const entries = brand.allowlist.filter((a) => a.kind === kind.value)
  const refresh = () => qc.invalidateQueries({ queryKey: keys.brands })
  const add = useMutation({
    mutationFn: () => api.addAllow(brand.id, kind.value as AllowKind, value.trim()),
    onSuccess: (row) => {
      toast.success(`Added ${row.value} to ${kind.label.toLowerCase()}`)
      setValue("")
      refresh()
    },
  })
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteAllow(brand.id, id),
    onSuccess: refresh,
  })
  return (
    <div className="py-3 first:pt-0 last:pb-0">
      <div className="mb-1.5 flex items-baseline justify-between">
        <h3 className="text-sm font-medium">{kind.label}</h3>
        <span className="tnum text-xs text-muted-foreground">{entries.length}</span>
      </div>
      {entries.length > 0 ? (
        <ul className="mb-2 flex flex-wrap gap-1.5">
          {entries.map((e) => (
            <li key={e.id} className="inline-flex items-center gap-1 rounded-md border bg-muted/50 py-0.5 pr-0.5 pl-2 font-mono text-xs">
              {e.value}
              {isAdmin && (
                <button
                  type="button"
                  aria-label={`Remove ${e.value}`}
                  onClick={() => remove.mutate(e.id)}
                  className="rounded p-0.5 text-muted-foreground hover:bg-background hover:text-foreground"
                >
                  <X className="size-3" />
                </button>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p className="mb-2 text-xs text-muted-foreground">None yet</p>
      )}
      {isAdmin && (
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            if (value.trim()) add.mutate()
          }}
        >
          <Input
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder={kind.placeholder}
            aria-label={`Add to ${kind.label.toLowerCase()}`}
            className="h-8 font-mono text-xs"
          />
          <Button type="submit" variant="outline" size="sm" disabled={!value.trim() || add.isPending}>
            <Plus />
            Add
          </Button>
        </form>
      )}
    </div>
  )
}

function Allowlists({ brand, isAdmin }: { brand: Brand; isAdmin: boolean }) {
  return (
    <Panel title="Allowlists" description="Official domains, apps and accounts are never raised as alerts">
      <div className="divide-y">
        {ALLOW_KINDS.map((k) => (
          <AllowGroup key={k.value} brand={brand} kind={k} isAdmin={isAdmin} />
        ))}
      </div>
    </Panel>
  )
}

// ------------------------------------------------------------------ page
function DeleteBrandDialog({ brand, open, onOpenChange }: { brand: Brand; open: boolean; onOpenChange: (o: boolean) => void }) {
  const router = useRouter()
  const qc = useQueryClient()
  const [typed, setTyped] = useState("")
  const del = useMutation({
    mutationFn: () => api.deleteBrand(brand.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: keys.brands })
      qc.invalidateQueries({ queryKey: ["alerts"] })
      qc.invalidateQueries({ queryKey: ["stats"] })
      toast.success(`${brand.name} deleted`)
      router.push("/brands")
    },
  })
  return (
    <Dialog open={open} onOpenChange={(o) => { setTyped(""); onOpenChange(o) }}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Delete {brand.name}?</DialogTitle>
          <DialogDescription>
            This permanently deletes the brand, its {fmtNumber(brand.open_alerts)} open alerts, all findings and closed alerts, evidence
            records and scan history. It cannot be undone.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-1.5">
          <label htmlFor="confirm-brand" className="text-sm">
            Type <span className="font-semibold">{brand.name}</span> to confirm
          </label>
          <Input id="confirm-brand" value={typed} onChange={(e) => setTyped(e.target.value)} autoComplete="off" />
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button variant="destructive" disabled={typed !== brand.name || del.isPending} onClick={() => del.mutate()}>
            {del.isPending && <Loader2 className="animate-spin" />}
            Delete brand
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

function EmailSecurity({ brandId }: { brandId: string }) {
  const q = useQuery({
    queryKey: ["email-security", brandId],
    queryFn: () => {
      const p = new URLSearchParams()
      p.set("brand_id", brandId)
      for (const m of ["email_posture", "dmarc"]) p.append("module", m)
      p.set("page_size", "50")
      return api.alerts(p)
    },
  })
  const items = q.data?.items ?? []
  return (
    <Panel title="Email security" description="Spoofing posture of this brand's email domains (SPF / DMARC / DKIM) and DMARC report findings">
      {q.isLoading ? (
        <Skeleton className="h-16 w-full" />
      ) : items.length === 0 ? (
        <p className="text-sm text-muted-foreground">No email-security issues found. Run an Email domain security scan, or configure a DMARC report mailbox.</p>
      ) : (
        <ul className="divide-y">
          {items.map((a) => (
            <li key={a.id} className="flex items-start justify-between gap-3 py-2">
              <div className="min-w-0">
                <Link href={`/alerts/${a.id}`} className="text-sm font-medium hover:underline">{a.title}</Link>
                <div className="truncate text-xs text-muted-foreground">
                  {String(a.details["Summary"] ?? a.details["Disposition"] ?? a.details["DMARC Issues"] ?? "")}
                </div>
              </div>
              <RiskBadge level={a.risk_level} score={a.score} />
            </li>
          ))}
        </ul>
      )}
    </Panel>
  )
}

export default function BrandDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { isAdmin } = useAuth()
  const qc = useQueryClient()
  const [scanOpen, setScanOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const brand = useQuery({ queryKey: keys.brand(id), queryFn: () => api.brand(id) })
  const scans = useQuery({
    queryKey: keys.scans(id),
    queryFn: () => api.scans({ brand_id: [id], limit: 15 }),
    refetchInterval: (q) => (q.state.data?.some(isActiveScan) ? 5000 : false),
  })
  const save = useMutation({
    mutationFn: (v: Parameters<typeof api.updateBrand>[1]) => api.updateBrand(id, v),
    onSuccess: (b) => {
      qc.setQueryData(keys.brand(id), b)
      qc.invalidateQueries({ queryKey: keys.brands })
      toast.success("Brand settings saved")
    },
  })

  const b = brand.data
  if (brand.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-8 w-64" />
        <Skeleton className="h-96 w-full" />
      </div>
    )
  }
  if (brand.error && !isNotFound(brand.error)) {
    return <ErrorPanel error={brand.error} onRetry={() => brand.refetch()} title="Couldn't load this brand" />
  }
  if (!b) {
    return (
      <EmptyState icon={Building2} title="Brand not found" action={<Button render={<Link href="/brands" />} nativeButton={false}>All brands</Button>}>
        It may have been deleted.
      </EmptyState>
    )
  }

  return (
    <>
      <Link href="/brands" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-3.5" />
        Brands
      </Link>
      <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-xl font-semibold tracking-tight sm:text-2xl">{b.name}</h1>
          <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
            <span>{b.is_active ? "Monitoring active" : "Monitoring paused"}</span>
            <span>Added {fmtDate(b.created_at)}</span>
            <Link href={`/alerts?brand_id=${b.id}&status=New&status=Investigating&status=Confirmed+Threat`} className="font-medium text-foreground hover:underline">
              {fmtNumber(b.open_alerts)} open {b.open_alerts === 1 ? "alert" : "alerts"}
            </Link>
          </div>
        </div>
        <div className="flex gap-2">
          {isAdmin && (
            <Button variant="outline" onClick={() => setDeleteOpen(true)}>
              <Trash2 />
              Delete brand
            </Button>
          )}
          <Button onClick={() => setScanOpen(true)}>
            <Play />
            Run scan now
          </Button>
        </div>
      </div>


      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="space-y-4">
          <Panel title="Monitoring settings" description={isAdmin ? undefined : "Only admins can change brand settings"}>
            <BrandForm initial={b} readOnly={!isAdmin} submitLabel="Save changes" onSubmit={(v) => save.mutateAsync(v).catch(() => {})} />
          </Panel>
          <Assets brand={b} isAdmin={isAdmin} />
        </div>
        <div className="space-y-4">
          <Allowlists brand={b} isAdmin={isAdmin} />
          <EmailSecurity brandId={b.id} />
          <section>
            <div className="mb-2 flex items-baseline justify-between">
              <h2 className="text-sm font-semibold">Recent scans</h2>
              <Link href="/scans" className="text-xs text-muted-foreground hover:text-foreground hover:underline">
                All scans
              </Link>
            </div>
            <ScanTable
              scans={scans.data}
              loading={scans.isLoading}
              error={scans.error}
              onRetry={() => scans.refetch()}
              showBrand={false}
              emptyText="Run a scan to check this brand now."
            />
          </section>
        </div>
      </div>
      <RunScanDialog brand={b} open={scanOpen} onOpenChange={setScanOpen} />
      {isAdmin && <DeleteBrandDialog brand={b} open={deleteOpen} onOpenChange={setDeleteOpen} />}
    </>
  )
}
