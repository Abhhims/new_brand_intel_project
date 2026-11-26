"use client"

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { keepPreviousData, useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { createColumnHelper, tableFeatures, useTable } from "@tanstack/react-table"
import { toast } from "sonner"
import { ChevronLeft, ChevronRight, Loader2, Mail, MailQuestion, Search, Upload } from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { RiskBadge } from "@/components/badges"
import { EmptyState, Panel, SimpleSelect } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type EmailOut } from "@/lib/api"
import { fmtDateTime, fmtNumber, fmtRelative } from "@/lib/format"
import { keys, useBrands } from "@/lib/queries"
import { cn } from "@/lib/utils"

const ACCEPT = ".eml,.msg,.txt,message/rfc822"
const PAGE_SIZE = 25

function channelLabel(c: string): string {
  const map: Record<string, string> = { upload: "Upload", mailbox: "Mailbox", graph: "Microsoft 365", gmail: "Google" }
  return map[c] ?? c
}

// ------------------------------------------------------------------ upload
function UploadPanel({ brandId, onBrandChange }: { brandId: string | null; onBrandChange: (id: string) => void }) {
  const brands = useBrands()
  const qc = useQueryClient()
  const router = useRouter()
  const fileRef = useRef<HTMLInputElement>(null)
  const [dragging, setDragging] = useState(false)

  const upload = useMutation({
    mutationFn: (file: File) => {
      if (!brandId) throw new Error("Choose a brand before uploading")
      return api.uploadEmail(brandId, file)
    },
    onSuccess: (detail) => {
      qc.invalidateQueries({ queryKey: ["emails"] })
      qc.invalidateQueries({ queryKey: ["alerts"] })
      qc.invalidateQueries({ queryKey: ["stats"] })
      toast.success(`Analysed: ${detail.verdict ?? "done"}`)
      router.push(`/emails/${detail.id}`)
    },
    onError: (e) => toast.error(e instanceof Error ? e.message : "Upload failed"),
  })

  const onFiles = useCallback(
    (files: FileList | null) => {
      const file = files?.[0]
      if (!file) return
      if (!brandId) {
        toast.error("Choose a brand before uploading")
        return
      }
      upload.mutate(file)
      if (fileRef.current) fileRef.current.value = ""
    },
    [brandId, upload],
  )

  const brandOptions = (brands.data ?? []).map((b) => ({ value: b.id, label: b.name }))

  return (
    <Panel title="Analyse an email" description="Upload a reported .eml, .msg or .txt message to score it against a brand">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start">
        <div className="sm:w-56">
          <label className="mb-1.5 block text-sm font-medium">Brand</label>
          <SimpleSelect
            ariaLabel="Brand to analyse against"
            value={brandId}
            onChange={onBrandChange}
            options={brandOptions}
            placeholder={brands.isLoading ? "Loading…" : "Choose a brand"}
            className="w-full"
          />
          <p className="mt-1.5 text-xs text-muted-foreground">The email is scored against this brand&apos;s domains and assets.</p>
        </div>
        <div
          onDragOver={(e) => {
            e.preventDefault()
            setDragging(true)
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault()
            setDragging(false)
            onFiles(e.dataTransfer.files)
          }}
          className={cn(
            "flex flex-1 flex-col items-center justify-center gap-2 rounded-lg border border-dashed p-6 text-center transition-colors",
            dragging ? "border-primary bg-accent/50" : "border-input",
            upload.isPending && "opacity-70",
          )}
        >
          {upload.isPending ? (
            <Loader2 className="size-6 animate-spin text-muted-foreground" aria-hidden />
          ) : (
            <Upload className="size-6 text-muted-foreground/70" aria-hidden />
          )}
          <div className="text-sm">
            <button
              type="button"
              onClick={() => fileRef.current?.click()}
              disabled={upload.isPending || !brandId}
              className="font-medium text-primary underline-offset-4 outline-none hover:underline focus-visible:ring-2 focus-visible:ring-ring disabled:opacity-50"
            >
              Choose a file
            </button>{" "}
            <span className="text-muted-foreground">or drag it here</span>
          </div>
          <p className="text-xs text-muted-foreground">.eml, .msg or .txt, up to 25 MB</p>
          <input
            ref={fileRef}
            type="file"
            accept={ACCEPT}
            className="sr-only"
            onChange={(e) => onFiles(e.target.files)}
          />
        </div>
      </div>
    </Panel>
  )
}

// ------------------------------------------------------------------ list
const features = tableFeatures({})
const helper = createColumnHelper<typeof features, EmailOut>()

function EmailsList() {
  const params = useSearchParams()
  const router = useRouter()
  const qc = useQueryClient()
  const brands = useBrands()

  const brandId = params.get("brand_id")
  const page = Math.max(1, Number(params.get("page") ?? 1) || 1)
  const urlQ = params.get("q") ?? ""

  const setParams = useCallback(
    (changes: Record<string, string | null>, resetPage = true) => {
      const next = new URLSearchParams(window.location.search)
      for (const [k, v] of Object.entries(changes)) {
        if (v) next.set(k, v)
        else next.delete(k)
      }
      if (resetPage) next.delete("page")
      const s = next.toString()
      router.replace(s ? `/emails?${s}` : "/emails", { scroll: false })
    },
    [router],
  )

  // debounced search
  const [q, setQ] = useState(urlQ)
  const [syncedQ, setSyncedQ] = useState(urlQ)
  if (urlQ !== syncedQ) {
    setSyncedQ(urlQ)
    setQ(urlQ)
  }
  useEffect(() => {
    if (q === urlQ) return
    const t = setTimeout(() => setParams({ q: q.trim() || null }), 350)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [q])

  const query = useMemo(
    () => ({
      brand_id: brandId ? [brandId] : undefined,
      q: urlQ || undefined,
      page,
      page_size: PAGE_SIZE,
    }),
    [brandId, urlQ, page],
  )

  const emails = useQuery({
    queryKey: keys.emails(JSON.stringify(query)),
    queryFn: () => api.emails(query),
    placeholderData: keepPreviousData,
  })

  const columns = useMemo(
    () =>
      helper.columns([
        helper.display({
          id: "verdict",
          header: () => "Verdict",
          cell: ({ row }) => {
            const e = row.original
            return (
              <div className="flex flex-col gap-1">
                {e.risk_level ? (
                  <RiskBadge level={e.risk_level} score={e.score ?? undefined} />
                ) : (
                  <span className="text-xs text-muted-foreground">Pending</span>
                )}
                {e.verdict && <span className="text-xs text-muted-foreground">{e.verdict}</span>}
              </div>
            )
          },
        }),
        helper.display({
          id: "sender",
          header: () => "Sender",
          cell: ({ row }) => (
            <span className="font-mono text-[13px] break-all">{row.original.from_addr ?? "—"}</span>
          ),
        }),
        helper.display({
          id: "subject",
          header: () => "Subject",
          cell: ({ row }) => (
            <span className="line-clamp-2 min-w-[12rem] max-w-[28rem] [overflow-wrap:anywhere]">
              {row.original.subject || "(no subject)"}
            </span>
          ),
        }),
        helper.display({
          id: "channel",
          header: () => "Channel",
          cell: ({ row }) => <span className="whitespace-nowrap text-sm">{channelLabel(row.original.channel)}</span>,
        }),
        helper.display({
          id: "received",
          header: () => "Received",
          cell: ({ row }) => (
            <span className="whitespace-nowrap text-sm text-muted-foreground" title={fmtDateTime(row.original.received_at)}>
              {fmtRelative(row.original.received_at)}
            </span>
          ),
        }),
      ]),
    [],
  )

  const EMPTY: EmailOut[] = useMemo(() => [], [])
  const table = useTable({ features, columns, data: emails.data?.items ?? EMPTY })

  const total = emails.data?.total ?? 0
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE))
  const from = total === 0 ? 0 : (page - 1) * PAGE_SIZE + 1
  const to = Math.min(total, page * PAGE_SIZE)
  const cellClass: Record<string, string> = {
    channel: "hidden md:table-cell",
    received: "hidden sm:table-cell",
    sender: "hidden lg:table-cell",
  }

  const brandOptions = [{ value: "all", label: "All brands" }, ...(brands.data ?? []).map((b) => ({ value: b.id, label: b.name }))]

  return (
    <>
      <PageHeader
        title="Phishing emails"
        description="Reported and collected emails analysed for brand impersonation, malicious links and attachments."
        actions={
          <Button variant="outline" size="sm" onClick={() => qc.invalidateQueries({ queryKey: ["emails"] })}>
            Refresh
          </Button>
        }
      />

      <div className="mb-4">
        <UploadPanel brandId={brandId} onBrandChange={(id) => setParams({ brand_id: id })} />
      </div>

      <div className="mb-3 flex flex-wrap items-center gap-2 rounded-lg border bg-card p-3">
        <div className="relative w-full sm:w-72">
          <Search className="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search subject or sender…"
            aria-label="Search emails"
            className="h-8 pl-8"
          />
        </div>
        <SimpleSelect
          ariaLabel="Filter by brand"
          size="sm"
          value={brandId ?? "all"}
          onChange={(v) => setParams({ brand_id: v === "all" ? null : v })}
          options={brandOptions}
          className="w-48"
        />
        <span className="tnum ml-auto text-sm text-muted-foreground" aria-live="polite">
          {emails.isLoading ? "Loading…" : `${fmtNumber(total)} ${total === 1 ? "email" : "emails"}`}
        </span>
        {emails.isFetching && !emails.isLoading && <Loader2 className="size-3.5 animate-spin" aria-label="Refreshing" />}
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
            {emails.isLoading &&
              Array.from({ length: 6 }).map((_, i) => (
                <TableRow key={i}>
                  {columns.map((c, j) => (
                    <TableCell key={j} className={cellClass[c.id ?? ""]}>
                      <Skeleton className="h-5 w-full" />
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            {!emails.isLoading &&
              table.getRowModel().rows.map((row) => (
                <TableRow
                  key={row.id}
                  onClick={() => router.push(`/emails/${row.original.id}`)}
                  className="cursor-pointer"
                  style={{
                    boxShadow: row.original.risk_level
                      ? `inset 3px 0 0 var(--risk-${row.original.risk_level.toLowerCase()})`
                      : undefined,
                  }}
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
        {!emails.isLoading && total === 0 && (
          <EmptyState icon={MailQuestion} title={urlQ || brandId ? "No emails match" : "No emails analysed yet"}>
            {urlQ || brandId
              ? "Clear the search or brand filter to see more."
              : "Upload a reported .eml above to analyse your first email."}
          </EmptyState>
        )}
        {total > 0 && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t px-3 py-2 text-sm">
            <span className="tnum text-muted-foreground">
              {fmtNumber(from)}–{fmtNumber(to)} of {fmtNumber(total)}
            </span>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="icon-sm"
                aria-label="Previous page"
                disabled={page <= 1}
                onClick={() => setParams({ page: page - 1 > 1 ? String(page - 1) : null }, false)}
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
                onClick={() => setParams({ page: String(page + 1) }, false)}
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

export default function EmailsPage() {
  return (
    <Suspense
      fallback={
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <Mail className="size-4" /> Loading…
        </div>
      }
    >
      <EmailsList />
    </Suspense>
  )
}
