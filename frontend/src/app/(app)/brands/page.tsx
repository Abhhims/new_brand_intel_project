"use client"

import { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useMutation, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"
import { Building2, ImageOff, Plus } from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { BrandForm } from "@/components/brand-form"
import { ErrorPanel } from "@/components/query-state"
import { EmptyState } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Brand } from "@/lib/api"
import { useAuth } from "@/lib/auth"
import { fmtDate, fmtDateTime, fmtNumber } from "@/lib/format"
import { AUTO_FREQUENCY_LABELS } from "@/lib/constants"
import { cn } from "@/lib/utils"
import { keys, useBrands } from "@/lib/queries"

function BrandLogo({ brand }: { brand: Brand }) {
  const logo = brand.assets.find((a) => a.kind === "logo") ?? brand.assets[0]
  return logo?.url ? (
    <img src={logo.url} alt="" className="size-9 rounded-md border bg-white object-contain p-1" />
  ) : (
    <div className="flex size-9 items-center justify-center rounded-md border border-dashed text-muted-foreground/60">
      <ImageOff className="size-3.5" />
    </div>
  )
}

function CreateBrandDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const qc = useQueryClient()
  const router = useRouter()
  const create = useMutation({
    mutationFn: api.createBrand,
    onSuccess: (b) => {
      qc.invalidateQueries({ queryKey: keys.brands })
      toast.success(`Brand ${b.name} created. Add its official logo and allowlists next.`)
      onOpenChange(false)
      router.push(`/brands/${b.id}`)
    },
  })
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[92vh] overflow-y-auto sm:max-w-xl">
        <DialogHeader>
          <DialogTitle>Add a brand</DialogTitle>
          <DialogDescription>Official logos, domains and handles are added on the next screen.</DialogDescription>
        </DialogHeader>
        <BrandForm onSubmit={(v) => create.mutateAsync(v).catch(() => {})} submitLabel="Create brand" onCancel={() => onOpenChange(false)} />
      </DialogContent>
    </Dialog>
  )
}

export default function BrandsPage() {
  const { isAdmin } = useAuth()
  const router = useRouter()
  const brands = useBrands()
  const [creating, setCreating] = useState(false)

  return (
    <>
      <PageHeader
        title="Brands"
        description="Each brand is monitored with its own keywords, official assets and allowlists."
        actions={
          isAdmin && (
            <Button onClick={() => setCreating(true)}>
              <Plus />
              Add brand
            </Button>
          )
        }
      />
      <div className="overflow-hidden rounded-lg border bg-card">
        <Table>
          <TableHeader>
            <TableRow className="hover:bg-transparent">
              <TableHead className="text-xs text-muted-foreground">Brand</TableHead>
              <TableHead className="hidden text-xs text-muted-foreground md:table-cell">Keywords</TableHead>
              <TableHead className="hidden text-xs text-muted-foreground sm:table-cell">Assets</TableHead>
              <TableHead className="hidden text-xs text-muted-foreground lg:table-cell">Allowlist</TableHead>
              <TableHead className="text-right text-xs text-muted-foreground">Open alerts</TableHead>
              <TableHead className="text-xs text-muted-foreground">Monitoring</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {brands.isLoading &&
              Array.from({ length: 3 }).map((_, i) => (
                <TableRow key={i}>
                  <TableCell colSpan={6}>
                    <Skeleton className="h-9 w-full" />
                  </TableCell>
                </TableRow>
              ))}
            {brands.data?.map((b) => (
              <TableRow key={b.id} className="cursor-pointer" onClick={() => router.push(`/brands/${b.id}`)}>
                <TableCell>
                  <div className="flex items-center gap-3">
                    <BrandLogo brand={b} />
                    <div className="min-w-0">
                      <Link href={`/brands/${b.id}`} className="font-medium hover:underline" onClick={(e) => e.stopPropagation()}>
                        {b.name}
                      </Link>
                      <div className="text-xs text-muted-foreground">Added {fmtDate(b.created_at)}</div>
                    </div>
                  </div>
                </TableCell>
                <TableCell className="hidden max-w-xs md:table-cell">
                  <div className="truncate text-sm text-muted-foreground">{b.keywords.join(", ") || "—"}</div>
                </TableCell>
                <TableCell className="tnum hidden sm:table-cell">{b.assets.length}</TableCell>
                <TableCell className="tnum hidden lg:table-cell">{b.allowlist.length}</TableCell>
                <TableCell className="text-right">
                  <Link
                    href={`/alerts?brand_id=${b.id}&status=New&status=Investigating&status=Confirmed+Threat`}
                    onClick={(e) => e.stopPropagation()}
                    className="tnum font-medium hover:underline"
                  >
                    {fmtNumber(b.open_alerts)}
                  </Link>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1 text-xs">
                    <span className={b.is_active ? "text-foreground" : "text-muted-foreground"}>{b.is_active ? "Active" : "Paused"}</span>
                    <span
                      className={cn(
                        "rounded-md px-1.5 py-0.5 whitespace-nowrap ring-1 ring-inset",
                        b.auto_scan_enabled ? "bg-sky-50 text-sky-700 ring-sky-200 dark:bg-sky-950/50 dark:text-sky-300 dark:ring-sky-900" : "bg-muted text-muted-foreground ring-border",
                      )}
                      title={b.auto_scan_enabled && b.next_auto_scan_at ? `Next automatic scan ${fmtDateTime(b.next_auto_scan_at)}` : "Automatic scanning is off for this brand"}
                    >
                      Auto: {b.auto_scan_enabled ? AUTO_FREQUENCY_LABELS[b.auto_scan_frequency] : "Off"}
                    </span>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
        {brands.error && (
          <ErrorPanel error={brands.error} onRetry={() => brands.refetch()} title="Couldn't load brands" className="m-3" />
        )}
        {brands.data?.length === 0 && (
          <EmptyState
            icon={Building2}
            title="No brands yet"
            action={
              isAdmin && (
                <Button onClick={() => setCreating(true)}>
                  <Plus />
                  Add the first brand
                </Button>
              )
            }
          >
            {isAdmin ? "Add a brand to start monitoring it." : "Ask an admin to add the brands you monitor."}
          </EmptyState>
        )}
      </div>
      {isAdmin && <CreateBrandDialog open={creating} onOpenChange={setCreating} />}
    </>
  )
}
