"use client"

import { useState } from "react"
import { useQuery } from "@tanstack/react-query"
import { Loader2 } from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { AutoScanBanner } from "@/components/auto-scan"
import { ScanTable, isActiveScan } from "@/components/scan-table"
import { SimpleSelect } from "@/components/widgets"
import { api } from "@/lib/api"
import { keys, useBrands } from "@/lib/queries"

export default function ScansPage() {
  const [brand, setBrand] = useState("all")
  const brands = useBrands()
  const brandId = brand === "all" ? undefined : brand
  const scans = useQuery({
    queryKey: keys.scans(brandId),
    queryFn: () => api.scans({ brand_id: brandId ? [brandId] : undefined, limit: 200 }),
    // Poll while anything is still queued or running
    refetchInterval: (q) => (q.state.data?.some(isActiveScan) ? 5000 : false),
  })
  const active = scans.data?.filter(isActiveScan).length ?? 0

  return (
    <>
      <PageHeader
        title="Scans"
        description="Every scheduled and manual scan, newest first. Open a row to see which parts ran, which could not run, and why."
        actions={
          <SimpleSelect
            ariaLabel="Brand"
            value={brand}
            onChange={setBrand}
            options={[{ value: "all", label: "All brands" }, ...(brands.data ?? []).map((b) => ({ value: b.id, label: b.name }))]}
            className="w-52"
          />
        }
      >
        {active > 0 && (
          <p className="mt-2 inline-flex items-center gap-1.5 text-sm text-muted-foreground" aria-live="polite">
            <Loader2 className="size-3.5 animate-spin" />
            {active} in progress, refreshing every 5 seconds
          </p>
        )}
      </PageHeader>
      <AutoScanBanner />
      <ScanTable scans={scans.data} loading={scans.isLoading} error={scans.error} onRetry={() => scans.refetch()} />
    </>
  )
}
