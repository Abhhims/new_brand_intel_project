"use client"

import { useQuery } from "@tanstack/react-query"
import { api } from "@/lib/api"

export const keys = {
  brands: ["brands"] as const,
  brand: (id: string) => ["brands", id] as const,
  alerts: (query: string) => ["alerts", "list", query] as const,
  alert: (id: string) => ["alerts", "detail", id] as const,
  findings: (query: string) => ["findings", "list", query] as const,
  finding: (id: string) => ["findings", "detail", id] as const,
  executive: (brandIds: string[]) => ["stats", "executive", brandIds] as const,
  trends: (days: number, brandIds: string[]) => ["stats", "trends", days, brandIds] as const,
  scans: (brandId?: string) => ["scans", brandId ?? "all"] as const,
  emails: (query: string) => ["emails", "list", query] as const,
  email: (id: string) => ["emails", "detail", id] as const,
  users: ["users"] as const,
  autoScan: ["settings", "auto-scan"] as const,
}

export function useBrands() {
  return useQuery({ queryKey: keys.brands, queryFn: api.brands, staleTime: 60_000 })
}
