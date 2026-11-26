"use client"

import Link from "next/link"
import { ChevronRight, Users } from "lucide-react"
import { PageHeader } from "@/components/app-shell"
import { AutoScanCard } from "@/components/auto-scan"
import { useAuth } from "@/lib/auth"

export default function SettingsPage() {
  const { isAdmin } = useAuth()
  return (
    <>
      <PageHeader title="Settings" description="Platform-wide settings" />
      <div className="max-w-3xl space-y-4">
        <AutoScanCard />
        {isAdmin && (
          <Link
            href="/settings/users"
            className="flex items-center justify-between gap-3 rounded-lg border bg-card p-4 outline-none transition-colors hover:border-primary/40 focus-visible:ring-2 focus-visible:ring-ring"
          >
            <span className="flex items-center gap-2.5">
              <Users className="size-4 text-muted-foreground" aria-hidden />
              <span>
                <span className="block text-sm font-medium">Users</span>
                <span className="block text-xs text-muted-foreground">Add analysts and admins, reset passwords</span>
              </span>
            </span>
            <ChevronRight className="size-4 text-muted-foreground" aria-hidden />
          </Link>
        )}
      </div>
    </>
  )
}
