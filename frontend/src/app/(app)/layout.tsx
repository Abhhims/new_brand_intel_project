"use client"

import { useEffect } from "react"
import { usePathname, useRouter } from "next/navigation"
import { AppShell } from "@/components/app-shell"
import { useAuth } from "@/lib/auth"

/** Every page in this group requires a signed-in user (FND-03). */
export default function AuthedLayout({ children }: { children: React.ReactNode }) {
  const { user } = useAuth()
  const router = useRouter()
  const pathname = usePathname()

  useEffect(() => {
    if (user === null) {
      const next = pathname && pathname !== "/" ? `?next=${encodeURIComponent(pathname + window.location.search)}` : ""
      router.replace(`/login${next}`)
    }
  }, [user, router, pathname])

  if (!user) {
    return (
      <div className="flex min-h-dvh items-center justify-center text-sm text-muted-foreground" aria-busy>
        Checking your session…
      </div>
    )
  }
  return <AppShell>{children}</AppShell>
}
