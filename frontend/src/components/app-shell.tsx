"use client"

import Link from "next/link"
import { usePathname, useRouter } from "next/navigation"
import { useState } from "react"
import { useTheme } from "next-themes"
import { Building2, Crosshair, Settings, LayoutDashboard, ListChecks, MessageSquareWarning, LogOut, Mail, Menu, Monitor, Moon, Plug, Radar, Sun, Users } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Sheet, SheetContent, SheetTitle } from "@/components/ui/sheet"
import { useAuth } from "@/lib/auth"
import { cn } from "@/lib/utils"

const NAV = [
  { href: "/", label: "Dashboard", icon: LayoutDashboard, admin: false },
  { href: "/alerts", label: "Alerts", icon: ListChecks, admin: false },
  { href: "/findings", label: "Findings", icon: Crosshair, admin: false },
  { href: "/social", label: "Social Media", icon: MessageSquareWarning, admin: false },
  { href: "/emails", label: "Emails", icon: Mail, admin: false },
  { href: "/brands", label: "Brands", icon: Building2, admin: false },
  { href: "/scans", label: "Scans", icon: Radar, admin: false },
  { href: "/integrations", label: "Integrations", icon: Plug, admin: false },
  { href: "/settings", label: "Settings", icon: Settings, admin: false },
  { href: "/settings/users", label: "Users", icon: Users, admin: true },
]

export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden>
      <rect width="32" height="32" rx="7" fill="var(--primary)" />
      <path d="M16 25a9 9 0 1 1 9-9" fill="none" stroke="var(--primary-foreground)" strokeWidth="2.2" strokeLinecap="round" opacity=".45" />
      <path d="M16 21a5 5 0 1 1 5-5" fill="none" stroke="var(--primary-foreground)" strokeWidth="2.2" strokeLinecap="round" opacity=".75" />
      <circle cx="16" cy="16" r="1.9" fill="var(--primary-foreground)" />
      <path d="M16 16 L24.5 9.5" stroke="var(--primary-foreground)" strokeWidth="2.2" strokeLinecap="round" />
    </svg>
  )
}

function ThemeSwitch() {
  const { theme, setTheme } = useTheme()
  const options = [
    { value: "light", icon: Sun, label: "Light" },
    { value: "dark", icon: Moon, label: "Dark" },
    { value: "system", icon: Monitor, label: "System" },
  ]
  return (
    <div role="radiogroup" aria-label="Colour theme" className="flex rounded-md bg-sidebar-accent/60 p-0.5">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={theme === o.value}
          aria-label={o.label}
          title={o.label}
          onClick={() => setTheme(o.value)}
          className={cn(
            "flex h-6 flex-1 items-center justify-center rounded-[5px] text-sidebar-foreground/60 transition-colors outline-none focus-visible:ring-2 focus-visible:ring-ring",
            theme === o.value && "bg-card text-sidebar-foreground shadow-xs",
          )}
        >
          <o.icon className="size-3.5" />
        </button>
      ))}
    </div>
  )
}

function SidebarBody({ onNavigate }: { onNavigate?: () => void }) {
  const pathname = usePathname()
  const router = useRouter()
  const { user, isAdmin, logout } = useAuth()
  const isActive = (href: string) => (href === "/" || href === "/settings" ? pathname === href : pathname.startsWith(href))

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2.5 px-4 pt-5 pb-6">
        <BrandMark className="size-8 shrink-0" />
        <div className="leading-tight">
          <div className="text-[13px] font-semibold tracking-tight">Brand Intelligence</div>
          <div className="text-xs text-sidebar-foreground/60">Beyond Cloud</div>
        </div>
      </div>
      <nav aria-label="Main" className="flex flex-col gap-0.5 px-2">
        {NAV.filter((n) => !n.admin || isAdmin).map((n) => {
          const active = isActive(n.href)
          return (
            <Link
              key={n.href}
              href={n.href}
              onClick={onNavigate}
              aria-current={active ? "page" : undefined}
              className={cn(
                "group relative flex h-9 items-center gap-2.5 rounded-md px-2.5 text-sm text-sidebar-foreground/75 transition-colors outline-none hover:bg-sidebar-accent hover:text-sidebar-foreground focus-visible:ring-2 focus-visible:ring-ring",
                active && "bg-sidebar-accent font-medium text-sidebar-foreground",
              )}
            >
              {active && <span className="absolute top-2 bottom-2 left-0 w-[3px] rounded-r bg-sidebar-primary" aria-hidden />}
              <n.icon className="size-4 shrink-0 opacity-80" />
              {n.label}
            </Link>
          )
        })}
      </nav>
      <div className="mt-auto space-y-3 border-t border-sidebar-border p-3">
        <ThemeSwitch />
        {user && (
          <div className="flex items-center gap-2">
            <div className="flex size-8 shrink-0 items-center justify-center rounded-full bg-sidebar-accent text-xs font-semibold uppercase">
              {user.name.slice(0, 2)}
            </div>
            <div className="min-w-0 flex-1 leading-tight">
              <div className="truncate text-sm font-medium">{user.name}</div>
              <div className="truncate text-xs text-sidebar-foreground/60 capitalize">{user.role}</div>
            </div>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label="Sign out"
              title="Sign out"
              onClick={() => {
                logout()
                router.replace("/login")
              }}
            >
              <LogOut />
            </Button>
          </div>
        )}
      </div>
    </div>
  )
}

export function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="min-h-dvh lg:pl-56">
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-56 border-r border-sidebar-border bg-sidebar text-sidebar-foreground lg:block">
        <SidebarBody />
      </aside>
      <header className="sticky top-0 z-20 flex h-12 items-center gap-2 border-b bg-background/90 px-3 backdrop-blur lg:hidden">
        <Button variant="ghost" size="icon" aria-label="Open navigation" onClick={() => setOpen(true)}>
          <Menu />
        </Button>
        <BrandMark className="size-6" />
        <span className="text-sm font-semibold">Brand Intelligence</span>
      </header>
      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="left" className="w-64 bg-sidebar p-0 text-sidebar-foreground" showCloseButton={false}>
          <SheetTitle className="sr-only">Navigation</SheetTitle>
          <SidebarBody onNavigate={() => setOpen(false)} />
        </SheetContent>
      </Sheet>
      <main className="mx-auto w-full max-w-[1600px] px-4 py-5 sm:px-6 lg:px-8 lg:py-7">{children}</main>
    </div>
  )
}

export function PageHeader({
  title,
  description,
  actions,
  children,
}: {
  title: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  children?: React.ReactNode
}) {
  return (
    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold tracking-tight text-balance sm:text-2xl">{title}</h1>
        {description && <p className="mt-1 max-w-prose text-sm text-muted-foreground">{description}</p>}
        {children}
      </div>
      {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
    </div>
  )
}
