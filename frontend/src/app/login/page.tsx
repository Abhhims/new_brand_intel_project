"use client"

import { Suspense, useEffect, useState } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Loader2 } from "lucide-react"
import { BrandMark } from "@/components/app-shell"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useAuth } from "@/lib/auth"

const schema = z.object({
  // Loose check on purpose: internal accounts may use non-public domains (e.g. .local)
  email: z.string().trim().min(1, "Enter your email").regex(/^[^\s@]+@[^\s@]+$/, "Enter a valid email address"),
  password: z.string().min(1, "Enter your password"),
})
type FormValues = z.infer<typeof schema>

function safeNext(next: string | null): string {
  return next && next.startsWith("/") && !next.startsWith("//") ? next : "/"
}

function LoginForm() {
  const { user, login } = useAuth()
  const router = useRouter()
  const params = useSearchParams()
  const [error, setError] = useState<string | null>(null)
  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting },
  } = useForm<FormValues>({ resolver: zodResolver(schema), defaultValues: { email: "", password: "" } })

  useEffect(() => {
    if (user) router.replace(safeNext(params.get("next")))
  }, [user, router, params])

  const onSubmit = handleSubmit(async (values) => {
    setError(null)
    try {
      await login(values.email, values.password)
      router.replace(safeNext(params.get("next")))
    } catch (e) {
      setError(e instanceof Error ? e.message : "Sign-in failed")
    }
  })

  return (
    <form onSubmit={onSubmit} noValidate className="space-y-4">
      <div className="space-y-1.5">
        <Label htmlFor="email">Email</Label>
        <Input
          id="email"
          type="email"
          autoComplete="username"
          autoFocus
          aria-invalid={!!errors.email}
          {...register("email")}
          className="h-10"
        />
        {errors.email && <p className="text-xs text-destructive">{errors.email.message}</p>}
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="password">Password</Label>
        <Input
          id="password"
          type="password"
          autoComplete="current-password"
          aria-invalid={!!errors.password}
          {...register("password")}
          className="h-10"
        />
        {errors.password && <p className="text-xs text-destructive">{errors.password.message}</p>}
      </div>
      {error && (
        <p role="alert" className="rounded-md bg-destructive/10 px-3 py-2 text-sm text-destructive">
          {error}
        </p>
      )}
      <Button type="submit" className="h-10 w-full" disabled={isSubmitting}>
        {isSubmitting && <Loader2 className="animate-spin" />}
        Sign in
      </Button>
    </form>
  )
}

export default function LoginPage() {
  return (
    <div className="grid min-h-dvh lg:grid-cols-[1fr_minmax(420px,40%)]">
      <section className="relative hidden overflow-hidden bg-sidebar lg:flex lg:flex-col lg:justify-between lg:p-12">
        <svg className="pointer-events-none absolute -right-40 -bottom-40 size-[720px] text-primary/15" viewBox="0 0 100 100" aria-hidden>
          {[48, 38, 28, 18, 8].map((r) => (
            <circle key={r} cx="50" cy="50" r={r} fill="none" stroke="currentColor" strokeWidth="0.25" />
          ))}
          <path d="M50 50 L84 16" stroke="currentColor" strokeWidth="0.4" />
        </svg>
        <div className="flex items-center gap-3">
          <BrandMark className="size-9" />
          <span className="text-sm font-semibold">Beyond Cloud</span>
        </div>
        <div className="relative max-w-md">
          <h2 className="text-3xl leading-tight font-semibold tracking-tight">
            See who is using your brand before your customers do.
          </h2>
          <p className="mt-4 text-sm leading-relaxed text-muted-foreground">
            Lookalike domains, phishing pages, fake apps, impersonating accounts and exposed documents — scored,
            evidenced and queued for review.
          </p>
        </div>
        <p className="relative text-xs text-muted-foreground">Internal tool. Access is logged.</p>
      </section>
      <section className="flex items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm">
          <div className="mb-8 flex items-center gap-3 lg:hidden">
            <BrandMark className="size-9" />
            <span className="text-sm font-semibold">Beyond Cloud Brand Intelligence</span>
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">Sign in</h1>
          <p className="mt-1 mb-6 text-sm text-muted-foreground">Use your analyst account.</p>
          <Suspense>
            <LoginForm />
          </Suspense>
        </div>
      </section>
    </div>
  )
}
