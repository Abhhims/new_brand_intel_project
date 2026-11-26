"use client"

import { createContext, useCallback, useContext, useEffect, useMemo, useState, useSyncExternalStore } from "react"
import { useQueryClient } from "@tanstack/react-query"
import { api, session, type User } from "@/lib/api"

interface AuthState {
  /** undefined while reading storage on first client render */
  user: User | null | undefined
  isAdmin: boolean
  login: (email: string, password: string) => Promise<User>
  logout: () => void
}

const AuthContext = createContext<AuthState | null>(null)

const subscribe = (cb: () => void) => {
  window.addEventListener("storage", cb)
  return () => window.removeEventListener("storage", cb)
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  // Hydration-safe read of the stored session: null on the server, the stored value on the client.
  const hydrated = useSyncExternalStore(
    subscribe,
    () => true,
    () => false,
  )
  const [override, setOverride] = useState<User | null | undefined>(undefined)
  const user = !hydrated ? undefined : override !== undefined ? override : session.token() ? session.user() : null

  // Refresh the profile once per load so role/active changes take effect; a 401 logs out via the API client.
  useEffect(() => {
    if (!hydrated || !session.token()) return
    let cancelled = false
    api
      .me()
      .then((me) => {
        if (cancelled) return
        const token = session.token()
        if (token) session.save(token, me)
        setOverride(me)
      })
      .catch(() => {})
    return () => {
      cancelled = true
    }
  }, [hydrated])

  const login = useCallback(async (email: string, password: string) => {
    const res = await api.login(email, password)
    session.save(res.access_token, res.user)
    setOverride(res.user)
    return res.user
  }, [])

  const logout = useCallback(() => {
    session.clear()
    setOverride(null)
    queryClient.clear()
  }, [queryClient])

  const value = useMemo<AuthState>(
    () => ({ user, isAdmin: user?.role === "admin", login, logout }),
    [user, login, logout],
  )
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error("useAuth must be used inside AuthProvider")
  return ctx
}
