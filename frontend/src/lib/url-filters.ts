"use client"

import { useEffect, useRef } from "react"
import { usePathname, useRouter, useSearchParams } from "next/navigation"

/** Filters live in the URL so a list view can be bookmarked and shared (DSH-11…16). */
export function useUrlFilters() {
  const params = useSearchParams()
  const router = useRouter()
  const pathname = usePathname()
  // URL we have asked the router for but that may not be committed yet; lets rapid updates build on each other
  const pending = useRef<string | null>(null)
  useEffect(() => {
    pending.current = null
  }, [params])
  const current = () => new URLSearchParams(pending.current ?? window.location.search)

  const update = (changes: Record<string, string | string[] | null>, resetPage = true) => {
    const next = current()
    for (const [k, v] of Object.entries(changes)) {
      next.delete(k)
      if (Array.isArray(v)) v.forEach((x) => next.append(k, x))
      else if (v) next.set(k, v)
    }
    if (resetPage) next.delete("page")
    const s = next.toString()
    pending.current = s ? `?${s}` : ""
    router.replace(s ? `${pathname}?${s}` : pathname, { scroll: false })
  }
  /** Toggle one value of a multi-value filter, based on the live URL so quick clicks accumulate */
  const toggle = (key: string) => (change: { value: string; checked: boolean } | []) => {
    if (Array.isArray(change)) return update({ [key]: null })
    const others = current().getAll(key).filter((v) => v !== change.value)
    update({ [key]: change.checked ? [...others, change.value] : others })
  }
  return { params, update, toggle }
}
