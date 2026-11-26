"use client"

import { CircleX, RotateCw } from "lucide-react"
import { Button } from "@/components/ui/button"
import { ApiError } from "@/lib/api"
import { cn } from "@/lib/utils"

/** True when a failed request means "this record does not exist" rather than "something broke". */
export const isNotFound = (error: unknown) => error instanceof ApiError && error.status === 404

/**
 * Shown when the API could not be reached or returned an error (RDA-19). A failed request is never shown as an
 * empty list or a zero — the analyst must know the data is missing, not clean.
 */
export function ErrorPanel({
  error,
  onRetry,
  title = "Couldn't load this",
  className,
}: {
  error: unknown
  onRetry?: () => void
  title?: string
  className?: string
}) {
  const message = error instanceof Error ? error.message : "The request failed."
  return (
    <div
      role="alert"
      className={cn(
        "flex flex-col items-center justify-center gap-2 rounded-lg border border-destructive/30 bg-destructive/5 px-6 py-10 text-center",
        className,
      )}
    >
      <CircleX className="size-7 text-destructive" aria-hidden />
      <p className="font-medium">{title}</p>
      <p className="max-w-md text-sm text-muted-foreground">
        {message} The numbers on this page are not shown because they could not be loaded — this is not a clean
        result.
      </p>
      {onRetry && (
        <Button variant="outline" size="sm" onClick={onRetry} className="mt-2">
          <RotateCw className="size-3.5" />
          Retry
        </Button>
      )}
    </div>
  )
}
