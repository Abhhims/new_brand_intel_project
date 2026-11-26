"use client"

import { useState } from "react"
import { ChevronDown, X } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Popover, PopoverContent, PopoverTrigger } from "@/components/ui/popover"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { cn } from "@/lib/utils"

export interface Option {
  value: string
  label: React.ReactNode
  /** plain text used for the trigger summary */
  text?: string
}

/** Checkbox list in a popover; the trigger summarises the selection. */
export function MultiFilter({
  label,
  options,
  value,
  onChange,
  className,
}: {
  label: string
  options: Option[]
  value: string[]
  /** Called with a value and whether it is now checked; [] means clear all */
  onChange: (change: { value: string; checked: boolean } | []) => void
  className?: string
}) {
  const selected = options.filter((o) => value.includes(o.value))
  const summary =
    selected.length === 0
      ? null
      : selected.length === 1
        ? (selected[0].text ?? String(selected[0].value))
        : `${selected.length} selected`
  return (
    <Popover>
      <PopoverTrigger
        render={
          <Button
            variant="outline"
            size="sm"
            className={cn("h-8 justify-between gap-1.5 font-normal", selected.length > 0 && "border-primary/50", className)}
          />
        }
      >
        <span className="text-muted-foreground">{label}</span>
        {summary && <span className="max-w-[9rem] truncate font-medium text-foreground">{summary}</span>}
        <ChevronDown className="size-3.5 opacity-60" />
      </PopoverTrigger>
      <PopoverContent align="start" className="w-64 gap-0 p-1">
        <div role="group" aria-label={label} className="max-h-72 overflow-y-auto">
          {options.map((o) => {
            const checked = value.includes(o.value)
            return (
              <label
                key={o.value}
                className="flex cursor-pointer items-center gap-2.5 rounded-md px-2 py-1.5 text-sm hover:bg-accent"
              >
                <Checkbox
                  checked={checked}
                  onCheckedChange={(c) => onChange({ value: o.value, checked: !!c })}
                />
                <span className="min-w-0 flex-1">{o.label}</span>
              </label>
            )
          })}
        </div>
        {value.length > 0 && (
          <div className="mt-1 border-t pt-1">
            <Button variant="ghost" size="sm" className="w-full justify-center" onClick={() => onChange([])}>
              Clear {label.toLowerCase()}
            </Button>
          </div>
        )}
      </PopoverContent>
    </Popover>
  )
}

/** Single-value select using Base UI's items map so the trigger shows labels, not raw values. */
export function SimpleSelect({
  value,
  onChange,
  options,
  placeholder,
  className,
  size = "default",
  ariaLabel,
  disabled,
}: {
  value: string | null
  onChange: (v: string) => void
  options: { value: string; label: string }[]
  placeholder?: string
  className?: string
  size?: "sm" | "default"
  ariaLabel?: string
  disabled?: boolean
}) {
  return (
    <Select
      value={value}
      onValueChange={(v) => v !== null && onChange(v as string)}
      items={options}
      disabled={disabled}
    >
      <SelectTrigger size={size} className={className} aria-label={ariaLabel}>
        <SelectValue placeholder={placeholder} />
      </SelectTrigger>
      <SelectContent alignItemWithTrigger={false} align="start">
        {options.map((o) => (
          <SelectItem key={o.value} value={o.value}>
            {o.label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  )
}

/** Free-text tags: Enter or comma adds, Backspace on empty removes the last. */
export function TagInput({
  value,
  onChange,
  placeholder,
  id,
  disabled,
}: {
  value: string[]
  onChange: (next: string[]) => void
  placeholder?: string
  id?: string
  disabled?: boolean
}) {
  const [draft, setDraft] = useState("")
  const add = (raw: string) => {
    const parts = raw
      .split(",")
      .map((s) => s.trim())
      .filter(Boolean)
    const next = [...value]
    for (const p of parts) if (!next.some((v) => v.toLowerCase() === p.toLowerCase())) next.push(p)
    if (next.length !== value.length) onChange(next)
    setDraft("")
  }
  return (
    <div
      className={cn(
        "flex min-h-9 flex-wrap items-center gap-1.5 rounded-lg border border-input bg-transparent px-1.5 py-1 focus-within:border-ring focus-within:ring-3 focus-within:ring-ring/50 dark:bg-input/30",
        disabled && "opacity-60",
      )}
    >
      {value.map((tag) => (
        <span key={tag} className="inline-flex items-center gap-1 rounded-md bg-secondary py-0.5 pr-1 pl-2 text-xs font-medium">
          {tag}
          {!disabled && (
            <button
              type="button"
              aria-label={`Remove ${tag}`}
              onClick={() => onChange(value.filter((v) => v !== tag))}
              className="rounded p-0.5 text-muted-foreground hover:bg-background hover:text-foreground"
            >
              <X className="size-3" />
            </button>
          )}
        </span>
      ))}
      <input
        id={id}
        value={draft}
        disabled={disabled}
        onChange={(e) => {
          const v = e.target.value
          if (v.includes(",")) add(v)
          else setDraft(v)
        }}
        onKeyDown={(e) => {
          if (e.key === "Enter") {
            e.preventDefault()
            if (draft.trim()) add(draft)
          } else if (e.key === "Backspace" && !draft && value.length) {
            onChange(value.slice(0, -1))
          }
        }}
        onBlur={() => draft.trim() && add(draft)}
        placeholder={value.length ? "" : placeholder}
        className="h-6 min-w-[8rem] flex-1 bg-transparent px-1 text-sm outline-none placeholder:text-muted-foreground"
      />
    </div>
  )
}

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
  className,
}: {
  icon?: React.ComponentType<{ className?: string }>
  title: string
  children?: React.ReactNode
  action?: React.ReactNode
  className?: string
}) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      {Icon && <Icon className="mb-3 size-8 text-muted-foreground/60" />}
      <p className="font-medium">{title}</p>
      {children && <div className="mt-1 max-w-md text-sm text-muted-foreground">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  )
}

export function Panel({
  title,
  description,
  actions,
  children,
  className,
  bodyClassName,
}: {
  title?: React.ReactNode
  description?: React.ReactNode
  actions?: React.ReactNode
  children: React.ReactNode
  className?: string
  bodyClassName?: string
}) {
  return (
    <section className={cn("rounded-lg border bg-card text-card-foreground", className)}>
      {(title || actions) && (
        <header className="flex flex-wrap items-start justify-between gap-2 border-b px-4 py-3">
          <div className="min-w-0">
            {title && <h2 className="text-sm font-semibold">{title}</h2>}
            {description && <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>}
          </div>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </header>
      )}
      <div className={cn("p-4", bodyClassName)}>{children}</div>
    </section>
  )
}
