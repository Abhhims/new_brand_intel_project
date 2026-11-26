"use client"

import { Controller, useForm, useWatch } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { z } from "zod"
import { Loader2 } from "lucide-react"
import { SimpleSelect, TagInput } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Switch } from "@/components/ui/switch"
import { Textarea } from "@/components/ui/textarea"
import type { Brand, BrandInput } from "@/lib/api"
import { AUTO_FREQUENCIES, AUTO_RUNNERS, RISK_LEVELS } from "@/lib/constants"
import { fmtDateTime } from "@/lib/format"
import { Checkbox } from "@/components/ui/checkbox"

const schema = z.object({
  name: z.string().trim().min(1, "Enter the brand name").max(200),
  description: z.string().max(2000).optional(),
  keywords: z.array(z.string()),
  product_terms: z.array(z.string()),
  is_active: z.boolean(),
  alert_min_level: z.enum(["Low", "Medium", "High", "Critical"]),
  auto_scan_enabled: z.boolean(),
  auto_scan_frequency: z.enum(["daily", "every_3_days", "weekly"]),
  auto_scan_runners: z.array(
    z.enum(["domains", "apk", "rogue_app", "social", "social_media", "documents", "logo", "email_posture"]),
  ),
})
export type BrandFormValues = z.infer<typeof schema>

export function brandDefaults(b?: Brand): BrandFormValues {
  return {
    name: b?.name ?? "",
    description: b?.description ?? "",
    keywords: b?.keywords ?? [],
    product_terms: b?.product_terms ?? [],
    is_active: b?.is_active ?? true,
    alert_min_level: b?.alert_min_level ?? "Medium",
    auto_scan_enabled: b?.auto_scan_enabled ?? false,
    auto_scan_frequency: b?.auto_scan_frequency ?? "daily",
    auto_scan_runners: b?.auto_scan_runners ?? [],
  }
}

export function BrandForm({
  initial,
  onSubmit,
  submitLabel,
  readOnly,
  onCancel,
}: {
  initial?: Brand
  onSubmit: (values: BrandInput) => Promise<unknown>
  submitLabel: string
  readOnly?: boolean
  onCancel?: () => void
}) {
  const {
    register,
    control,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting, isDirty },
  } = useForm<BrandFormValues>({ resolver: zodResolver(schema), values: brandDefaults(initial) })

  const submit = handleSubmit(async (v) => {
    await onSubmit({ ...v, description: v.description?.trim() || null })
    if (initial) reset(v)
  })

  const autoOn = useWatch({ control, name: "auto_scan_enabled" })

  return (
    <form onSubmit={submit} className="space-y-4" noValidate>
      <fieldset disabled={readOnly} className="space-y-4">
        <div className="space-y-1.5">
          <Label htmlFor="brand-name">Brand name</Label>
          <Input id="brand-name" aria-invalid={!!errors.name} {...register("name")} placeholder="Your company name" />
          {errors.name && <p className="text-xs text-destructive">{errors.name.message}</p>}
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="brand-description">Description</Label>
          <Textarea id="brand-description" rows={2} {...register("description")} placeholder="What the brand is, for other analysts" />
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="brand-keywords">Keywords</Label>
          <Controller
            control={control}
            name="keywords"
            render={({ field }) => (
              <TagInput
                id="brand-keywords"
                value={field.value}
                onChange={field.onChange}
                placeholder="brandname, brand name"
                disabled={readOnly}
              />
            )}
          />
          <p className="text-xs text-muted-foreground">
            Used to generate lookalike domains and to search stores, social networks and documents. Press Enter or comma to add. If left
            empty, the brand name is used.
          </p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor="brand-products">Product terms</Label>
          <Controller
            control={control}
            name="product_terms"
            render={({ field }) => (
              <TagInput id="brand-products" value={field.value} onChange={field.onChange} placeholder="mobile banking, zpay" disabled={readOnly} />
            )}
          />
          <p className="text-xs text-muted-foreground">Product and service names that impersonators often combine with the brand.</p>
        </div>
        <div className="grid gap-3 sm:grid-cols-2">
          <Controller
            control={control}
            name="is_active"
            render={({ field }) => (
              <label className="flex cursor-pointer items-start justify-between gap-3 rounded-lg border p-3">
                <span>
                  <span className="block text-sm font-medium">Monitoring active</span>
                  <span className="block text-xs text-muted-foreground">Scheduled scans include this brand</span>
                </span>
                <Switch checked={field.value} onCheckedChange={field.onChange} disabled={readOnly} />
              </label>
            )}
          />
          <Controller
            control={control}
            name="alert_min_level"
            render={({ field }) => (
              <div className="space-y-1.5 rounded-lg border p-3">
                <Label>Alert from</Label>
                <SimpleSelect
                  ariaLabel="Alert from risk level"
                  value={field.value}
                  onChange={(v) => field.onChange(v)}
                  options={[...RISK_LEVELS].reverse().map((r) => ({ value: r, label: `${r} and above` }))}
                  className="w-full"
                  disabled={readOnly}
                />
                <span className="block text-xs text-muted-foreground">
                  Lower-risk findings stay on the Findings page but do not raise an alert
                </span>
              </div>
            )}
          />
        </div>
        <section className="space-y-3 rounded-lg border p-3" aria-labelledby="auto-scan-heading">
          <Controller
            control={control}
            name="auto_scan_enabled"
            render={({ field }) => (
              <label className="flex cursor-pointer items-start justify-between gap-3">
                <span>
                  <span id="auto-scan-heading" className="block text-sm font-medium">
                    Automatic scanning
                  </span>
                  <span className="block text-xs text-muted-foreground">
                    Runs on a schedule only while the master switch in Settings is also on. Run scan now always works.
                  </span>
                </span>
                <Switch checked={field.value} onCheckedChange={field.onChange} disabled={readOnly} aria-label="Automatic scanning" />
              </label>
            )}
          />
          <div className={autoOn ? "space-y-3" : "space-y-3 opacity-60"}>
            <div className="space-y-1.5">
              <Label>Frequency</Label>
              <Controller
                control={control}
                name="auto_scan_frequency"
                render={({ field }) => (
                  <SimpleSelect
                    ariaLabel="Automatic scan frequency"
                    value={field.value}
                    onChange={(v) => field.onChange(v)}
                    options={AUTO_FREQUENCIES}
                    className="w-full sm:w-56"
                    disabled={readOnly || !autoOn}
                  />
                )}
              />
            </div>
            <Controller
              control={control}
              name="auto_scan_runners"
              render={({ field }) => (
                <fieldset className="space-y-1.5">
                  <legend className="text-sm font-medium">Scanners</legend>
                  <p className="text-xs text-muted-foreground">None ticked = every scanner.</p>
                  <div className="grid grid-cols-1 gap-1.5 pt-1 sm:grid-cols-2">
                    {AUTO_RUNNERS.map((r) => (
                      <label key={r.value} className="flex cursor-pointer items-center gap-2 text-sm">
                        <Checkbox
                          checked={field.value.includes(r.value)}
                          disabled={readOnly || !autoOn}
                          onCheckedChange={(c) =>
                            field.onChange(c ? [...field.value, r.value] : field.value.filter((v) => v !== r.value))
                          }
                        />
                        {r.label}
                      </label>
                    ))}
                  </div>
                </fieldset>
              )}
            />
          </div>
          {initial && (
            <dl className="grid grid-cols-2 gap-3 border-t pt-3 text-sm">
              <div>
                <dt className="text-xs text-muted-foreground">Last automatic scan</dt>
                <dd className="tnum">{initial.last_auto_scan_at ? fmtDateTime(initial.last_auto_scan_at) : "Never"}</dd>
              </div>
              <div>
                <dt className="text-xs text-muted-foreground">Next automatic scan</dt>
                <dd className="tnum">
                  {initial.auto_scan_enabled && initial.next_auto_scan_at ? fmtDateTime(initial.next_auto_scan_at) : "Off"}
                </dd>
              </div>
            </dl>
          )}
        </section>
      </fieldset>
      {!readOnly && (
        <div className="flex justify-end gap-2">
          {onCancel && (
            <Button type="button" variant="ghost" onClick={onCancel}>
              Cancel
            </Button>
          )}
          <Button type="submit" disabled={isSubmitting || (!!initial && !isDirty)}>
            {isSubmitting && <Loader2 className="animate-spin" />}
            {submitLabel}
          </Button>
        </div>
      )}
    </form>
  )
}
