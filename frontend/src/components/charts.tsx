"use client"

import { useRouter } from "next/navigation"
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis, type TooltipContentProps } from "recharts"
import type { NameType, ValueType } from "recharts/types/component/DefaultTooltipContent"
import type { TrendPoint } from "@/lib/api"
import { fmtDay, fmtNumber } from "@/lib/format"
import { RiskMeter } from "@/components/badges"
import type { RiskLevel } from "@/lib/api"

const RISK_SERIES: { key: keyof TrendPoint; level: RiskLevel }[] = [
  { key: "low", level: "Low" },
  { key: "medium", level: "Medium" },
  { key: "high", level: "High" },
  { key: "critical", level: "Critical" },
]

function TrendTooltip({ active, payload, label }: TooltipContentProps<ValueType, NameType>) {
  if (!active || !payload?.length) return null
  const point = payload[0].payload as TrendPoint
  return (
    <div className="min-w-40 rounded-md border bg-popover px-3 py-2 text-xs shadow-md">
      <div className="mb-1.5 flex justify-between gap-4 font-medium">
        <span>{fmtDay(String(label))}</span>
        <span className="tnum">{fmtNumber(point.total)} new</span>
      </div>
      {[...RISK_SERIES].reverse().map((s) => (
        <div key={s.key} className="flex items-center justify-between gap-4 py-0.5">
          <span className="flex items-center gap-1.5 text-muted-foreground">
            <span className="size-2 rounded-[2px]" style={{ background: `var(--risk-${s.key})` }} />
            {s.level}
          </span>
          <span className="tnum">{fmtNumber(point[s.key] as number)}</span>
        </div>
      ))}
    </div>
  )
}

export function RiskLegend() {
  return (
    <ul className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
      {[...RISK_SERIES].reverse().map((s) => (
        <li key={s.key} className="flex items-center gap-1.5">
          <RiskMeter level={s.level} />
          {s.level}
        </li>
      ))}
    </ul>
  )
}

/** 30-day new-alert trend, stacked by risk level (DSH-17). Clicking a day opens that day's alerts. */
export function TrendChart({ data, alertsHref }: { data: TrendPoint[]; alertsHref: (day: string) => string }) {
  const router = useRouter()
  return (
    <>
      <div className="h-64 w-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart
            data={data}
            margin={{ top: 8, right: 4, bottom: 0, left: -12 }}
            barCategoryGap={2}
            onClick={(state) => {
              const day = state?.activeLabel
              if (day) router.push(alertsHref(String(day)))
            }}
            className="cursor-pointer"
          >
            <CartesianGrid vertical={false} stroke="var(--grid)" />
            <XAxis
              dataKey="date"
              tickFormatter={fmtDay}
              interval="preserveStartEnd"
              tickLine={false}
              axisLine={{ stroke: "var(--grid)" }}
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
              minTickGap={28}
            />
            <YAxis
              allowDecimals={false}
              tickLine={false}
              axisLine={false}
              width={44}
              tick={{ fill: "var(--muted-foreground)", fontSize: 11 }}
            />
            <Tooltip content={TrendTooltip} cursor={{ fill: "var(--muted)", opacity: 0.6 }} />
            {RISK_SERIES.map((s, i) => (
              <Bar
                key={s.key}
                dataKey={s.key}
                stackId="risk"
                fill={`var(--risk-${s.key})`}
                stroke="var(--card)"
                strokeWidth={1}
                maxBarSize={24}
                radius={i === RISK_SERIES.length - 1 ? [3, 3, 0, 0] : 0}
                isAnimationActive={false}
                name={s.level}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
      <table className="sr-only">
        <caption>New alerts per day by risk level</caption>
        <thead>
          <tr>
            <th>Date</th>
            <th>Critical</th>
            <th>High</th>
            <th>Medium</th>
            <th>Low</th>
            <th>Total</th>
          </tr>
        </thead>
        <tbody>
          {data.map((d) => (
            <tr key={d.date}>
              <td>{d.date}</td>
              <td>{d.critical}</td>
              <td>{d.high}</td>
              <td>{d.medium}</td>
              <td>{d.low}</td>
              <td>{d.total}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  )
}

export interface BarRow {
  key: string
  label: string
  value: number
  href: string
  /** CSS colour for the bar; defaults to the single-series hue */
  color?: string
  marker?: React.ReactNode
}

/**
 * Horizontal bar list: label left, value at the tip. Plain HTML so labels never clip and each
 * row is a real link to the filtered queue.
 */
export function BarList({ rows, emptyText = "Nothing open" }: { rows: BarRow[]; emptyText?: string }) {
  const router = useRouter()
  const max = Math.max(1, ...rows.map((r) => r.value))
  const total = rows.reduce((a, r) => a + r.value, 0)
  return (
    <div>
      <ul className="space-y-1">
        {rows.map((r) => (
          <li key={r.key}>
            <button
              type="button"
              onClick={() => router.push(r.href)}
              className="group grid w-full grid-cols-[minmax(7rem,38%)_1fr] items-center gap-3 rounded-md px-1.5 py-1 text-left text-sm outline-none hover:bg-muted/70 focus-visible:ring-2 focus-visible:ring-ring"
              title={`${r.label}: ${r.value}`}
            >
              <span className="flex min-w-0 items-center gap-2">
                {r.marker}
                <span className="truncate text-foreground/85">{r.label}</span>
              </span>
              <span className="flex items-center gap-2">
                <span
                  className="h-3.5 rounded-r-[4px] transition-[width]"
                  style={{
                    width: r.value === 0 ? "2px" : `calc(${(r.value / max) * 100}% - 2.5rem)`,
                    minWidth: r.value === 0 ? 2 : 4,
                    background: r.value === 0 ? "var(--meter-track)" : (r.color ?? "var(--series-1)"),
                  }}
                />
                <span className="tnum text-xs font-medium text-foreground/80">{fmtNumber(r.value)}</span>
              </span>
            </button>
          </li>
        ))}
      </ul>
      {total === 0 && <p className="mt-2 px-1.5 text-xs text-muted-foreground">{emptyText}</p>}
    </div>
  )
}
