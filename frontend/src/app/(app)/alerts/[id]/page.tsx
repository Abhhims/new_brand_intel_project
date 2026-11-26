"use client"

import { ErrorPanel, isNotFound } from "@/components/query-state"
import Link from "next/link"
import { useParams } from "next/navigation"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeft, BellRing, FileQuestion } from "lucide-react"
import { ModuleLabel, PhishingBadge, RiskBadge, StageBadge, StatusBadge } from "@/components/badges"
import {
  AlertHistory,
  DecisionControl,
  EvidenceGallery,
  ModuleFields,
  ObservationsTable,
  RelatedPanel,
  ScorePanel,
  SocialMisusePanel,
  SourceWarning,
  Timeline,
  shortId,
  triggerLabel,
} from "@/components/finding-detail"
import { EmptyState, Panel } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { api, type AlertDetail } from "@/lib/api"
import { fmtDateTime } from "@/lib/format"
import { keys } from "@/lib/queries"

function WhyThisAlert({ alert }: { alert: AlertDetail }) {
  return (
    <Panel
      title={
        <span className="inline-flex items-center gap-1.5">
          <BellRing className="size-3.5" aria-hidden />
          Why this alert
        </span>
      }
      description={triggerLabel(alert.trigger)}
    >
      <p className="text-sm break-words">{alert.reason || "No reason was recorded."}</p>
      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
        <div>
          <dt className="text-xs text-muted-foreground">Alerted</dt>
          <dd className="tnum">{fmtDateTime(alert.alerted_at)}</dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Stage</dt>
          <dd>
            <StageBadge stage={alert.stage} />
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Scan</dt>
          <dd className="font-mono text-xs" title={alert.scan_id ?? undefined}>
            {alert.scan_id ? (
              <Link href="/scans" className="hover:underline">
                {shortId(alert.scan_id)}
              </Link>
            ) : (
              "—"
            )}
          </dd>
        </div>
        <div>
          <dt className="text-xs text-muted-foreground">Finding</dt>
          <dd className="font-mono text-xs" title={alert.finding_id}>
            <Link href={`/findings/${alert.finding_id}`} className="hover:underline">
              {shortId(alert.finding_id)}
            </Link>
          </dd>
        </div>
      </dl>
    </Panel>
  )
}

export default function AlertDetailPage() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const alert = useQuery({ queryKey: keys.alert(id), queryFn: () => api.alert(id) })
  const a = alert.data

  if (alert.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-9 w-2/3" />
        <Skeleton className="h-80 w-full" />
      </div>
    )
  }
  if (alert.error && !isNotFound(alert.error)) {
    return <ErrorPanel error={alert.error} onRetry={() => alert.refetch()} title="Couldn't load this alert" />
  }
  if (!a) {
    return (
      <EmptyState icon={FileQuestion} title="Alert not found" action={<Button render={<Link href="/alerts" />} nativeButton={false}>Back to the queue</Button>}>
        It may have been removed, or the link is incomplete.
      </EmptyState>
    )
  }

  return (
    <>
      <Link href="/alerts" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-3.5" />
        Alert queue
      </Link>
      <header
        className="mb-4 rounded-lg border bg-card p-4 sm:p-5"
        style={{ boxShadow: `inset 4px 0 0 var(--risk-${a.risk_level.toLowerCase()})` }}
      >
        <div className="flex flex-wrap items-center gap-2">
          <RiskBadge level={a.risk_level} score={a.score} size="lg" />
          <StatusBadge status={a.status} />
          <StageBadge stage={a.stage} />
          {a.suspected_phishing && <PhishingBadge />}
        </div>
        <h1 className="mt-3 text-xl font-semibold tracking-tight [overflow-wrap:anywhere] sm:text-2xl">{a.title}</h1>
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-4">
          <div>
            <dt className="text-xs text-muted-foreground">Module</dt>
            <dd>
              <ModuleLabel module={a.module} />
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Brand</dt>
            <dd>
              <Link href={`/brands/${a.brand_id}`} className="hover:underline">
                {a.brand_name}
              </Link>
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">First seen</dt>
            <dd className="tnum">{fmtDateTime(a.first_seen)}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Last seen</dt>
            <dd className="tnum">{fmtDateTime(a.last_seen)}</dd>
          </div>
        </dl>
        {a.source_url && <SourceWarning url={a.source_url} />}
      </header>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          <WhyThisAlert alert={a} />
          {a.module === "social_media" && <SocialMisusePanel details={a.details} sourceUrl={a.source_url} />}
          <Panel title="Evidence" description={`${a.evidence.length} ${a.evidence.length === 1 ? "item" : "items"} captured`}>
            <EvidenceGallery evidence={a.evidence} />
          </Panel>
          <Panel title="Module output" description={<ModuleLabel module={a.module} />}>
            <ModuleFields module={a.module} details={a.details} />
          </Panel>
          <ObservationsTable observations={a.observations ?? []} />
        </div>
        <div className="space-y-4">
          <DecisionControl
            current={a.status}
            module={a.module}
            note={a.decision_note}
            onDecide={async (v) => {
              const updated = await api.setStatus(a.id, v.decision, v.note, v.addToAllowlist)
              qc.setQueryData(keys.alert(a.id), updated)
              return updated
            }}
            onDone={() => {
              qc.invalidateQueries({ queryKey: ["alerts", "list"] })
              qc.invalidateQueries({ queryKey: ["findings"] })
              qc.invalidateQueries({ queryKey: ["stats"] })
              qc.invalidateQueries({ queryKey: ["brands"] })
            }}
          />
          <ScorePanel score={a.score} signals={a.signals} />
          <RelatedPanel findingId={a.finding_id} />
          <AlertHistory alerts={a.alerts ?? []} currentId={a.id} />
          <Timeline events={a.events} />
        </div>
      </div>
    </>
  )
}
