"use client"

import { ErrorPanel, isNotFound } from "@/components/query-state"
import Link from "next/link"
import { useParams } from "next/navigation"
import { useQuery, useQueryClient } from "@tanstack/react-query"
import { ArrowLeft, FileQuestion } from "lucide-react"
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
} from "@/components/finding-detail"
import { EmptyState, Panel } from "@/components/widgets"
import { Button } from "@/components/ui/button"
import { Skeleton } from "@/components/ui/skeleton"
import { api } from "@/lib/api"
import { fmtDateTime } from "@/lib/format"
import { keys } from "@/lib/queries"

export default function FindingDetailPage() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const finding = useQuery({ queryKey: keys.finding(id), queryFn: () => api.finding(id) })
  const f = finding.data

  if (finding.isLoading) {
    return (
      <div className="space-y-4">
        <Skeleton className="h-5 w-32" />
        <Skeleton className="h-9 w-2/3" />
        <Skeleton className="h-80 w-full" />
      </div>
    )
  }
  if (finding.error && !isNotFound(finding.error)) {
    return <ErrorPanel error={finding.error} onRetry={() => finding.refetch()} title="Couldn't load this finding" />
  }
  if (!f) {
    return (
      <EmptyState
        icon={FileQuestion}
        title="Finding not found"
        action={<Button render={<Link href="/findings" />} nativeButton={false}>Back to findings</Button>}
      >
        It may have been removed, or the link is incomplete.
      </EmptyState>
    )
  }

  return (
    <>
      <Link href="/findings" className="mb-3 inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground">
        <ArrowLeft className="size-3.5" />
        Findings
      </Link>
      <header
        className="mb-4 rounded-lg border bg-card p-4 sm:p-5"
        style={{ boxShadow: `inset 4px 0 0 var(--risk-${f.risk_level.toLowerCase()})` }}
      >
        <div className="flex flex-wrap items-center gap-2">
          <RiskBadge level={f.risk_level} score={f.score} size="lg" />
          <StatusBadge status={f.decision} />
          <StageBadge stage={f.stage} />
          {f.suspected_phishing && <PhishingBadge />}
        </div>
        <h1 className="mt-3 text-xl font-semibold tracking-tight [overflow-wrap:anywhere] sm:text-2xl">{f.title}</h1>
        <div className="mt-1 font-mono text-xs break-all text-muted-foreground">{f.entity_key}</div>
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-2 text-sm sm:grid-cols-5">
          <div>
            <dt className="text-xs text-muted-foreground">Module</dt>
            <dd>
              <ModuleLabel module={f.module} />
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Brand</dt>
            <dd>
              <Link href={`/brands/${f.brand_id}`} className="hover:underline">
                {f.brand_name}
              </Link>
            </dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">First seen</dt>
            <dd className="tnum">{fmtDateTime(f.first_seen)}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Last seen</dt>
            <dd className="tnum">{fmtDateTime(f.last_seen)}</dd>
          </div>
          <div>
            <dt className="text-xs text-muted-foreground">Last alert</dt>
            <dd className="tnum">{f.last_alert_at ? fmtDateTime(f.last_alert_at) : "Not alerted"}</dd>
          </div>
        </dl>
        {f.source_url && <SourceWarning url={f.source_url} />}
      </header>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_22rem]">
        <div className="min-w-0 space-y-4">
          {f.module === "social_media" && <SocialMisusePanel details={f.details} sourceUrl={f.source_url} />}
          <Panel title="Evidence" description={`${f.evidence.length} ${f.evidence.length === 1 ? "item" : "items"} captured`}>
            <EvidenceGallery evidence={f.evidence} />
          </Panel>
          <Panel title="Module output" description={<ModuleLabel module={f.module} />}>
            <ModuleFields module={f.module} details={f.details} />
          </Panel>
          <ObservationsTable observations={f.observations} />
        </div>
        <div className="space-y-4">
          <DecisionControl
            current={f.decision}
            module={f.module}
            note={f.decision_note}
            decidedBy={f.decided_by_name}
            decidedAt={f.decided_at}
            onDecide={async (v) => {
              const updated = await api.decide(f.id, v.decision, v.note, v.addToAllowlist)
              qc.setQueryData(keys.finding(f.id), updated)
              return updated
            }}
            onDone={() => {
              qc.invalidateQueries({ queryKey: ["findings", "list"] })
              qc.invalidateQueries({ queryKey: ["alerts"] })
              qc.invalidateQueries({ queryKey: ["stats"] })
              qc.invalidateQueries({ queryKey: ["brands"] })
            }}
          />
          <ScorePanel score={f.score} signals={f.signals} />
          <RelatedPanel findingId={f.id} />
          <AlertHistory alerts={f.alerts} />
          <Timeline events={f.events} />
        </div>
      </div>
    </>
  )
}
