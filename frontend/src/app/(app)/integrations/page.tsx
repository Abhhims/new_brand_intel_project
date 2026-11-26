"use client"

import { useQuery } from "@tanstack/react-query"
import { PageHeader } from "@/components/app-shell"
import { ErrorPanel } from "@/components/query-state"
import { ComponentStatusIcon } from "@/components/scan-components"
import { Skeleton } from "@/components/ui/skeleton"
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table"
import { api, type Integration } from "@/lib/api"
import { COMPONENT_STATUS_LABELS } from "@/lib/constants"
import { fmtDateTime, fmtRelative } from "@/lib/format"

/** Every tool and service the platform uses, whether it is configured, and how it last ran (RDA-03). */
export default function IntegrationsPage() {
  const q = useQuery({ queryKey: ["integrations"], queryFn: api.integrations, refetchInterval: 60_000 })
  const groups = new Map<string, Integration[]>()
  for (const i of q.data ?? []) groups.set(i.category, [...(groups.get(i.category) ?? []), i])

  return (
    <>
      <PageHeader
        title="Integrations"
        description="Every tool and service the scanners depend on. A source that is not configured or not reachable is shown here and on each scan — it is never reported as 'nothing found'."
      />
      {q.error && <ErrorPanel error={q.error} onRetry={() => q.refetch()} title="Couldn't load integrations" />}
      {q.isLoading && <Skeleton className="h-96 w-full" />}
      <div className="space-y-4">
        {[...groups.entries()].map(([category, items]) => (
          <section key={category} className="overflow-hidden rounded-lg border bg-card">
            <h2 className="border-b px-4 py-2 text-sm font-semibold">{category}</h2>
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-xs text-muted-foreground">Integration</TableHead>
                  <TableHead className="hidden text-xs text-muted-foreground md:table-cell">Used by</TableHead>
                  <TableHead className="text-xs text-muted-foreground">Configured</TableHead>
                  <TableHead className="text-xs text-muted-foreground">Last result</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {items.map((i) => (
                  <TableRow key={i.id}>
                    <TableCell className="align-top font-medium whitespace-normal">{i.name}</TableCell>
                    <TableCell className="hidden align-top text-sm text-muted-foreground md:table-cell">
                      {i.modules.join(", ")}
                    </TableCell>
                    <TableCell className="align-top text-sm whitespace-normal">
                      {i.configured ? (
                        "Yes"
                      ) : (
                        <>
                          <span className="font-medium text-amber-700 dark:text-amber-400">No</span>
                          <div className="text-xs text-muted-foreground">{i.how_to_configure}</div>
                        </>
                      )}
                    </TableCell>
                    <TableCell className="align-top text-sm whitespace-normal">
                      {i.last_status ? (
                        <div className="flex items-start gap-1.5">
                          <ComponentStatusIcon status={i.last_status} className="mt-0.5" />
                          <div>
                            <span>{COMPONENT_STATUS_LABELS[i.last_status] ?? i.last_status}</span>
                            {i.last_checked_at && (
                              <span className="text-xs text-muted-foreground" title={fmtDateTime(i.last_checked_at)}>
                                {" "}
                                · {fmtRelative(i.last_checked_at)}
                              </span>
                            )}
                            {i.last_message && <div className="text-xs break-words text-muted-foreground">{i.last_message}</div>}
                          </div>
                        </div>
                      ) : (
                        <span className="text-muted-foreground">Not run yet</span>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </section>
        ))}
      </div>
    </>
  )
}
