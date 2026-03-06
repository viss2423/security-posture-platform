import Link from 'next/link';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import type { ThreatIntelSummary } from '@/lib/api';
import { requireServerSession, withServerSession } from '@/lib/session';

function statusBadge(status: string): string {
  if (status === 'done') return 'bg-[var(--green)]/20 text-[var(--green)]';
  if (status === 'failed') return 'bg-[var(--red)]/20 text-[var(--red)]';
  if (status === 'running') return 'bg-[var(--amber)]/20 text-[var(--amber)]';
  return 'bg-[var(--surface-elevated)] text-[var(--muted)]';
}

export default async function ThreatIntelPage() {
  await requireServerSession();

  let summary: ThreatIntelSummary | null = null;
  let error: string | null = null;

  try {
    summary = await withServerSession<ThreatIntelSummary>('/threat-intel/summary', {
      cache: 'no-store',
    });
  } catch (requestError) {
    error =
      requestError instanceof Error ? requestError.message : 'Threat-intel summary unavailable';
  }

  return (
    <main className="page-shell">
      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="page-title">Threat intelligence</h1>
          <p className="mt-2 max-w-3xl text-sm text-[var(--text-muted)]">
            Monitor IOC feed coverage, recent refresh jobs, and which assets currently overlap
            with known malicious domains or IPs.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Link href="/jobs" className="btn-primary text-sm">
            Refresh feeds
          </Link>
          <Link href="/assets" className="btn-secondary text-sm">
            Review assets
          </Link>
        </div>
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {!summary ? (
        <div className="section-panel py-12 text-center text-sm text-[var(--muted)]">
          Threat-intelligence data is unavailable right now.
        </div>
      ) : summary.total_indicators === 0 ? (
        <EmptyState
          title="No threat-intel data yet"
          description="Run a threat_intel_refresh job to load IOC feeds and compute asset matches."
        />
      ) : (
        <>
          <section className="mb-8">
            <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
              <div className="metric-card animate-in">
                <div className="text-4xl font-bold text-[var(--text)]">
                  {summary.total_indicators}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                  Active indicators
                </div>
              </div>
              <div className="metric-card red animate-in">
                <div className="text-4xl font-bold text-[var(--red)]">
                  {summary.matched_asset_count}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                  Matched assets
                </div>
              </div>
              <div className="metric-card animate-in">
                <div className="text-4xl font-bold text-[var(--amber)]">
                  {summary.total_asset_matches}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                  Asset matches
                </div>
              </div>
              <div className="metric-card animate-in">
                <div className="text-4xl font-bold text-[var(--text)]">
                  {summary.source_count}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                  Feed sources
                </div>
              </div>
            </div>
            {summary.last_refreshed_at ? (
              <p className="mt-3 text-xs uppercase tracking-[0.14em] text-[var(--muted)]">
                Last refreshed {formatDateTime(summary.last_refreshed_at)}
              </p>
            ) : null}
          </section>

          <section className="mb-8 grid gap-6 xl:grid-cols-[minmax(0,1.15fr)_minmax(320px,0.85fr)]">
            <div className="section-panel animate-in">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="section-title">Matched assets</h2>
                <span className="stat-chip-strong">{summary.matched_assets.length} assets</span>
              </div>
              {summary.matched_assets.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">
                  No current asset matches. IOC coverage is loaded, but nothing in inventory
                  overlaps with those indicators right now.
                </p>
              ) : (
                <div className="space-y-3">
                  {summary.matched_assets.map((asset) => (
                    <div
                      key={asset.asset_key}
                      className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <Link
                            href={`/assets/${encodeURIComponent(asset.asset_key)}`}
                            className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                          >
                            {asset.asset_name || asset.asset_key}
                          </Link>
                          <p className="mt-1 text-xs uppercase tracking-[0.14em] text-[var(--muted)]">
                            {asset.environment || 'unknown'} | {asset.criticality || 'n/a'}
                          </p>
                        </div>
                        <span className="stat-chip-strong">{asset.match_count} matches</span>
                      </div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        {asset.indicators.map((indicator) => (
                          <span
                            key={`${asset.asset_key}-${indicator}`}
                            className="rounded-full border border-[var(--border)] px-2.5 py-1 text-xs text-[var(--text)]"
                          >
                            {indicator}
                          </span>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div className="section-panel animate-in">
              <h2 className="section-title">Latest refresh jobs</h2>
              {summary.latest_jobs.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">
                  No threat-intel refresh jobs have completed yet.
                </p>
              ) : (
                <ul className="space-y-3">
                  {summary.latest_jobs.map((job) => (
                    <li
                      key={job.job_id}
                      className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <Link href="/jobs" className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline">
                          Job {job.job_id}
                        </Link>
                        <span
                          className={`rounded-full px-2 py-0.5 text-xs font-semibold uppercase ${statusBadge(job.status)}`}
                        >
                          {job.status}
                        </span>
                      </div>
                      <p className="mt-2 text-xs text-[var(--muted)]">
                        Created {job.created_at ? formatDateTime(job.created_at) : '-'}
                      </p>
                      {job.error ? (
                        <p className="mt-2 text-xs text-[var(--red)]">{job.error}</p>
                      ) : null}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </section>

          <section className="grid gap-6 xl:grid-cols-2">
            <div className="section-panel animate-in">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="section-title">Feed sources</h2>
                <span className="stat-chip">{summary.sources.length} configured</span>
              </div>
              <div className="space-y-3">
                {summary.sources.map((source) => (
                  <div
                    key={source.source}
                    className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <p className="font-medium text-[var(--text)]">{source.source}</p>
                        <p className="mt-1 text-xs text-[var(--muted)]">
                          {source.feed_url || 'Manual or configuration-defined source'}
                        </p>
                      </div>
                      <span className="stat-chip-strong">{source.indicator_count} IOCs</span>
                    </div>
                    <p className="mt-3 text-sm text-[var(--muted)]">
                      IP {source.by_type.ip} | Domain {source.by_type.domain}
                      {source.last_seen_at ? ` | ${formatDateTime(source.last_seen_at)}` : ''}
                    </p>
                  </div>
                ))}
              </div>
            </div>

            <div className="section-panel animate-in">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h2 className="section-title">Recent indicators</h2>
                <span className="stat-chip">{summary.recent_indicators.length} recent</span>
              </div>
              <div className="space-y-3">
                {summary.recent_indicators.map((ioc) => (
                  <div
                    key={`${ioc.source}-${ioc.indicator_type}-${ioc.indicator}`}
                    className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4"
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="font-medium text-[var(--text)]">{ioc.indicator}</span>
                      <span className="stat-chip uppercase">{ioc.indicator_type}</span>
                    </div>
                    <p className="mt-2 text-xs text-[var(--muted)]">
                      {ioc.source}
                      {ioc.last_seen_at ? ` | ${formatDateTime(ioc.last_seen_at)}` : ''}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        </>
      )}
    </main>
  );
}
