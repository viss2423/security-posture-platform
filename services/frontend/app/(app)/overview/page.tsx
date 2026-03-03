import Link from 'next/link';
import { EmptyState, ApiDownHint } from '@/components/EmptyState';
import OverviewAnomaliesPanel from '@/components/OverviewAnomaliesPanel';
import { ProgressRing } from '@/components/ProgressRing';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import type {
  Finding,
  OverviewResponse,
  PostureAnomaly,
  TrendPoint,
} from '@/lib/api';
import {
  parsePostureFilters,
  type SearchParamsInput,
  writePostureFilters,
} from '@/lib/postureFilters';
import { requireServerSession, withServerSession } from '@/lib/session';

type TrendRange = '24h' | '7d' | '30d';
type RiskyAsset = {
  asset_key: string;
  asset_name: string;
  max_risk_score: number;
  risk_level: string;
  active_findings: number;
};

type PageProps = {
  searchParams?: Promise<SearchParamsInput>;
};

function riskBadgeClass(level?: string | null): string {
  switch ((level || '').toLowerCase()) {
    case 'critical':
      return 'bg-[var(--red)] text-white';
    case 'high':
      return 'bg-orange-600 text-white';
    case 'medium':
      return 'bg-yellow-500 text-black';
    case 'low':
      return 'bg-blue-500 text-white';
    default:
      return 'bg-[var(--muted)]/20 text-[var(--muted)]';
  }
}

function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return (
      <p className="py-8 text-center text-sm text-[var(--muted)]">
        No snapshot data for this range. Save a report snapshot to see trend.
      </p>
    );
  }

  const scores = points
    .map((point) =>
      point.posture_score_avg != null ? Number(point.posture_score_avg) : null
    )
    .filter((score): score is number => score != null);
  const min = Math.min(0, ...scores);
  const max = Math.max(100, ...scores);
  const rangeY = max - min || 1;
  const width = 600;
  const height = 160;
  const padding = { top: 8, right: 8, bottom: 24, left: 32 };
  const chartWidth = width - padding.left - padding.right;
  const chartHeight = height - padding.top - padding.bottom;
  const xScale = (index: number) =>
    padding.left +
    (points.length > 1 ? (index / (points.length - 1)) * chartWidth : chartWidth / 2);
  const yScale = (value: number) =>
    padding.top + chartHeight - ((value - min) / rangeY) * chartHeight;
  const pathD = points
    .map((point, index) => {
      const value =
        point.posture_score_avg != null ? Number(point.posture_score_avg) : null;
      if (value == null) return null;
      return `${index === 0 ? 'M' : 'L'} ${xScale(index)} ${yScale(value)}`;
    })
    .filter(Boolean)
    .join(' ');

  return (
    <div className="overflow-x-auto">
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-40 min-w-full"
        preserveAspectRatio="none"
      >
        {pathD && (
          <path
            d={pathD}
            fill="none"
            stroke="var(--green)"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
          />
        )}
        <line
          x1={padding.left}
          y1={padding.top}
          x2={padding.left}
          y2={padding.top + chartHeight}
          stroke="var(--border)"
          strokeWidth="1"
        />
        <line
          x1={padding.left}
          y1={padding.top + chartHeight}
          x2={padding.left + chartWidth}
          y2={padding.top + chartHeight}
          stroke="var(--border)"
          strokeWidth="1"
        />
      </svg>
    </div>
  );
}

function normalizeTrendRange(value?: string): TrendRange {
  return value === '24h' || value === '30d' ? value : '7d';
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : 'Request failed';
}

function buildTopRiskSections(rows: Finding[]) {
  const topRiskFindings = [...rows]
    .sort((a, b) => Number(b.risk_score ?? -1) - Number(a.risk_score ?? -1))
    .slice(0, 5);

  const assets = new Map<string, RiskyAsset>();
  for (const finding of rows) {
    if (!finding.asset_key || finding.risk_score == null) continue;
    const riskScore = Number(finding.risk_score);
    const activeFinding = finding.status !== 'remediated';
    const existing = assets.get(finding.asset_key);
    if (!existing) {
      assets.set(finding.asset_key, {
        asset_key: finding.asset_key,
        asset_name: finding.asset_name || finding.asset_key,
        max_risk_score: riskScore,
        risk_level: finding.risk_level || 'risk',
        active_findings: activeFinding ? 1 : 0,
      });
      continue;
    }
    existing.active_findings += activeFinding ? 1 : 0;
    if (riskScore > existing.max_risk_score) {
      existing.max_risk_score = riskScore;
      existing.risk_level = finding.risk_level || existing.risk_level;
    }
  }

  const topRiskAssets = Array.from(assets.values())
    .sort(
      (a, b) =>
        b.max_risk_score - a.max_risk_score || b.active_findings - a.active_findings
    )
    .slice(0, 5);

  return { topRiskFindings, topRiskAssets };
}

function filtersToSuffix(filters: ReturnType<typeof parsePostureFilters>): string {
  const params = writePostureFilters(new URLSearchParams(), filters);
  const query = params.toString();
  return query ? `?${query}` : '';
}

function buildOverviewHref(
  range: TrendRange,
  filters: ReturnType<typeof parsePostureFilters>
): string {
  const params = writePostureFilters(new URLSearchParams(), filters);
  if (range !== '7d') {
    params.set('range', range);
  } else {
    params.delete('range');
  }
  const query = params.toString();
  return query ? `/overview?${query}` : '/overview';
}

export default async function OverviewPage({ searchParams }: PageProps) {
  const user = await requireServerSession();
  const resolvedSearchParams = (await searchParams) ?? {};
  const filters = parsePostureFilters(resolvedSearchParams);
  const filterSuffix = filtersToSuffix(filters);
  const rangeValue = Array.isArray(resolvedSearchParams.range)
    ? resolvedSearchParams.range[0]
    : resolvedSearchParams.range;
  const trendRange = normalizeTrendRange(rangeValue);

  const [overviewResult, trendResult, findingsResult, anomaliesResult] =
    await Promise.allSettled([
      withServerSession<OverviewResponse>(`/posture/overview${filterSuffix}`, {
        cache: 'no-store',
      }),
      withServerSession<{ range: string; points: TrendPoint[] }>(
        `/posture/trend?range=${trendRange}`,
        {
          cache: 'no-store',
        }
      ),
      withServerSession<Finding[]>('/findings/?limit=100', { cache: 'no-store' }),
      withServerSession<{ items: PostureAnomaly[] }>('/ai/posture/anomalies?limit=5', {
        cache: 'no-store',
      }),
    ]);

  const overview = overviewResult.status === 'fulfilled' ? overviewResult.value : null;
  const trend =
    trendResult.status === 'fulfilled'
      ? trendResult.value
      : { range: trendRange, points: [] as TrendPoint[] };
  const findings = findingsResult.status === 'fulfilled' ? findingsResult.value : [];
  const anomalies =
    anomaliesResult.status === 'fulfilled' ? anomaliesResult.value.items ?? [] : [];
  const errors = [
    overviewResult.status === 'rejected' ? getErrorMessage(overviewResult.reason) : null,
    trendResult.status === 'rejected' ? getErrorMessage(trendResult.reason) : null,
    findingsResult.status === 'rejected' ? getErrorMessage(findingsResult.reason) : null,
    anomaliesResult.status === 'rejected' ? getErrorMessage(anomaliesResult.reason) : null,
  ].filter(Boolean) as string[];
  const { topRiskFindings, topRiskAssets } = buildTopRiskSections(findings);
  const strip = overview?.executive_strip;
  const drivers = overview?.top_drivers;
  const scoreNum =
    strip?.posture_score_avg != null ? Number(strip.posture_score_avg) : null;
  const showRing =
    typeof scoreNum === 'number' &&
    !Number.isNaN(scoreNum) &&
    scoreNum >= 0 &&
    scoreNum <= 100;

  return (
    <main className="page-shell">
      <p className="mb-5 text-sm text-[var(--muted)]">
        Track posture movement, highest-risk entities, and recent anomalies from a
        single operating view.
      </p>

      {errors[0] && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(errors[0])}
          <ApiDownHint />
        </div>
      )}

      {overview && strip?.total_assets === 0 && (
        <EmptyState
          icon={<span className="text-2xl font-bold text-[var(--muted)]">0</span>}
          title="No posture data yet"
          description="Ingestion hasn't run or no assets are configured. Start the stack and wait for the first ingestion cycle (runs every 60s)."
        />
      )}

      {overview && strip && strip.total_assets > 0 && (
        <>
          <section className="mb-10">
            <h2 className="section-title">Executive summary</h2>
            <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
              <div className="metric-card neutral animate-in flex flex-col items-center justify-center">
                {showRing ? (
                  <>
                    <div className="relative">
                      <ProgressRing value={scoreNum} className="block" />
                      <span className="absolute inset-0 flex items-center justify-center text-lg font-bold text-[var(--text)]">
                        {Math.round(scoreNum)}
                      </span>
                    </div>
                    <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                      Posture score
                    </div>
                    {strip.score_trend_vs_yesterday && (
                      <span
                        className={
                          strip.score_trend_vs_yesterday === 'up'
                            ? 'text-[var(--green)]'
                            : strip.score_trend_vs_yesterday === 'down'
                              ? 'text-[var(--red)]'
                              : 'text-[var(--muted)]'
                        }
                      >
                        {strip.score_trend_vs_yesterday === 'up'
                          ? 'Up vs yesterday'
                          : strip.score_trend_vs_yesterday === 'down'
                            ? 'Down vs yesterday'
                            : 'Same'}
                      </span>
                    )}
                  </>
                ) : (
                  <>
                    <div className="text-4xl font-bold text-[var(--text)]">
                      {strip.posture_score_avg ?? '-'}
                    </div>
                    <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                      Posture score
                    </div>
                  </>
                )}
              </div>
              <div className="metric-card animate-in">
                <div className="text-4xl font-bold text-[var(--text)]">
                  {strip.total_assets}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                  Assets monitored
                </div>
              </div>
              <div className="metric-card red animate-in">
                <div className="text-4xl font-bold text-[var(--red)]">
                  {strip.alerts_firing}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                  Alerts firing
                </div>
              </div>
              <div className="metric-card animate-in">
                <div className="text-4xl font-bold text-[var(--text)]">
                  {strip.risk_change_24h != null
                    ? strip.risk_change_24h >= 0
                      ? `+${strip.risk_change_24h}`
                      : strip.risk_change_24h
                    : '-'}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">
                  Risk change (24h)
                </div>
              </div>
            </div>
          </section>

          <section className="mb-10">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <h2 className="section-title">Posture trend</h2>
              <div className="flex gap-2">
                {(['24h', '7d', '30d'] as const).map((range) => (
                  <Link
                    key={range}
                    href={buildOverviewHref(range, filters)}
                    className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                      trendRange === range
                        ? 'bg-[var(--green)] text-white'
                        : 'bg-[var(--border)]/50 text-[var(--muted)] hover:bg-[var(--border)]'
                    }`}
                  >
                    {range === '24h' ? '24h' : range === '7d' ? '7 days' : '30 days'}
                  </Link>
                ))}
              </div>
            </div>
            <div className="card overflow-hidden">
              <TrendChart points={trend.points} />
            </div>
          </section>

          <OverviewAnomaliesPanel
            initialAnomalies={anomalies}
            canMutate={user.canMutate}
          />

          <section className="mb-10">
            <h2 className="section-title">Highest-risk entities</h2>
            <div className="grid gap-6 lg:grid-cols-2">
              <div className="card">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                  Findings
                </h3>
                {topRiskFindings.length === 0 ? (
                  <p className="text-sm text-[var(--muted)]">No scored findings yet.</p>
                ) : (
                  <ul className="space-y-3">
                    {topRiskFindings.map((finding) => (
                      <li
                        key={finding.finding_id}
                        className="flex flex-wrap items-start justify-between gap-3 rounded border border-[var(--border)] p-3"
                      >
                        <div className="min-w-0 flex-1">
                          <p className="font-medium text-[var(--text)]">{finding.title}</p>
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            {finding.asset_key ? (
                              <Link
                                href={`/assets/${encodeURIComponent(finding.asset_key)}`}
                                className="hover:text-[var(--green)] hover:underline"
                              >
                                {finding.asset_name || finding.asset_key}
                              </Link>
                            ) : (
                              'Unlinked asset'
                            )}
                            {finding.category ? ` / ${finding.category}` : ''}
                          </p>
                        </div>
                        <div className="text-right">
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(finding.risk_level)}`}
                          >
                            {finding.risk_level || 'risk'}{' '}
                            {Math.round(Number(finding.risk_score ?? 0))}
                          </span>
                          <p className="mt-1 text-[11px] capitalize text-[var(--muted)]">
                            {finding.status.replace('_', ' ')}
                          </p>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
              <div className="card">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">Assets</h3>
                {topRiskAssets.length === 0 ? (
                  <p className="text-sm text-[var(--muted)]">No scored assets yet.</p>
                ) : (
                  <ul className="space-y-3">
                    {topRiskAssets.map((asset) => (
                      <li
                        key={asset.asset_key}
                        className="flex flex-wrap items-start justify-between gap-3 rounded border border-[var(--border)] p-3"
                      >
                        <div className="min-w-0 flex-1">
                          <Link
                            href={`/assets/${encodeURIComponent(asset.asset_key)}`}
                            className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                          >
                            {asset.asset_name}
                          </Link>
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            {asset.active_findings} active finding
                            {asset.active_findings === 1 ? '' : 's'}
                          </p>
                        </div>
                        <div className="text-right">
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(asset.risk_level)}`}
                          >
                            {asset.risk_level || 'risk'}{' '}
                            {Math.round(asset.max_risk_score)}
                          </span>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          </section>

          <section className="mb-10">
            <h2 className="section-title">Top drivers</h2>
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="card animate-in">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                  Top 5 impacting score
                </h3>
                {drivers?.worst_assets?.length ? (
                  <ul className="space-y-2">
                    {drivers.worst_assets.map((asset) => (
                      <li key={asset.asset_id}>
                        <Link
                          href={`/assets/${encodeURIComponent(asset.asset_id)}`}
                          className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                        >
                          {asset.name || asset.asset_id}
                        </Link>
                        <span className="ml-2 text-sm text-[var(--muted)]">
                          score {asset.posture_score ?? '-'} | {asset.status}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-[var(--muted)]">No data</p>
                )}
              </div>
              <div className="card animate-in">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                  Incident categories
                </h3>
                {drivers?.by_reason?.length ? (
                  <ul className="space-y-2">
                    {drivers.by_reason.map((reason) => (
                      <li key={reason.reason} className="flex justify-between text-sm">
                        <span className="text-[var(--text)]">{reason.reason}</span>
                        <span className="font-medium text-[var(--muted)]">
                          {reason.count}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-[var(--muted)]">No data</p>
                )}
              </div>
              <div className="card animate-in">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                  Recently updated
                </h3>
                {drivers?.recently_updated?.length ? (
                  <ul className="space-y-2">
                    {drivers.recently_updated.map((asset) => (
                      <li key={asset.asset_id}>
                        <Link
                          href={`/assets/${encodeURIComponent(asset.asset_id)}`}
                          className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                        >
                          {asset.name || asset.asset_id}
                        </Link>
                        <span className="ml-2 text-xs text-[var(--muted)]">
                          {asset.last_seen ? formatDateTime(asset.last_seen) : '-'}
                        </span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-[var(--muted)]">No data</p>
                )}
              </div>
            </div>
          </section>

          {strip.red > 0 && strip.down_assets?.length > 0 && (
            <section className="animate-in">
              <h2 className="section-title">Down assets</h2>
              <div className="card" style={{ borderColor: 'var(--red-border-subtle)' }}>
                <ul className="space-y-3">
                  {strip.down_assets.map((assetId) => (
                    <li key={assetId}>
                      <Link
                        href={`/assets/${encodeURIComponent(assetId)}`}
                        className="font-medium text-[var(--red)] transition hover:underline"
                      >
                        {assetId}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          )}
        </>
      )}

      {!overview && (
        <div className="card py-12 text-center text-sm text-[var(--muted)]">
          Overview data is unavailable right now.
        </div>
      )}
    </main>
  );
}
