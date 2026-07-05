import Link from 'next/link';
import { EmptyState, ApiDownHint } from '@/components/EmptyState';
import GettingStartedBanner from '@/components/GettingStartedBanner';
import OverviewAnomaliesPanel from '@/components/OverviewAnomaliesPanel';
import { ProgressRing } from '@/components/ProgressRing';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import type {
  Finding,
  OverviewResponse,
  PostureAnomaly,
  RepositoryScanSummary,
  TelemetrySummary,
  ThreatIntelSummary,
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
      return 'bg-red-600 text-white';
    case 'high':
      return 'bg-orange-700 text-white';
    case 'medium':
      return 'bg-yellow-500 text-black';
    case 'low':
      return 'bg-blue-600 text-white';
    default:
      return 'bg-[var(--muted)]/20 text-[var(--muted)]';
  }
}

function TrendChart({ points }: { points: TrendPoint[] }) {
  if (points.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-10 text-center">
        <div className="mb-2 text-[var(--text-subtle)]">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
        </div>
        <p className="text-sm text-[var(--text-subtle)]">No snapshot data for this range.</p>
        <p className="mt-1 text-xs text-[var(--text-subtle)]">Save a report snapshot to see trend.</p>
      </div>
    );
  }

  const scores = points
    .map((p) => p.posture_score_avg != null ? Number(p.posture_score_avg) : null)
    .filter((s): s is number => s != null);
  const min = Math.min(0, ...scores);
  const max = Math.max(100, ...scores);
  const rangeY = max - min || 1;
  const width = 600;
  const height = 160;
  const pad = { top: 12, right: 12, bottom: 28, left: 36 };
  const cw = width - pad.left - pad.right;
  const ch = height - pad.top - pad.bottom;
  const xs = (i: number) => pad.left + (points.length > 1 ? (i / (points.length - 1)) * cw : cw / 2);
  const ys = (v: number) => pad.top + ch - ((v - min) / rangeY) * ch;

  const lineParts: string[] = [];
  points.forEach((p, i) => {
    const v = p.posture_score_avg != null ? Number(p.posture_score_avg) : null;
    if (v == null) return;
    lineParts.push(`${lineParts.length === 0 ? 'M' : 'L'} ${xs(i)} ${ys(v)}`);
  });
  const lineD = lineParts.join(' ');
  const lastValid = (() => {
    for (let i = points.length - 1; i >= 0; i--) {
      const v = points[i].posture_score_avg != null ? Number(points[i].posture_score_avg) : null;
      if (v != null) return { x: xs(i), y: ys(v), v };
    }
    return null;
  })();
  const areaD = lineD
    ? `${lineD} L ${xs(points.length - 1)} ${pad.top + ch} L ${xs(0)} ${pad.top + ch} Z`
    : '';

  /* horizontal grid lines at 25 / 50 / 75 */
  const gridLines = [25, 50, 75].map((val) => ({ val, y: ys(val) }));

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${width} ${height}`} className="h-44 min-w-full" preserveAspectRatio="none">
        <defs>
          <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="var(--green)" stopOpacity="0.22" />
            <stop offset="100%" stopColor="var(--green)" stopOpacity="0" />
          </linearGradient>
        </defs>

        {/* grid */}
        {gridLines.map(({ val, y }) => (
          <g key={val}>
            <line x1={pad.left} y1={y} x2={pad.left + cw} y2={y}
              stroke="rgba(255,255,255,0.05)" strokeWidth="1" strokeDasharray="4 4" />
            <text x={pad.left - 4} y={y + 4} fontSize="9" fill="var(--text-subtle)" textAnchor="end">
              {val}
            </text>
          </g>
        ))}

        {/* axes */}
        <line x1={pad.left} y1={pad.top} x2={pad.left} y2={pad.top + ch}
          stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
        <line x1={pad.left} y1={pad.top + ch} x2={pad.left + cw} y2={pad.top + ch}
          stroke="rgba(255,255,255,0.06)" strokeWidth="1" />

        {/* area fill */}
        {areaD && <path d={areaD} fill="url(#trendFill)" />}

        {/* line */}
        {lineD && (
          <path d={lineD} fill="none" stroke="var(--green)"
            strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" />
        )}

        {/* last-point indicator */}
        {lastValid && (
          <>
            <circle cx={lastValid.x} cy={lastValid.y} r="4" fill="var(--surface)" stroke="var(--green)" strokeWidth="2" />
            <circle cx={lastValid.x} cy={lastValid.y} r="1.5" fill="var(--green)" />
            <text x={lastValid.x + 7} y={lastValid.y + 4} fontSize="9.5" fill="var(--green)" fontWeight="600">
              {Math.round(lastValid.v)}
            </text>
          </>
        )}
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

function isOptionalRepositorySummaryError(message: string | null): boolean {
  const normalized = (message || '').toLowerCase();
  return normalized.includes('asset not found') || normalized.includes('404');
}

function isPermissionError(message: string | null): boolean {
  const normalized = (message || '').toLowerCase();
  return normalized.includes('insufficient permissions') || normalized.includes('403');
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

  const [
    overviewResult,
    trendResult,
    findingsResult,
    anomaliesResult,
    repositorySummaryResult,
    telemetrySummaryResult,
    threatIntelSummaryResult,
  ] =
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
      withServerSession<RepositoryScanSummary>('/findings/repository-summary', {
        cache: 'no-store',
      }),
      withServerSession<TelemetrySummary>('/telemetry/summary', {
        cache: 'no-store',
      }),
      withServerSession<ThreatIntelSummary>('/threat-intel/summary', {
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
  const repositorySummary =
    repositorySummaryResult.status === 'fulfilled' ? repositorySummaryResult.value : null;
  const repositorySummaryError =
    repositorySummaryResult.status === 'rejected'
      ? getErrorMessage(repositorySummaryResult.reason)
      : null;
  const telemetrySummary =
    telemetrySummaryResult.status === 'fulfilled'
      ? telemetrySummaryResult.value
      : null;
  const telemetrySummaryError =
    telemetrySummaryResult.status === 'rejected'
      ? getErrorMessage(telemetrySummaryResult.reason)
      : null;
  const threatIntelSummary =
    threatIntelSummaryResult.status === 'fulfilled'
      ? threatIntelSummaryResult.value
      : null;
  const threatIntelSummaryError =
    threatIntelSummaryResult.status === 'rejected'
      ? getErrorMessage(threatIntelSummaryResult.reason)
      : null;
  const suppressViewerOperatorErrors = !user.canMutate;
  const errors = [
    overviewResult.status === 'rejected' ? getErrorMessage(overviewResult.reason) : null,
    suppressViewerOperatorErrors &&
    trendResult.status === 'rejected' &&
    isPermissionError(getErrorMessage(trendResult.reason))
      ? null
      : trendResult.status === 'rejected'
        ? getErrorMessage(trendResult.reason)
        : null,
    findingsResult.status === 'rejected' ? getErrorMessage(findingsResult.reason) : null,
    suppressViewerOperatorErrors &&
    anomaliesResult.status === 'rejected' &&
    isPermissionError(getErrorMessage(anomaliesResult.reason))
      ? null
      : anomaliesResult.status === 'rejected'
        ? getErrorMessage(anomaliesResult.reason)
        : null,
    isOptionalRepositorySummaryError(repositorySummaryError) ? null : repositorySummaryError,
    suppressViewerOperatorErrors && isPermissionError(telemetrySummaryError)
      ? null
      : telemetrySummaryError,
    suppressViewerOperatorErrors && isPermissionError(threatIntelSummaryError)
      ? null
      : threatIntelSummaryError,
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
  const scoreColor =
    scoreNum == null ? 'var(--text-subtle)' :
    scoreNum >= 75 ? 'var(--green)' :
    scoreNum >= 50 ? 'var(--amber)' :
    'var(--red)';
  const trendDir = strip?.score_trend_vs_yesterday;
  const trendColor = trendDir === 'up' ? 'var(--green)' : trendDir === 'down' ? 'var(--red)' : 'var(--text-subtle)';
  const trendLabel = trendDir === 'up' ? '↑ Improving' : trendDir === 'down' ? '↓ Declining' : '→ Stable';

  return (
    <main className="page-shell">
      <GettingStartedBanner />
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <h1 className="sr-only">Security posture overview</h1>
            {/* Live status badge */}
            <span className="live-pill">
              <span className="dot-online" />
              Live · Security Posture
            </span>

            {/* Giant posture score */}
            <div className="mt-5 flex items-end gap-4">
              <span
                className="text-[5.5rem] font-black leading-none tabular-nums animate-count"
                style={{
                  color: scoreColor,
                  textShadow: `0 0 40px ${scoreColor}55, 0 0 80px ${scoreColor}22`,
                }}
              >
                {scoreNum != null ? scoreNum : '--'}
              </span>
              <div className="mb-4 flex flex-col gap-1">
                <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">
                  Posture score
                </span>
                <span className="text-sm font-semibold" style={{ color: trendColor }}>
                  {trendLabel}
                </span>
              </div>
            </div>

            {/* Score progress bar */}
            <div
              className="mt-1 h-1.5 w-full overflow-hidden rounded-full"
              style={{ background: 'rgba(255,255,255,0.06)' }}
            >
              <div
                className="h-full rounded-full transition-all duration-1000"
                style={{
                  width: `${scoreNum ?? 0}%`,
                  background: scoreColor,
                  boxShadow: `0 0 8px ${scoreColor}66`,
                }}
              />
            </div>

            {/* G / A / R status chips */}
            <div className="mt-4 flex flex-wrap gap-2">
              <span
                className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold"
                style={{ color: 'var(--green)', borderColor: 'rgba(52,211,153,0.28)', background: 'rgba(52,211,153,0.08)' }}
              >
                <span className="dot-online" />
                {strip?.green ?? 0} Healthy
              </span>
              <span
                className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold"
                style={{ color: 'var(--amber)', borderColor: 'rgba(251,191,36,0.28)', background: 'rgba(251,191,36,0.08)' }}
              >
                <span className="dot-warning" />
                {strip?.amber ?? 0} Degraded
              </span>
              <span
                className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold"
                style={{ color: 'var(--red)', borderColor: 'rgba(248,113,113,0.28)', background: 'rgba(248,113,113,0.08)' }}
              >
                <span className="dot-critical" />
                {strip?.red ?? 0} Critical
              </span>
              {user.canMutate && strip != null && strip.alerts_firing > 0 && (
                <Link
                  href="/alerts"
                  className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-bold transition-colors hover:border-[var(--red)]/60"
                  style={{ color: 'var(--red)', borderColor: 'rgba(248,113,113,0.42)', background: 'rgba(248,113,113,0.14)' }}
                >
                  ⚡ {strip.alerts_firing} alert{strip.alerts_firing === 1 ? '' : 's'} firing
                </Link>
              )}
            </div>

            {/* Action buttons */}
            <div className="mt-5 flex flex-wrap gap-2">
              {user.canMutate ? (
                <Link href="/alerts" className="btn-primary text-sm">
                  View alerts
                </Link>
              ) : (
                <Link href="/assets" className="btn-primary text-sm">
                  Browse assets
                </Link>
              )}
              <Link href="/findings" className="btn-secondary text-sm">
                All findings
              </Link>
              {user.canMutate ? (
                <Link href="/telemetry" className="btn-secondary text-sm">
                  Telemetry
                </Link>
              ) : (
                <Link href="/onboarding" className="btn-secondary text-sm">
                  Launch checklist
                </Link>
              )}
            </div>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Visible findings</p>
              <p className="hero-stat-value text-[var(--red)]">{findings.length}</p>
              <div className="risk-bar-wrap mt-2">
                <div className="risk-bar-fill red" style={{ width: `${Math.min(100, findings.length * 5)}%` }} />
              </div>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Anomalies queued</p>
              <p className="hero-stat-value text-[var(--amber)]">{anomalies.length}</p>
              <div className="risk-bar-wrap mt-2">
                <div className="risk-bar-fill amber" style={{ width: `${Math.min(100, anomalies.length * 10)}%` }} />
              </div>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Trend window</p>
              <p className="hero-stat-value text-[var(--accent)]">{trendRange.toUpperCase()}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Assets monitored</p>
              <p className="hero-stat-value">{strip?.total_assets ?? 0}</p>
              <div className="mt-2 flex items-center gap-1.5">
                <span className="dot-online" />
                <span className="text-[10px] text-[var(--text-subtle)]">live</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="command-lane animate-in">
        <div className="mb-2 flex items-center justify-between gap-2">
          <span className="text-[10px] font-semibold uppercase tracking-[0.12em] text-[var(--text-subtle)]">
            Live status
          </span>
          <span className="live-pill">
            <span className="dot-online" />
            Updated now
          </span>
        </div>
        <div className="command-lane-grid">
          <span className="command-pill-strong">
            Score {scoreNum != null ? scoreNum : '--'}
          </span>
          <span className="command-pill" style={{ color: trendColor }}>
            {trendLabel}
          </span>
          <span className="command-pill">{strip?.total_assets ?? 0} assets</span>
          {user.canMutate && strip != null && strip.alerts_firing > 0 ? (
            <Link
              href="/alerts"
              className="inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1 text-xs font-bold transition-colors hover:border-[var(--red)]/60"
              style={{ color: 'var(--red)', borderColor: 'rgba(248,113,113,0.35)', background: 'rgba(248,113,113,0.12)' }}
            >
              ⚡ {strip.alerts_firing} firing
            </Link>
          ) : (
            <span className="command-pill" style={{ color: 'var(--green)' }}>No alerts</span>
          )}
          <span className="command-pill">{findings.length} findings</span>
          <span className="command-pill">{anomalies.length} anomalies</span>
          <span className="command-pill">
            <span style={{ color: 'var(--green)' }}>{strip?.green ?? 0}G</span>
            {' · '}
            <span style={{ color: 'var(--amber)' }}>{strip?.amber ?? 0}A</span>
            {' · '}
            <span style={{ color: 'var(--red)' }}>{strip?.red ?? 0}R</span>
          </span>
          <span className="command-pill">
            {trendRange === '24h' ? '24h' : trendRange === '30d' ? '30 days' : '7 days'} window
          </span>
        </div>
      </section>

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
        <div className="view-stack">
          <div className="canvas-split">
            <section className="section-panel animate-in">
              <h2 className="section-title">Posture summary</h2>
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

            <section className="section-panel animate-in">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <h2 className="section-title">Posture trend</h2>
                <div className="flex gap-2">
                  {(['24h', '7d', '30d'] as const).map((range) => (
                    <Link
                      key={range}
                      href={buildOverviewHref(range, filters)}
                      className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                        trendRange === range
                          ? 'bg-[var(--green)] text-black'
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
              <div className="mt-4 grid gap-2 sm:grid-cols-2">
                <div className="signal-card">
                  <p className="text-[10px] uppercase tracking-[0.14em] text-[var(--muted)]">Top driver</p>
                  <p className="mt-2 text-sm font-medium text-[var(--text)]">
                    {drivers?.by_reason && drivers.by_reason.length > 0
                      ? drivers.by_reason[0].reason
                      : 'No primary driver'}
                  </p>
                </div>
                <div className="signal-card">
                  <p className="text-[10px] uppercase tracking-[0.14em] text-[var(--muted)]">Driver pressure</p>
                  <p className="mt-2 text-sm text-[var(--text)]">
                    {drivers?.by_reason && drivers.by_reason.length > 0
                      ? `${drivers.by_reason.length} active risk vectors`
                      : 'Stable'}
                  </p>
                </div>
              </div>
            </section>
          </div>

          {user.canMutate && (
            <OverviewAnomaliesPanel
              initialAnomalies={anomalies}
              canMutate={user.canMutate}
            />
          )}

          {repositorySummary && (
            <section className="section-panel animate-in">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="section-title">Repository risk</h2>
                  <p className="text-sm text-[var(--muted)]">
                    Live OSV and Trivy findings for{' '}
                    <Link
                      href={`/assets/${encodeURIComponent(repositorySummary.asset_key)}`}
                      className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                    >
                      {repositorySummary.asset_name || repositorySummary.asset_key}
                    </Link>
                    .
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Link
                    href={`/assets/${encodeURIComponent(repositorySummary.asset_key)}`}
                    className="btn-secondary text-sm"
                  >
                    Open asset
                  </Link>
                  {user.canMutate && (
                    <Link href="/jobs" className="btn-secondary text-sm">
                      Run scan
                    </Link>
                  )}
                </div>
              </div>

              <div className="grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(320px,0.9fr)]">
                <div className="card animate-in">
                  <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--red)]">
                        {repositorySummary.open_findings}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">Open findings</p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--amber)]">
                        {repositorySummary.in_progress_findings}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">In progress</p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--text)]">
                        {repositorySummary.accepted_risk_findings}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">Accepted risk</p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--green)]">
                        {repositorySummary.remediated_findings}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">Remediated</p>
                    </div>
                  </div>

                  <div className="mt-6 grid gap-6 lg:grid-cols-2">
                    <div>
                      <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                        Sources
                      </h3>
                      <ul className="space-y-3">
                        {repositorySummary.sources.map((source) => (
                          <li
                            key={source.source}
                            className="rounded-xl border border-[var(--border)] p-3"
                          >
                            <div className="flex items-center justify-between gap-3">
                              <span className="font-medium text-[var(--text)]">
                                {source.label}
                              </span>
                              <span className="stat-chip">{source.total} findings</span>
                            </div>
                            <p className="mt-2 text-xs text-[var(--muted)]">
                              Open {source.open} | In progress {source.in_progress} |
                              Accepted {source.accepted_risk} | Remediated {source.remediated}
                            </p>
                            <div className="mt-3 flex flex-wrap gap-2">
                              {Object.entries(source.by_severity).map(([severity, count]) => (
                                <span
                                  key={`${source.source}-${severity}`}
                                  className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(severity)}`}
                                >
                                  {severity} {count}
                                </span>
                              ))}
                            </div>
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                        Top packages
                      </h3>
                      {repositorySummary.top_packages.length === 0 ? (
                        <p className="text-sm text-[var(--muted)]">
                          No dependency packages are currently implicated. Recent detections are
                          configuration-oriented.
                        </p>
                      ) : (
                        <ul className="space-y-3">
                          {repositorySummary.top_packages.map((pkg) => (
                            <li
                              key={pkg.package_name}
                              className="flex items-center justify-between gap-3 rounded-xl border border-[var(--border)] p-3"
                            >
                              <div>
                                <p className="font-medium text-[var(--text)]">
                                  {pkg.package_name}
                                </p>
                                <p className="mt-1 text-xs text-[var(--muted)]">
                                  {pkg.active_count} active / {pkg.total_count} total
                                </p>
                              </div>
                              <span
                                className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(pkg.max_severity)}`}
                              >
                                {pkg.max_severity}
                              </span>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>
                </div>

                <div className="card animate-in">
                  <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                    Latest repository scans
                  </h3>
                  {repositorySummary.latest_jobs.length === 0 ? (
                    <p className="text-sm text-[var(--muted)]">
                      No repository scan jobs have completed yet.
                    </p>
                  ) : (
                    <ul className="space-y-3">
                      {repositorySummary.latest_jobs.map((job) => (
                        <li
                          key={job.job_id}
                          className="rounded-xl border border-[var(--border)] p-3"
                        >
                          <div className="flex items-center justify-between gap-3">
                            {user.canMutate ? (
                              <Link
                                href="/jobs"
                                className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                              >
                                Job {job.job_id}
                              </Link>
                            ) : (
                              <span className="font-medium text-[var(--text)]">Job {job.job_id}</span>
                            )}
                            <span
                              className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase ${
                                job.status === 'done'
                                  ? 'bg-[var(--green)]/20 text-[var(--green)]'
                                  : job.status === 'failed'
                                    ? 'bg-[var(--red)]/20 text-[var(--red)]'
                                    : job.status === 'running'
                                      ? 'bg-[var(--amber)]/20 text-[var(--amber)]'
                                      : 'bg-[var(--surface-elevated)] text-[var(--muted)]'
                              }`}
                            >
                              {job.status}
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            Created {job.created_at ? formatDateTime(job.created_at) : '-'}
                          </p>
                          {job.error ? (
                            <p className="mt-2 text-xs text-[var(--red)]">{job.error}</p>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  )}

                  <h3 className="mb-3 mt-6 text-sm font-medium text-[var(--muted)]">
                    Recent repository findings
                  </h3>
                  {repositorySummary.recent_findings.length === 0 ? (
                    <p className="text-sm text-[var(--muted)]">
                      The repository asset exists, but no OSV or Trivy findings have been recorded.
                    </p>
                  ) : (
                    <ul className="space-y-3">
                      {repositorySummary.recent_findings.slice(0, 5).map((finding) => (
                        <li
                          key={finding.finding_id}
                          className="rounded-xl border border-[var(--border)] p-3"
                        >
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div className="min-w-0 flex-1">
                              <p className="font-medium text-[var(--text)]">
                                {finding.title}
                              </p>
                              <p className="mt-1 text-xs text-[var(--muted)]">
                                {finding.source || 'scanner'}
                                {finding.package_name
                                  ? ` | ${finding.package_name}${
                                      finding.package_version
                                        ? `@${finding.package_version}`
                                        : ''
                                    }`
                                  : ''}
                                {finding.vulnerability_id
                                  ? ` | ${finding.vulnerability_id}`
                                  : ''}
                              </p>
                            </div>
                            <div className="text-right">
                              <span
                                className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(finding.risk_level || finding.severity)}`}
                              >
                                {finding.risk_level || finding.severity}
                              </span>
                              <p className="mt-1 text-[11px] capitalize text-[var(--muted)]">
                                {finding.status.replace('_', ' ')}
                              </p>
                            </div>
                          </div>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </section>
          )}

          {telemetrySummary && (
            <section className="section-panel animate-in">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="section-title">Signal coverage</h2>
                  <p className="text-sm text-[var(--muted)]">
                    Event volume, IOC-linked activity, and latest anomaly observations.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Link href="/telemetry" className="btn-secondary text-sm">
                    Open telemetry
                  </Link>
                  <Link href="/alerts" className="btn-secondary text-sm">
                    Open alerts
                  </Link>
                </div>
              </div>
              <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                  <div className="text-3xl font-bold text-[var(--text)]">
                    {telemetrySummary.totals.events}
                  </div>
                  <p className="mt-2 text-sm text-[var(--muted)]">Events</p>
                </div>
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                  <div className="text-3xl font-bold text-[var(--red)]">
                    {telemetrySummary.totals.ti_matches}
                  </div>
                  <p className="mt-2 text-sm text-[var(--muted)]">IOC matches</p>
                </div>
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                  <div className="text-3xl font-bold text-[var(--amber)]">
                    {telemetrySummary.totals.assets}
                  </div>
                  <p className="mt-2 text-sm text-[var(--muted)]">Assets observed</p>
                </div>
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                  <div className="text-3xl font-bold text-[var(--text)]">
                    {telemetrySummary.totals.sources}
                  </div>
                  <p className="mt-2 text-sm text-[var(--muted)]">Sources</p>
                </div>
              </div>
            </section>
          )}

          {threatIntelSummary && (
            <section className="section-panel animate-in">
              <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="section-title">Threat intelligence</h2>
                  <p className="text-sm text-[var(--muted)]">
                    IOC feeds, matched assets, and latest refresh health.
                  </p>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Link href="/threat-intel" className="btn-secondary text-sm">
                    Open intel
                  </Link>
                  <Link href="/jobs" className="btn-secondary text-sm">
                    Refresh feeds
                  </Link>
                </div>
              </div>

              <div className="grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(320px,0.9fr)]">
                <div className="card animate-in">
                  <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--text)]">
                        {threatIntelSummary.total_indicators}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">Active indicators</p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--red)]">
                        {threatIntelSummary.matched_asset_count}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">Matched assets</p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--amber)]">
                        {threatIntelSummary.total_asset_matches}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">Asset matches</p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                      <div className="text-3xl font-bold text-[var(--text)]">
                        {threatIntelSummary.source_count}
                      </div>
                      <p className="mt-2 text-sm text-[var(--muted)]">Feed sources</p>
                    </div>
                  </div>

                  <div className="mt-6 grid gap-6 lg:grid-cols-2">
                    <div>
                      <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                        Feed sources
                      </h3>
                      {threatIntelSummary.sources.length === 0 ? (
                        <p className="text-sm text-[var(--muted)]">
                          No threat-intel data loaded yet. Run a feed refresh from Jobs.
                        </p>
                      ) : (
                        <ul className="space-y-3">
                          {threatIntelSummary.sources.map((source) => (
                            <li
                              key={source.source}
                              className="rounded-xl border border-[var(--border)] p-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <span className="font-medium text-[var(--text)]">
                                  {source.source}
                                </span>
                                <span className="stat-chip">
                                  {source.indicator_count} IOCs
                                </span>
                              </div>
                              <p className="mt-2 text-xs text-[var(--muted)]">
                                IP {source.by_type.ip} | Domain {source.by_type.domain}
                                {source.last_seen_at
                                  ? ` | ${formatDateTime(source.last_seen_at)}`
                                  : ''}
                              </p>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                    <div>
                      <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                        Matched assets
                      </h3>
                      {threatIntelSummary.matched_assets.length === 0 ? (
                        <p className="text-sm text-[var(--muted)]">
                          No current asset matches. Feed coverage is loaded, but nothing in
                          inventory currently overlaps with those indicators.
                        </p>
                      ) : (
                        <ul className="space-y-3">
                          {threatIntelSummary.matched_assets.map((asset) => (
                            <li
                              key={asset.asset_key}
                              className="rounded-xl border border-[var(--border)] p-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <Link
                                  href={`/assets/${encodeURIComponent(asset.asset_key)}`}
                                  className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                                >
                                  {asset.asset_name || asset.asset_key}
                                </Link>
                                <span className="stat-chip-strong">
                                  {asset.match_count} matches
                                </span>
                              </div>
                              <p className="mt-2 text-xs text-[var(--muted)]">
                                {(asset.indicators || []).slice(0, 3).join(', ')}
                              </p>
                            </li>
                          ))}
                        </ul>
                      )}
                    </div>
                  </div>
                </div>

                <div className="card animate-in">
                  <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                    Latest refresh jobs
                  </h3>
                  {threatIntelSummary.latest_jobs.length === 0 ? (
                    <p className="text-sm text-[var(--muted)]">
                      No threat-intel refresh jobs have been run yet.
                    </p>
                  ) : (
                    <ul className="space-y-3">
                      {threatIntelSummary.latest_jobs.map((job) => (
                        <li
                          key={job.job_id}
                          className="rounded-xl border border-[var(--border)] p-3"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <Link
                              href="/jobs"
                              className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline"
                            >
                              Job {job.job_id}
                            </Link>
                            <span
                              className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase ${
                                job.status === 'done'
                                  ? 'bg-[var(--green)]/20 text-[var(--green)]'
                                  : job.status === 'failed'
                                    ? 'bg-[var(--red)]/20 text-[var(--red)]'
                                    : job.status === 'running'
                                      ? 'bg-[var(--amber)]/20 text-[var(--amber)]'
                                      : 'bg-[var(--surface-elevated)] text-[var(--muted)]'
                              }`}
                            >
                              {job.status}
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            Created {job.created_at ? formatDateTime(job.created_at) : '-'}
                          </p>
                          {job.error ? (
                            <p className="mt-2 text-xs text-[var(--red)]">{job.error}</p>
                          ) : null}
                        </li>
                      ))}
                    </ul>
                  )}

                  <h3 className="mb-3 mt-6 text-sm font-medium text-[var(--muted)]">
                    Recent indicators
                  </h3>
                  {threatIntelSummary.recent_indicators.length === 0 ? (
                    <p className="text-sm text-[var(--muted)]">
                      No indicators stored yet.
                    </p>
                  ) : (
                    <ul className="space-y-3">
                      {threatIntelSummary.recent_indicators.map((ioc) => (
                        <li
                          key={`${ioc.source}-${ioc.indicator_type}-${ioc.indicator}`}
                          className="rounded-xl border border-[var(--border)] p-3"
                        >
                          <div className="flex items-center justify-between gap-3">
                            <span className="font-medium text-[var(--text)]">
                              {ioc.indicator}
                            </span>
                            <span className="stat-chip uppercase">
                              {ioc.indicator_type}
                            </span>
                          </div>
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            {ioc.source}
                            {ioc.last_seen_at ? ` | ${formatDateTime(ioc.last_seen_at)}` : ''}
                          </p>
                        </li>
                      ))}
                    </ul>
                  )}
                </div>
              </div>
            </section>
          )}

          <section className="section-panel animate-in">
            <h2 className="section-title">What needs attention</h2>
            <div className="grid gap-6 lg:grid-cols-2">
              <div className="card">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                  Findings
                </h3>
                {topRiskFindings.length === 0 ? (
                  <p className="text-sm text-[var(--muted)]">No scored findings yet.</p>
                ) : (
                  <ul className="space-y-2">
                    {topRiskFindings.map((finding) => {
                      const level = (finding.risk_level || '').toLowerCase();
                      const severityClass =
                        level === 'critical' ? 'severity-critical' :
                        level === 'high' ? 'severity-high' :
                        level === 'medium' ? 'severity-medium' :
                        level === 'low' ? 'severity-low' : '';
                      return (
                        <li key={finding.finding_id} className={`data-row ${severityClass}`}>
                          <div className="min-w-0 flex-1">
                            <p className="text-sm font-medium text-[var(--text)]">{finding.title}</p>
                            <p className="mt-0.5 text-xs text-[var(--text-muted)]">
                              {finding.asset_key ? (
                                <Link href={`/assets/${encodeURIComponent(finding.asset_key)}`} className="hover:text-[var(--accent)]">
                                  {finding.asset_name || finding.asset_key}
                                </Link>
                              ) : 'Unlinked asset'}
                              {finding.category ? ` · ${finding.category}` : ''}
                            </p>
                          </div>
                          <div className="text-right">
                            <span className={`inline-block rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase ${riskBadgeClass(finding.risk_level)}`}>
                              {finding.risk_level || 'risk'} {Math.round(Number(finding.risk_score ?? 0))}
                            </span>
                            <p className="mt-0.5 text-[10px] capitalize text-[var(--text-subtle)]">
                              {finding.status.replace('_', ' ')}
                            </p>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
              <div className="card">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">Assets</h3>
                {topRiskAssets.length === 0 ? (
                  <p className="text-sm text-[var(--muted)]">No scored assets yet.</p>
                ) : (
                  <ul className="space-y-2">
                    {topRiskAssets.map((asset) => {
                      const level = (asset.risk_level || '').toLowerCase();
                      const severityClass =
                        level === 'critical' ? 'severity-critical' :
                        level === 'high' ? 'severity-high' :
                        level === 'medium' ? 'severity-medium' :
                        level === 'low' ? 'severity-low' : '';
                      return (
                        <li key={asset.asset_key} className={`data-row ${severityClass}`}>
                          <div className="min-w-0 flex-1">
                            <Link href={`/assets/${encodeURIComponent(asset.asset_key)}`} className="text-sm font-medium text-[var(--text)] hover:text-[var(--accent)]">
                              {asset.asset_name}
                            </Link>
                            <p className="mt-0.5 text-xs text-[var(--text-muted)]">
                              {asset.active_findings} active finding{asset.active_findings === 1 ? '' : 's'}
                            </p>
                            <div className="risk-bar-wrap mt-2">
                              <div className="risk-bar-fill" style={{
                                width: `${Math.round(asset.max_risk_score)}%`,
                                background: level === 'critical' ? 'var(--red)' : level === 'high' ? 'var(--orange)' : level === 'medium' ? 'var(--amber)' : 'var(--green)',
                              }} />
                            </div>
                          </div>
                          <div className="text-right shrink-0">
                            <span className={`inline-block rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase ${riskBadgeClass(asset.risk_level)}`}>
                              {asset.risk_level || 'risk'} {Math.round(asset.max_risk_score)}
                            </span>
                          </div>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            </div>
          </section>

          <section className="section-panel animate-in">
            <h2 className="section-title">Why the score is moving</h2>
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
            <section className="section-panel animate-in">
              <h2 className="section-title">Unavailable assets</h2>
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
        </div>
      )}

      {!overview && (
        <div className="card py-12 text-center text-sm text-[var(--muted)]">
          Overview data is unavailable right now.
        </div>
      )}
    </main>
  );
}
