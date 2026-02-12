'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { getPostureOverview, getPostureTrend, type OverviewResponse, type TrendPoint } from '@/lib/api';
import { useFilters } from '@/contexts/FilterContext';
import { OverviewSkeleton } from '@/components/Skeleton';
import { ProgressRing } from '@/components/ProgressRing';
import { EmptyState, ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';

type TrendRange = '24h' | '7d' | '30d';

function TrendChart({ points, range }: { points: TrendPoint[]; range: TrendRange }) {
  if (points.length === 0) {
    return (
      <p className="text-sm text-[var(--muted)] py-8 text-center">
        No snapshot data for this range. Save a report snapshot to see trend.
      </p>
    );
  }
  const scores = points.map((p) => (p.posture_score_avg != null ? Number(p.posture_score_avg) : null)).filter((s): s is number => s != null);
  const min = Math.min(0, ...scores);
  const max = Math.max(100, ...scores);
  const rangeY = max - min || 1;
  const w = 600;
  const h = 160;
  const padding = { top: 8, right: 8, bottom: 24, left: 32 };
  const chartW = w - padding.left - padding.right;
  const chartH = h - padding.top - padding.bottom;
  const xScale = (i: number) => padding.left + (points.length > 1 ? (i / (points.length - 1)) * chartW : chartW / 2);
  const yScale = (v: number) => padding.top + chartH - ((v - min) / rangeY) * chartH;
  const pathD = points
    .map((p, i) => {
      const v = p.posture_score_avg != null ? Number(p.posture_score_avg) : null;
      if (v == null) return null;
      return `${i === 0 ? 'M' : 'L'} ${xScale(i)} ${yScale(v)}`;
    })
    .filter(Boolean)
    .join(' ');

  return (
    <div className="overflow-x-auto">
      <svg viewBox={`0 0 ${w} ${h}`} className="min-w-full h-40" preserveAspectRatio="none">
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
        <line x1={padding.left} y1={padding.top} x2={padding.left} y2={padding.top + chartH} stroke="var(--border)" strokeWidth="1" />
        <line x1={padding.left} y1={padding.top + chartH} x2={padding.left + chartW} y2={padding.top + chartH} stroke="var(--border)" strokeWidth="1" />
      </svg>
    </div>
  );
}

export default function OverviewPage() {
  const filters = useFilters();
  const filterParams = {
    environment: filters.environment ?? undefined,
    criticality: filters.criticality ?? undefined,
    owner: filters.owner ?? undefined,
    status: filters.status ?? undefined,
  };
  const [overview, setOverview] = useState<OverviewResponse | null>(null);
  const [trend, setTrend] = useState<{ range: string; points: TrendPoint[] } | null>(null);
  const [trendRange, setTrendRange] = useState<TrendRange>('7d');
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    getPostureOverview(filterParams)
      .then(setOverview)
      .catch((e) => setError(e.message));
    getPostureTrend(trendRange)
      .then(setTrend)
      .catch(() => setTrend(null));
  }, [filterParams.environment, filterParams.criticality, filterParams.owner, filterParams.status, trendRange]);

  useEffect(() => {
    load();
    const t = setInterval(load, 60000);
    return () => clearInterval(t);
  }, [load]);

  const strip = overview?.executive_strip;
  const drivers = overview?.top_drivers;
  const scoreNum = strip?.posture_score_avg != null ? Number(strip.posture_score_avg) : null;
  const showRing = typeof scoreNum === 'number' && !Number.isNaN(scoreNum) && scoreNum >= 0 && scoreNum <= 100;

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-10">Posture Overview</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
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
          {/* 1) Executive strip */}
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
                    <div className="mt-2 text-sm font-medium text-[var(--muted)]">Posture score</div>
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
                        {strip.score_trend_vs_yesterday === 'up' ? 'Up vs yesterday' : strip.score_trend_vs_yesterday === 'down' ? 'Down vs yesterday' : 'Same'}
                      </span>
                    )}
                  </>
                ) : (
                  <>
                    <div className="text-4xl font-bold text-[var(--text)]">{strip.posture_score_avg ?? '–'}</div>
                    <div className="mt-2 text-sm font-medium text-[var(--muted)]">Posture score</div>
                  </>
                )}
              </div>
              <div className="metric-card animate-in">
                <div className="text-4xl font-bold text-[var(--text)]">{strip.total_assets}</div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">Assets monitored</div>
              </div>
              <div className="metric-card red animate-in">
                <div className="text-4xl font-bold text-[var(--red)]">{strip.alerts_firing}</div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">Alerts firing</div>
              </div>
              <div className="metric-card animate-in">
                <div className="text-4xl font-bold text-[var(--text)]">
                  {strip.risk_change_24h != null ? (strip.risk_change_24h >= 0 ? `+${strip.risk_change_24h}` : strip.risk_change_24h) : '–'}
                </div>
                <div className="mt-2 text-sm font-medium text-[var(--muted)]">Risk change (24h)</div>
              </div>
            </div>
          </section>

          {/* 2) Posture trend */}
          <section className="mb-10">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
              <h2 className="section-title">Posture trend</h2>
              <div className="flex gap-2">
                {(['24h', '7d', '30d'] as const).map((r) => (
                  <button
                    key={r}
                    type="button"
                    onClick={() => setTrendRange(r)}
                    className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                      trendRange === r ? 'bg-[var(--green)] text-white' : 'bg-[var(--border)]/50 text-[var(--muted)] hover:bg-[var(--border)]'
                    }`}
                  >
                    {r === '24h' ? '24h' : r === '7d' ? '7 days' : '30 days'}
                  </button>
                ))}
              </div>
            </div>
            <div className="card overflow-hidden">
              <TrendChart points={trend?.points ?? []} range={trendRange} />
            </div>
          </section>

          {/* 3) Top drivers */}
          <section className="mb-10">
            <h2 className="section-title">Top drivers</h2>
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="card animate-in">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">Top 5 impacting score</h3>
                {drivers?.worst_assets?.length ? (
                  <ul className="space-y-2">
                    {drivers.worst_assets.map((a) => (
                      <li key={a.asset_id}>
                        <Link href={`/assets/${encodeURIComponent(a.asset_id)}`} className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline">
                          {a.name || a.asset_id}
                        </Link>
                        <span className="ml-2 text-sm text-[var(--muted)]">score {a.posture_score ?? '–'} · {a.status}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-[var(--muted)]">No data</p>
                )}
              </div>
              <div className="card animate-in">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">Incident categories</h3>
                {drivers?.by_reason?.length ? (
                  <ul className="space-y-2">
                    {drivers.by_reason.map((r) => (
                      <li key={r.reason} className="flex justify-between text-sm">
                        <span className="text-[var(--text)]">{r.reason}</span>
                        <span className="font-medium text-[var(--muted)]">{r.count}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-[var(--muted)]">No data</p>
                )}
              </div>
              <div className="card animate-in">
                <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">Recently updated</h3>
                {drivers?.recently_updated?.length ? (
                  <ul className="space-y-2">
                    {drivers.recently_updated.map((a) => (
                      <li key={a.asset_id}>
                        <Link href={`/assets/${encodeURIComponent(a.asset_id)}`} className="font-medium text-[var(--text)] hover:text-[var(--green)] hover:underline">
                          {a.name || a.asset_id}
                        </Link>
                        <span className="ml-2 text-xs text-[var(--muted)]">{a.last_seen ? formatDateTime(a.last_seen) : '–'}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-sm text-[var(--muted)]">No data</p>
                )}
              </div>
            </div>
          </section>

          {/* Down assets (unchanged) */}
          {strip?.red != null && strip.red > 0 && strip.down_assets?.length > 0 && (
            <section className="animate-in">
              <h2 className="section-title">Down assets</h2>
              <div className="card" style={{ borderColor: 'var(--red-border-subtle)' }}>
                <ul className="space-y-3">
                  {strip.down_assets.map((id) => (
                    <li key={id}>
                      <Link href={`/assets/${encodeURIComponent(id)}`} className="font-medium text-[var(--red)] transition hover:underline">
                        {id}
                      </Link>
                    </li>
                  ))}
                </ul>
              </div>
            </section>
          )}
        </>
      )}

      {!overview && !error && <OverviewSkeleton />}
    </main>
  );
}
