'use client';

import { useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  getReportSummary,
  getReportHistory,
  getReportSnapshot,
  saveReportSnapshot,
  downloadPostureCsv,
  downloadExecutivePdf,
  getReportWhatChanged,
  type ReportSummary,
  type ReportSnapshot,
  type ReportWhatChanged,
} from '@/lib/api';
import { formatDateTime } from '@/lib/format';
import { EmptyState } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';

function SummaryCards({ summary }: { summary: ReportSummary | ReportSnapshot }) {
  return (
    <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
      <div className="metric-card">
        <div className="text-3xl font-bold text-[var(--text)]">{summary.uptime_pct}%</div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">Uptime</div>
      </div>
      <div className="metric-card neutral">
        <div className="text-3xl font-bold text-[var(--text)]">
          {summary.posture_score_avg ?? '-'}
        </div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">Posture score (avg)</div>
      </div>
      <div className="metric-card amber">
        <div className="text-3xl font-bold text-[var(--amber)]">
          {summary.avg_latency_ms ?? '-'} ms
        </div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">Avg latency</div>
      </div>
      <div className="metric-card">
        <div className="text-3xl font-bold text-[var(--text)]">{summary.total_assets}</div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">
          Assets (G/A/R: {summary.green}/{summary.amber}/{summary.red})
        </div>
      </div>
    </div>
  );
}

function topIncidentsList(summary: ReportSummary | ReportSnapshot): string[] {
  const top = summary.top_incidents;
  if (Array.isArray(top)) return top;
  if (typeof top === 'string' && top) return [top];
  return [];
}

export default function ReportsPage() {
  const { canMutate } = useAuth();
  const [summary, setSummary] = useState<ReportSummary | null>(null);
  const [history, setHistory] = useState<ReportSnapshot[]>([]);
  const [viewSnapshot, setViewSnapshot] = useState<ReportSnapshot | null>(null);
  const [loadingCsv, setLoadingCsv] = useState(false);
  const [loadingPdf, setLoadingPdf] = useState(false);
  const [savingSnapshot, setSavingSnapshot] = useState(false);
  const [whatChangedFromId, setWhatChangedFromId] = useState<number | ''>('');
  const [whatChangedToId, setWhatChangedToId] = useState<number | 'current'>('current');
  const [whatChangedResult, setWhatChangedResult] = useState<ReportWhatChanged | null>(null);
  const [whatChangedLoading, setWhatChangedLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadSummary = () => {
    getReportSummary('24h').then(setSummary).catch((err) => setError(err.message));
  };

  const loadHistory = () => {
    getReportHistory(20)
      .then((result) => setHistory(result.items))
      .catch((err) => setError(err.message));
  };

  useEffect(() => {
    loadSummary();
    loadHistory();
  }, []);

  async function handleDownloadCsv() {
    setLoadingCsv(true);
    setError(null);
    try {
      await downloadPostureCsv();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'CSV download failed');
    } finally {
      setLoadingCsv(false);
    }
  }

  async function handleSaveSnapshot() {
    setSavingSnapshot(true);
    setError(null);
    try {
      await saveReportSnapshot('24h');
      loadHistory();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Snapshot save failed');
    } finally {
      setSavingSnapshot(false);
    }
  }

  async function handleViewSnapshot(snapshotId: number) {
    setError(null);
    try {
      const snapshot = await getReportSnapshot(snapshotId);
      setViewSnapshot(snapshot);
      setWhatChangedResult(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Snapshot load failed');
    }
  }

  async function handleDownloadPdf() {
    setLoadingPdf(true);
    setError(null);
    try {
      await downloadExecutivePdf(viewSnapshot?.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'PDF download failed');
    } finally {
      setLoadingPdf(false);
    }
  }

  async function handleWhatChanged() {
    if (whatChangedFromId === '') return;
    setWhatChangedLoading(true);
    setError(null);
    setWhatChangedResult(null);
    try {
      const toId = whatChangedToId === 'current' ? undefined : whatChangedToId;
      const result = await getReportWhatChanged(whatChangedFromId, toId);
      setWhatChangedResult(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Compare failed');
    } finally {
      setWhatChangedLoading(false);
    }
  }

  const currentSummary = summary && !viewSnapshot ? summary : viewSnapshot;
  const incidents = currentSummary ? topIncidentsList(currentSummary) : [];
  const historyCount = history.length;
  const latestSnapshot = history[0] ?? null;

  const comparisonReady =
    whatChangedFromId !== '' && !(whatChangedToId !== 'current' && whatChangedFromId === whatChangedToId);

  const snapshotOptions = useMemo(
    () =>
      history.map((snapshot) => ({
        id: snapshot.id,
        label: `#${snapshot.id} ${formatDateTime(snapshot.created_at)}`,
      })),
    [history]
  );

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <h1 className="hero-title">Reporting Center</h1>
            <p className="hero-copy">
              Create polished customer snapshots, compare reporting windows, and export
              board-ready views.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <button type="button" onClick={handleDownloadPdf} disabled={loadingPdf} className="btn-primary text-sm">
                {loadingPdf
                  ? 'Preparing...'
                  : viewSnapshot
                    ? `Download PDF (snapshot #${viewSnapshot.id})`
                    : 'Download PDF (current)'}
              </button>
              <button type="button" onClick={handleDownloadCsv} disabled={loadingCsv} className="btn-secondary text-sm">
                {loadingCsv ? 'Preparing...' : 'Download CSV'}
              </button>
              {canMutate && (
                <button
                  type="button"
                  onClick={handleSaveSnapshot}
                  disabled={savingSnapshot}
                  className="btn-secondary text-sm"
                >
                  {savingSnapshot ? 'Saving...' : 'Save snapshot'}
                </button>
              )}
              <Link href="/overview" className="btn-secondary text-sm">
                Open overview
              </Link>
            </div>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Snapshots stored</p>
              <p className="hero-stat-value">{historyCount}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Current score</p>
              <p className="hero-stat-value">{summary?.posture_score_avg ?? '-'}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Current uptime</p>
              <p className="hero-stat-value">{summary?.uptime_pct ?? '-'}%</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">View mode</p>
              <p className="hero-stat-value">{viewSnapshot ? `#${viewSnapshot.id}` : 'Current'}</p>
            </div>
          </div>
        </div>
      </section>

      <section className="command-lane animate-in">
        <div className="command-lane-grid">
          <span className="command-pill-strong">
            Latest snapshot {latestSnapshot ? `#${latestSnapshot.id}` : 'none'}
          </span>
          <span className="command-pill">
            Latest saved {latestSnapshot ? formatDateTime(latestSnapshot.created_at) : '-'}
          </span>
          <span className="command-pill">Comparison {whatChangedResult ? 'ready' : 'idle'}</span>
        </div>
      </section>

      {error && (
        <div className="alert-error animate-in" role="alert">
          {error}
        </div>
      )}

      {currentSummary && (
        <section className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">
                {viewSnapshot
                  ? `Snapshot #${viewSnapshot.id} (${formatDateTime(viewSnapshot.created_at)})`
                  : 'Current Summary (24h)'}
              </h2>
              <p className="section-head-copy">
                {viewSnapshot
                  ? `Period ${viewSnapshot.period}`
                  : 'Live summary aggregated over the last 24 hours.'}
              </p>
            </div>
            {viewSnapshot && (
              <button type="button" onClick={() => setViewSnapshot(null)} className="btn-secondary text-sm">
                Back to current
              </button>
            )}
          </div>
          <SummaryCards summary={currentSummary} />
          {incidents.length > 0 && (
            <div className="mt-5">
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-[0.14em] text-[var(--muted)]">
                Top incidents (down)
              </h3>
              <div className="flex flex-wrap gap-2">
                {incidents.map((assetId) => (
                  <Link
                    key={assetId}
                    href={`/assets/${encodeURIComponent(assetId)}`}
                    className="command-pill border-rose-300/35 bg-rose-300/10 text-[var(--red)] hover:text-[var(--red)]"
                  >
                    {assetId}
                  </Link>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      <section className="canvas-split">
        <section className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Report history</h2>
              <p className="section-head-copy">Open stored reporting checkpoints or compare them against current state.</p>
            </div>
          </div>
          {history.length === 0 ? (
            <EmptyState
              title="No report history yet"
              description="Save a snapshot to create baseline checkpoints for audits and trend analysis."
            />
          ) : (
            <div className="table-shell overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] bg-[var(--surface-elevated)]/55">
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Date</th>
                    <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Period</th>
                    <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Uptime %</th>
                    <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Score</th>
                    <th className="px-4 py-3 text-right text-xs font-medium uppercase tracking-wider text-[var(--muted)]">G / A / R</th>
                  </tr>
                </thead>
                <tbody>
                  {history.map((row) => (
                    <tr
                      key={row.id}
                      className="cursor-pointer border-b border-[var(--border)] transition hover:bg-[var(--border)]/30"
                      onClick={() => void handleViewSnapshot(row.id)}
                    >
                      <td className="px-4 py-3">{formatDateTime(row.created_at)}</td>
                      <td className="px-4 py-3">{row.period}</td>
                      <td className="px-4 py-3 text-right">{row.uptime_pct}%</td>
                      <td className="px-4 py-3 text-right">{row.posture_score_avg ?? '-'}</td>
                      <td className="px-4 py-3 text-right">
                        {row.green} / {row.amber} / {row.red}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        <aside className="section-panel animate-in h-fit">
          <h2 className="section-title mb-3">What changed</h2>
          <p className="mb-3 text-sm text-[var(--muted)]">
            Compare two snapshots or compare a snapshot against current state.
          </p>
          <div className="space-y-2">
            <select
              value={whatChangedFromId}
              onChange={(event) =>
                setWhatChangedFromId(event.target.value === '' ? '' : Number(event.target.value))
              }
              className="input"
            >
              <option value="">From snapshot...</option>
              {snapshotOptions.map((option) => (
                <option key={`from-${option.id}`} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
            <select
              value={whatChangedToId === 'current' ? 'current' : whatChangedToId}
              onChange={(event) =>
                setWhatChangedToId(event.target.value === 'current' ? 'current' : Number(event.target.value))
              }
              className="input"
            >
              <option value="current">Current</option>
              {snapshotOptions.map((option) => (
                <option key={`to-${option.id}`} value={option.id}>
                  {option.label}
                </option>
              ))}
            </select>
            <button
              type="button"
              onClick={handleWhatChanged}
              disabled={whatChangedLoading || !comparisonReady}
              className="btn-secondary w-full"
            >
              {whatChangedLoading ? 'Comparing...' : 'Compare snapshots'}
            </button>
          </div>

          {whatChangedResult && (
            <div className="mt-4 space-y-3 rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/45 p-4 text-sm">
              <div>
                <p className="text-xs uppercase tracking-[0.14em] text-[var(--muted)]">Score delta</p>
                <p className="mt-1 text-[var(--text)]">
                  {whatChangedResult.score_delta != null
                    ? `${whatChangedResult.score_delta >= 0 ? '+' : ''}${whatChangedResult.score_delta}`
                    : '-'}
                </p>
              </div>
              <div className="grid grid-cols-3 gap-2 text-xs">
                <span>Green {whatChangedResult.green_delta >= 0 ? '+' : ''}{whatChangedResult.green_delta}</span>
                <span>Amber {whatChangedResult.amber_delta >= 0 ? '+' : ''}{whatChangedResult.amber_delta}</span>
                <span>Red {whatChangedResult.red_delta >= 0 ? '+' : ''}{whatChangedResult.red_delta}</span>
              </div>
              {(whatChangedResult.incidents_added.length > 0 ||
                whatChangedResult.incidents_removed.length > 0) && (
                <div className="space-y-2 border-t border-[var(--border)] pt-3">
                  {whatChangedResult.incidents_added.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-rose-200">
                        Incidents Added
                      </p>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {whatChangedResult.incidents_added.map((assetId) => (
                          <Link
                            key={`add-${assetId}`}
                            href={`/assets/${encodeURIComponent(assetId)}`}
                            className="command-pill border-rose-300/35 bg-rose-300/10 text-[var(--red)]"
                          >
                            {assetId}
                          </Link>
                        ))}
                      </div>
                    </div>
                  )}
                  {whatChangedResult.incidents_removed.length > 0 && (
                    <div>
                      <p className="text-xs font-semibold uppercase tracking-[0.14em] text-emerald-200">
                        Incidents Removed
                      </p>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {whatChangedResult.incidents_removed.map((assetId) => (
                          <Link
                            key={`remove-${assetId}`}
                            href={`/assets/${encodeURIComponent(assetId)}`}
                            className="command-pill border-emerald-300/35 bg-emerald-300/10 text-[var(--green)]"
                          >
                            {assetId}
                          </Link>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </aside>
      </section>
    </main>
  );
}
