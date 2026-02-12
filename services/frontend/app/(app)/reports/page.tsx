'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getReportSummary,
  getReportHistory,
  getReportSnapshot,
  saveReportSnapshot,
  downloadPostureCsv,
  type ReportSummary,
  type ReportSnapshot,
} from '@/lib/api';
import { formatDateTime } from '@/lib/format';
import { EmptyState } from '@/components/EmptyState';

function SummaryCards({ s }: { s: ReportSummary | ReportSnapshot }) {
  return (
    <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
      <div className="metric-card">
        <div className="text-3xl font-bold text-[var(--text)]">{s.uptime_pct}%</div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">Uptime</div>
      </div>
      <div className="metric-card neutral">
        <div className="text-3xl font-bold text-[var(--text)]">{s.posture_score_avg ?? '–'}</div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">Posture score (avg)</div>
      </div>
      <div className="metric-card amber">
        <div className="text-3xl font-bold text-[var(--amber)]">{s.avg_latency_ms ?? '–'} ms</div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">Avg latency</div>
      </div>
      <div className="metric-card">
        <div className="text-3xl font-bold text-[var(--text)]">{s.total_assets}</div>
        <div className="mt-2 text-sm font-medium text-[var(--muted)]">Assets (G/A/R: {s.green}/{s.amber}/{s.red})</div>
      </div>
    </div>
  );
}

function topIncidentsList(s: ReportSummary | ReportSnapshot): string[] {
  const t = s.top_incidents;
  if (Array.isArray(t)) return t;
  if (typeof t === 'string' && t) return [t];
  return [];
}

export default function ReportsPage() {
  const [summary, setSummary] = useState<ReportSummary | null>(null);
  const [history, setHistory] = useState<ReportSnapshot[]>([]);
  const [viewSnapshot, setViewSnapshot] = useState<ReportSnapshot | null>(null);
  const [loading, setLoading] = useState(false);
  const [saveLoading, setSaveLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  function loadSummary() {
    getReportSummary('24h').then(setSummary).catch((e) => setError(e.message));
  }
  function loadHistory() {
    getReportHistory(20).then((r) => setHistory(r.items)).catch((e) => setError(e.message));
  }

  useEffect(() => {
    loadSummary();
    loadHistory();
  }, []);

  async function handleDownload() {
    setLoading(true);
    setError(null);
    try {
      await downloadPostureCsv();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Download failed');
    } finally {
      setLoading(false);
    }
  }

  async function handleSaveSnapshot() {
    setSaveLoading(true);
    setError(null);
    try {
      await saveReportSnapshot('24h');
      loadHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaveLoading(false);
    }
  }

  async function handleViewSnapshot(id: number) {
    setError(null);
    try {
      const snap = await getReportSnapshot(id);
      setViewSnapshot(snap);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Load failed');
    }
  }

  const currentSummary = summary && !viewSnapshot ? summary : viewSnapshot;
  const incidents = currentSummary ? topIncidentsList(currentSummary) : [];

  return (
    <main className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
      <h1 className="page-title mb-8">Reports</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {error}
        </div>
      )}

      {summary && !viewSnapshot && (
        <section className="mb-10">
          <h2 className="section-title">Summary (last 24h)</h2>
          <SummaryCards s={summary} />
          {incidents.length > 0 && (
            <div className="mt-4">
              <h3 className="mb-2 text-sm font-medium text-[var(--muted)]">Top incidents (down)</h3>
              <ul className="space-y-1">
                {incidents.map((id) => (
                  <li key={id}>
                    <Link href={`/assets/${encodeURIComponent(id)}`} className="text-[var(--red)] hover:underline">{id}</Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      {viewSnapshot && (
        <section className="mb-10">
          <div className="mb-4 flex flex-wrap items-center gap-3">
            <h2 className="text-base font-medium text-[var(--muted)]">
              Snapshot #{viewSnapshot.id} · {formatDateTime(viewSnapshot.created_at)} ({viewSnapshot.period})
            </h2>
            <button type="button" onClick={() => setViewSnapshot(null)} className="btn-secondary text-sm">
              Back to current
            </button>
          </div>
          <SummaryCards s={viewSnapshot} />
          {topIncidentsList(viewSnapshot).length > 0 && (
            <div className="mt-4">
              <h3 className="mb-2 text-sm font-medium text-[var(--muted)]">Top incidents (down)</h3>
              <ul className="space-y-1">
                {topIncidentsList(viewSnapshot).map((id: string) => (
                  <li key={id}>
                    <Link href={`/assets/${encodeURIComponent(id)}`} className="text-[var(--red)] hover:underline">{id}</Link>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}

      <section className="mb-10">
        <h2 className="section-title">Save snapshot</h2>
        <p className="mb-3 text-sm text-[var(--muted)]">
          Store current 24h summary in the database for report history.
        </p>
        <button type="button" onClick={handleSaveSnapshot} disabled={saveLoading} className="btn-secondary">
          {saveLoading ? 'Saving…' : 'Save current as snapshot'}
        </button>
      </section>

      <section className="mb-10">
        <h2 className="section-title">Report history</h2>
        <p className="mb-3 text-sm text-[var(--muted)]">
          Stored snapshots. Click a row to view.
        </p>
        {history.length === 0 ? (
          <EmptyState
            title="No report history yet"
            description="Save a snapshot above to store the current 24h summary. Saved snapshots appear here for trend and audit."
          />
        ) : (
          <div className="card overflow-hidden p-0 animate-in">
            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] bg-[var(--bg)]/50">
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
                      onClick={() => handleViewSnapshot(row.id)}
                    >
                      <td className="px-4 py-3">{formatDateTime(row.created_at)}</td>
                      <td className="px-4 py-3">{row.period}</td>
                      <td className="px-4 py-3 text-right">{row.uptime_pct}%</td>
                      <td className="px-4 py-3 text-right">{row.posture_score_avg ?? '–'}</td>
                      <td className="px-4 py-3 text-right">{row.green} / {row.amber} / {row.red}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </section>

      <section>
        <h2 className="section-title">Export</h2>
        <p className="mb-3 text-sm text-[var(--muted)]">
          Export current posture as CSV for weekly reports.
        </p>
        <button type="button" onClick={handleDownload} disabled={loading} className="btn-primary">
          {loading ? 'Preparing…' : 'Download CSV'}
        </button>
      </section>
    </main>
  );
}
