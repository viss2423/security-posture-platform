'use client';

import { useEffect, useState } from 'react';
import {
  getSoc2Evidence,
  downloadSoc2EvidencePdf,
  type Soc2EvidenceReport,
  type Soc2ControlEvidence,
} from '@/lib/api';
import { EmptyState, ApiDownHint } from '@/components/EmptyState';

// ---------------------------------------------------------------------------
// Colour helpers
// ---------------------------------------------------------------------------

function statusBg(status: string): string {
  if (status === 'pass') return 'bg-[var(--green-dim)] border-[var(--green-ring)]';
  if (status === 'fail') return 'bg-[var(--red-dim)] border-red-400/30';
  return 'bg-[var(--muted)]/10 border-[var(--muted)]/30';
}

function statusBadge(status: string): string {
  if (status === 'pass') return 'bg-[var(--green)]/15 text-[var(--green)]';
  if (status === 'fail') return 'bg-[var(--red)]/15 text-[var(--red)]';
  return 'bg-[var(--muted)]/20 text-[var(--muted)]';
}

function sevBadge(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return 'bg-red-600 text-white';
    case 'high': return 'bg-orange-700 text-white';
    case 'medium': return 'bg-yellow-500 text-black';
    case 'low': return 'bg-blue-600 text-white';
    default: return 'bg-gray-500 text-white';
  }
}

// ---------------------------------------------------------------------------
// Control card
// ---------------------------------------------------------------------------

function ControlCard({ control }: { control: Soc2ControlEvidence }) {
  const [open, setOpen] = useState(false);
  const label =
    control.status === 'pass' ? 'PASS'
    : control.status === 'fail' ? 'FAIL'
    : 'N/A';

  return (
    <div className={`rounded-2xl border p-5 ${statusBg(control.status)}`}>
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-sm font-mono font-semibold text-[var(--text)]">
              {control.control_id}
            </span>
            <span
              className={`inline-block rounded-md px-2 py-0.5 text-[11px] font-semibold uppercase ${statusBadge(control.status)}`}
            >
              {label}
            </span>
          </div>
          <h3 className="mt-1 text-base font-semibold text-[var(--text)]">
            {control.name}
          </h3>
          <p className="mt-1 text-sm text-[var(--text-muted)] max-w-prose">
            {control.description}
          </p>
          <p className="mt-2 text-xs text-[var(--muted)]">
            {control.open_count > 0 && (
              <span className="text-[var(--red)]">
                {control.open_count} open
              </span>
            )}
            {control.open_count > 0 && control.remediated_count > 0 && ' · '}
            {control.remediated_count > 0 && (
              <span className="text-[var(--green)]">
                {control.remediated_count} remediated
              </span>
            )}
            {control.total_checks === 0 && 'No checks run yet'}
          </p>
        </div>
      </div>

      {control.evidence.length > 0 && (
        <div className="mt-4">
          <button
            type="button"
            onClick={() => setOpen(!open)}
            className="text-xs font-medium text-[var(--accent)] hover:underline"
          >
            {open ? 'Hide evidence' : `Show ${control.evidence.length} item${control.evidence.length !== 1 ? 's' : ''}`}
          </button>
          {open && (
            <div className="mt-3 space-y-2">
              {control.evidence.map((ev) => (
                <div
                  key={ev.finding_id}
                  className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/60 p-3 text-sm"
                >
                  <div className="flex items-start justify-between gap-2">
                    <p className="font-medium text-[var(--text)]">{ev.title}</p>
                    <span
                      className={`shrink-0 rounded px-2 py-0.5 text-[11px] font-semibold uppercase ${sevBadge(ev.severity)}`}
                    >
                      {ev.severity}
                    </span>
                  </div>
                  {ev.evidence && (
                    <p className="mt-1.5 text-xs text-[var(--text-muted)] bg-[var(--surface-elevated)]/40 rounded-md p-2 font-mono">
                      {ev.evidence}
                    </p>
                  )}
                  {ev.remediation && (
                    <p className="mt-1.5 text-xs text-[var(--text-muted)]">
                      <span className="font-semibold text-[var(--text)]">Fix: </span>
                      {ev.remediation}
                    </p>
                  )}
                  <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-[var(--muted)] items-center">
                    {ev.status && (
                      <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase ${
                        ev.status === 'remediated'
                          ? 'bg-[var(--green)]/10 text-[var(--green)]'
                          : 'bg-[var(--red)]/10 text-[var(--red)]'
                      }`}>
                        {ev.status}
                      </span>
                    )}
                    {ev.repo && <span>Repo: {ev.repo}</span>}
                    {ev.check_type && <span>Check: {ev.check_type}</span>}
                    {ev.last_seen && (
                      <span>Last seen: {new Date(ev.last_seen).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}


// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------

export default function CompliancePage() {
  const [report, setReport] = useState<Soc2EvidenceReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [pdfBusy, setPdfBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    getSoc2Evidence()
      .then(setReport)
      .catch((err) => setError(err.message))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  const handlePdf = async () => {
    setPdfBusy(true);
    try { await downloadSoc2EvidencePdf(); }
    catch (err) { setError(err instanceof Error ? err.message : 'PDF download failed'); }
    finally { setPdfBusy(false); }
  };

  if (loading) {
    return (
      <main className="standard-main">
        <div className="mx-auto max-w-3xl animate-pulse space-y-4 py-20">
          <div className="h-8 w-64 rounded bg-[var(--surface-elevated)]" />
          <div className="h-4 w-96 rounded bg-[var(--surface-elevated)]" />
          <div className="h-48 rounded-2xl bg-[var(--surface-elevated)]" />
          <div className="h-48 rounded-2xl bg-[var(--surface-elevated)]" />
          <div className="h-48 rounded-2xl bg-[var(--surface-elevated)]" />
        </div>
      </main>
    );
  }

  if (error) {
    return (
      <main className="standard-main">
        <div className="mx-auto max-w-3xl py-20">
          <EmptyState icon={null} title="Couldn't load compliance report" description={error} action={<button onClick={load} className="btn-primary mt-4">Retry</button>} />
          <ApiDownHint />
        </div>
      </main>
    );
  }

  if (!report) return null;
  const { score, controls, scope } = report;
  const pct = score.percentage;

  return (
    <main className="standard-main">
      <div className="mx-auto max-w-3xl">
        <section className="mb-8">
          <h1 className="hero-title">SOC 2 Compliance Evidence</h1>
          <p className="hero-copy">
            Live evidence from your GitHub posture scan, mapped to SOC 2 Trust
            Services Criteria controls.
          </p>
          <div className="mt-4 flex flex-wrap gap-2">
            <button onClick={load} disabled={loading} className="btn-secondary text-sm">Refresh</button>
            <button onClick={handlePdf} disabled={pdfBusy} className="btn-primary text-sm">
              {pdfBusy ? 'Preparing...' : 'Download PDF Report'}
            </button>
          </div>
        </section>

        <section className="mb-8">
          <div className="grid grid-cols-2 gap-3 sm:gap-4 lg:grid-cols-4">
            <div className="metric-card">
              <div className="text-3xl font-bold" style={{
                color: pct != null && pct >= 80 ? 'var(--green)' : pct != null && pct >= 50 ? 'var(--amber)' : 'var(--red)'
              }}>{pct != null ? `${pct}%` : '—'}</div>
              <div className="mt-2 text-sm font-medium text-[var(--muted)]">Pass rate</div>
            </div>
            <div className="metric-card neutral">
              <div className="text-3xl font-bold text-[var(--green)]">{score.pass}</div>
              <div className="mt-2 text-sm font-medium text-[var(--muted)]">Passing</div>
            </div>
            <div className="metric-card neutral">
              <div className="text-3xl font-bold text-[var(--red)]">{score.fail}</div>
              <div className="mt-2 text-sm font-medium text-[var(--muted)]">Failing</div>
            </div>
            <div className="metric-card neutral">
              <div className="text-3xl font-bold text-[var(--text)]">{scope.asset_count}</div>
              <div className="mt-2 text-sm font-medium text-[var(--muted)]">Assets</div>
            </div>
          </div>
          {!report.scan_ran && (
            <p className="mt-4 text-xs font-medium text-[var(--amber)]">
              No GitHub posture scan has completed yet. Run a scan to populate
              control evidence and see pass/fail results.
            </p>
          )}
          <p className="mt-4 text-xs text-[var(--muted)]">
            Report ID: {report.report_id} · {new Date(report.generated_at).toLocaleString()} ·{' '}
            {scope.open_findings} open · {scope.remediated_findings} remediated ·{' '}
            {scope.asset_count} asset{scope.asset_count !== 1 ? 's' : ''}
          </p>
        </section>

        <section className="space-y-4">
          {controls.length === 0 ? (
            <EmptyState icon={null} title="No SOC 2 controls evaluated" description="Run a GitHub posture scan to populate control evidence." />
          ) : (
            controls.map((ctrl) => <ControlCard key={ctrl.control_id} control={ctrl} />)
          )}
        </section>

        <section className="mt-12 mb-8 rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/30 p-5 text-sm text-[var(--text-muted)]">
          <p className="font-semibold text-[var(--text)]">About this report</p>
          <p className="mt-2 leading-relaxed">
            Generated from live GitHub posture findings via the read-only GitHub connector.
          </p>
          <p className="mt-2 leading-relaxed">
            <span className="font-medium text-[var(--text)]">Use cases:</span>{' '}
            Audit readiness, customer security reviews, SOC 2 evidence collection.
          </p>
        </section>
      </div>
    </main>
  );
}
