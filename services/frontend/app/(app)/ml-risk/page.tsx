'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  bootstrapRiskModelLabels,
  createFindingRiskLabel,
  createRiskModelSnapshot,
  getDependencyRiskSummary,
  getRiskModelEvaluation,
  getRiskModelSnapshot,
  getRiskModelStatus,
  listRiskModelSnapshots,
  setRiskModelThreshold,
  trainRiskModel,
  type DependencyRiskSummary,
  type RiskModelEvaluation,
  type RiskModelSnapshotSummary,
  type RiskModelStatus,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

function driftSeverityClass(level: string): string {
  switch (level) {
    case 'high':
      return 'bg-[var(--red)]/15 text-[var(--red)]';
    case 'medium':
      return 'bg-[var(--amber)]/20 text-[var(--amber)]';
    default:
      return 'bg-[var(--green)]/15 text-[var(--green)]';
  }
}

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

function labelBadgeClass(label: 'incident_worthy' | 'benign'): string {
  return label === 'incident_worthy'
    ? 'bg-[var(--red)]/15 text-[var(--red)]'
    : 'bg-[var(--green)]/15 text-[var(--green)]';
}

function eventTypeClass(eventType: 'train' | 'manual'): string {
  return eventType === 'train'
    ? 'bg-[var(--green)]/15 text-[var(--green)]'
    : 'bg-[var(--amber)]/20 text-[var(--amber)]';
}

function formatPct(value?: number | null): string {
  if (value == null || Number.isNaN(Number(value))) return '-';
  return `${(Number(value) * 100).toFixed(1)}%`;
}

function formatThreshold(value?: number | null): string {
  if (value == null || Number.isNaN(Number(value))) return '-';
  return Number(value).toFixed(2);
}

function MetricCard({
  label,
  value,
  subtext,
}: {
  label: string;
  value: string | number;
  subtext?: string;
}) {
  return (
    <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
      <p className="text-[11px] uppercase tracking-[0.12em] text-[var(--muted)]">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-[var(--text)]">{value}</p>
      {subtext && <p className="mt-1 text-xs text-[var(--muted)]">{subtext}</p>}
    </div>
  );
}

function Sparkline({
  values,
  stroke,
}: {
  values: Array<number | null | undefined>;
  stroke: string;
}) {
  const cleaned = values
    .map((value) => (value == null || Number.isNaN(Number(value)) ? null : Number(value)))
    .filter((value): value is number => value != null);
  if (cleaned.length < 2) {
    return <div className="h-14 rounded-lg border border-dashed border-[var(--border)]" />;
  }
  const width = 220;
  const height = 56;
  const min = Math.min(...cleaned);
  const max = Math.max(...cleaned);
  const range = max - min || 1;
  const points = cleaned
    .map((value, index) => {
      const x = (index / Math.max(cleaned.length - 1, 1)) * width;
      const y = height - ((value - min) / range) * height;
      return `${x},${y}`;
    })
    .join(' ');
  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="h-14 w-full overflow-visible">
      <polyline
        fill="none"
        stroke={stroke}
        strokeWidth="3"
        strokeLinejoin="round"
        strokeLinecap="round"
        points={points}
      />
    </svg>
  );
}

export default function MlRiskPage() {
  const { canMutate, isAdmin } = useAuth();
  const [status, setStatus] = useState<RiskModelStatus | null>(null);
  const [evaluation, setEvaluation] = useState<RiskModelEvaluation | null>(null);
  const [snapshots, setSnapshots] = useState<RiskModelSnapshotSummary[]>([]);
  const [dependencyRisk, setDependencyRisk] = useState<DependencyRiskSummary | null>(null);
  const [dependencyRiskError, setDependencyRiskError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [busy, setBusy] = useState<
    'bootstrap' | 'train' | 'snapshot' | 'preview-threshold' | 'save-threshold' | null
  >(null);
  const [labelingKey, setLabelingKey] = useState<string | null>(null);
  const [thresholdDraft, setThresholdDraft] = useState<string>('0.50');

  const load = useCallback((thresholdOverride?: number) => {
    setLoading(true);
    Promise.allSettled([
      getRiskModelStatus(),
      getRiskModelEvaluation({ review_limit: 12, threshold: thresholdOverride }),
      listRiskModelSnapshots({ limit: 12 }),
      getDependencyRiskSummary('secplat-repo', 20),
    ])
      .then(([statusOut, evaluationOut, snapshotsOut, dependencyOut]) => {
        const primaryError =
          statusOut.status === 'rejected'
            ? statusOut.reason
            : evaluationOut.status === 'rejected'
              ? evaluationOut.reason
              : snapshotsOut.status === 'rejected'
                ? snapshotsOut.reason
                : null;
        if (primaryError) {
          setError(primaryError instanceof Error ? primaryError.message : 'Failed to load model evaluation');
        } else {
          if (statusOut.status === 'fulfilled') {
            setStatus(statusOut.value);
          }
          if (evaluationOut.status === 'fulfilled') {
            setEvaluation(evaluationOut.value);
            setThresholdDraft(formatThreshold(evaluationOut.value.threshold));
          }
          if (snapshotsOut.status === 'fulfilled') {
            setSnapshots(snapshotsOut.value.items);
          }
          setError(null);
        }

        if (dependencyOut.status === 'fulfilled') {
          setDependencyRisk(dependencyOut.value);
          setDependencyRiskError(null);
        } else {
          setDependencyRisk(null);
          setDependencyRiskError(
            dependencyOut.reason instanceof Error
              ? dependencyOut.reason.message
              : 'Failed to load dependency risk'
          );
        }
      })
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  const thresholdNumber = Number(thresholdDraft || 0.5);
  const activeThreshold = evaluation?.threshold ?? status?.model_metadata?.active_threshold ?? 0.5;
  const recommendedThreshold =
    evaluation?.recommended_threshold ?? status?.model_metadata?.recommended_threshold ?? null;

  const historySeries = useMemo(
    () => ({
      auc: [...snapshots].reverse().map((item) => item.auc),
      f1: [...snapshots].reverse().map((item) => item.f1),
      drift: [...snapshots].reverse().map((item) => item.drift_psi),
    }),
    [snapshots]
  );

  const handleBootstrap = async () => {
    setError(null);
    setMessage(null);
    setBusy('bootstrap');
    try {
      const out = await bootstrapRiskModelLabels();
      setMessage(
        `Bootstrapped ${out.inserted_total} labels (${out.inserted_positive} positive, ${out.inserted_negative} negative).`
      );
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Bootstrap failed');
    } finally {
      setBusy(null);
    }
  };

  const handleTrain = async () => {
    setError(null);
    setMessage(null);
    setBusy('train');
    try {
      const out = await trainRiskModel();
      setMessage(
        `Trained ${out.metadata.algorithm || 'baseline'} model on ${out.training_rows} rows, rescored ${out.rescored_findings ?? 0} findings, and saved snapshot ${out.snapshot_id ?? '-'}.`
      );
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Training failed');
    } finally {
      setBusy(null);
    }
  };

  const handlePreviewThreshold = async () => {
    setError(null);
    setMessage(null);
    setBusy('preview-threshold');
    try {
      await load(Number.isFinite(thresholdNumber) ? thresholdNumber : activeThreshold);
      setMessage(`Previewed threshold ${formatThreshold(thresholdNumber)}.`);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Threshold preview failed');
    } finally {
      setBusy(null);
    }
  };

  const handleSaveThreshold = async (threshold: number, source = 'manual') => {
    setError(null);
    setMessage(null);
    setBusy('save-threshold');
    try {
      const out = await setRiskModelThreshold({ threshold, source });
      setMessage(
        `Saved active threshold ${formatThreshold(out.active_threshold)} and rescored ${out.rescored_findings ?? 0} findings.`
      );
      await load(out.active_threshold);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Threshold save failed');
    } finally {
      setBusy(null);
    }
  };

  const handleSnapshot = async () => {
    setError(null);
    setMessage(null);
    setBusy('snapshot');
    try {
      const out = await createRiskModelSnapshot({
        threshold: Number.isFinite(thresholdNumber) ? thresholdNumber : activeThreshold,
      });
      setMessage(`Saved evaluation snapshot ${out.snapshot_id} at threshold ${formatThreshold(out.threshold)}.`);
      await load(out.threshold);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Snapshot creation failed');
    } finally {
      setBusy(null);
    }
  };

  const handleDownloadSnapshot = async (snapshotId: number) => {
    setError(null);
    try {
      const snapshot = await getRiskModelSnapshot(snapshotId);
      const blob = new Blob([JSON.stringify(snapshot.summary_json, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement('a');
      anchor.href = url;
      anchor.download = `risk-model-snapshot-${snapshotId}.json`;
      anchor.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Snapshot download failed');
    }
  };

  const handleLabel = async (
    findingId: number,
    label: 'incident_worthy' | 'benign'
  ) => {
    const opKey = `${findingId}:${label}`;
    setError(null);
    setMessage(null);
    setLabelingKey(opKey);
    try {
      await createFindingRiskLabel(findingId, { label, source: 'analyst' });
      setMessage(`Saved analyst label: ${label.replace(/_/g, ' ')}.`);
      await load(activeThreshold);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Label save failed');
    } finally {
      setLabelingKey(null);
    }
  };

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <h1 className="hero-title">ML Risk Operations Lab</h1>
            <p className="hero-copy">
              Train, calibrate, and continuously validate the live classifier with drift tracking,
              threshold controls, and analyst feedback loops.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Link href="/findings" className="btn-secondary text-sm">
                Back to findings
              </Link>
              {canMutate && (
                <button
                  type="button"
                  onClick={handleBootstrap}
                  disabled={busy !== null}
                  className="btn-secondary text-sm"
                >
                  {busy === 'bootstrap' ? 'Bootstrapping...' : 'Bootstrap labels'}
                </button>
              )}
              {canMutate && (
                <button
                  type="button"
                  onClick={handleSnapshot}
                  disabled={busy !== null}
                  className="btn-secondary text-sm"
                >
                  {busy === 'snapshot' ? 'Saving snapshot...' : 'Save snapshot'}
                </button>
              )}
              {isAdmin && (
                <button
                  type="button"
                  onClick={handleTrain}
                  disabled={busy !== null}
                  className="btn-primary text-sm"
                >
                  {busy === 'train' ? 'Training...' : 'Train model'}
                </button>
              )}
            </div>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Scoring mode</p>
              <p className="hero-stat-value">
                {status?.current_scoring_mode === 'ml' ? 'ML' : 'Heuristic'}
              </p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Active threshold</p>
              <p className="hero-stat-value">{formatThreshold(activeThreshold)}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Precision</p>
              <p className="hero-stat-value">
                {formatPct(evaluation?.labeled_evaluation.precision)}
              </p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Drift PSI</p>
              <p className="hero-stat-value">
                {evaluation?.drift.score_distribution_psi != null
                  ? Number(evaluation.drift.score_distribution_psi).toFixed(3)
                  : '-'}
              </p>
            </div>
          </div>
        </div>
      </section>

      {error && (
        <div className="alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {message && (
        <div className="rounded-xl border border-[var(--green)]/30 bg-[var(--green)]/10 px-4 py-3 text-sm text-[var(--text)]">
          {message}
        </div>
      )}

      {loading && !status && !evaluation ? (
        <div className="card">
          <p className="text-sm text-[var(--muted)]">Loading model operations view...</p>
        </div>
      ) : (
        <>
          {status && (
            <section className="section-panel animate-in">
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div>
                  <h2 className="section-title mb-2">Live model status</h2>
                  <div className="flex flex-wrap gap-2">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${
                        status.current_scoring_mode === 'ml'
                          ? 'bg-[var(--green)] text-white'
                          : 'bg-[var(--muted)]/20 text-[var(--muted)]'
                      }`}
                    >
                      {status.current_scoring_mode === 'ml' ? 'ML active' : 'Heuristic active'}
                    </span>
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${
                        status.readiness.status === 'ready'
                          ? 'bg-[var(--green)]/15 text-[var(--green)]'
                          : 'bg-[var(--amber)]/20 text-[var(--amber)]'
                      }`}
                    >
                      {status.readiness.status === 'ready' ? 'Ready to scale' : 'More labels needed'}
                    </span>
                    <span className="inline-block rounded bg-[var(--surface-elevated)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
                      {status.model_metadata?.algorithm || 'no algorithm'}
                    </span>
                    <span className="inline-block rounded bg-[var(--surface-elevated)] px-2 py-0.5 text-xs font-semibold uppercase text-[var(--muted)]">
                      threshold {formatThreshold(status.model_metadata?.active_threshold)}
                    </span>
                  </div>
                  <p className="mt-3 text-xs text-[var(--muted)]">Signature: {status.scoring_signature}</p>
                  {status.model_metadata?.trained_at && (
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      Trained {formatDateTime(status.model_metadata.trained_at)}
                    </p>
                  )}
                  {status.latest_snapshot?.created_at && (
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      Latest snapshot {formatDateTime(status.latest_snapshot.created_at)}
                    </p>
                  )}
                </div>
                <div className="grid min-w-[18rem] gap-3 sm:grid-cols-2">
                  <MetricCard
                    label="Total labels"
                    value={status.readiness.summary.total_labels}
                    subtext={`${status.readiness.summary.positive_labels} positive / ${status.readiness.summary.negative_labels} negative`}
                  />
                  <MetricCard
                    label="Calibration"
                    value={status.model_metadata?.calibration_method || 'none'}
                    subtext={`Brier ${formatPct(status.model_metadata?.brier_score)}`}
                  />
                </div>
              </div>
            </section>
          )}
          {status && evaluation && (
            <>
              <section className="grid gap-4 md:grid-cols-2 xl:grid-cols-6">
                <MetricCard
                  label="Labeled rows"
                  value={evaluation.labeled_evaluation.rows}
                  subtext="Current labeled evaluation set"
                />
                <MetricCard
                  label="Active threshold"
                  value={formatThreshold(evaluation.threshold)}
                  subtext={`Recommended ${formatThreshold(evaluation.recommended_threshold)}`}
                />
                <MetricCard
                  label="Precision"
                  value={formatPct(evaluation.labeled_evaluation.precision)}
                  subtext="Positive prediction precision"
                />
                <MetricCard
                  label="Recall"
                  value={formatPct(evaluation.labeled_evaluation.recall)}
                  subtext="Positive class recall"
                />
                <MetricCard
                  label="F1"
                  value={formatPct(evaluation.labeled_evaluation.f1)}
                  subtext={`Threshold source ${evaluation.threshold_source || 'recommended'}`}
                />
                <MetricCard
                  label="Brier"
                  value={formatPct(evaluation.calibration.brier_score)}
                  subtext="Probability calibration error"
                />
              </section>

              {(dependencyRisk || dependencyRiskError) && (
                <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                  <div className="section-panel-tight">
                    <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <h2 className="section-title">Dependency risk</h2>
                        <p className="mt-1 text-sm text-[var(--muted)]">
                          Live OSV/Trivy package exposure for ML feature context and remediation priority.
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Link href="/findings" className="btn-secondary text-xs">
                          Open findings
                        </Link>
                        <Link href="/jobs" className="btn-secondary text-xs">
                          Run scan
                        </Link>
                      </div>
                    </div>
                    {dependencyRiskError && (
                      <div className="rounded-xl border border-[var(--red)]/30 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--text)]">
                        {dependencyRiskError}
                      </div>
                    )}
                    {dependencyRisk && (
                      <>
                        <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
                          <MetricCard
                            label="Active findings"
                            value={dependencyRisk.active_findings}
                            subtext={`${dependencyRisk.total_findings} total`}
                          />
                          <MetricCard
                            label="Active packages"
                            value={dependencyRisk.active_dependency_count}
                            subtext="Distinct vulnerable dependencies"
                          />
                          <MetricCard
                            label="Accepted risk"
                            value={dependencyRisk.accepted_risk_findings}
                            subtext="Requires periodic review"
                          />
                          <MetricCard
                            label="Remediated"
                            value={dependencyRisk.remediated_findings}
                            subtext="Closed from latest scans"
                          />
                        </div>
                        <div className="grid gap-4 lg:grid-cols-2">
                          <div className="rounded-xl border border-[var(--border)] p-4">
                            <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">Source distribution</h3>
                            <ul className="space-y-2">
                              {dependencyRisk.source_distribution.map((source) => (
                                <li key={source.source} className="flex items-center justify-between text-sm">
                                  <span className="text-[var(--text)]">{source.source}</span>
                                  <span className="text-[var(--muted)]">
                                    active {source.active} / total {source.total}
                                  </span>
                                </li>
                              ))}
                            </ul>
                          </div>
                          <div className="rounded-xl border border-[var(--border)] p-4">
                            <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">Top vulnerable packages</h3>
                            {dependencyRisk.dependency_distribution.length === 0 ? (
                              <p className="text-sm text-[var(--muted)]">No package vulnerabilities found.</p>
                            ) : (
                              <ul className="space-y-2">
                                {dependencyRisk.dependency_distribution.slice(0, 8).map((pkg) => (
                                  <li key={`${pkg.package_ecosystem}:${pkg.package_name}`} className="rounded-lg border border-[var(--border)] px-3 py-2">
                                    <div className="flex items-center justify-between gap-2 text-sm">
                                      <span className="font-medium text-[var(--text)]">
                                        {pkg.package_name}
                                      </span>
                                      <span className="text-[var(--muted)]">
                                        {pkg.active_count} active
                                      </span>
                                    </div>
                                    <p className="mt-1 text-xs text-[var(--muted)]">
                                      {pkg.package_ecosystem} | max risk {pkg.max_risk_score} | {pkg.max_severity}
                                    </p>
                                  </li>
                                ))}
                              </ul>
                            )}
                          </div>
                        </div>
                      </>
                    )}
                  </div>

                  <div className="section-panel-tight">
                    <h2 className="section-title mb-4">Remediation queue</h2>
                    {!dependencyRisk || dependencyRisk.remediation_queue.length === 0 ? (
                      <p className="text-sm text-[var(--muted)]">No active dependency remediation items.</p>
                    ) : (
                      <ul className="space-y-3">
                        {dependencyRisk.remediation_queue.map((item) => (
                          <li key={item.finding_id} className="rounded-xl border border-[var(--border)] p-3">
                            <div className="flex items-start justify-between gap-3">
                              <div className="min-w-0 flex-1">
                                <p className="font-medium text-[var(--text)]">{item.title}</p>
                                <p className="mt-1 text-xs text-[var(--muted)]">
                                  {item.package_name || 'package'}{item.package_version ? `@${item.package_version}` : ''}
                                  {item.fixed_version ? ` -> ${item.fixed_version}` : ''}
                                </p>
                                <p className="mt-1 text-xs text-[var(--muted)]">
                                  {item.source || 'scanner'}
                                  {item.vulnerability_id ? ` | ${item.vulnerability_id}` : ''}
                                  {item.last_seen ? ` | ${formatDateTime(item.last_seen)}` : ''}
                                </p>
                              </div>
                              <div className="text-right">
                                <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(item.risk_level || item.severity)}`}>
                                  {item.risk_level || item.severity} {item.risk_score ?? '-'}
                                </span>
                                <p className="mt-1 text-[11px] capitalize text-[var(--muted)]">
                                  {item.status.replace('_', ' ')}
                                </p>
                              </div>
                            </div>
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </section>
              )}

              <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
                <div className="section-panel-tight">
                  <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className="section-title">Threshold tuning</h2>
                      <p className="mt-1 text-sm text-[var(--muted)]">
                        Preview operating-threshold changes before promoting them into live scoring metadata.
                      </p>
                    </div>
                    <span className="text-xs text-[var(--muted)]">
                      Active {formatThreshold(activeThreshold)} / recommended {formatThreshold(recommendedThreshold)}
                    </span>
                  </div>
                  <div className="mb-4 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
                    <div className="flex flex-wrap items-center gap-3">
                      <input
                        type="range"
                        min="0.05"
                        max="0.95"
                        step="0.01"
                        value={thresholdDraft}
                        onChange={(e) => setThresholdDraft(e.target.value)}
                        className="min-w-[16rem] flex-1"
                      />
                      <input
                        type="number"
                        min="0.05"
                        max="0.95"
                        step="0.01"
                        value={thresholdDraft}
                        onChange={(e) => setThresholdDraft(e.target.value)}
                        className="w-24 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text)]"
                      />
                      <button
                        type="button"
                        onClick={handlePreviewThreshold}
                        disabled={busy !== null}
                        className="btn-secondary text-sm"
                      >
                        {busy === 'preview-threshold' ? 'Previewing...' : 'Preview'}
                      </button>
                      {isAdmin && (
                        <button
                          type="button"
                          onClick={() => handleSaveThreshold(thresholdNumber)}
                          disabled={busy !== null || !Number.isFinite(thresholdNumber)}
                          className="btn-primary text-sm"
                        >
                          {busy === 'save-threshold' ? 'Saving...' : 'Save threshold'}
                        </button>
                      )}
                      {isAdmin && recommendedThreshold != null && (
                        <button
                          type="button"
                          onClick={() => handleSaveThreshold(recommendedThreshold, 'recommended')}
                          disabled={busy !== null}
                          className="btn-secondary text-sm"
                        >
                          Use recommended
                        </button>
                      )}
                    </div>
                  </div>
                  <details className="disclosure mt-4">
                    <summary className="cursor-pointer list-none text-sm font-medium text-[var(--text)]">
                      Threshold sweep details
                    </summary>
                    <div className="disclosure-body mt-4 max-h-[28rem] space-y-2 overflow-auto pr-1">
                      {evaluation.threshold_sweep.map((item) => {
                        const isActive = Math.abs(item.threshold - evaluation.threshold) < 0.0001;
                        const isRecommended =
                          evaluation.recommended_threshold != null &&
                          Math.abs(item.threshold - evaluation.recommended_threshold) < 0.0001;
                        return (
                          <div
                            key={item.threshold}
                            className={`rounded-xl border p-3 ${
                              isActive
                                ? 'border-[var(--green)]/60 bg-[var(--green)]/10'
                                : 'border-[var(--border)]'
                            }`}
                          >
                            <div className="flex flex-wrap items-center justify-between gap-3">
                              <div className="flex flex-wrap items-center gap-2">
                                <span className="text-sm font-semibold text-[var(--text)]">
                                  {formatThreshold(item.threshold)}
                                </span>
                                {isActive && (
                                  <span className="rounded bg-[var(--green)] px-2 py-0.5 text-[10px] font-semibold uppercase text-white">
                                    active
                                  </span>
                                )}
                                {isRecommended && (
                                  <span className="rounded bg-[var(--amber)] px-2 py-0.5 text-[10px] font-semibold uppercase text-black">
                                    recommended
                                  </span>
                                )}
                              </div>
                              <div className="flex flex-wrap gap-4 text-xs text-[var(--muted)]">
                                <span>precision {formatPct(item.precision)}</span>
                                <span>recall {formatPct(item.recall)}</span>
                                <span>f1 {formatPct(item.f1)}</span>
                                <span>predicted + {item.positive_predictions}</span>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </details>
                </div>

                <details className="section-panel-tight disclosure">
                  <summary className="cursor-pointer list-none">
                    <h2 className="section-title mb-0">Calibration quality</h2>
                  </summary>
                  <div className="disclosure-body mt-4">
                    <div className="mb-4 grid gap-3 sm:grid-cols-2">
                      <MetricCard
                        label="Method"
                        value={evaluation.calibration.method || 'none'}
                        subtext="Probability calibration"
                      />
                      <MetricCard
                        label="Brier score"
                        value={formatPct(evaluation.calibration.brier_score)}
                        subtext="Lower is better"
                      />
                    </div>
                    <div className="space-y-3">
                      {evaluation.calibration.bins.map((bin) => (
                        <div key={bin.bucket} className="rounded-xl border border-[var(--border)] p-3">
                          <div className="mb-2 flex items-center justify-between text-xs text-[var(--muted)]">
                            <span>{bin.bucket}</span>
                            <span>{bin.count} rows</span>
                          </div>
                          <div className="space-y-2">
                            <div>
                              <div className="mb-1 flex items-center justify-between text-[11px] text-[var(--muted)]">
                                <span>Predicted</span>
                                <span>{formatPct(bin.average_predicted_probability)}</span>
                              </div>
                              <div className="h-2 rounded-full bg-[var(--surface)]">
                                <div
                                  className="h-2 rounded-full bg-[var(--green)]"
                                  style={{
                                    width: `${Math.max(
                                      2,
                                      (bin.average_predicted_probability ?? 0) * 100
                                    )}%`,
                                  }}
                                />
                              </div>
                            </div>
                            <div>
                              <div className="mb-1 flex items-center justify-between text-[11px] text-[var(--muted)]">
                                <span>Observed</span>
                                <span>{formatPct(bin.observed_positive_rate)}</span>
                              </div>
                              <div className="h-2 rounded-full bg-[var(--surface)]">
                                <div
                                  className="h-2 rounded-full bg-blue-500"
                                  style={{
                                    width: `${Math.max(2, (bin.observed_positive_rate ?? 0) * 100)}%`,
                                  }}
                                />
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </details>
              </section>
              <details className="section-panel disclosure">
                <summary className="cursor-pointer list-none">
                  <h2 className="section-title mb-0">Performance breakdown</h2>
                </summary>
                <div className="disclosure-body mt-4 grid gap-6 xl:grid-cols-[1.1fr_1fr_1fr]">
                  <div className="section-panel-tight">
                  <h2 className="section-title mb-4">Confusion matrix</h2>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--green)]/10 p-4">
                      <p className="text-xs uppercase text-[var(--muted)]">True positive</p>
                      <p className="mt-2 text-3xl font-semibold">
                        {evaluation.labeled_evaluation.confusion_matrix.tp}
                      </p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--red)]/10 p-4">
                      <p className="text-xs uppercase text-[var(--muted)]">False positive</p>
                      <p className="mt-2 text-3xl font-semibold">
                        {evaluation.labeled_evaluation.confusion_matrix.fp}
                      </p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--green)]/10 p-4">
                      <p className="text-xs uppercase text-[var(--muted)]">True negative</p>
                      <p className="mt-2 text-3xl font-semibold">
                        {evaluation.labeled_evaluation.confusion_matrix.tn}
                      </p>
                    </div>
                    <div className="rounded-xl border border-[var(--border)] bg-[var(--amber)]/15 p-4">
                      <p className="text-xs uppercase text-[var(--muted)]">False negative</p>
                      <p className="mt-2 text-3xl font-semibold">
                        {evaluation.labeled_evaluation.confusion_matrix.fn}
                      </p>
                    </div>
                  </div>
                  </div>

                  <div className="section-panel-tight">
                  <h2 className="section-title mb-4">Label sources</h2>
                  <ul className="space-y-2">
                    {Object.entries(evaluation.labeled_evaluation.label_source_counts).map(
                      ([key, value]) => (
                        <li
                          key={key}
                          className="flex items-center justify-between rounded-lg border border-[var(--border)] px-3 py-2 text-sm"
                        >
                          <span className="capitalize text-[var(--text)]">
                            {key.replace(/_/g, ' ')}
                          </span>
                          <span className="font-semibold text-[var(--muted)]">{value}</span>
                        </li>
                      )
                    )}
                  </ul>
                  <h3 className="mt-4 mb-2 text-sm font-medium text-[var(--muted)]">Label balance</h3>
                  <ul className="space-y-2">
                    {Object.entries(evaluation.labeled_evaluation.label_counts).map(([key, value]) => (
                      <li
                        key={key}
                        className="flex items-center justify-between rounded-lg border border-[var(--border)] px-3 py-2 text-sm"
                      >
                        <span
                          className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${labelBadgeClass(
                            key as 'incident_worthy' | 'benign'
                          )}`}
                        >
                          {key.replace(/_/g, ' ')}
                        </span>
                        <span className="font-semibold text-[var(--muted)]">{value}</span>
                      </li>
                    ))}
                  </ul>
                  </div>

                  <div className="section-panel-tight">
                  <h2 className="section-title mb-4">Score distribution</h2>
                  <div className="space-y-3">
                    {Object.entries(evaluation.current_population.prediction_buckets).map(
                      ([bucket, currentCount]) => (
                        <div key={bucket} className="rounded-lg border border-[var(--border)] p-3">
                          <div className="flex items-center justify-between text-sm">
                            <span className="font-medium text-[var(--text)]">{bucket}</span>
                            <span className="text-[var(--muted)]">
                              train {evaluation.training_baseline.prediction_buckets[bucket] ?? 0} / current{' '}
                              {currentCount}
                            </span>
                          </div>
                        </div>
                      )
                    )}
                  </div>
                  <p className="mt-3 text-xs text-[var(--muted)]">
                    Avg current probability: {formatPct(evaluation.current_population.average_probability)}
                  </p>
                  </div>
                </div>
              </details>

              <details className="section-panel disclosure">
                <summary className="cursor-pointer list-none">
                  <h2 className="section-title mb-0">Drift and population shifts</h2>
                </summary>
                <div className="disclosure-body mt-4 grid gap-6 xl:grid-cols-[1.05fr_0.95fr]">
                  <div className="section-panel-tight">
                  <h2 className="section-title mb-4">Drift signals</h2>
                  <div className="mb-4 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
                    <p className="text-[11px] uppercase tracking-[0.12em] text-[var(--muted)]">
                      Score distribution PSI
                    </p>
                    <p className="mt-2 text-3xl font-semibold">
                      {evaluation.drift.score_distribution_psi != null
                        ? Number(evaluation.drift.score_distribution_psi).toFixed(3)
                        : '-'}
                    </p>
                  </div>
                  <ul className="space-y-3">
                    {evaluation.drift.signals.map((signal) => (
                      <li key={signal.metric} className="rounded-xl border border-[var(--border)] p-3">
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <p className="font-medium text-[var(--text)]">{signal.detail}</p>
                          <span
                            className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${driftSeverityClass(
                              signal.severity
                            )}`}
                          >
                            {signal.severity}
                          </span>
                        </div>
                        <p className="mt-1 text-xs text-[var(--muted)]">
                          {signal.metric}: {Number(signal.value).toFixed(4)}
                        </p>
                      </li>
                    ))}
                  </ul>
                  </div>

                  <div className="section-panel-tight">
                  <h2 className="section-title mb-4">Largest population shifts</h2>
                  <div className="space-y-3">
                    {Object.entries(evaluation.drift.feature_shifts).map(([feature, payload]) => (
                      <div key={feature} className="rounded-xl border border-[var(--border)] p-3">
                        <div className="flex items-center justify-between gap-3">
                          <p className="font-medium capitalize text-[var(--text)]">{feature}</p>
                          <span className="text-xs text-[var(--muted)]">
                            {payload ? `${(payload.delta * 100).toFixed(1)} pts` : '-'}
                          </span>
                        </div>
                        {payload ? (
                          <p className="mt-1 text-xs text-[var(--muted)]">
                            {payload.value}: train {formatPct(payload.training_share)} / current{' '}
                            {formatPct(payload.current_share)}
                          </p>
                        ) : (
                          <p className="mt-1 text-xs text-[var(--muted)]">No baseline available.</p>
                        )}
                      </div>
                    ))}
                  </div>
                  </div>
                </div>
              </details>

              <details className="section-panel animate-in disclosure">
                <summary className="cursor-pointer list-none">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h2 className="section-title mb-0">Evaluation history</h2>
                    </div>
                    <span className="text-xs text-[var(--muted)]">{snapshots.length} saved snapshots</span>
                  </div>
                </summary>
                <div className="disclosure-body mt-4">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="mt-1 text-sm text-[var(--muted)]">
                      Stored snapshots let you compare each retrain and export exact evaluation payloads.
                    </p>
                  </div>
                </div>
                <div className="mb-6 grid gap-4 md:grid-cols-3">
                  <div className="rounded-xl border border-[var(--border)] p-4">
                    <p className="mb-3 text-xs uppercase tracking-[0.12em] text-[var(--muted)]">AUC trend</p>
                    <Sparkline values={historySeries.auc} stroke="var(--green)" />
                  </div>
                  <div className="rounded-xl border border-[var(--border)] p-4">
                    <p className="mb-3 text-xs uppercase tracking-[0.12em] text-[var(--muted)]">F1 trend</p>
                    <Sparkline values={historySeries.f1} stroke="#f59e0b" />
                  </div>
                  <div className="rounded-xl border border-[var(--border)] p-4">
                    <p className="mb-3 text-xs uppercase tracking-[0.12em] text-[var(--muted)]">PSI trend</p>
                    <Sparkline values={historySeries.drift} stroke="#ef4444" />
                  </div>
                </div>
                <div className="space-y-3">
                  {snapshots.length === 0 ? (
                    <p className="text-sm text-[var(--muted)]">No snapshots saved yet.</p>
                  ) : (
                    snapshots.map((snapshot) => (
                      <div key={snapshot.id} className="rounded-xl border border-[var(--border)] p-4">
                        <div className="flex flex-wrap items-start justify-between gap-4">
                          <div>
                            <div className="flex flex-wrap items-center gap-2">
                              <span
                                className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${eventTypeClass(
                                  snapshot.event_type
                                )}`}
                              >
                                {snapshot.event_type}
                              </span>
                              <span className="text-sm font-semibold text-[var(--text)]">
                                Snapshot {snapshot.id}
                              </span>
                            </div>
                            <p className="mt-1 text-xs text-[var(--muted)]">
                              {formatDateTime(snapshot.created_at)}
                              {snapshot.created_by ? ` by ${snapshot.created_by}` : ''}
                            </p>
                          </div>
                          <div className="flex flex-wrap gap-4 text-xs text-[var(--muted)]">
                            <span>threshold {formatThreshold(snapshot.threshold)}</span>
                            <span>f1 {formatPct(snapshot.f1)}</span>
                            <span>auc {snapshot.auc != null ? Number(snapshot.auc).toFixed(3) : '-'}</span>
                            <span>psi {snapshot.drift_psi != null ? Number(snapshot.drift_psi).toFixed(3) : '-'}</span>
                            <button
                              type="button"
                              onClick={() => handleDownloadSnapshot(snapshot.id)}
                              className="text-[var(--green)] hover:underline"
                            >
                              Download JSON
                            </button>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
                </div>
              </details>
              <section className="section-panel animate-in">
                <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <h2 className="section-title">Analyst review queue</h2>
                    <p className="mt-1 text-sm text-[var(--muted)]">
                      Prioritize unlabeled findings closest to the current decision boundary.
                    </p>
                  </div>
                  <span className="text-xs text-[var(--muted)]">
                    Threshold {Math.round(evaluation.threshold * 100)} / 100
                  </span>
                </div>
                {evaluation.review_queue.length === 0 ? (
                  <p className="text-sm text-[var(--muted)]">
                    No unlabeled findings need review right now.
                  </p>
                ) : (
                  <ul className="space-y-3">
                    {evaluation.review_queue.map((item) => (
                      <li key={item.finding_id} className="rounded-xl border border-[var(--border)] p-4">
                        <div className="flex flex-wrap items-start justify-between gap-4">
                          <div className="min-w-0 flex-1">
                            <p className="font-medium text-[var(--text)]">
                              {item.title || item.finding_key || `Finding ${item.finding_id}`}
                            </p>
                            <p className="mt-1 text-xs text-[var(--muted)]">
                              {item.asset_key ? (
                                <Link
                                  href={`/assets/${encodeURIComponent(item.asset_key)}`}
                                  className="hover:text-[var(--green)] hover:underline"
                                >
                                  {item.asset_key}
                                </Link>
                              ) : (
                                'Unlinked asset'
                              )}
                              {item.source ? ` / ${item.source}` : ''}
                              {item.severity ? ` / ${item.severity}` : ''}
                            </p>
                            <p className="mt-2 text-xs text-[var(--muted)]">
                              Predicted probability {formatPct(item.predicted_probability)} | review priority{' '}
                              {(item.uncertainty * 100).toFixed(1)}%
                              {item.distance_from_threshold != null
                                ? ` | distance ${(item.distance_from_threshold * 100).toFixed(1)} pts from boundary`
                                : ''}
                            </p>
                          </div>
                          <div className="text-right">
                            <span
                              className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(
                                item.current_risk_level
                              )}`}
                            >
                              {item.current_risk_level || 'risk'} {item.current_risk_score ?? item.predicted_score}
                            </span>
                            {canMutate && (
                              <div className="mt-3 flex flex-wrap justify-end gap-2">
                                <button
                                  type="button"
                                  onClick={() => handleLabel(item.finding_id, 'incident_worthy')}
                                  disabled={labelingKey === `${item.finding_id}:incident_worthy`}
                                  className="btn-secondary text-xs"
                                >
                                  {labelingKey === `${item.finding_id}:incident_worthy`
                                    ? 'Saving...'
                                    : 'Incident-worthy'}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleLabel(item.finding_id, 'benign')}
                                  disabled={labelingKey === `${item.finding_id}:benign`}
                                  className="btn-secondary text-xs"
                                >
                                  {labelingKey === `${item.finding_id}:benign` ? 'Saving...' : 'Benign'}
                                </button>
                              </div>
                            )}
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </section>
            </>
          )}
        </>
      )}
    </main>
  );
}
