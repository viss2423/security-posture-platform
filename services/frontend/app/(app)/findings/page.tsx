'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getFindings,
  updateFindingStatus,
  acceptFindingRisk,
  createFindingRiskLabel,
  getRiskModelStatus,
  bootstrapRiskModelLabels,
  trainRiskModel,
  generateFindingAIExplanation,
  type AIFindingExplanation,
  type Finding,
  type FindingStatus,
  type RiskModelStatus,
} from '@/lib/api';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-[var(--red)] text-white',
  high: 'bg-orange-600 text-white',
  medium: 'bg-yellow-500 text-black',
  low: 'bg-blue-500 text-white',
  info: 'bg-gray-500 text-white',
};

const STATUS_OPTIONS: FindingStatus[] = ['open', 'in_progress', 'remediated', 'accepted_risk'];
const RISK_FILTER_OPTIONS = [
  { value: '', label: 'All risk' },
  { value: 'critical', label: 'Critical' },
  { value: 'high', label: 'High' },
  { value: 'medium', label: 'Medium' },
  { value: 'low', label: 'Low' },
  { value: 'unscored', label: 'Pending' },
] as const;
type RiskLevelFilter = (typeof RISK_FILTER_OPTIONS)[number]['value'];

function statusBadgeClass(status: string): string {
  switch (status) {
    case 'open':
      return 'bg-[var(--red)]/20 text-[var(--red)]';
    case 'in_progress':
      return 'bg-[var(--amber)]/20 text-[var(--amber)]';
    case 'remediated':
      return 'bg-[var(--green)]/20 text-[var(--green)]';
    case 'accepted_risk':
      return 'bg-[var(--muted)]/30 text-[var(--muted)]';
    default:
      return 'bg-[var(--muted)]/20 text-[var(--muted)]';
  }
}

function isFallbackProvider(provider?: string | null): boolean {
  return (provider || '').toLowerCase().includes('fallback');
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

function riskLabelBadgeClass(label?: string | null): string {
  switch ((label || '').toLowerCase()) {
    case 'incident_worthy':
      return 'bg-[var(--red)]/15 text-[var(--red)]';
    case 'benign':
      return 'bg-[var(--green)]/15 text-[var(--green)]';
    default:
      return 'bg-[var(--muted)]/20 text-[var(--muted)]';
  }
}

function formatRiskLabel(label?: string | null): string {
  if (!label) return 'Unlabeled';
  return label.replace(/_/g, ' ');
}

function scoreSource(finding: Finding): string {
  const raw = finding.risk_factors_json;
  if (!raw || typeof raw !== 'object') return 'heuristic';
  const source = (raw as Record<string, unknown>).score_source;
  return typeof source === 'string' ? source : 'heuristic';
}

function riskDrivers(finding: Finding): string[] {
  const raw = finding.risk_factors_json;
  if (!raw || typeof raw !== 'object') return [];
  const drivers = (raw as Record<string, unknown>).drivers;
  if (!Array.isArray(drivers)) return [];
  return drivers.filter((x): x is string => typeof x === 'string').slice(0, 3);
}

function formatRiskDriverLabel(driver: string): string {
  return driver.replace(/_/g, ' ');
}

export default function FindingsPage() {
  const { canMutate, isAdmin } = useAuth();
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [modelStatus, setModelStatus] = useState<RiskModelStatus | null>(null);
  const [modelBusy, setModelBusy] = useState<'bootstrap' | 'train' | null>(null);
  const [modelMessage, setModelMessage] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [sourceFilter, setSourceFilter] = useState<string>('');
  const [riskLevelFilter, setRiskLevelFilter] = useState<RiskLevelFilter>('');
  const [updatingId, setUpdatingId] = useState<number | null>(null);
  const [labelingKey, setLabelingKey] = useState<string | null>(null);
  const [acceptRiskId, setAcceptRiskId] = useState<number | null>(null);
  const [acceptReason, setAcceptReason] = useState('');
  const [acceptExpires, setAcceptExpires] = useState('');
  const [aiByFindingId, setAiByFindingId] = useState<Record<number, AIFindingExplanation>>({});
  const [aiErrorByFindingId, setAiErrorByFindingId] = useState<Record<number, string>>({});
  const [explainingId, setExplainingId] = useState<number | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    getRiskModelStatus()
      .then((data) => setModelStatus(data))
      .catch(() => setModelStatus(null));
    getFindings({
      status: statusFilter || undefined,
      source: sourceFilter || undefined,
      risk_level: riskLevelFilter || undefined,
      limit: 200,
    })
      .then((data) => {
        const sorted = [...data].sort(
          (a, b) =>
            (Number(b.risk_score ?? -1) - Number(a.risk_score ?? -1)) ||
            ((SEVERITY_ORDER[a.severity] ?? 5) - (SEVERITY_ORDER[b.severity] ?? 5))
        );
        setFindings(sorted);
        setError(null);
      })
      .catch((e) => setError(e.message === 'Failed to fetch' ? 'API unreachable' : e.message))
      .finally(() => setLoading(false));
  }, [riskLevelFilter, statusFilter, sourceFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const defaultExpires = () => {
    const d = new Date();
    d.setMonth(d.getMonth() + 3);
    return d.toISOString().slice(0, 10);
  };

  const handleStatusChange = async (finding_id: number, status: FindingStatus) => {
    setError(null);
    setUpdatingId(finding_id);
    try {
      await updateFindingStatus(finding_id, status);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Update failed');
    } finally {
      setUpdatingId(null);
    }
  };

  const openAcceptRisk = (id: number) => {
    setAcceptRiskId(id);
    setAcceptReason('');
    setAcceptExpires(defaultExpires());
  };

  const handleAcceptRisk = async () => {
    if (acceptRiskId == null) return;
    setError(null);
    setUpdatingId(acceptRiskId);
    try {
      await acceptFindingRisk(acceptRiskId, acceptReason, new Date(acceptExpires).toISOString());
      setAcceptRiskId(null);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Accept risk failed');
    } finally {
      setUpdatingId(null);
    }
  };

  const handleExplainRisk = async (findingId: number, force: boolean = false) => {
    setError(null);
    setExplainingId(findingId);
    setAiErrorByFindingId((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
    try {
      const out = await generateFindingAIExplanation(findingId, force);
      setAiByFindingId((prev) => ({ ...prev, [findingId]: out }));
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'AI explanation failed';
      setAiErrorByFindingId((prev) => ({ ...prev, [findingId]: msg }));
    } finally {
      setExplainingId(null);
    }
  };

  const handleLabelFinding = async (
    findingId: number,
    label: 'incident_worthy' | 'benign'
  ) => {
    const opKey = `${findingId}:${label}`;
    setError(null);
    setModelMessage(null);
    setLabelingKey(opKey);
    try {
      await createFindingRiskLabel(findingId, { label, source: 'analyst' });
      setModelMessage(`Saved analyst label: ${formatRiskLabel(label)}.`);
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Saving label failed');
    } finally {
      setLabelingKey(null);
    }
  };

  const handleBootstrapLabels = async () => {
    setError(null);
    setModelMessage(null);
    setModelBusy('bootstrap');
    try {
      const out = await bootstrapRiskModelLabels();
      setModelMessage(
        `Bootstrapped ${out.inserted_total} labels (${out.inserted_positive} positive, ${out.inserted_negative} negative).`
      );
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Bootstrap failed');
    } finally {
      setModelBusy(null);
    }
  };

  const handleTrainModel = async () => {
    setError(null);
    setModelMessage(null);
    setModelBusy('train');
    try {
      const out = await trainRiskModel();
      setModelMessage(
        `Trained ${out.metadata.algorithm || 'baseline'} model on ${out.training_rows} labeled rows.`
      );
      load();
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Training failed');
    } finally {
      setModelBusy(null);
    }
  };

  const sources = Array.from(new Set(findings.map((f) => f.source).filter((s): s is string => !!s)));

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-8">Findings</h1>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {modelMessage && (
        <div className="mb-6 rounded-xl border border-[var(--green)]/30 bg-[var(--green)]/10 px-4 py-3 text-sm text-[var(--text)]">
          {modelMessage}
        </div>
      )}

      {modelStatus && (
        <section className="card mb-6 animate-in">
          <div className="flex flex-wrap items-start justify-between gap-4">
            <div>
              <h2 className="section-title mb-2">ML risk model</h2>
              <div className="flex flex-wrap gap-2">
                <span
                  className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${
                    modelStatus.current_scoring_mode === 'ml'
                      ? 'bg-[var(--green)] text-white'
                      : 'bg-[var(--muted)]/20 text-[var(--muted)]'
                  }`}
                >
                  {modelStatus.current_scoring_mode === 'ml' ? 'ML active' : 'Heuristic active'}
                </span>
                <span
                  className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${
                    modelStatus.artifact_exists
                      ? 'bg-[var(--green)]/15 text-[var(--green)]'
                      : 'bg-[var(--muted)]/20 text-[var(--muted)]'
                  }`}
                >
                  {modelStatus.artifact_exists ? 'Artifact ready' : 'No artifact'}
                </span>
                <span
                  className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${
                    modelStatus.readiness.status === 'ready'
                      ? 'bg-[var(--green)]/15 text-[var(--green)]'
                      : 'bg-[var(--amber)]/20 text-[var(--amber)]'
                  }`}
                >
                  {modelStatus.readiness.status === 'ready' ? 'Data ready' : 'Data limited'}
                </span>
              </div>
              <p className="mt-3 text-xs text-[var(--muted)]">
                Signature: {modelStatus.scoring_signature}
              </p>
            </div>
            {canMutate && (
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={handleBootstrapLabels}
                  disabled={modelBusy !== null}
                  className="btn-secondary text-sm"
                >
                  {modelBusy === 'bootstrap' ? 'Bootstrapping...' : 'Bootstrap labels'}
                </button>
                {isAdmin && (
                  <button
                    type="button"
                    onClick={handleTrainModel}
                    disabled={modelBusy !== null}
                    className="btn-primary text-sm"
                  >
                    {modelBusy === 'train' ? 'Training...' : 'Train baseline'}
                  </button>
                )}
                <Link href="/ml-risk" className="btn-secondary text-sm">
                  Open ML lab
                </Link>
              </div>
            )}
          </div>

          <div className="mt-4 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[11px] uppercase text-[var(--muted)]">Labels</p>
              <p className="mt-1 text-lg font-semibold">{modelStatus.readiness.summary.total_labels}</p>
            </div>
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[11px] uppercase text-[var(--muted)]">Positive</p>
              <p className="mt-1 text-lg font-semibold">{modelStatus.readiness.summary.positive_labels}</p>
            </div>
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[11px] uppercase text-[var(--muted)]">Negative</p>
              <p className="mt-1 text-lg font-semibold">{modelStatus.readiness.summary.negative_labels}</p>
            </div>
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[11px] uppercase text-[var(--muted)]">Linked incidents</p>
              <p className="mt-1 text-lg font-semibold">{modelStatus.readiness.summary.incident_linked_findings}</p>
            </div>
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[11px] uppercase text-[var(--muted)]">Algorithm</p>
              <p className="mt-1 text-sm font-semibold">{modelStatus.model_metadata?.algorithm || '-'}</p>
            </div>
            <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] p-3">
              <p className="text-[11px] uppercase text-[var(--muted)]">Test AUC</p>
              <p className="mt-1 text-sm font-semibold">
                {modelStatus.model_metadata?.test_auc != null
                  ? Number(modelStatus.model_metadata.test_auc).toFixed(3)
                  : '-'}
              </p>
            </div>
          </div>
          {modelStatus.model_metadata?.trained_at && (
            <p className="mt-3 text-xs text-[var(--muted)]">
              Trained {formatDateTime(modelStatus.model_metadata.trained_at)} on{' '}
              {modelStatus.model_metadata.dataset_size ?? '-'} rows.
            </p>
          )}
        </section>
      )}

      <div className="mb-6 flex flex-wrap items-center gap-4">
        <label className="flex items-center gap-2 text-sm text-[var(--muted)]">
          Status
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm"
          >
            <option value="">All</option>
            {STATUS_OPTIONS.map((s) => (
              <option key={s} value={s}>
                {s === 'accepted_risk' ? 'Accepted risk' : s.replace('_', ' ')}
              </option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-2 text-sm text-[var(--muted)]">
          Source
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm"
          >
            <option value="">All</option>
            <option value="tls_scan">TLS scan</option>
            <option value="header_scan">Header scan</option>
            {sources
              .filter((s) => s !== 'tls_scan' && s !== 'header_scan')
              .map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
          </select>
        </label>
      </div>

      <div className="mb-6 flex flex-wrap gap-2">
        {RISK_FILTER_OPTIONS.map((option) => {
          const selected = riskLevelFilter === option.value;
          const riskStyle =
            option.value && option.value !== 'unscored'
              ? riskBadgeClass(option.value)
              : 'bg-[var(--surface)] text-[var(--muted)]';
          return (
            <button
              key={option.value || 'all'}
              type="button"
              onClick={() => setRiskLevelFilter(option.value)}
              className={`rounded-full border px-3 py-1.5 text-xs font-semibold uppercase transition ${
                selected
                  ? `border-transparent ${riskStyle} shadow-sm`
                  : 'border-[var(--border)] bg-[var(--surface)] text-[var(--muted)] hover:bg-[var(--surface-elevated)]'
              }`}
            >
              {option.label}
            </button>
          );
        })}
      </div>

      {loading ? (
        <p className="text-sm text-[var(--muted)]">Loading...</p>
      ) : findings.length === 0 ? (
        <EmptyState
          title="No findings"
          description="Run the scanner to generate TLS and security header findings, or wait for the scheduled scan."
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-[var(--border)] bg-[var(--surface)]">
          <table className="w-full text-left text-sm">
            <thead className="border-b border-[var(--border)] text-xs uppercase text-[var(--muted)]">
              <tr>
                <th className="px-4 py-3">Severity</th>
                <th className="px-4 py-3">Risk</th>
                <th className="px-4 py-3">Title</th>
                <th className="px-4 py-3">Asset</th>
                <th className="px-4 py-3">Category</th>
                <th className="px-4 py-3">Status</th>
                {canMutate && <th className="px-4 py-3">Actions</th>}
                <th className="px-4 py-3">First seen</th>
                <th className="px-4 py-3">Last seen</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[var(--border)]">
              {findings.map((f) => (
                <tr key={f.finding_id} className="hover:bg-[var(--surface-elevated)]">
                  <td className="px-4 py-3">
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${SEVERITY_COLORS[f.severity] ?? 'bg-gray-600 text-white'}`}
                    >
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    {f.risk_score != null ? (
                      <div className="space-y-1">
                        <div className="flex flex-wrap items-center gap-1">
                          <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(f.risk_level)}`}>
                            {f.risk_level || 'risk'} {Math.round(Number(f.risk_score))}
                          </span>
                          <span className="inline-block rounded bg-[var(--surface-elevated)] px-2 py-0.5 text-[11px] font-medium uppercase text-[var(--muted)]">
                            {scoreSource(f)}
                          </span>
                        </div>
                        {riskDrivers(f).length > 0 && (
                          <p className="max-w-[12rem] text-[11px] text-[var(--muted)]">
                            {riskDrivers(f).map(formatRiskDriverLabel).join(' / ')}
                          </p>
                        )}
                      </div>
                    ) : (
                      <span className="text-xs text-[var(--muted)]">Pending</span>
                    )}
                  </td>
                  <td className="px-4 py-3 font-medium text-[var(--text)]">
                    {f.title}
                    {f.risk_label && (
                      <p className="mt-1 text-[11px]">
                        <span className={`inline-block rounded px-2 py-0.5 font-semibold uppercase ${riskLabelBadgeClass(f.risk_label)}`}>
                          {formatRiskLabel(f.risk_label)}
                        </span>
                        <span className="ml-2 text-[var(--muted)]">
                          {f.risk_label_source || 'label'}
                          {f.risk_label_created_at && ` / ${formatDateTime(f.risk_label_created_at)}`}
                        </span>
                      </p>
                    )}
                    {f.evidence && (
                      <p className="mt-1 text-xs text-[var(--muted)] line-clamp-1">{f.evidence}</p>
                    )}
                    {f.risk_score != null && (
                      <p className="mt-1 text-xs text-[var(--muted)]">
                        {scoreSource(f) === 'ml'
                          ? 'Score is coming from the trained ML model with heuristic fallback retained for explainability.'
                          : 'Context score uses severity, criticality, environment, exposure, confidence, and workflow state.'}
                      </p>
                    )}
                    {aiByFindingId[f.finding_id]?.explanation_text && (
                      <>
                        <p className="mt-2 whitespace-pre-wrap rounded-md border border-[var(--border)] bg-[var(--surface-elevated)] p-2 text-xs text-[var(--text)]">
                          {aiByFindingId[f.finding_id].explanation_text}
                        </p>
                        <p className="mt-1 text-[11px] text-[var(--muted)]">
                          AI generated {formatDateTime(aiByFindingId[f.finding_id].generated_at)} via{' '}
                          {aiByFindingId[f.finding_id].provider}/{aiByFindingId[f.finding_id].model}
                        </p>
                        {isFallbackProvider(aiByFindingId[f.finding_id].provider) && (
                          <p className="mt-1 text-[11px] text-[var(--amber)]">
                            Showing fallback guidance because the AI provider was temporarily slow or unavailable. Retry for a full model response.
                          </p>
                        )}
                      </>
                    )}
                    {aiErrorByFindingId[f.finding_id] && (
                      <p className="mt-2 text-xs text-[var(--red)]">
                        AI explain failed: {friendlyApiMessage(aiErrorByFindingId[f.finding_id])}
                      </p>
                    )}
                    {f.status === 'accepted_risk' && (f.accepted_risk_reason || f.accepted_risk_by || f.accepted_risk_expires_at) && (
                      <p className="mt-1 text-xs text-[var(--muted)]">
                        Accepted{f.accepted_risk_by && ` by ${f.accepted_risk_by}`}
                        {f.accepted_risk_expires_at && ` until ${formatDateTime(f.accepted_risk_expires_at)}`}
                        {f.accepted_risk_reason && `: ${f.accepted_risk_reason}`}
                      </p>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {f.asset_key ? (
                      <Link href={`/assets/${encodeURIComponent(f.asset_key)}`} className="text-[var(--green)] hover:underline">
                        {f.asset_name || f.asset_key}
                      </Link>
                    ) : (
                      <span className="text-[var(--muted)]">-</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[var(--muted)]">{f.category || '-'}</td>
                  <td className="px-4 py-3">
                    <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium capitalize ${statusBadgeClass(f.status)}`}>
                      {f.status.replace('_', ' ')}
                    </span>
                  </td>
                  {canMutate && (
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        <select
                          value={f.status}
                          onChange={(e) => handleStatusChange(f.finding_id, e.target.value as FindingStatus)}
                          disabled={updatingId === f.finding_id}
                          className="rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-xs"
                        >
                          {STATUS_OPTIONS.map((s) => (
                            <option key={s} value={s}>
                              {s.replace('_', ' ')}
                            </option>
                          ))}
                        </select>
                        {f.status !== 'accepted_risk' && (
                          <button
                            type="button"
                            onClick={() => openAcceptRisk(f.finding_id)}
                            disabled={updatingId === f.finding_id}
                            className="rounded border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--muted)] hover:bg-[var(--border)]"
                          >
                            Accept risk
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => handleExplainRisk(f.finding_id, Boolean(aiByFindingId[f.finding_id]))}
                          disabled={explainingId === f.finding_id}
                          className="rounded border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--muted)] hover:bg-[var(--border)]"
                        >
                          {explainingId === f.finding_id
                            ? 'Explaining...'
                            : aiByFindingId[f.finding_id]
                              ? 'Refresh AI'
                              : 'Explain risk'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleLabelFinding(f.finding_id, 'incident_worthy')}
                          disabled={
                            labelingKey === `${f.finding_id}:incident_worthy` ||
                            (f.risk_label === 'incident_worthy' && f.risk_label_source === 'analyst')
                          }
                          className="rounded border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--muted)] hover:bg-[var(--border)]"
                        >
                          {labelingKey === `${f.finding_id}:incident_worthy`
                            ? 'Saving...'
                            : 'Label incident-worthy'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleLabelFinding(f.finding_id, 'benign')}
                          disabled={
                            labelingKey === `${f.finding_id}:benign` ||
                            (f.risk_label === 'benign' && f.risk_label_source === 'analyst')
                          }
                          className="rounded border border-[var(--border)] bg-[var(--surface)] px-2 py-1 text-xs text-[var(--muted)] hover:bg-[var(--border)]"
                        >
                          {labelingKey === `${f.finding_id}:benign`
                            ? 'Saving...'
                            : 'Label benign'}
                        </button>
                      </div>
                    </td>
                  )}
                  <td className="px-4 py-3 text-[var(--muted)]">{f.first_seen ? formatDateTime(f.first_seen) : '-'}</td>
                  <td className="px-4 py-3 text-[var(--muted)]">{f.last_seen ? formatDateTime(f.last_seen) : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {findings.length > 0 && (
        <p className="mt-4 text-xs text-[var(--muted)]">
          Showing {findings.length} finding{findings.length === 1 ? '' : 's'}
          {canMutate && '. Change status or accept risk with expiry; re-review when risk acceptance expires.'}
        </p>
      )}

      {acceptRiskId != null && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4" role="dialog" aria-modal="true" aria-labelledby="accept-risk-title">
          <div className="card max-w-md w-full animate-in">
            <h2 id="accept-risk-title" className="section-title mb-3">Accept risk</h2>
            <p className="text-sm text-[var(--muted)] mb-3">Finding will be marked as accepted_risk. Set an expiry date for when it must be reviewed again.</p>
            <div className="space-y-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-[var(--muted)]">Reason</label>
                <textarea
                  value={acceptReason}
                  onChange={(e) => setAcceptReason(e.target.value)}
                  placeholder="e.g. Low impact, will fix in Q2"
                  rows={2}
                  className="input w-full text-sm"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-[var(--muted)]">Review by (date)</label>
                <input
                  type="date"
                  value={acceptExpires}
                  onChange={(e) => setAcceptExpires(e.target.value)}
                  className="input w-full"
                />
              </div>
            </div>
            <div className="mt-4 flex gap-2">
              <button type="button" onClick={handleAcceptRisk} className="btn-primary text-sm">
                Accept risk
              </button>
              <button type="button" onClick={() => setAcceptRiskId(null)} className="btn-secondary text-sm">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  );
}
