'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  createAIFeedback,
  createAISummaryVersion,
  getFindings,
  updateFindingStatus,
  acceptFindingRisk,
  createFindingRiskLabel,
  getRiskModelStatus,
  bootstrapRiskModelLabels,
  trainRiskModel,
  generateFindingAIExplanation,
  type AIFeedbackValue,
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

function packageChip(finding: Finding): string | null {
  if (!finding.package_name) return null;
  if (!finding.package_version) return finding.package_name;
  return `${finding.package_name}@${finding.package_version}`;
}

type GuardrailItem = { statement: string; evidence: string[] };
type GuardrailSectionKey = 'facts' | 'inference' | 'recommendations';

function parseGuardrailItems(raw: unknown): GuardrailItem[] {
  if (!Array.isArray(raw)) return [];
  const out: GuardrailItem[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const statement = String((entry as Record<string, unknown>).statement || '').trim();
    if (!statement) continue;
    const evidenceRaw = (entry as Record<string, unknown>).evidence;
    const evidence = Array.isArray(evidenceRaw)
      ? evidenceRaw
          .map((value) => String(value || '').trim().toUpperCase())
          .filter((value) => value.length > 0)
      : [];
    out.push({ statement, evidence });
  }
  return out;
}

function parseFindingGuardrails(ai?: AIFindingExplanation | null): {
  mode: string;
  usedFallbackSections: boolean;
  sections: Record<GuardrailSectionKey, GuardrailItem[]>;
  evidenceMap: Record<string, string>;
} | null {
  if (!ai?.context_json || typeof ai.context_json !== 'object') return null;
  const guardrails = (ai.context_json as Record<string, unknown>).guardrails;
  if (!guardrails || typeof guardrails !== 'object') return null;

  const guardrailObj = guardrails as Record<string, unknown>;
  const mode = String(guardrailObj.mode || '').trim();
  const usedFallbackSections = Boolean(guardrailObj.used_fallback_sections);
  const sectionsRaw = guardrailObj.sections;
  const sectionsObj =
    sectionsRaw && typeof sectionsRaw === 'object'
      ? (sectionsRaw as Record<string, unknown>)
      : {};

  const sections: Record<GuardrailSectionKey, GuardrailItem[]> = {
    facts: parseGuardrailItems(sectionsObj.facts),
    inference: parseGuardrailItems(sectionsObj.inference),
    recommendations: parseGuardrailItems(sectionsObj.recommendations),
  };

  if (
    sections.facts.length === 0 &&
    sections.inference.length === 0 &&
    sections.recommendations.length === 0
  ) {
    return null;
  }

  const evidenceMap: Record<string, string> = {};
  const catalog = guardrailObj.evidence_catalog;
  if (Array.isArray(catalog)) {
    for (const item of catalog) {
      if (!item || typeof item !== 'object') continue;
      const row = item as Record<string, unknown>;
      const id = String(row.id || '').trim().toUpperCase();
      if (!id) continue;
      const kind = String(row.kind || '').trim();
      const value = String(row.value ?? '').trim();
      const label = kind && value ? `${kind}: ${value}` : kind || value || id;
      evidenceMap[id] = label.slice(0, 140);
    }
  }

  return { mode, usedFallbackSections, sections, evidenceMap };
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
  const [aiVersionIdByFindingId, setAiVersionIdByFindingId] = useState<Record<number, number>>({});
  const [aiMessageByFindingId, setAiMessageByFindingId] = useState<Record<number, string>>({});
  const [aiErrorByFindingId, setAiErrorByFindingId] = useState<Record<number, string>>({});
  const [explainingId, setExplainingId] = useState<number | null>(null);
  const [savingVersionId, setSavingVersionId] = useState<number | null>(null);
  const [feedbackBusyKey, setFeedbackBusyKey] = useState<string | null>(null);

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
    setAiMessageByFindingId((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
    try {
      const out = await generateFindingAIExplanation(findingId, force);
      setAiByFindingId((prev) => ({ ...prev, [findingId]: out }));
      setAiVersionIdByFindingId((prev) => {
        const next = { ...prev };
        delete next[findingId];
        return next;
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'AI explanation failed';
      setAiErrorByFindingId((prev) => ({ ...prev, [findingId]: msg }));
    } finally {
      setExplainingId(null);
    }
  };

  const saveFindingAiVersion = async (findingId: number): Promise<number | null> => {
    const ai = aiByFindingId[findingId];
    if (!ai?.explanation_text) {
      setAiMessageByFindingId((prev) => ({
        ...prev,
        [findingId]: 'Generate an AI explanation before saving a version.',
      }));
      return null;
    }
    setSavingVersionId(findingId);
    setAiErrorByFindingId((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
    try {
      const created = await createAISummaryVersion('finding', findingId, {
        content_text: ai.explanation_text,
        provider: ai.provider,
        model: ai.model,
        source_type: 'generated',
        context_json: ai.context_json || {},
        evidence_json: {
          generated_at: ai.generated_at,
          remediation_patch: ai.remediation_patch || null,
        },
      });
      setAiVersionIdByFindingId((prev) => ({ ...prev, [findingId]: created.version_id }));
      setAiMessageByFindingId((prev) => ({
        ...prev,
        [findingId]: `Saved version v${created.version_no}.`,
      }));
      return created.version_id;
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save AI version';
      setAiErrorByFindingId((prev) => ({ ...prev, [findingId]: msg }));
      return null;
    } finally {
      setSavingVersionId(null);
    }
  };

  const handleFindingAiFeedback = async (findingId: number, feedback: AIFeedbackValue) => {
    const ai = aiByFindingId[findingId];
    if (!ai?.explanation_text) {
      setAiMessageByFindingId((prev) => ({
        ...prev,
        [findingId]: 'Generate an AI explanation before submitting feedback.',
      }));
      return;
    }
    const opKey = `${findingId}:${feedback}`;
    setFeedbackBusyKey(opKey);
    setAiErrorByFindingId((prev) => {
      const next = { ...prev };
      delete next[findingId];
      return next;
    });
    try {
      let versionId = aiVersionIdByFindingId[findingId];
      if (!versionId) {
        const saved = await saveFindingAiVersion(findingId);
        if (!saved) return;
        versionId = saved;
      }
      await createAIFeedback({
        entity_type: 'finding',
        entity_id: findingId,
        version_id: versionId,
        feedback,
        context_json: { surface: 'findings_page' },
      });
      setAiMessageByFindingId((prev) => ({
        ...prev,
        [findingId]:
          feedback === 'up'
            ? 'Feedback saved: explanation was useful.'
            : 'Feedback saved: explanation needs improvement.',
      }));
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save AI feedback';
      setAiErrorByFindingId((prev) => ({ ...prev, [findingId]: msg }));
    } finally {
      setFeedbackBusyKey(null);
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
  const visibleRiskCounts = findings.reduce(
    (acc, finding) => {
      const key = (finding.risk_level || 'unscored') as 'critical' | 'high' | 'medium' | 'low' | 'unscored';
      acc[key] += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, unscored: 0 }
  );
  const activeFilters = [
    statusFilter ? `status: ${statusFilter.replace('_', ' ')}` : null,
    sourceFilter ? `source: ${sourceFilter}` : null,
    riskLevelFilter ? `risk: ${riskLevelFilter}` : null,
  ].filter(Boolean) as string[];

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <h1 className="hero-title">Findings Command Queue</h1>
            <p className="hero-copy">
              Risk-ranked vulnerability and detection findings with direct workflow control,
              analyst labels, and AI-backed investigation context.
            </p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Link href="/ml-risk" className="btn-secondary text-sm">
                Open ML lab
              </Link>
              <Link href="/incidents" className="btn-secondary text-sm">
                Open incidents
              </Link>
              <Link href="/jobs" className="btn-secondary text-sm">
                Run scans
              </Link>
            </div>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Visible findings</p>
              <p className="hero-stat-value">{findings.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Critical</p>
              <p className="hero-stat-value">{visibleRiskCounts.critical}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">High</p>
              <p className="hero-stat-value">{visibleRiskCounts.high}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Pending score</p>
              <p className="hero-stat-value">{visibleRiskCounts.unscored}</p>
            </div>
          </div>
        </div>
      </section>

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
        <details className="section-panel mb-6 animate-in disclosure">
          <summary className="flex cursor-pointer list-none flex-wrap items-start justify-between gap-4">
            <div>
              <p className="section-title mb-2">ML risk model</p>
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
            </div>
            <div className="flex flex-wrap gap-2 text-xs text-[var(--muted)]">
              <span className="stat-chip">Labels {modelStatus.readiness.summary.total_labels}</span>
              <span className="stat-chip">
                Test AUC{' '}
                {modelStatus.model_metadata?.test_auc != null
                  ? Number(modelStatus.model_metadata.test_auc).toFixed(3)
                  : '-'}
              </span>
            </div>
          </summary>
          <div className="disclosure-body mt-4 space-y-4">
            <div className="flex flex-wrap items-start justify-between gap-4">
              <p className="text-xs text-[var(--muted)]">
                Signature: {modelStatus.scoring_signature}
                {modelStatus.model_metadata?.trained_at &&
                  ` | trained ${formatDateTime(modelStatus.model_metadata.trained_at)}`}
              </p>
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
            <div className="meta-grid">
              <div className="kv-item">
                <p className="kv-label">Labels</p>
                <p className="kv-value">{modelStatus.readiness.summary.total_labels}</p>
              </div>
              <div className="kv-item">
                <p className="kv-label">Positive</p>
                <p className="kv-value">{modelStatus.readiness.summary.positive_labels}</p>
              </div>
              <div className="kv-item">
                <p className="kv-label">Negative</p>
                <p className="kv-value">{modelStatus.readiness.summary.negative_labels}</p>
              </div>
              <div className="kv-item">
                <p className="kv-label">Linked incidents</p>
                <p className="kv-value">{modelStatus.readiness.summary.incident_linked_findings}</p>
              </div>
              <div className="kv-item">
                <p className="kv-label">Algorithm</p>
                <p className="kv-value">{modelStatus.model_metadata?.algorithm || '-'}</p>
              </div>
              <div className="kv-item">
                <p className="kv-label">Test AUC</p>
                <p className="kv-value">
                  {modelStatus.model_metadata?.test_auc != null
                    ? Number(modelStatus.model_metadata.test_auc).toFixed(3)
                    : '-'}
                </p>
              </div>
            </div>
          </div>
        </details>
      )}

      <section className="section-panel animate-in">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <p className="section-title mb-2">Filter queue</p>
            <p className="text-xs text-[var(--muted)]">Use queue-level filters only for the issues you are actively reviewing.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            {activeFilters.length === 0 ? (
              <span className="stat-chip">No filters</span>
            ) : (
              activeFilters.map((filter) => (
                <span key={filter} className="stat-chip">
                  {filter}
                </span>
              ))
            )}
          </div>
        </div>
        <div className="mt-4 grid gap-4 lg:grid-cols-[13rem_13rem_1fr]">
          <label className="text-sm text-[var(--muted)]">
            <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.12em]">
              Status
            </span>
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="input py-2.5"
            >
              <option value="">All</option>
              {STATUS_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s === 'accepted_risk' ? 'Accepted risk' : s.replace('_', ' ')}
                </option>
              ))}
            </select>
          </label>
          <label className="text-sm text-[var(--muted)]">
            <span className="mb-2 block text-xs font-semibold uppercase tracking-[0.12em]">
              Source
            </span>
            <select
              value={sourceFilter}
              onChange={(e) => setSourceFilter(e.target.value)}
              className="input py-2.5"
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
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
              Risk level
            </p>
            <div className="flex flex-wrap gap-2">
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
          </div>
        </div>
      </section>

      {loading ? (
        <p className="text-sm text-[var(--muted)]">Loading...</p>
      ) : findings.length === 0 ? (
        <EmptyState
          title="No findings"
          description="Run the scanner to generate TLS and security header findings, or wait for the scheduled scan."
        />
      ) : (
        <div className="space-y-5">
          {findings.map((f) => {
            const drivers = riskDrivers(f);
            const ai = aiByFindingId[f.finding_id];
            const guardrails = parseFindingGuardrails(ai);
            return (
              <article key={f.finding_id} className="section-panel animate-in">
                <div className="flex flex-wrap items-start justify-between gap-4">
                  <div className="min-w-0 flex-1">
                    <div className="mb-3 flex flex-wrap items-center gap-2">
                      <span
                        className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${SEVERITY_COLORS[f.severity] ?? 'bg-gray-600 text-white'}`}
                      >
                        {f.severity}
                      </span>
                      {f.risk_score != null ? (
                        <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(f.risk_level)}`}>
                          {f.risk_level || 'risk'} {Math.round(Number(f.risk_score))}
                        </span>
                      ) : (
                        <span className="stat-chip">Risk pending</span>
                      )}
                      <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium capitalize ${statusBadgeClass(f.status)}`}>
                        {f.status.replace('_', ' ')}
                      </span>
                    </div>
                    <h2 className="text-lg font-semibold text-[var(--text)]">{f.title}</h2>
                    <p className="mt-2 text-sm text-[var(--muted)]">
                      {f.asset_key ? (
                        <Link href={`/assets/${encodeURIComponent(f.asset_key)}`} className="font-medium text-[var(--green)] hover:underline">
                          {f.asset_name || f.asset_key}
                        </Link>
                      ) : (
                        'Unlinked asset'
                      )}
                      {f.source ? ` | ${f.source}` : ''}
                      {f.category ? ` | ${f.category}` : ''}
                      {f.first_seen ? ` | first seen ${formatDateTime(f.first_seen)}` : ''}
                      {f.last_seen ? ` | last seen ${formatDateTime(f.last_seen)}` : ''}
                    </p>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <span className="stat-chip">{scoreSource(f)}</span>
                      {f.vulnerability_id && <span className="stat-chip">{f.vulnerability_id}</span>}
                      {packageChip(f) && <span className="stat-chip">{packageChip(f)}</span>}
                      {f.fixed_version && (
                        <span className="stat-chip">Fix {f.fixed_version}</span>
                      )}
                      {drivers.map((driver) => (
                        <span key={driver} className="stat-chip">
                          {formatRiskDriverLabel(driver)}
                        </span>
                      ))}
                    </div>
                  </div>
                  {f.risk_label && (
                    <div className="text-right text-xs text-[var(--muted)]">
                      <span className={`inline-block rounded px-2 py-0.5 font-semibold uppercase ${riskLabelBadgeClass(f.risk_label)}`}>
                        {formatRiskLabel(f.risk_label)}
                      </span>
                      <p className="mt-1">
                        {f.risk_label_source || 'label'}
                        {f.risk_label_created_at && ` | ${formatDateTime(f.risk_label_created_at)}`}
                      </p>
                    </div>
                  )}
                </div>

                <div className="mt-4 grid gap-4 lg:grid-cols-[minmax(0,1fr)_18rem]">
                  <div className="space-y-3">
                    {f.evidence && (
                      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] px-4 py-3">
                        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                          Evidence
                        </p>
                        <p className="mt-2 line-clamp-3 text-sm text-[var(--text)]">{f.evidence}</p>
                      </div>
                    )}
                    {f.risk_score != null && (
                      <p className="text-xs text-[var(--muted)]">
                        {scoreSource(f) === 'ml'
                          ? 'Score is coming from the trained ML model.'
                          : 'Score is coming from the contextual heuristic scorer.'}
                      </p>
                    )}
                    {f.status === 'accepted_risk' && (f.accepted_risk_reason || f.accepted_risk_by || f.accepted_risk_expires_at) && (
                      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] px-4 py-3 text-sm text-[var(--muted)]">
                        Accepted{f.accepted_risk_by && ` by ${f.accepted_risk_by}`}
                        {f.accepted_risk_expires_at && ` until ${formatDateTime(f.accepted_risk_expires_at)}`}
                        {f.accepted_risk_reason && ` | ${f.accepted_risk_reason}`}
                      </div>
                    )}
                  </div>
                  <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
                    <p className="section-title mb-3">Context</p>
                    <dl className="space-y-3">
                      <div>
                        <dt className="kv-label">Asset</dt>
                        <dd className="text-sm text-[var(--text)] break-words">{f.asset_name || f.asset_key || '-'}</dd>
                      </div>
                      <div>
                        <dt className="kv-label">Vulnerability</dt>
                        <dd className="text-sm text-[var(--text)]">{f.vulnerability_id || '-'}</dd>
                      </div>
                      <div>
                        <dt className="kv-label">Package</dt>
                        <dd className="text-sm text-[var(--text)]">
                          {packageChip(f) || '-'}
                          {f.package_ecosystem ? ` (${f.package_ecosystem})` : ''}
                        </dd>
                      </div>
                      <div>
                        <dt className="kv-label">Fixed version</dt>
                        <dd className="text-sm text-[var(--text)]">{f.fixed_version || '-'}</dd>
                      </div>
                      <div>
                        <dt className="kv-label">Category</dt>
                        <dd className="text-sm text-[var(--text)]">{f.category || '-'}</dd>
                      </div>
                      <div>
                        <dt className="kv-label">First seen</dt>
                        <dd className="text-sm text-[var(--text)]">{f.first_seen ? formatDateTime(f.first_seen) : '-'}</dd>
                      </div>
                      <div>
                        <dt className="kv-label">Last seen</dt>
                        <dd className="text-sm text-[var(--text)]">{f.last_seen ? formatDateTime(f.last_seen) : '-'}</dd>
                      </div>
                    </dl>
                  </div>
                </div>

                <details className="disclosure mt-4">
                  <summary className="cursor-pointer list-none text-sm font-medium text-[var(--text)]">
                    Investigation and actions
                  </summary>
                  <div className="disclosure-body mt-4 grid gap-4 lg:grid-cols-[0.95fr_1.05fr]">
                    <div className="space-y-4">
                      {canMutate ? (
                        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
                          <p className="mb-3 text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                            Workflow
                          </p>
                          <div className="grid gap-2 sm:grid-cols-2">
                            <select
                              value={f.status}
                              onChange={(e) => handleStatusChange(f.finding_id, e.target.value as FindingStatus)}
                              disabled={updatingId === f.finding_id}
                              className="input py-2.5 text-sm"
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
                                className="btn-secondary text-sm"
                              >
                                Accept risk
                              </button>
                            )}
                          </div>
                          <div className="mt-3 flex flex-wrap gap-2">
                            <button
                              type="button"
                              onClick={() => handleLabelFinding(f.finding_id, 'incident_worthy')}
                              disabled={
                                labelingKey === `${f.finding_id}:incident_worthy` ||
                                (f.risk_label === 'incident_worthy' && f.risk_label_source === 'analyst')
                              }
                              className="btn-secondary text-xs"
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
                              className="btn-secondary text-xs"
                            >
                              {labelingKey === `${f.finding_id}:benign`
                                ? 'Saving...'
                                : 'Label benign'}
                            </button>
                          </div>
                        </div>
                      ) : (
                        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] px-4 py-3 text-sm text-[var(--muted)]">
                          Read-only mode. Workflow changes and analyst labels require write access.
                        </div>
                      )}
                    </div>
                    <div className="space-y-4">
                      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
                        <div className="flex flex-wrap items-center justify-between gap-3">
                          <div>
                            <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                              AI explanation
                            </p>
                            {ai?.generated_at && (
                              <p className="mt-1 text-xs text-[var(--muted)]">
                                {formatDateTime(ai.generated_at)} via {ai.provider}/{ai.model}
                              </p>
                            )}
                          </div>
                          <button
                            type="button"
                            onClick={() => handleExplainRisk(f.finding_id, Boolean(aiByFindingId[f.finding_id]))}
                            disabled={explainingId === f.finding_id}
                            className="btn-secondary text-sm"
                          >
                            {explainingId === f.finding_id
                              ? 'Explaining...'
                              : aiByFindingId[f.finding_id]
                                ? 'Refresh AI'
                                : 'Explain risk'}
                          </button>
                        </div>
                        {ai?.explanation_text ? (
                          <div className="mt-3 space-y-2">
                            <p className="whitespace-pre-wrap text-sm text-[var(--text)]">
                              {ai.explanation_text}
                            </p>
                            {guardrails && (
                              <div className="rounded-xl border border-[var(--border)] bg-[var(--bg)] px-3 py-2">
                                <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                                  Evidence-backed breakdown
                                </p>
                                {guardrails.mode && (
                                  <p className="mt-1 text-[11px] text-[var(--muted)]">
                                    Mode: {guardrails.mode}
                                  </p>
                                )}
                                {guardrails.usedFallbackSections && (
                                  <p className="mt-1 text-[11px] text-[var(--amber)]">
                                    Some sections used guarded fallback statements.
                                  </p>
                                )}
                                <div className="mt-2 space-y-2 text-xs">
                                  {(
                                    [
                                      ['facts', 'Facts'],
                                      ['inference', 'Inference'],
                                      ['recommendations', 'Recommendations'],
                                    ] as const
                                  ).map(([key, label]) =>
                                    guardrails.sections[key].length > 0 ? (
                                      <div key={key}>
                                        <p className="font-semibold text-[var(--text)]">{label}</p>
                                        <ul className="mt-1 space-y-1 text-[var(--muted)]">
                                          {guardrails.sections[key].map((item, idx) => (
                                            <li key={`${key}-${idx}`} className="rounded border border-[var(--border)] px-2 py-1">
                                              <p>{item.statement}</p>
                                              {item.evidence.length > 0 && (
                                                <div className="mt-1 flex flex-wrap gap-1">
                                                  {item.evidence.map((eid) => (
                                                    <span
                                                      key={`${key}-${idx}-${eid}`}
                                                      className="stat-chip"
                                                      title={guardrails.evidenceMap[eid] || eid}
                                                    >
                                                      {eid}
                                                    </span>
                                                  ))}
                                                </div>
                                              )}
                                            </li>
                                          ))}
                                        </ul>
                                      </div>
                                    ) : null
                                  )}
                                </div>
                              </div>
                            )}
                            {aiMessageByFindingId[f.finding_id] && (
                              <p className="text-xs text-[var(--muted)]">
                                {aiMessageByFindingId[f.finding_id]}
                              </p>
                            )}
                            {isFallbackProvider(ai.provider) && (
                              <p className="text-xs text-[var(--amber)]">
                                Showing fallback guidance because the AI provider was temporarily slow or unavailable.
                              </p>
                            )}
                            {canMutate && (
                              <div className="flex flex-wrap gap-2 pt-1">
                                <button
                                  type="button"
                                  onClick={() => saveFindingAiVersion(f.finding_id)}
                                  disabled={savingVersionId === f.finding_id}
                                  className="btn-secondary text-xs"
                                >
                                  {savingVersionId === f.finding_id ? 'Saving...' : 'Save version'}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleFindingAiFeedback(f.finding_id, 'up')}
                                  disabled={feedbackBusyKey != null}
                                  className="btn-secondary text-xs"
                                >
                                  {feedbackBusyKey === `${f.finding_id}:up` ? 'Saving...' : 'Thumbs up'}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleFindingAiFeedback(f.finding_id, 'down')}
                                  disabled={feedbackBusyKey != null}
                                  className="btn-secondary text-xs"
                                >
                                  {feedbackBusyKey === `${f.finding_id}:down` ? 'Saving...' : 'Thumbs down'}
                                </button>
                              </div>
                            )}
                          </div>
                        ) : aiErrorByFindingId[f.finding_id] ? (
                          <p className="mt-3 text-sm text-[var(--red)]">
                            AI explain failed: {friendlyApiMessage(aiErrorByFindingId[f.finding_id])}
                          </p>
                        ) : (
                          <p className="mt-3 text-sm text-[var(--muted)]">
                            Generate an explanation when you need exploit context or remediation framing.
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                </details>
              </article>
            );
          })}
        </div>
      )}

      {findings.length > 0 && (
        <p className="mt-4 text-xs text-[var(--muted)]">
          Showing {findings.length} finding{findings.length === 1 ? '' : 's'}
          {canMutate && '. Open a finding to change workflow state, add analyst labels, or request AI help.'}
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
