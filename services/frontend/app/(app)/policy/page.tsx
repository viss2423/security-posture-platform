'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  compareAISummaryVersions,
  createAIFeedback,
  createAISummaryVersion,
  approvePolicyBundle,
  createPolicyBundle,
  deletePolicyBundle,
  evaluatePolicyBundle,
  generatePolicyEvaluationAISummary,
  getPolicyBundle,
  getPolicyBundles,
  getPolicyEvaluation,
  getPolicyEvaluationAISummary,
  getPolicyEvaluationHistory,
  listAISummaryVersions,
  type AIFeedbackValue,
  type AIPolicyEvaluationSummary,
  type AISummaryVersion,
  type AISummaryVersionCompare,
  updatePolicyBundle,
  type PolicyBundle,
  type PolicyBundleDetail,
  type PolicyEvaluateResult,
  type PolicyEvaluationSummary,
} from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';

const DEFAULT_YAML = `rules:
  - id: asset-green
    name: "Asset status green"
    type: asset_status
    params:
      status: green
  - id: no-critical
    name: "No open critical findings"
    type: no_critical_findings
  - id: required-csp
    name: "CSP header required"
    type: require_header
    params:
      header: content-security-policy
  - id: min-score
    name: "Minimum posture score 70"
    type: posture_score_min
    params:
      min_score: 70
`;
type GuardrailSectionKey = 'facts' | 'inference' | 'recommendations';
type GuardrailItem = { statement: string; evidence: string[] };

function fmtDate(value?: string | null): string {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
}

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

function parsePolicyGuardrails(ai?: AIPolicyEvaluationSummary | null): {
  mode: string;
  parseMode: string;
  usedFallbackSections: boolean;
  sections: Record<GuardrailSectionKey, GuardrailItem[]>;
  evidenceMap: Record<string, string>;
} | null {
  if (!ai?.context_json || typeof ai.context_json !== 'object') return null;
  const guardrails = (ai.context_json as Record<string, unknown>).guardrails;
  if (!guardrails || typeof guardrails !== 'object') return null;

  const guardrailObj = guardrails as Record<string, unknown>;
  const mode = String(guardrailObj.mode || '').trim();
  const parseMode = String(guardrailObj.parse_mode || '').trim();
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

  return { mode, parseMode, usedFallbackSections, sections, evidenceMap };
}

export default function PolicyPage() {
  const { canMutate, isAdmin } = useAuth();
  const [bundles, setBundles] = useState<PolicyBundle[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<PolicyBundleDetail | null>(null);
  const [evaluateResult, setEvaluateResult] = useState<PolicyEvaluateResult | null>(null);
  const [evaluationHistory, setEvaluationHistory] = useState<PolicyEvaluationSummary[]>([]);
  const [showCreate, setShowCreate] = useState(false);
  const [createName, setCreateName] = useState('');
  const [createDesc, setCreateDesc] = useState('');
  const [createDef, setCreateDef] = useState(DEFAULT_YAML);
  const [editDef, setEditDef] = useState('');
  const [aiSummary, setAiSummary] = useState<AIPolicyEvaluationSummary | null>(null);
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false);
  const [aiSummaryGenerating, setAiSummaryGenerating] = useState(false);
  const [aiSummaryMessage, setAiSummaryMessage] = useState<string | null>(null);
  const [summaryVersions, setSummaryVersions] = useState<AISummaryVersion[]>([]);
  const [summaryVersionsLoading, setSummaryVersionsLoading] = useState(false);
  const [savingSummaryVersion, setSavingSummaryVersion] = useState(false);
  const [summaryFeedbackBusy, setSummaryFeedbackBusy] = useState<AIFeedbackValue | null>(null);
  const [compareFrom, setCompareFrom] = useState<number | null>(null);
  const [compareTo, setCompareTo] = useState<number | null>(null);
  const [summaryComparison, setSummaryComparison] = useState<AISummaryVersionCompare | null>(null);
  const [comparingVersions, setComparingVersions] = useState(false);
  const summaryGuardrails = parsePolicyGuardrails(aiSummary);

  const loadBundles = useCallback(() => {
    setLoading(true);
    getPolicyBundles()
      .then((r) => {
        setBundles(r.items);
        setError(null);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const loadEvaluationHistory = useCallback((bundleId: number) => {
    return getPolicyEvaluationHistory(bundleId)
      .then((r) => setEvaluationHistory(r.items || []))
      .catch((e) => setError(e.message));
  }, []);

  const loadSummaryVersions = useCallback((evaluationId: number) => {
    setSummaryVersionsLoading(true);
    listAISummaryVersions('policy_evaluation', evaluationId, 30)
      .then((out) => {
        const items = out.items || [];
        setSummaryVersions(items);
        const versionNos = items.map((item) => Number(item.version_no)).filter(Number.isFinite);
        setCompareTo((prev) => {
          if (versionNos.length === 0) return null;
          if (prev != null && versionNos.includes(prev)) return prev;
          return versionNos[0];
        });
        setCompareFrom((prev) => {
          if (versionNos.length === 0) return null;
          if (prev != null && versionNos.includes(prev)) return prev;
          return versionNos.length > 1 ? versionNos[1] : versionNos[0];
        });
      })
      .catch(() => setSummaryVersions([]))
      .finally(() => setSummaryVersionsLoading(false));
  }, []);

  useEffect(() => {
    loadBundles();
  }, [loadBundles]);

  const openDetail = (id: number) => {
    Promise.all([getPolicyBundle(id), getPolicyEvaluationHistory(id)])
      .then(([b, history]) => {
        setDetail(b);
        setEditDef(b.definition);
        setEvaluateResult(null);
        setAiSummary(null);
        setAiSummaryMessage(null);
        setEvaluationHistory(history.items || []);
      })
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    const evaluationId = evaluateResult?.evaluation_id;
    if (!evaluationId) {
      setAiSummary(null);
      setAiSummaryLoading(false);
      setAiSummaryMessage(null);
      setSummaryVersions([]);
      setSummaryComparison(null);
      setCompareFrom(null);
      setCompareTo(null);
      return;
    }
    setAiSummaryLoading(true);
    setAiSummaryMessage(null);
    setSummaryComparison(null);
    getPolicyEvaluationAISummary(evaluationId)
      .then(setAiSummary)
      .catch((e) => {
        const message = e instanceof Error ? e.message : 'Failed to load AI summary';
        if (!message.toLowerCase().includes('not found')) {
          setAiSummaryMessage(message);
        }
        setAiSummary(null);
      })
      .finally(() => setAiSummaryLoading(false));
    loadSummaryVersions(evaluationId);
  }, [evaluateResult?.evaluation_id, loadSummaryVersions]);

  const handleCreate = () => {
    if (!createName.trim()) return;
    setError(null);
    createPolicyBundle({
      name: createName.trim(),
      description: createDesc.trim() || undefined,
      definition: createDef,
    })
      .then(() => {
        setShowCreate(false);
        setCreateName('');
        setCreateDesc('');
        setCreateDef(DEFAULT_YAML);
        loadBundles();
      })
      .catch((e) => setError(e.message));
  };

  const handleUpdate = () => {
    if (!detail) return;
    setError(null);
    updatePolicyBundle(detail.id, { definition: editDef })
      .then((b) => {
        setDetail(b);
        setEditDef(b.definition);
      })
      .catch((e) => setError(e.message));
  };

  const handleApprove = () => {
    if (!detail) return;
    setError(null);
    approvePolicyBundle(detail.id)
      .then(() => openDetail(detail.id))
      .catch((e) => setError(e.message));
  };

  const handleEvaluate = () => {
    if (!detail) return;
    setError(null);
    evaluatePolicyBundle(detail.id)
      .then((r) => {
        setEvaluateResult(r);
        setAiSummary(null);
        setAiSummaryMessage(null);
        return loadEvaluationHistory(detail.id);
      })
      .catch((e) => setError(e.message));
  };

  const handleLoadEvaluation = (evaluationId: number) => {
    if (!detail) return;
    setError(null);
    getPolicyEvaluation(detail.id, evaluationId)
      .then((r) =>
        setEvaluateResult({
          ...r.result,
          evaluation_id: r.id,
          evaluated_at: r.evaluated_at ?? r.result.evaluated_at,
          bundle_approved_by: r.bundle_approved_by ?? r.result.bundle_approved_by,
        })
      )
      .catch((e) => setError(e.message));
  };

  const handleGenerateAISummary = async (force: boolean) => {
    if (!evaluateResult?.evaluation_id) return;
    setAiSummaryGenerating(true);
    setAiSummaryMessage(null);
    try {
      const out = await generatePolicyEvaluationAISummary(evaluateResult.evaluation_id, force);
      setAiSummary(out);
      setAiSummaryMessage(out.cached ? 'Showing cached AI summary.' : 'AI summary generated.');
    } catch (e) {
      setAiSummaryMessage(e instanceof Error ? e.message : 'AI summary generation failed');
    } finally {
      setAiSummaryGenerating(false);
    }
  };

  const handleSaveAISummaryVersion = async () => {
    const evaluationId = evaluateResult?.evaluation_id;
    if (!evaluationId || !aiSummary?.summary_text) {
      setAiSummaryMessage('Generate an AI summary before saving a version.');
      return;
    }
    setSavingSummaryVersion(true);
    setAiSummaryMessage(null);
    try {
      const created = await createAISummaryVersion('policy_evaluation', evaluationId, {
        content_text: aiSummary.summary_text,
        provider: aiSummary.provider,
        model: aiSummary.model,
        source_type: aiSummary.cached ? 'cached' : 'generated',
        context_json: aiSummary.context_json || {},
        evidence_json: {
          generated_at: aiSummary.generated_at,
          generated_by: aiSummary.generated_by || null,
        },
      });
      loadSummaryVersions(evaluationId);
      setAiSummaryMessage(`Saved version v${created.version_no}.`);
    } catch (e) {
      setAiSummaryMessage(e instanceof Error ? e.message : 'Saving AI summary version failed');
    } finally {
      setSavingSummaryVersion(false);
    }
  };

  const handleAISummaryFeedback = async (feedback: AIFeedbackValue) => {
    const evaluationId = evaluateResult?.evaluation_id;
    if (!evaluationId || !aiSummary?.summary_text) {
      setAiSummaryMessage('Generate an AI summary before submitting feedback.');
      return;
    }
    setSummaryFeedbackBusy(feedback);
    setAiSummaryMessage(null);
    try {
      let latestVersionId = summaryVersions[0]?.version_id ?? null;
      if (!latestVersionId) {
        const created = await createAISummaryVersion('policy_evaluation', evaluationId, {
          content_text: aiSummary.summary_text,
          provider: aiSummary.provider,
          model: aiSummary.model,
          source_type: 'feedback_seed',
          context_json: aiSummary.context_json || {},
          evidence_json: {
            generated_at: aiSummary.generated_at,
            generated_by: aiSummary.generated_by || null,
          },
        });
        latestVersionId = created.version_id;
        loadSummaryVersions(evaluationId);
      }
      await createAIFeedback({
        entity_type: 'policy_evaluation',
        entity_id: evaluationId,
        version_id: latestVersionId,
        feedback,
        context_json: { surface: 'policy_page' },
      });
      setAiSummaryMessage(
        feedback === 'up'
          ? 'Feedback recorded: summary was useful.'
          : 'Feedback recorded: summary needs improvement.'
      );
    } catch (e) {
      setAiSummaryMessage(e instanceof Error ? e.message : 'Saving AI feedback failed');
    } finally {
      setSummaryFeedbackBusy(null);
    }
  };

  const handleCompareSummaryVersions = async () => {
    const evaluationId = evaluateResult?.evaluation_id;
    if (!evaluationId || compareFrom == null || compareTo == null || compareFrom === compareTo) return;
    setComparingVersions(true);
    setAiSummaryMessage(null);
    try {
      const out = await compareAISummaryVersions(
        'policy_evaluation',
        evaluationId,
        compareFrom,
        compareTo
      );
      setSummaryComparison(out);
    } catch (e) {
      setAiSummaryMessage(e instanceof Error ? e.message : 'Comparing summary versions failed');
      setSummaryComparison(null);
    } finally {
      setComparingVersions(false);
    }
  };

  const handleDelete = () => {
    if (!detail || !confirm('Delete this bundle?')) return;
    setError(null);
    deletePolicyBundle(detail.id)
      .then(() => {
        setDetail(null);
        setEvaluateResult(null);
        setEvaluationHistory([]);
        setAiSummary(null);
        setAiSummaryMessage(null);
        loadBundles();
      })
      .catch((e) => setError(e.message));
  };

  const totalViolations = (evaluateResult?.violations || []).length;

  return (
    <main className="page-shell">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-[var(--text-muted)]">
          Manage policy bundles, run evaluations, and review AI summaries without staring at raw
          evidence first.
        </p>
        {canMutate && (
          <button type="button" onClick={() => setShowCreate(true)} className="btn-primary">
            New bundle
          </button>
        )}
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {error}
          <ApiDownHint />
        </div>
      )}

      {showCreate && (
        <div className="section-panel mb-8 animate-in">
          <h2 className="mb-4 text-lg font-semibold text-[var(--text)]">New policy bundle</h2>
          <div className="space-y-4">
            <div>
              <label className="mb-1 block text-sm font-medium text-[var(--muted)]">Name</label>
              <input
                type="text"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="e.g. Default security rules"
                className="input w-full"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-[var(--muted)]">
                Description (optional)
              </label>
              <input
                type="text"
                value={createDesc}
                onChange={(e) => setCreateDesc(e.target.value)}
                className="input w-full"
              />
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium text-[var(--muted)]">
                YAML definition
              </label>
              <textarea
                value={createDef}
                onChange={(e) => setCreateDef(e.target.value)}
                rows={16}
                className="input w-full font-mono text-sm"
                spellCheck={false}
              />
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={handleCreate}
                className="btn-primary"
                disabled={!createName.trim()}
              >
                Create draft
              </button>
              <button type="button" onClick={() => setShowCreate(false)} className="btn-secondary">
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      {loading ? (
        <p className="text-[var(--muted)]">Loading...</p>
      ) : bundles.length === 0 ? (
        <EmptyState
          title="No policy bundles"
          description="Create a bundle to define policy-as-code rules and evaluate posture with evidence."
          action={
            canMutate ? (
              <button type="button" onClick={() => setShowCreate(true)} className="btn-primary">
                New bundle
              </button>
            ) : undefined
          }
        />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {bundles.map((b) => (
            <div
              key={b.id}
              className="section-panel-tight cursor-pointer transition-all hover:ring-2 hover:ring-[var(--green)]/20"
              onClick={() => openDetail(b.id)}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-[var(--text)]">{b.name}</h3>
                  {b.description && (
                    <p className="mt-1 line-clamp-2 text-sm text-[var(--muted)]">{b.description}</p>
                  )}
                </div>
                <span
                  className={`shrink-0 rounded px-2 py-0.5 text-xs font-medium ${
                    b.status === 'approved'
                      ? 'bg-[var(--green)]/20 text-[var(--green)]'
                      : 'bg-[var(--amber)]/20 text-[var(--amber)]'
                  }`}
                >
                  {b.status}
                </span>
              </div>
              <p className="mt-2 text-xs text-[var(--muted)]">
                Updated {fmtDate(b.updated_at)} {b.approved_by ? `- Approved by ${b.approved_by}` : ''}
              </p>
            </div>
          ))}
        </div>
      )}

      {detail && (
        <div className="mt-10 grid gap-6 xl:grid-cols-[minmax(0,1fr)_320px]">
          <div className="space-y-6">
            <section className="section-panel animate-in">
              <div className="mb-5 flex flex-wrap items-start justify-between gap-4">
                <div>
                  <h2 className="text-xl font-semibold text-[var(--text)]">{detail.name}</h2>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <span
                      className={`rounded-full px-3 py-1 text-xs font-medium uppercase ${
                        detail.status === 'approved'
                          ? 'bg-[var(--green)]/20 text-[var(--green)]'
                          : 'bg-[var(--amber)]/20 text-[var(--amber)]'
                      }`}
                    >
                      {detail.status}
                    </span>
                    {detail.approved_by && <span className="stat-chip">Approved by {detail.approved_by}</span>}
                    <span className="stat-chip">Updated {fmtDate(detail.updated_at)}</span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-2">
                  <button type="button" onClick={handleEvaluate} className="btn-primary">
                    Evaluate
                  </button>
                  {canMutate && detail.status === 'draft' && (
                    <button type="button" onClick={handleUpdate} className="btn-secondary">
                      Save edits
                    </button>
                  )}
                  {isAdmin && detail.status === 'draft' && (
                    <button type="button" onClick={handleApprove} className="btn-primary">
                      Approve
                    </button>
                  )}
                  {isAdmin && (
                    <button
                      type="button"
                      onClick={handleDelete}
                      className="btn-secondary text-[var(--red)]"
                    >
                      Delete
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => {
                      setDetail(null);
                      setEvaluateResult(null);
                      setEvaluationHistory([]);
                      setAiSummary(null);
                      setAiSummaryMessage(null);
                    }}
                    className="btn-secondary"
                  >
                    Close
                  </button>
                </div>
              </div>

              {detail.description && (
                <p className="mb-4 text-sm text-[var(--text-muted)]">{detail.description}</p>
              )}

              <details className="disclosure" open>
                <summary>Bundle definition</summary>
                <div className="disclosure-body">
                  {canMutate && detail.status === 'draft' ? (
                    <textarea
                      value={editDef}
                      onChange={(e) => setEditDef(e.target.value)}
                      rows={16}
                      className="input w-full font-mono text-sm"
                      spellCheck={false}
                    />
                  ) : (
                    <pre className="overflow-x-auto whitespace-pre-wrap rounded-lg border border-[var(--border)] bg-[var(--bg)] p-4 font-mono text-sm text-[var(--text)]">
                      {detail.definition}
                    </pre>
                  )}
                </div>
              </details>
            </section>

            {evaluateResult && (
              <section className="section-panel animate-in">
                <h3 className="mb-4 text-lg font-semibold text-[var(--text)]">Latest evaluation</h3>
                <div className="meta-grid">
                  <div className="kv-item">
                    <span className="kv-label">Score</span>
                    <div className="kv-value text-xl font-semibold text-[var(--green)]">
                      {evaluateResult.score}%
                    </div>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Evaluation ID</span>
                    <div className="kv-value">#{evaluateResult.evaluation_id ?? '-'}</div>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Evaluated</span>
                    <div className="kv-value">{fmtDate(evaluateResult.evaluated_at)}</div>
                  </div>
                  <div className="kv-item">
                    <span className="kv-label">Violations</span>
                    <div className="kv-value">{totalViolations}</div>
                  </div>
                </div>

                <div className="mt-6 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/70 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div>
                      <h4 className="text-base font-semibold text-[var(--text)]">AI summary</h4>
                      <p className="mt-1 text-xs text-[var(--muted)]">
                        Short remediation brief for the current evaluation snapshot.
                      </p>
                    </div>
                    {canMutate && evaluateResult.evaluation_id != null && (
                      <div className="flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => handleGenerateAISummary(false)}
                          disabled={aiSummaryGenerating}
                          className="btn-primary text-sm"
                        >
                          {aiSummaryGenerating
                            ? 'Generating...'
                            : aiSummary
                              ? 'Refresh summary'
                              : 'Generate summary'}
                        </button>
                        {aiSummary && (
                          <button
                            type="button"
                            onClick={() => handleGenerateAISummary(true)}
                            disabled={aiSummaryGenerating}
                            className="btn-secondary text-sm"
                          >
                            Force regenerate
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={handleSaveAISummaryVersion}
                          disabled={savingSummaryVersion || !aiSummary?.summary_text}
                          className="btn-secondary text-sm"
                        >
                          {savingSummaryVersion ? 'Saving...' : 'Save version'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleAISummaryFeedback('up')}
                          disabled={summaryFeedbackBusy != null || !aiSummary?.summary_text}
                          className="btn-secondary text-sm"
                        >
                          {summaryFeedbackBusy === 'up' ? 'Saving...' : 'Thumbs up'}
                        </button>
                        <button
                          type="button"
                          onClick={() => handleAISummaryFeedback('down')}
                          disabled={summaryFeedbackBusy != null || !aiSummary?.summary_text}
                          className="btn-secondary text-sm"
                        >
                          {summaryFeedbackBusy === 'down' ? 'Saving...' : 'Thumbs down'}
                        </button>
                      </div>
                    )}
                  </div>
                  <div className="mt-4">
                    {aiSummaryLoading ? (
                      <p className="text-sm text-[var(--muted)]">Loading summary...</p>
                    ) : aiSummary?.summary_text ? (
                      <>
                        <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">
                          {aiSummary.summary_text}
                        </p>
                        <p className="mt-3 text-xs text-[var(--muted)]">
                          Generated {fmtDate(aiSummary.generated_at)} via {aiSummary.provider}/{aiSummary.model}
                        </p>
                        {summaryGuardrails && (
                          <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--bg)] p-3">
                            <div className="flex flex-wrap items-center gap-2">
                              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                                Evidence-backed breakdown
                              </p>
                              {summaryGuardrails.mode && (
                                <span className="stat-chip">Mode: {summaryGuardrails.mode}</span>
                              )}
                              {summaryGuardrails.parseMode && (
                                <span className="stat-chip">Parse: {summaryGuardrails.parseMode}</span>
                              )}
                              {summaryGuardrails.usedFallbackSections && (
                                <span className="rounded-full border border-[var(--amber)]/30 bg-[var(--amber)]/15 px-2 py-0.5 text-[11px] text-[var(--amber)]">
                                  fallback sections used
                                </span>
                              )}
                            </div>
                            <div className="mt-3 grid gap-3 lg:grid-cols-3">
                              {(['facts', 'inference', 'recommendations'] as GuardrailSectionKey[]).map(
                                (key) => (
                                  <div
                                    key={key}
                                    className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-3"
                                  >
                                    <p className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                                      {key}
                                    </p>
                                    {summaryGuardrails.sections[key].length > 0 ? (
                                      <ul className="mt-2 space-y-2">
                                        {summaryGuardrails.sections[key].map((entry, idx) => (
                                          <li key={`${key}-${idx}`} className="text-xs text-[var(--text)]">
                                            <p>{entry.statement}</p>
                                            {entry.evidence.length > 0 && (
                                              <div className="mt-1 flex flex-wrap gap-1">
                                                {entry.evidence.map((eid) => (
                                                  <span
                                                    key={`${key}-${idx}-${eid}`}
                                                    className="rounded-full border border-[var(--border)] px-2 py-0.5 font-mono text-[10px] text-[var(--muted)]"
                                                    title={summaryGuardrails.evidenceMap[eid] || eid}
                                                  >
                                                    {eid}
                                                  </span>
                                                ))}
                                              </div>
                                            )}
                                          </li>
                                        ))}
                                      </ul>
                                    ) : (
                                      <p className="mt-2 text-xs text-[var(--muted)]">No entries</p>
                                    )}
                                  </div>
                                )
                              )}
                            </div>
                          </div>
                        )}
                      </>
                    ) : (
                      <p className="text-sm text-[var(--muted)]">
                        No AI summary generated yet for this evaluation.
                      </p>
                    )}
                    {aiSummaryMessage && (
                      <p
                        className={`mt-3 text-xs ${
                          aiSummaryMessage.toLowerCase().includes('failed')
                            ? 'text-[var(--red)]'
                            : 'text-[var(--muted)]'
                        }`}
                      >
                        {friendlyApiMessage(aiSummaryMessage)}
                      </p>
                    )}
                  </div>
                  <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--bg)] p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                        Summary versions
                      </p>
                      <span className="stat-chip">{summaryVersions.length} saved</span>
                    </div>
                    {summaryVersionsLoading ? (
                      <p className="mt-2 text-xs text-[var(--muted)]">Loading versions...</p>
                    ) : summaryVersions.length === 0 ? (
                      <p className="mt-2 text-xs text-[var(--muted)]">
                        No saved versions yet. Save the summary to enable change tracking.
                      </p>
                    ) : (
                      <ul className="mt-2 space-y-1 text-xs text-[var(--muted)]">
                        {summaryVersions.slice(0, 5).map((version) => (
                          <li key={version.version_id} className="flex items-center justify-between gap-2">
                            <span>
                              v{version.version_no} - {version.source_type || 'generated'}
                            </span>
                            <span>{fmtDate(version.created_at)}</span>
                          </li>
                        ))}
                      </ul>
                    )}
                    {summaryVersions.length >= 2 && (
                      <div className="mt-3 space-y-2 border-t border-[var(--border)] pt-3">
                        <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                          Compare versions
                        </p>
                        <div className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
                          <select
                            value={compareFrom ?? ''}
                            onChange={(e) =>
                              setCompareFrom(e.target.value ? Number(e.target.value) : null)
                            }
                            className="input py-2 text-sm"
                          >
                            {summaryVersions.map((version) => (
                              <option key={`from-${version.version_id}`} value={version.version_no}>
                                From v{version.version_no}
                              </option>
                            ))}
                          </select>
                          <select
                            value={compareTo ?? ''}
                            onChange={(e) =>
                              setCompareTo(e.target.value ? Number(e.target.value) : null)
                            }
                            className="input py-2 text-sm"
                          >
                            {summaryVersions.map((version) => (
                              <option key={`to-${version.version_id}`} value={version.version_no}>
                                To v{version.version_no}
                              </option>
                            ))}
                          </select>
                          <button
                            type="button"
                            onClick={handleCompareSummaryVersions}
                            disabled={
                              comparingVersions ||
                              compareFrom == null ||
                              compareTo == null ||
                              compareFrom === compareTo
                            }
                            className="btn-secondary text-sm"
                          >
                            {comparingVersions ? 'Comparing...' : 'Compare'}
                          </button>
                        </div>
                        {summaryComparison && (
                          <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-3 py-2 text-xs text-[var(--muted)]">
                            <p>
                              Word delta: {summaryComparison.word_delta >= 0 ? '+' : ''}
                              {summaryComparison.word_delta}
                            </p>
                            <p className="mt-1">
                              v{summaryComparison.from_version}: {summaryComparison.before_excerpt || '(empty)'}
                            </p>
                            <p className="mt-1">
                              v{summaryComparison.to_version}: {summaryComparison.after_excerpt || '(empty)'}
                            </p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                </div>

                <div className="mt-6 space-y-4">
                  <details className="disclosure" open>
                    <summary>Rule-by-rule results</summary>
                    <div className="disclosure-body overflow-x-auto">
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                            <th className="py-2">Rule</th>
                            <th className="py-2">Type</th>
                            <th className="py-2 text-right">Passed</th>
                            <th className="py-2 text-right">Failed</th>
                            <th className="py-2 text-right">Pass %</th>
                          </tr>
                        </thead>
                        <tbody>
                          {evaluateResult.rules.map((rule) => (
                            <tr key={rule.id} className="border-b border-[var(--border)]/50">
                              <td className="py-3 text-[var(--text)]">{rule.name}</td>
                              <td className="py-3 text-[var(--muted)]">{rule.type}</td>
                              <td className="py-3 text-right text-[var(--green)]">{rule.passed}</td>
                              <td className="py-3 text-right text-[var(--red)]">{rule.failed}</td>
                              <td className="py-3 text-right font-medium text-[var(--text)]">{rule.pass_pct}%</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </details>

                  {totalViolations > 0 && (
                    <details className="disclosure">
                      <summary>Raw violations ({totalViolations})</summary>
                      <div className="disclosure-body space-y-3">
                        {(evaluateResult.violations || []).map((violation, idx) => (
                          <div
                            key={`${violation.rule_id}-${violation.asset_key}-${idx}`}
                            className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/55 p-3"
                          >
                            <div className="text-sm text-[var(--text)]">
                              <span className="font-semibold">{violation.rule_name}</span> ({violation.rule_type}) on{' '}
                              <span className="font-mono">{violation.asset_key}</span>
                            </div>
                            <div className="mt-1 text-xs text-[var(--muted)]">
                              {fmtDate(violation.timestamp)} | Approved by {violation.bundle_approved_by || 'n/a'}
                            </div>
                            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded bg-[var(--bg)] p-3 text-xs text-[var(--text-muted)]">
                              {JSON.stringify(violation.evidence, null, 2)}
                            </pre>
                          </div>
                        ))}
                      </div>
                    </details>
                  )}
                </div>
              </section>
            )}
          </div>

          <aside className="section-panel animate-in">
            <h3 className="text-lg font-semibold text-[var(--text)]">Evaluation history</h3>
            <p className="mt-1 text-sm text-[var(--text-muted)]">
              Load a previous run to compare AI summaries and evidence.
            </p>
            <div className="mt-4 space-y-3">
              {evaluationHistory.length === 0 ? (
                <p className="text-sm text-[var(--muted)]">No persisted evaluations yet.</p>
              ) : (
                evaluationHistory.map((item) => (
                  <div
                    key={item.id}
                    className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/55 p-4"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-sm font-medium text-[var(--text)]">Evaluation #{item.id}</p>
                        <p className="mt-1 text-xs text-[var(--muted)]">{fmtDate(item.evaluated_at)}</p>
                        <p className="mt-2 text-xs text-[var(--text-muted)]">
                          Score {item.score ?? '-'}% | {item.violations_count} violations
                        </p>
                      </div>
                      <button
                        type="button"
                        className="btn-secondary text-sm"
                        onClick={() => handleLoadEvaluation(item.id)}
                      >
                        Load
                      </button>
                    </div>
                  </div>
                ))
              )}
            </div>
          </aside>
        </div>
      )}
    </main>
  );
}
