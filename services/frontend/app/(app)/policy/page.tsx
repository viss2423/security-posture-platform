'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  approvePolicyBundle,
  createPolicyBundle,
  deletePolicyBundle,
  evaluatePolicyBundle,
  getPolicyBundle,
  getPolicyBundles,
  getPolicyEvaluation,
  getPolicyEvaluationHistory,
  updatePolicyBundle,
  type PolicyBundle,
  type PolicyBundleDetail,
  type PolicyEvaluateResult,
  type PolicyEvaluationSummary,
} from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';

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

function fmtDate(value?: string | null): string {
  if (!value) return '-';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return value;
  return d.toLocaleString();
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

  useEffect(() => {
    loadBundles();
  }, [loadBundles]);

  const openDetail = (id: number) => {
    Promise.all([getPolicyBundle(id), getPolicyEvaluationHistory(id)])
      .then(([b, history]) => {
        setDetail(b);
        setEditDef(b.definition);
        setEvaluateResult(null);
        setEvaluationHistory(history.items || []);
      })
      .catch((e) => setError(e.message));
  };

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
        return loadEvaluationHistory(detail.id);
      })
      .catch((e) => setError(e.message));
  };

  const handleLoadEvaluation = (evaluationId: number) => {
    if (!detail) return;
    setError(null);
    getPolicyEvaluation(detail.id, evaluationId)
      .then((r) => setEvaluateResult(r.result))
      .catch((e) => setError(e.message));
  };

  const handleDelete = () => {
    if (!detail || !confirm('Delete this bundle?')) return;
    setError(null);
    deletePolicyBundle(detail.id)
      .then(() => {
        setDetail(null);
        setEvaluateResult(null);
        setEvaluationHistory([]);
        loadBundles();
      })
      .catch((e) => setError(e.message));
  };

  const totalViolations = (evaluateResult?.violations || []).length;

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <h1 className="page-title">Policy</h1>
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
        <div className="card-glass mb-8 p-6 animate-in">
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
              className="card-glass cursor-pointer p-4 transition-all hover:ring-2 hover:ring-[var(--green)]/30"
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
        <div className="card-glass mt-10 p-6 animate-in">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
            <div>
              <h2 className="text-xl font-semibold text-[var(--text)]">{detail.name}</h2>
              <span
                className={`mt-1 inline-block rounded px-2 py-0.5 text-xs font-medium ${
                  detail.status === 'approved'
                    ? 'bg-[var(--green)]/20 text-[var(--green)]'
                    : 'bg-[var(--amber)]/20 text-[var(--amber)]'
                }`}
              >
                {detail.status}
              </span>
            </div>
            <div className="flex gap-2">
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
                <button type="button" onClick={handleDelete} className="btn-secondary text-[var(--red)]">
                  Delete
                </button>
              )}
              <button
                type="button"
                onClick={() => {
                  setDetail(null);
                  setEvaluateResult(null);
                  setEvaluationHistory([]);
                }}
                className="btn-secondary"
              >
                Close
              </button>
            </div>
          </div>

          {detail.description && <p className="mb-4 text-sm text-[var(--muted)]">{detail.description}</p>}

          <div>
            <label className="mb-1 block text-sm font-medium text-[var(--muted)]">Definition (YAML)</label>
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

          <div className="mt-8 border-t border-[var(--border)] pt-6">
            <h3 className="mb-2 text-lg font-semibold text-[var(--text)]">Recent evaluations</h3>
            {evaluationHistory.length === 0 ? (
              <p className="text-sm text-[var(--muted)]">No persisted evaluations yet.</p>
            ) : (
              <div className="space-y-2">
                {evaluationHistory.map((item) => (
                  <div
                    key={item.id}
                    className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-[var(--border)] px-3 py-2 text-sm"
                  >
                    <div className="text-[var(--muted)]">
                      #{item.id} - {fmtDate(item.evaluated_at)} - score {item.score ?? '-'}% -{' '}
                      {item.violations_count} violations
                    </div>
                    <button
                      type="button"
                      className="btn-secondary"
                      onClick={() => handleLoadEvaluation(item.id)}
                    >
                      Load
                    </button>
                  </div>
                ))}
              </div>
            )}
          </div>

          {evaluateResult && (
            <div className="mt-8 border-t border-[var(--border)] pt-6">
              <h3 className="mb-2 text-lg font-semibold text-[var(--text)]">Evaluation result</h3>
              <p className="mb-2 text-2xl font-bold text-[var(--green)]">Score: {evaluateResult.score}%</p>
              <p className="mb-4 text-sm text-[var(--muted)]">
                Evaluation #{evaluateResult.evaluation_id ?? '-'} - evaluated {fmtDate(evaluateResult.evaluated_at)} -
                approved by {evaluateResult.bundle_approved_by || 'n/a'} - {totalViolations} violations
              </p>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[var(--border)]">
                      <th className="py-2 text-left font-medium text-[var(--muted)]">Rule</th>
                      <th className="py-2 text-left font-medium text-[var(--muted)]">Type</th>
                      <th className="py-2 text-right font-medium text-[var(--muted)]">Passed</th>
                      <th className="py-2 text-right font-medium text-[var(--muted)]">Failed</th>
                      <th className="py-2 text-right font-medium text-[var(--muted)]">Pass %</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evaluateResult.rules.map((r) => (
                      <tr key={r.id} className="border-b border-[var(--border)]/50">
                        <td className="py-2 text-[var(--text)]">{r.name}</td>
                        <td className="py-2 text-[var(--muted)]">{r.type}</td>
                        <td className="py-2 text-right text-[var(--green)]">{r.passed}</td>
                        <td className="py-2 text-right text-[var(--red)]">{r.failed}</td>
                        <td className="py-2 text-right font-medium">{r.pass_pct}%</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {totalViolations > 0 && (
                <div className="mt-6">
                  <h4 className="mb-2 text-base font-semibold text-[var(--text)]">Violations</h4>
                  <div className="space-y-3">
                    {(evaluateResult.violations || []).map((v, idx) => (
                      <div key={`${v.rule_id}-${v.asset_key}-${idx}`} className="rounded-lg border border-[var(--border)] p-3">
                        <div className="text-sm text-[var(--text)]">
                          <span className="font-semibold">{v.rule_name}</span> ({v.rule_type}) on{' '}
                          <span className="font-mono">{v.asset_key}</span>
                        </div>
                        <div className="mt-1 text-xs text-[var(--muted)]">
                          Timestamp: {fmtDate(v.timestamp)} | Approved by: {v.bundle_approved_by || 'n/a'}
                        </div>
                        <pre className="mt-2 overflow-x-auto whitespace-pre-wrap rounded bg-[var(--bg)] p-2 text-xs text-[var(--muted)]">
                          {JSON.stringify(v.evidence, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </main>
  );
}
