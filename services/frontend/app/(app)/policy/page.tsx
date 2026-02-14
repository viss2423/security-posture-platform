'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  getPolicyBundles,
  getPolicyBundle,
  createPolicyBundle,
  updatePolicyBundle,
  approvePolicyBundle,
  evaluatePolicyBundle,
  deletePolicyBundle,
  type PolicyBundle,
  type PolicyBundleDetail,
  type PolicyEvaluateResult,
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
    type: no_open_findings
    params:
      severity: critical
  - id: min-score
    name: "Minimum posture score 70"
    type: posture_score_min
    params:
      min_score: 70
`;

export default function PolicyPage() {
  const { canMutate, isAdmin } = useAuth();
  const [bundles, setBundles] = useState<PolicyBundle[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [detail, setDetail] = useState<PolicyBundleDetail | null>(null);
  const [evaluateResult, setEvaluateResult] = useState<PolicyEvaluateResult | null>(null);
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

  useEffect(() => {
    loadBundles();
  }, [loadBundles]);

  const openDetail = (id: number) => {
    getPolicyBundle(id)
      .then((b) => {
        setDetail(b);
        setEditDef(b.definition);
        setEvaluateResult(null);
      })
      .catch((e) => setError(e.message));
  };

  const handleCreate = () => {
    if (!createName.trim()) return;
    setError(null);
    createPolicyBundle({ name: createName.trim(), description: createDesc.trim() || undefined, definition: createDef })
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
      .then(setEvaluateResult)
      .catch((e) => setError(e.message));
  };

  const handleDelete = () => {
    if (!detail || !confirm('Delete this bundle?')) return;
    setError(null);
    deletePolicyBundle(detail.id)
      .then(() => {
        setDetail(null);
        setEvaluateResult(null);
        loadBundles();
      })
      .catch((e) => setError(e.message));
  };

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <div className="mb-8 flex flex-wrap items-center justify-between gap-4">
        <h1 className="page-title">Policy</h1>
        {canMutate && (
          <button
            type="button"
            onClick={() => setShowCreate(true)}
            className="btn-primary"
          >
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
          <h2 className="text-lg font-semibold text-[var(--text)] mb-4">New policy bundle</h2>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-[var(--muted)] mb-1">Name</label>
              <input
                type="text"
                value={createName}
                onChange={(e) => setCreateName(e.target.value)}
                placeholder="e.g. Default security rules"
                className="input w-full"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[var(--muted)] mb-1">Description (optional)</label>
              <input
                type="text"
                value={createDesc}
                onChange={(e) => setCreateDesc(e.target.value)}
                className="input w-full"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-[var(--muted)] mb-1">YAML definition (rules list)</label>
              <textarea
                value={createDef}
                onChange={(e) => setCreateDef(e.target.value)}
                rows={14}
                className="input w-full font-mono text-sm"
                spellCheck={false}
              />
            </div>
            <div className="flex gap-2">
              <button type="button" onClick={handleCreate} className="btn-primary" disabled={!createName.trim()}>
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
        <p className="text-[var(--muted)]">Loading…</p>
      ) : bundles.length === 0 ? (
        <EmptyState
          title="No policy bundles"
          description="Create a bundle to define policy-as-code rules (asset status, posture score, open findings). Evaluate against current posture and findings."
          action={canMutate ? <button type="button" onClick={() => setShowCreate(true)} className="btn-primary">New bundle</button> : undefined}
        />
      ) : (
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {bundles.map((b) => (
            <div
              key={b.id}
              className="card-glass p-4 cursor-pointer transition-all hover:ring-2 hover:ring-[var(--green)]/30"
              onClick={() => openDetail(b.id)}
            >
              <div className="flex items-start justify-between gap-2">
                <div>
                  <h3 className="font-semibold text-[var(--text)]">{b.name}</h3>
                  {b.description && <p className="mt-1 text-sm text-[var(--muted)] line-clamp-2">{b.description}</p>}
                </div>
                <span
                  className={`shrink-0 rounded px-2 py-0.5 text-xs font-medium ${
                    b.status === 'approved' ? 'bg-[var(--green)]/20 text-[var(--green)]' : 'bg-[var(--amber)]/20 text-[var(--amber)]'
                  }`}
                >
                  {b.status}
                </span>
              </div>
              <p className="mt-2 text-xs text-[var(--muted)]">
                Updated {b.updated_at ? new Date(b.updated_at).toLocaleDateString() : '–'}
                {b.approved_by && ` · Approved by ${b.approved_by}`}
              </p>
            </div>
          ))}
        </div>
      )}

      {detail && (
        <div className="card-glass mt-10 p-6 animate-in">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
            <div>
              <h2 className="text-xl font-semibold text-[var(--text)]">{detail.name}</h2>
              <span className={`mt-1 inline-block rounded px-2 py-0.5 text-xs font-medium ${detail.status === 'approved' ? 'bg-[var(--green)]/20 text-[var(--green)]' : 'bg-[var(--amber)]/20 text-[var(--amber)]'}`}>
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
              <button type="button" onClick={() => { setDetail(null); setEvaluateResult(null); }} className="btn-secondary">
                Close
              </button>
            </div>
          </div>
          {detail.description && <p className="text-sm text-[var(--muted)] mb-4">{detail.description}</p>}
          <div>
            <label className="block text-sm font-medium text-[var(--muted)] mb-1">Definition (YAML)</label>
            {canMutate && detail.status === 'draft' ? (
              <textarea
                value={editDef}
                onChange={(e) => setEditDef(e.target.value)}
                rows={14}
                className="input w-full font-mono text-sm"
                spellCheck={false}
              />
            ) : (
              <pre className="rounded-lg border border-[var(--border)] bg-[var(--bg)] p-4 text-sm overflow-x-auto whitespace-pre-wrap font-mono text-[var(--text)]">
                {detail.definition}
              </pre>
            )}
          </div>

          {evaluateResult && (
            <div className="mt-8 pt-6 border-t border-[var(--border)]">
              <h3 className="text-lg font-semibold text-[var(--text)] mb-2">Evaluation result</h3>
              <p className="text-2xl font-bold text-[var(--green)] mb-4">Score: {evaluateResult.score}%</p>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[var(--border)]">
                      <th className="text-left py-2 font-medium text-[var(--muted)]">Rule</th>
                      <th className="text-left py-2 font-medium text-[var(--muted)]">Type</th>
                      <th className="text-right py-2 font-medium text-[var(--muted)]">Passed</th>
                      <th className="text-right py-2 font-medium text-[var(--muted)]">Failed</th>
                      <th className="text-right py-2 font-medium text-[var(--muted)]">Pass %</th>
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
            </div>
          )}
        </div>
      )}
    </main>
  );
}
