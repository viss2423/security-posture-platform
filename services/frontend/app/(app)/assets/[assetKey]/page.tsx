'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  generateAssetAIDiagnosis,
  getAssetAIDiagnosis,
  getAssetDetail,
  updateAssetByKey,
  type AIAssetDiagnosis,
  type AssetDetail,
} from '@/lib/api';
import { AssetDetailSkeleton } from '@/components/Skeleton';
import { ApiDownHint } from '@/components/EmptyState';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

type TabId = 'summary' | 'timeline' | 'evidence' | 'config';

function lastUpdatedAgo(lastSeen: string | null | undefined): string {
  if (!lastSeen) return '—';
  const sec = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  return `${Math.floor(sec / 3600)}h ago`;
}

const ALL_TABS: { id: TabId; label: string; mutateOnly?: boolean }[] = [
  { id: 'summary', label: 'Summary' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'config', label: 'Config', mutateOnly: true },
];

export default function AssetDetailPage() {
  const params = useParams();
  const assetKey = params.assetKey as string;
  const { canMutate } = useAuth();
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('summary');
  const [editOwner, setEditOwner] = useState('');
  const [editCriticality, setEditCriticality] = useState<'high' | 'medium' | 'low'>('medium');
  const [editName, setEditName] = useState('');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [aiDiagnosis, setAiDiagnosis] = useState<AIAssetDiagnosis | null>(null);
  const [loadingDiagnosis, setLoadingDiagnosis] = useState(false);
  const [generatingDiagnosis, setGeneratingDiagnosis] = useState(false);
  const [diagnosisMessage, setDiagnosisMessage] = useState<string | null>(null);

  useEffect(() => {
    if (!assetKey) return;
    setDiagnosisMessage(null);
    getAssetDetail(assetKey)
      .then((d) => {
        setDetail(d);
        setEditOwner(d?.state?.owner?.trim() ?? '');
        setEditCriticality((d?.state?.criticality as 'high' | 'medium' | 'low') ?? 'medium');
        setEditName(d?.state?.name?.trim() ?? '');
      })
      .catch((e) => setError(e.message));

    setLoadingDiagnosis(true);
    getAssetAIDiagnosis(assetKey)
      .then((out) => setAiDiagnosis(out))
      .catch((e) => {
        const message = e instanceof Error ? e.message : 'Failed to load AI diagnosis';
        if (!message.toLowerCase().includes('not found')) {
          setDiagnosisMessage(message);
        }
        setAiDiagnosis(null);
      })
      .finally(() => setLoadingDiagnosis(false));
  }, [assetKey]);

  const openEdit = () => {
    if (detail?.state) {
      setEditOwner(detail.state.owner?.trim() ?? '');
      setEditCriticality((detail.state.criticality as 'high' | 'medium' | 'low') ?? 'medium');
      setEditName(detail.state.name?.trim() ?? '');
    }
    setSaveError(null);
    setActiveTab('config');
  };
  const saveEdit = async () => {
    setSaveError(null);
    setSaving(true);
    try {
      await updateAssetByKey(assetKey, {
        owner: editOwner,
        criticality: editCriticality,
        name: editName || assetKey,
      });
      const d = await getAssetDetail(assetKey);
      setDetail(d);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const asset = detail?.state;
  const latencySloMs = detail?.latency_slo_ms ?? 200;
  const isSpike = (ms: number | undefined) => typeof ms === 'number' && ms > latencySloMs;

  const copyEvidence = () => {
    if (!detail?.evidence) return;
    navigator.clipboard.writeText(JSON.stringify(detail.evidence, null, 2));
  };
  const openSearchUrl = process.env.NEXT_PUBLIC_OPENSEARCH_DASHBOARDS_URL;

  const handleGenerateDiagnosis = async (force: boolean) => {
    setGeneratingDiagnosis(true);
    setDiagnosisMessage(null);
    try {
      const out = await generateAssetAIDiagnosis(assetKey, force);
      setAiDiagnosis(out);
      setDiagnosisMessage(out.cached ? 'Showing cached AI diagnosis.' : 'AI diagnosis generated.');
    } catch (e) {
      setDiagnosisMessage(e instanceof Error ? e.message : 'AI diagnosis generation failed');
    } finally {
      setGeneratingDiagnosis(false);
    }
  };

  return (
    <main className="page-shell">
      <nav className="mb-6 flex items-center gap-2 text-sm" aria-label="Breadcrumb">
        <Link href="/assets" className="font-medium text-[var(--muted)] transition hover:text-[var(--text)]">
          Assets
        </Link>
        <span className="text-[var(--border)]">/</span>
        <span className="font-medium text-[var(--text)] truncate max-w-[200px] sm:max-w-none" title={assetKey}>
          {assetKey}
        </span>
      </nav>
      <h1 className="page-title mb-2 animate-in truncate" title={assetKey}>{assetKey}</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {error}
          <ApiDownHint />
        </div>
      )}
      {asset && detail && (
        <>
          <p className="mb-6 max-w-3xl text-sm text-[var(--text-muted)] animate-in">
            Last updated {lastUpdatedAgo(asset.last_seen)}
            {detail.expected_interval_sec != null && <> | Expected interval every {detail.expected_interval_sec}s</>}
            {detail.data_completeness?.label_24h != null && (
              <> | Data completeness (24h): {detail.data_completeness.label_24h}{detail.data_completeness.pct_24h != null ? ` (${detail.data_completeness.pct_24h}%)` : ''}</>
            )}
          </p>

          <div className="mb-6 flex flex-wrap gap-2">
            {ALL_TABS.filter((t) => !t.mutateOnly || canMutate).map(({ id, label }) => (
              <button
                key={id}
                type="button"
                onClick={() => setActiveTab(id)}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  activeTab === id
                    ? 'bg-[var(--green)] text-white shadow-lg shadow-[var(--green-glow)]'
                    : 'border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--muted)] hover:bg-[var(--surface)]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {activeTab === 'summary' && (
            <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px] animate-in">
              <div className="space-y-6">
                <section className="section-panel">
                  <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap gap-2">
                      <span className={`badge ${(asset.status || 'unknown').toLowerCase()}`}>{asset.status || 'unknown'}</span>
                      {asset.criticality && <span className="stat-chip capitalize">{asset.criticality}</span>}
                      {asset.environment && <span className="stat-chip">{asset.environment}</span>}
                      {asset.posture_score != null && <span className="stat-chip">Posture {asset.posture_score}</span>}
                    </div>
                    {canMutate && (
                      <button type="button" onClick={openEdit} className="btn-secondary text-sm">
                        Edit metadata
                      </button>
                    )}
                  </div>
                  <div className="meta-grid">
                    <div className="kv-item">
                      <span className="kv-label">Reason</span>
                      <div className="kv-value">{detail.reason_display ?? asset.reason ?? '-'}</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Last seen</span>
                      <div className="kv-value">{asset.last_seen ? formatDateTime(asset.last_seen) : '-'}</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Staleness</span>
                      <div className="kv-value">{asset.staleness_seconds ?? '-'}s</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Owner</span>
                      <div className="kv-value">{asset.owner?.trim() || 'Unassigned'}</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Latency SLO</span>
                      <div className="kv-value">
                        {detail.latency_slo_ok ? `Passing < ${detail.latency_slo_ms}ms` : `Over ${detail.latency_slo_ms}ms`}
                      </div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">24h error rate</span>
                      <div className="kv-value">{detail.error_rate_24h ?? 0}%</div>
                    </div>
                  </div>
                </section>

                {detail.recommendations.length > 0 && (
                  <section className="section-panel">
                    <h2 className="section-title">Recommended actions</h2>
                    <ul className="space-y-3">
                      {detail.recommendations.map((recommendation, index) => (
                        <li key={index} className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/60 px-4 py-3 text-sm text-[var(--text)]">
                          {recommendation}
                        </li>
                      ))}
                    </ul>
                  </section>
                )}
              </div>

              <aside className="section-panel">
                <h2 className="section-title">AI diagnosis</h2>
                <p className="mb-4 text-sm text-[var(--text-muted)]">
                  Summarized operational diagnosis using current posture, recent events, and linked risk signals.
                </p>
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/60 p-4">
                  {loadingDiagnosis ? (
                    <p className="text-sm text-[var(--muted)]">Loading diagnosis...</p>
                  ) : aiDiagnosis?.diagnosis_text ? (
                    <>
                      <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">
                        {aiDiagnosis.diagnosis_text}
                      </p>
                      <p className="mt-3 text-xs text-[var(--muted)]">
                        Generated {formatDateTime(aiDiagnosis.generated_at)} via {aiDiagnosis.provider}/
                        {aiDiagnosis.model}
                      </p>
                    </>
                  ) : (
                    <p className="text-sm text-[var(--muted)]">
                      No AI diagnosis generated yet for this asset.
                    </p>
                  )}
                  {diagnosisMessage && (
                    <p
                      className={`mt-3 text-xs ${
                        diagnosisMessage.toLowerCase().includes('failed')
                          ? 'text-[var(--red)]'
                          : 'text-[var(--muted)]'
                      }`}
                    >
                      {diagnosisMessage}
                    </p>
                  )}
                  {canMutate && (
                    <div className="mt-4 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => handleGenerateDiagnosis(false)}
                        disabled={generatingDiagnosis}
                        className="btn-primary text-sm"
                      >
                        {generatingDiagnosis
                          ? 'Generating...'
                          : aiDiagnosis
                            ? 'Refresh diagnosis'
                            : 'Generate diagnosis'}
                      </button>
                      {aiDiagnosis && (
                        <button
                          type="button"
                          onClick={() => handleGenerateDiagnosis(true)}
                          disabled={generatingDiagnosis}
                          className="btn-secondary text-sm"
                        >
                          Force regenerate
                        </button>
                        )}
                    </div>
                  )}
                </div>
              </aside>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="animate-in">
              <h2 className="section-title">Timeline (last 24h)</h2>
              {detail.timeline.length === 0 ? (
                <div className="section-panel py-12 text-center text-sm text-[var(--muted)]">No events in the last 24h.</div>
              ) : (
                <div className="section-panel overflow-hidden p-0">
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse text-sm">
                      <thead>
                        <tr className="border-b border-[var(--border)] bg-[var(--bg)]/50">
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Time</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Status</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Code</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Latency (ms)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detail.timeline.slice(0, 50).map((ev, i) => {
                          const codeBad = ev.code != null && ev.code !== 200;
                          const latencySpike = isSpike(ev.latency_ms);
                          const isAnomaly = codeBad || latencySpike;
                          return (
                            <tr key={i} className={`border-b border-[var(--border)] ${isAnomaly ? 'bg-[var(--red)]/10' : ''}`}>
                              <td className="px-4 py-3">{ev['@timestamp'] ? formatDateTime(ev['@timestamp']) : '–'}</td>
                              <td className="px-4 py-3">{ev.status ?? '–'}</td>
                              <td className={`px-4 py-3 ${codeBad ? 'font-semibold text-[var(--red)]' : ''}`}>{ev.code ?? '–'}</td>
                              <td className={`px-4 py-3 ${latencySpike ? 'font-semibold text-[var(--amber)]' : ''}`}>
                                {ev.latency_ms ?? '–'}
                                {latencySpike && <span className="ml-1.5 text-xs text-[var(--amber)]">spike</span>}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  {detail.timeline.length > 50 && <p className="px-4 py-2 text-xs text-[var(--muted)]">Showing latest 50 of {detail.timeline.length}</p>}
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="animate-in">
              <h2 className="section-title">Last check (evidence)</h2>
              {!detail.evidence ? (
                <div className="section-panel py-12 text-center text-sm text-[var(--muted)]">No evidence yet.</div>
              ) : (
                <section className="section-panel">
                  <div className="mb-2 flex flex-wrap gap-2">
                    <button type="button" onClick={copyEvidence} className="btn-secondary text-sm">Copy JSON</button>
                    {openSearchUrl && (
                      <a href={openSearchUrl} target="_blank" rel="noopener noreferrer" className="btn-secondary text-sm">View in OpenSearch</a>
                    )}
                  </div>
                  <details className="disclosure" open>
                    <summary>Raw evidence JSON</summary>
                    <div className="disclosure-body">
                      <pre className="overflow-auto rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4 text-xs text-[var(--text-muted)]">{JSON.stringify(detail.evidence, null, 2)}</pre>
                    </div>
                  </details>
                </section>
              )}
            </div>
          )}

          {canMutate && activeTab === 'config' && (
            <div className="animate-in">
              <h2 className="section-title">Config</h2>
              <div className="section-panel">
                {saveError && <p className="mb-3 text-sm text-[var(--red)]">{saveError}</p>}
                <div className="flex max-w-sm flex-col gap-4">
                  <div>
                    <label className="mb-1.5 block text-sm font-medium text-[var(--muted)]">Owner</label>
                    <input type="text" value={editOwner} onChange={(e) => setEditOwner(e.target.value)} placeholder="e.g. Platform team" className="input" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-sm font-medium text-[var(--muted)]">Criticality</label>
                    <select value={editCriticality} onChange={(e) => setEditCriticality(e.target.value as 'high' | 'medium' | 'low')} className="input">
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-sm font-medium text-[var(--muted)]">Name</label>
                    <input type="text" value={editName} onChange={(e) => setEditName(e.target.value)} placeholder="Display name" className="input" />
                  </div>
                  <div className="flex gap-2">
                    <button type="button" onClick={saveEdit} disabled={saving} className="btn-primary">{saving ? 'Saving...' : 'Save'}</button>
                    <button type="button" onClick={() => { setSaveError(null); }} disabled={saving} className="btn-secondary">Cancel</button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
      {!detail && !error && <AssetDetailSkeleton />}
    </main>
  );
}
