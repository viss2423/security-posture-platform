'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import { getAssetDetail, updateAssetByKey, type AssetDetail } from '@/lib/api';
import { AssetDetailSkeleton } from '@/components/Skeleton';
import { formatDateTime } from '@/lib/format';

function lastUpdatedAgo(lastSeen: string | null | undefined): string {
  if (!lastSeen) return '—';
  const sec = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  return `${Math.floor(sec / 3600)}h ago`;
}

export default function AssetDetailPage() {
  const params = useParams();
  const assetKey = params.assetKey as string;
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [now, setNow] = useState(Date.now());
  const [editing, setEditing] = useState(false);
  const [editOwner, setEditOwner] = useState('');
  const [editCriticality, setEditCriticality] = useState<'high' | 'medium' | 'low'>('medium');
  const [editName, setEditName] = useState('');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!assetKey) return;
    getAssetDetail(assetKey)
      .then((d) => {
        setDetail(d);
        setEditOwner(d?.state?.owner?.trim() ?? '');
        setEditCriticality((d?.state?.criticality as 'high' | 'medium' | 'low') ?? 'medium');
        setEditName(d?.state?.name?.trim() ?? '');
      })
      .catch((e) => setError(e.message));
  }, [assetKey]);

  const openEdit = () => {
    if (detail?.state) {
      setEditOwner(detail.state.owner?.trim() ?? '');
      setEditCriticality((detail.state.criticality as 'high' | 'medium' | 'low') ?? 'medium');
      setEditName(detail.state.name?.trim() ?? '');
    }
    setSaveError(null);
    setEditing(true);
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
      setEditing(false);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  useEffect(() => {
    if (!detail?.state?.last_seen) return;
    const t = setInterval(() => setNow(Date.now()), 10000);
    return () => clearInterval(t);
  }, [detail?.state?.last_seen]);

  const asset = detail?.state;
  const latencySloMs = detail?.latency_slo_ms ?? 200;
  const isSpike = (ms: number | undefined) => typeof ms === 'number' && ms > latencySloMs;

  const copyEvidence = () => {
    if (!detail?.evidence) return;
    navigator.clipboard.writeText(JSON.stringify(detail.evidence, null, 2));
  };
  const openSearchUrl = process.env.NEXT_PUBLIC_OPENSEARCH_DASHBOARDS_URL;

  return (
    <main className="mx-auto max-w-4xl px-4 py-10 sm:px-6 lg:px-8">
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
        </div>
      )}
      {asset && detail && (
        <>
          <p className="mb-6 text-sm text-[var(--muted)] animate-in">
            Last updated {lastUpdatedAgo(asset.last_seen)}
            {detail.expected_interval_sec != null && (
              <> · Expected interval: every {detail.expected_interval_sec}s</>
            )}
            {detail.data_completeness?.label_24h != null && (
              <> · Data completeness (24h): {detail.data_completeness.label_24h}{detail.data_completeness.pct_24h != null ? ` (${detail.data_completeness.pct_24h}%)` : ''}</>
            )}
          </p>
          <div className="card mb-8 animate-in">
            <dl className="grid grid-cols-[auto_1fr] gap-x-6 gap-y-3 text-sm">
              <dt className="text-[var(--muted)]">Status</dt>
              <dd><span className={`badge ${(asset.status || 'unknown').toLowerCase()}`}>{asset.status || 'unknown'}</span></dd>
              <dt className="text-[var(--muted)]">Reason</dt>
              <dd>{detail.reason_display ?? asset.reason ?? '–'}</dd>
              <dt className="text-[var(--muted)]">Score</dt>
              <dd>{asset.posture_score ?? '–'}</dd>
              <dt className="text-[var(--muted)]">Criticality</dt>
              <dd className="capitalize">{asset.criticality ?? '–'}</dd>
              <dt className="text-[var(--muted)]">Last seen</dt>
              <dd>{asset.last_seen ? formatDateTime(asset.last_seen) : '–'}</dd>
              <dt className="text-[var(--muted)]">Staleness (s)</dt>
              <dd>{asset.staleness_seconds ?? '–'}</dd>
              <dt className="text-[var(--muted)]">Environment</dt>
              <dd>{asset.environment ?? '–'}</dd>
              <dt className="text-[var(--muted)]">Owner</dt>
              <dd>{asset.owner?.trim() || 'Unassigned'}</dd>
              <dt className="text-[var(--muted)]">Latency SLO</dt>
              <dd>{detail.latency_slo_ok ? <span className="text-[var(--green)]">Pass &lt; {detail.latency_slo_ms}ms</span> : <span className="text-[var(--red)]">Over &gt; {detail.latency_slo_ms}ms</span>}</dd>
              <dt className="text-[var(--muted)]">Error rate (24h)</dt>
              <dd>{detail.error_rate_24h ?? 0}%</dd>
            </dl>
            {!editing && (
              <div className="mt-4">
                <button type="button" onClick={openEdit} className="btn-secondary text-sm">
                  Edit metadata (owner, criticality, name)
                </button>
              </div>
            )}
          </div>

          {editing && (
            <div className="card mb-8">
              <h2 className="section-title">Edit metadata</h2>
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
                  <button type="button" onClick={saveEdit} disabled={saving} className="btn-primary">{saving ? 'Saving…' : 'Save'}</button>
                  <button type="button" onClick={() => { setEditing(false); setSaveError(null); }} disabled={saving} className="btn-secondary">Cancel</button>
                </div>
              </div>
            </div>
          )}

          {detail.recommendations.length > 0 && (
            <section className="mb-8">
              <h2 className="section-title">Recommended actions</h2>
              <ul className="card list-inside list-disc space-y-1">
                {detail.recommendations.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            </section>
          )}

          {detail.timeline.length > 0 && (
            <section className="mb-8">
              <h2 className="section-title">Timeline (last 24h)</h2>
              <div className="card overflow-hidden p-0">
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
                      {detail.timeline.slice(0, 20).map((ev, i) => {
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
                {detail.timeline.length > 20 && <p className="px-4 py-2 text-xs text-[var(--muted)]">Showing latest 20 of {detail.timeline.length}</p>}
              </div>
            </section>
          )}

          {detail.evidence && (
            <section className="mb-8">
              <h2 className="section-title">Last check (evidence)</h2>
              <div className="mb-2 flex flex-wrap gap-2">
                <button type="button" onClick={copyEvidence} className="btn-secondary text-sm">Copy JSON</button>
                {openSearchUrl && (
                  <a href={openSearchUrl} target="_blank" rel="noopener noreferrer" className="btn-secondary text-sm">View in OpenSearch</a>
                )}
              </div>
              <pre className="overflow-auto rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4 text-xs text-[var(--text-muted)]">{JSON.stringify(detail.evidence, null, 2)}</pre>
            </section>
          )}
        </>
      )}
      {!detail && !error && (
        <AssetDetailSkeleton />
      )}
    </main>
  );
}
