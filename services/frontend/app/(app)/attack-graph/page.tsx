'use client';

import { useEffect, useMemo, useState } from 'react';
import {
  getAttackGraphIncident,
  getIncidents,
  queryAttackGraph,
  type AttackGraph,
  type IncidentListItem,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';

function relationBadge(value: string): JSX.Element {
  const text = String(value || '').toLowerCase();
  const className =
    text.includes('target') || text.includes('contain')
      ? 'bg-cyan-300/20 text-cyan-100 border-cyan-300/30'
      : text.includes('auth') || text.includes('execute')
        ? 'bg-emerald-300/20 text-emerald-100 border-emerald-300/30'
        : 'bg-[var(--surface-elevated)] text-[var(--muted)] border-[var(--border)]';
  return (
    <span className={`rounded-full border px-2 py-0.5 text-xs font-medium uppercase ${className}`}>
      {text || 'linked'}
    </span>
  );
}

export default function AttackGraphPage() {
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [incidentId, setIncidentId] = useState<string>('');
  const [assetKey, setAssetKey] = useState('');
  const [lookbackHours, setLookbackHours] = useState('72');
  const [graph, setGraph] = useState<AttackGraph | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getIncidents({ limit: 100 })
      .then((result) => setIncidents(result.items || []))
      .catch(() => setIncidents([]));
  }, []);

  const runIncidentGraph = async () => {
    const parsedIncidentId = Number(incidentId);
    const parsedLookback = Math.max(1, Math.min(720, Number(lookbackHours || 72)));
    if (Number.isNaN(parsedIncidentId) || parsedIncidentId <= 0) {
      setError('Select a valid incident first');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const out = await getAttackGraphIncident(parsedIncidentId, parsedLookback);
      setGraph(out);
    } catch (graphError) {
      setError(graphError instanceof Error ? graphError.message : 'Failed to load incident graph');
      setGraph(null);
    } finally {
      setLoading(false);
    }
  };

  const runAssetGraph = async () => {
    const normalizedAssetKey = assetKey.trim();
    const parsedLookback = Math.max(1, Math.min(720, Number(lookbackHours || 72)));
    if (!normalizedAssetKey) {
      setError('Asset key is required for asset graph query');
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const out = await queryAttackGraph({
        asset_key: normalizedAssetKey,
        lookback_hours: parsedLookback,
      });
      setGraph(out);
    } catch (graphError) {
      setError(graphError instanceof Error ? graphError.message : 'Failed to load asset graph');
      setGraph(null);
    } finally {
      setLoading(false);
    }
  };

  const summary = useMemo(() => graph?.summary || {}, [graph]);

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <span className="stat-chip-strong">Attack Graph</span>
            <h1 className="hero-title mt-3">Investigation Path Visualizer</h1>
            <p className="hero-copy">
              Reconstruct attacker movement and pivot context from incidents, alerts, assets, and
              observed communications.
            </p>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Nodes</p>
              <p className="hero-stat-value">{graph?.nodes.length ?? 0}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Edges</p>
              <p className="hero-stat-value">{graph?.edges.length ?? 0}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Kill-chain phases</p>
              <p className="hero-stat-value">{graph?.kill_chain.length ?? 0}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Incident source</p>
              <p className="hero-stat-value">
                {summary.incident_id != null ? String(summary.incident_id) : '--'}
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

      <section className="grid gap-6 xl:grid-cols-2">
        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Incident query</h2>
              <p className="section-head-copy">Build graph from incident evidence and linked alerts.</p>
            </div>
          </div>
          <div className="grid gap-3">
            <label className="text-sm text-[var(--muted)]">
              Incident
              <select
                value={incidentId}
                onChange={(event) => setIncidentId(event.target.value)}
                className="input mt-1"
              >
                <option value="">Select incident</option>
                {incidents.map((incident) => (
                  <option key={incident.id} value={incident.id}>
                    #{incident.id} | {incident.severity} | {incident.status} |{' '}
                    {formatDateTime(incident.created_at)}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-sm text-[var(--muted)]">
              Lookback hours
              <input
                type="number"
                min={1}
                max={720}
                value={lookbackHours}
                onChange={(event) => setLookbackHours(event.target.value)}
                className="input mt-1"
              />
            </label>
            <button type="button" onClick={() => void runIncidentGraph()} className="btn-primary text-sm">
              Load incident graph
            </button>
          </div>
        </div>

        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Asset query</h2>
              <p className="section-head-copy">Pivot from one asset to related signals and communications.</p>
            </div>
          </div>
          <div className="grid gap-3">
            <label className="text-sm text-[var(--muted)]">
              Asset key
              <input
                type="text"
                value={assetKey}
                onChange={(event) => setAssetKey(event.target.value)}
                className="input mt-1"
                placeholder="e.g. secplat-api"
              />
            </label>
            <label className="text-sm text-[var(--muted)]">
              Lookback hours
              <input
                type="number"
                min={1}
                max={720}
                value={lookbackHours}
                onChange={(event) => setLookbackHours(event.target.value)}
                className="input mt-1"
              />
            </label>
            <button type="button" onClick={() => void runAssetGraph()} className="btn-secondary text-sm">
              Load asset graph
            </button>
          </div>
        </div>
      </section>

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">Kill-chain coverage</h2>
            <p className="section-head-copy">Detected ATT&CK technique phases in this graph scope.</p>
          </div>
        </div>
        {graph && graph.kill_chain.length > 0 ? (
          <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-5">
            {graph.kill_chain.map((item) => (
              <div key={item.phase} className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
                <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">{item.phase}</p>
                <p className="mt-1 text-2xl font-semibold text-[var(--text)]">{item.count}</p>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-sm text-[var(--muted)]">No kill-chain mapping available for the selected graph.</p>
        )}
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Nodes</h2>
              <p className="section-head-copy">Assets, identities, network indicators, and detections.</p>
            </div>
            <span className="stat-chip">{graph?.nodes.length ?? 0}</span>
          </div>
          {!graph || graph.nodes.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">Run an incident or asset query to load graph nodes.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                    <th className="px-4 py-3">ID</th>
                    <th className="px-4 py-3">Type</th>
                    <th className="px-4 py-3">Label</th>
                  </tr>
                </thead>
                <tbody>
                  {graph.nodes.map((node) => (
                    <tr key={node.id} className="border-b border-[var(--border)]/40">
                      <td className="px-4 py-3 font-mono text-xs">{node.id}</td>
                      <td className="px-4 py-3 uppercase">{node.type}</td>
                      <td className="px-4 py-3">{node.label}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Edges</h2>
              <p className="section-head-copy">Relationship path between discovered entities.</p>
            </div>
            <span className="stat-chip">{graph?.edges.length ?? 0}</span>
          </div>
          {!graph || graph.edges.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">Run an incident or asset query to load graph edges.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                    <th className="px-4 py-3">Source</th>
                    <th className="px-4 py-3">Relation</th>
                    <th className="px-4 py-3">Target</th>
                    <th className="px-4 py-3">Weight</th>
                  </tr>
                </thead>
                <tbody>
                  {graph.edges.map((edge) => (
                    <tr key={edge.id} className="border-b border-[var(--border)]/40">
                      <td className="px-4 py-3 font-mono text-xs">{edge.source}</td>
                      <td className="px-4 py-3">{relationBadge(edge.relation)}</td>
                      <td className="px-4 py-3 font-mono text-xs">{edge.target}</td>
                      <td className="px-4 py-3">{edge.weight ?? 1}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </section>

      {loading && <p className="text-sm text-[var(--muted)]">Loading graph...</p>}
    </main>
  );
}
