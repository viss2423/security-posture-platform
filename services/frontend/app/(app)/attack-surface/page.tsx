'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  getAttackSurfaceCertificates,
  getAttackSurfaceDiscoveryRuns,
  getAttackSurfaceDrift,
  getAttackSurfaceExposures,
  getAttackSurfaceHosts,
  getAttackSurfaceRelationships,
  getAttackSurfaceServices,
  runAttackSurfaceDiscovery,
  upsertAttackSurfaceRelationship,
  type AttackSurfaceCertificate,
  type AttackSurfaceDiscoveryRun,
  type AttackSurfaceDriftEvent,
  type AttackSurfaceExposure,
  type AttackSurfaceHost,
  type AttackSurfaceRelationship,
  type AttackSurfaceService,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';

function statusBadge(status: string): JSX.Element {
  const value = String(status || '').toLowerCase();
  const classes =
    value === 'done'
      ? 'bg-[var(--green)]/20 text-[var(--green)] border border-[var(--green)]/20'
      : value === 'failed'
        ? 'bg-[var(--red)]/20 text-[var(--red)] border border-[var(--red)]/20'
        : value === 'running'
          ? 'bg-[var(--amber)]/20 text-[var(--amber)] border border-[var(--amber)]/20'
          : 'bg-[var(--surface-elevated)] text-[var(--muted)] border border-[var(--border)]';
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-[0.06em] ${classes}`}>
      {value || 'unknown'}
    </span>
  );
}

function severityBadge(severity: string): JSX.Element {
  const value = String(severity || '').toLowerCase();
  const classes =
    value === 'critical' || value === 'high'
      ? 'bg-[var(--red)]/20 text-[var(--red)] border border-[var(--red)]/20'
      : value === 'medium'
        ? 'bg-[var(--amber)]/20 text-[var(--amber)] border border-[var(--amber)]/20'
        : 'bg-[var(--green)]/20 text-[var(--green)] border border-[var(--green)]/20';
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-[0.06em] ${classes}`}>
      {value || 'low'}
    </span>
  );
}

export default function AttackSurfacePage() {
  const { canMutate } = useAuth();
  const [runs, setRuns] = useState<AttackSurfaceDiscoveryRun[]>([]);
  const [exposures, setExposures] = useState<AttackSurfaceExposure[]>([]);
  const [drift, setDrift] = useState<AttackSurfaceDriftEvent[]>([]);
  const [relationships, setRelationships] = useState<AttackSurfaceRelationship[]>([]);
  const [hosts, setHosts] = useState<AttackSurfaceHost[]>([]);
  const [services, setServices] = useState<AttackSurfaceService[]>([]);
  const [certificates, setCertificates] = useState<AttackSurfaceCertificate[]>([]);
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);

  const [domainsInput, setDomainsInput] = useState('alpha.example.test,beta.example.test');
  const [certSalt, setCertSalt] = useState('');
  const [runningDiscovery, setRunningDiscovery] = useState(false);
  const [savingRelationship, setSavingRelationship] = useState(false);

  const [relationshipSource, setRelationshipSource] = useState('');
  const [relationshipTarget, setRelationshipTarget] = useState('');
  const [relationshipType, setRelationshipType] = useState('talks_to');
  const [relationshipConfidence, setRelationshipConfidence] = useState('0.8');

  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const loadOverview = useCallback(async () => {
    setLoading(true);
    try {
      const [runsResult, exposureResult, driftResult, relationshipResult] = await Promise.all([
        getAttackSurfaceDiscoveryRuns({ limit: 50 }),
        getAttackSurfaceExposures({ limit: 200 }),
        getAttackSurfaceDrift({ limit: 200 }),
        getAttackSurfaceRelationships({ limit: 200 }),
      ]);
      const runItems = runsResult.items || [];
      setRuns(runItems);
      setExposures(exposureResult.items || []);
      setDrift(driftResult.items || []);
      setRelationships(relationshipResult.items || []);
      setError(null);
      if (!selectedRunId && runItems.length > 0) {
        setSelectedRunId(runItems[0].run_id);
      }
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load attack-surface data');
    } finally {
      setLoading(false);
    }
  }, [selectedRunId]);

  const loadRunDetails = useCallback(async (runId: number | null) => {
    if (!runId) {
      setHosts([]);
      setServices([]);
      setCertificates([]);
      return;
    }
    try {
      const [hostResult, serviceResult, certResult] = await Promise.all([
        getAttackSurfaceHosts({ run_id: runId, limit: 1000 }),
        getAttackSurfaceServices({ run_id: runId, limit: 2000 }),
        getAttackSurfaceCertificates({ run_id: runId, limit: 1000 }),
      ]);
      setHosts(hostResult.items || []);
      setServices(serviceResult.items || []);
      setCertificates(certResult.items || []);
    } catch (detailError) {
      setError(detailError instanceof Error ? detailError.message : 'Failed to load discovery artifacts');
    }
  }, []);

  useEffect(() => {
    void loadOverview();
    const timer = window.setInterval(() => {
      void loadOverview();
    }, 30000);
    return () => window.clearInterval(timer);
  }, [loadOverview]);

  useEffect(() => {
    void loadRunDetails(selectedRunId);
  }, [loadRunDetails, selectedRunId]);

  const runDiscovery = async () => {
    if (!canMutate) return;
    const domains = domainsInput
      .split(',')
      .map((item) => item.trim().toLowerCase())
      .filter(Boolean);
    setRunningDiscovery(true);
    setError(null);
    setMessage(null);
    try {
      const out = await runAttackSurfaceDiscovery({
        domains,
        cert_salt: certSalt.trim() || undefined,
      });
      setMessage(
        `Discovery run ${out.run_id} completed. Hosts ${
          Number(out.summary?.hosts_discovered || 0) || 0
        }, drift ${Number(out.summary?.drift_events || 0) || 0}.`
      );
      await loadOverview();
      setSelectedRunId(out.run_id);
    } catch (runError) {
      setError(runError instanceof Error ? runError.message : 'Failed to run discovery');
    } finally {
      setRunningDiscovery(false);
    }
  };

  const saveRelationship = async () => {
    if (!canMutate) return;
    const source = relationshipSource.trim();
    const target = relationshipTarget.trim();
    const relationType = relationshipType.trim().toLowerCase();
    if (!source || !target || !relationType) {
      setError('Relationship source, target, and type are required');
      return;
    }
    const confidence = Number(relationshipConfidence);
    if (Number.isNaN(confidence)) {
      setError('Relationship confidence must be numeric');
      return;
    }
    setSavingRelationship(true);
    setError(null);
    setMessage(null);
    try {
      await upsertAttackSurfaceRelationship({
        source_asset_key: source,
        target_asset_key: target,
        relation_type: relationType,
        confidence,
      });
      setMessage(`Relationship ${source} -> ${target} (${relationType}) saved.`);
      await loadOverview();
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Failed to save relationship');
    } finally {
      setSavingRelationship(false);
    }
  };

  const selectedRun = useMemo(
    () => runs.find((item) => item.run_id === selectedRunId) || null,
    [runs, selectedRunId]
  );

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <span className="stat-chip-strong">Attack Surface</span>
            <h1 className="hero-title mt-3">Discovery and Drift Workspace</h1>
            <p className="hero-copy">
              Track exposed hosts and services, monitor infrastructure drift, and maintain service
              dependency relationships.
            </p>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Discovery runs</p>
              <p className="hero-stat-value">{runs.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Exposures</p>
              <p className="hero-stat-value">{exposures.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Drift events</p>
              <p className="hero-stat-value">{drift.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Relationships</p>
              <p className="hero-stat-value">{relationships.length}</p>
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
        <div className="rounded-xl border border-cyan-300/35 bg-cyan-300/12 px-4 py-3 text-sm text-[var(--text)]">
          {message}
        </div>
      )}

      <section className="grid gap-6 xl:grid-cols-2">
        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Discovery control</h2>
              <p className="section-head-copy">Run inventory discovery and certificate collection.</p>
            </div>
          </div>
          <div className="grid gap-3">
            <label className="text-sm text-[var(--muted)]">
              Domain list (comma separated)
              <input
                type="text"
                value={domainsInput}
                onChange={(event) => setDomainsInput(event.target.value)}
                className="input mt-1"
              />
            </label>
            <label className="text-sm text-[var(--muted)]">
              Certificate seed (optional, for drift simulation)
              <input
                type="text"
                value={certSalt}
                onChange={(event) => setCertSalt(event.target.value)}
                className="input mt-1"
              />
            </label>
            {canMutate && (
              <button
                type="button"
                onClick={() => void runDiscovery()}
                disabled={runningDiscovery}
                className="btn-primary text-sm"
              >
                {runningDiscovery ? 'Running...' : 'Run discovery'}
              </button>
            )}
          </div>
        </div>

        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Asset relationship mapper</h2>
              <p className="section-head-copy">Capture service-to-service dependencies.</p>
            </div>
          </div>
          <div className="grid gap-3">
            <label className="text-sm text-[var(--muted)]">
              Source asset key
              <input
                type="text"
                value={relationshipSource}
                onChange={(event) => setRelationshipSource(event.target.value)}
                className="input mt-1"
              />
            </label>
            <label className="text-sm text-[var(--muted)]">
              Target asset key
              <input
                type="text"
                value={relationshipTarget}
                onChange={(event) => setRelationshipTarget(event.target.value)}
                className="input mt-1"
              />
            </label>
            <div className="grid gap-3 md:grid-cols-2">
              <label className="text-sm text-[var(--muted)]">
                Relation type
                <input
                  type="text"
                  value={relationshipType}
                  onChange={(event) => setRelationshipType(event.target.value)}
                  className="input mt-1"
                />
              </label>
              <label className="text-sm text-[var(--muted)]">
                Confidence (0-1)
                <input
                  type="text"
                  value={relationshipConfidence}
                  onChange={(event) => setRelationshipConfidence(event.target.value)}
                  className="input mt-1"
                />
              </label>
            </div>
            {canMutate && (
              <button
                type="button"
                onClick={() => void saveRelationship()}
                disabled={savingRelationship}
                className="btn-secondary text-sm"
              >
                {savingRelationship ? 'Saving...' : 'Save relationship'}
              </button>
            )}
          </div>
        </div>
      </section>

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">Exposure inventory</h2>
            <p className="section-head-copy">Prioritized by exposure score.</p>
          </div>
        </div>
        {exposures.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No exposure records yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">Asset</th>
                  <th className="px-4 py-3">Environment</th>
                  <th className="px-4 py-3">Internet exposed</th>
                  <th className="px-4 py-3">Open ports</th>
                  <th className="px-4 py-3">Score</th>
                  <th className="px-4 py-3">Level</th>
                  <th className="px-4 py-3">Updated</th>
                </tr>
              </thead>
              <tbody>
                {exposures.map((item) => (
                  <tr key={item.asset_key} className="border-b border-[var(--border)]/40">
                    <td className="px-4 py-3">
                      <div className="text-[var(--text)]">{item.asset_name || item.asset_key}</div>
                      <div className="text-xs text-[var(--muted)]">{item.asset_key}</div>
                    </td>
                    <td className="px-4 py-3">{item.environment || '-'}</td>
                    <td className="px-4 py-3">{item.internet_exposed ? 'Yes' : 'No'}</td>
                    <td className="px-4 py-3">
                      {item.open_port_count}
                      {item.open_management_ports?.length
                        ? ` (${item.open_management_ports.join(', ')})`
                        : ''}
                    </td>
                    <td className="px-4 py-3">{item.exposure_score}</td>
                    <td className="px-4 py-3">{severityBadge(item.exposure_level)}</td>
                    <td className="px-4 py-3">{formatDateTime(item.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.05fr)_minmax(0,0.95fr)]">
        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Drift timeline</h2>
              <p className="section-head-copy">Recent surface changes and certificate drift indicators.</p>
            </div>
          </div>
          {drift.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No drift events detected.</p>
          ) : (
            <ul className="space-y-3">
              {drift.slice(0, 30).map((item) => (
                <li key={item.event_id} className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-medium text-[var(--text)]">
                      {item.event_type} | run {item.run_id}
                    </p>
                    {severityBadge(item.severity)}
                  </div>
                  <p className="mt-1 text-xs text-[var(--muted)]">
                    {item.asset_key || item.hostname || item.domain || '-'}
                    {item.port ? `:${item.port}` : ''} | {formatDateTime(item.created_at)}
                  </p>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Discovery run browser</h2>
              <p className="section-head-copy">Inspect hosts, services, and certificates by run.</p>
            </div>
          </div>
          <label className="text-sm text-[var(--muted)]">
            Select run
            <select
              value={selectedRunId ?? ''}
              onChange={(event) => {
                const value = Number(event.target.value);
                setSelectedRunId(Number.isNaN(value) ? null : value);
              }}
              className="input mt-1"
            >
              <option value="">No run selected</option>
              {runs.map((item) => (
                <option key={item.run_id} value={item.run_id}>
                  Run {item.run_id} | {item.status} | {formatDateTime(item.started_at)}
                </option>
              ))}
            </select>
          </label>
          {selectedRun ? (
            <div className="mt-3 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3 text-sm text-[var(--text)]">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-medium">Run {selectedRun.run_id}</p>
                {statusBadge(selectedRun.status)}
              </div>
              <p className="mt-1 text-xs text-[var(--muted)]">
                Requested by {selectedRun.requested_by || '-'} | Started{' '}
                {formatDateTime(selectedRun.started_at)}
              </p>
            </div>
          ) : null}
          <div className="mt-4 grid gap-4 md:grid-cols-3">
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">Hosts</p>
              <p className="mt-1 text-2xl font-semibold text-[var(--text)]">{hosts.length}</p>
            </div>
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">Services</p>
              <p className="mt-1 text-2xl font-semibold text-[var(--text)]">{services.length}</p>
            </div>
            <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
              <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">Certificates</p>
              <p className="mt-1 text-2xl font-semibold text-[var(--text)]">{certificates.length}</p>
            </div>
          </div>
        </div>
      </section>

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">Asset relationships</h2>
            <p className="section-head-copy">Dependency map entries used for investigation and graph overlays.</p>
          </div>
        </div>
        {relationships.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No relationships defined.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Relation</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Confidence</th>
                  <th className="px-4 py-3">Updated</th>
                </tr>
              </thead>
              <tbody>
                {relationships.map((item) => (
                  <tr key={item.relationship_id} className="border-b border-[var(--border)]/40">
                    <td className="px-4 py-3">{item.source_asset_key}</td>
                    <td className="px-4 py-3">{item.relation_type}</td>
                    <td className="px-4 py-3">{item.target_asset_key}</td>
                    <td className="px-4 py-3">{item.confidence.toFixed(2)}</td>
                    <td className="px-4 py-3">{formatDateTime(item.updated_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {loading && <p className="text-sm text-[var(--muted)]">Refreshing attack-surface data...</p>}
    </main>
  );
}
