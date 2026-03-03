'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import Link from 'next/link';
import {
  generateAlertAIGuidance,
  getAlertAIGuidance,
  getAlerts,
  postAlertAck,
  postAlertAssign,
  postAlertResolve,
  postAlertSuppress,
  type AIAlertGuidance,
  type AlertItem,
  type AlertsResponse,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

type TabId = 'firing' | 'acked' | 'suppressed' | 'resolved';
type ActionMode = 'ack' | 'suppress' | 'assign' | null;

const TABS: { id: TabId; label: string }[] = [
  { id: 'firing', label: 'Firing' },
  { id: 'acked', label: 'Acknowledged' },
  { id: 'suppressed', label: 'Suppressed' },
  { id: 'resolved', label: 'Resolved' },
];

function badgeClass(value: string | null | undefined): string {
  const normalized = (value || '').toLowerCase();
  if (normalized === 'critical' || normalized === 'red' || normalized === 'escalate') {
    return 'bg-[var(--red)]/15 text-[var(--red)] border border-[var(--red)]/20';
  }
  if (
    normalized === 'high' ||
    normalized === 'amber' ||
    normalized === 'ack' ||
    normalized === 'assign'
  ) {
    return 'bg-[var(--amber)]/15 text-[var(--amber)] border border-[var(--amber)]/20';
  }
  if (normalized === 'medium' || normalized === 'suppress' || normalized === 'monitor') {
    return 'bg-[var(--green)]/10 text-[var(--green)] border border-[var(--green)]/20';
  }
  if (normalized === 'low' || normalized === 'resolve' || normalized === 'green') {
    return 'bg-[var(--muted)]/15 text-[var(--text)] border border-[var(--border)]';
  }
  return 'bg-[var(--surface-elevated)] text-[var(--muted)] border border-[var(--border)]';
}

function labelize(value: string | null | undefined): string {
  return (value || 'n/a').replaceAll('_', ' ');
}

function formatLastSeen(item: AlertItem): string {
  if (!item.last_seen) return 'No recent posture sample';
  return `Last seen ${formatDateTime(item.last_seen)}`;
}

function AlertRow({
  item,
  onAck,
  onSuppress,
  onResolve,
  onAssign,
  loading,
  canMutate,
}: {
  item: AlertItem;
  onAck: (key: string, reason?: string) => void;
  onSuppress: (key: string, until: string) => void;
  onResolve: (key: string) => void;
  onAssign: (key: string, who: string) => void;
  loading: string | null;
  canMutate: boolean;
}) {
  const [actionMode, setActionMode] = useState<ActionMode>(null);
  const [guidanceOpen, setGuidanceOpen] = useState(false);
  const [ackReason, setAckReason] = useState('');
  const [suppressUntil, setSuppressUntil] = useState('');
  const [assignTo, setAssignTo] = useState(item.assigned_to ?? '');
  const [guidance, setGuidance] = useState<AIAlertGuidance | null>(null);
  const [guidanceLoading, setGuidanceLoading] = useState(false);
  const [guidanceGenerating, setGuidanceGenerating] = useState(false);
  const [guidanceMessage, setGuidanceMessage] = useState<string | null>(null);
  const key = item.asset_key;
  const isBusy = loading === key;

  useEffect(() => {
    setAssignTo(item.assigned_to ?? '');
  }, [item.assigned_to]);

  const defaultSuppress = () => {
    const d = new Date();
    d.setHours(d.getHours() + 2);
    return d.toISOString().slice(0, 16);
  };

  const loadGuidance = useCallback(async () => {
    setGuidanceLoading(true);
    setGuidanceMessage(null);
    try {
      const out = await getAlertAIGuidance(key);
      setGuidance(out);
      if (out.stale) {
        setGuidanceMessage('Stored guidance is stale for the current alert context. Refresh it.');
      }
    } catch (e) {
      const message = e instanceof Error ? e.message : 'Failed to load AI guidance';
      if (!message.toLowerCase().includes('not found')) {
        setGuidanceMessage(message);
      }
      setGuidance(null);
    } finally {
      setGuidanceLoading(false);
    }
  }, [key]);

  const handleGenerateGuidance = async (force: boolean) => {
    setGuidanceGenerating(true);
    setGuidanceMessage(null);
    try {
      const out = await generateAlertAIGuidance(key, force);
      setGuidance(out);
      setGuidanceMessage(out.cached ? 'Showing cached guidance.' : 'AI guidance generated.');
      setGuidanceOpen(true);
    } catch (e) {
      setGuidanceMessage(e instanceof Error ? e.message : 'AI guidance generation failed');
    } finally {
      setGuidanceGenerating(false);
    }
  };

  const toggleGuidance = () => {
    const next = !guidanceOpen;
    setGuidanceOpen(next);
    if (next && !guidance && !guidanceLoading) {
      void loadGuidance();
    }
  };

  const keySignals = useMemo(() => {
    const values: string[] = [];
    if (item.reason) values.push(`Reason ${labelize(item.reason)}`);
    if (item.active_finding_count) values.push(`${item.active_finding_count} active findings`);
    if (item.top_risk_score != null) values.push(`Top risk ${item.top_risk_score}`);
    if (item.open_incident_count) values.push(`${item.open_incident_count} open incidents`);
    return values;
  }, [item]);

  const maintenanceNote = item.maintenance_active
    ? `Maintenance window${item.maintenance_reason ? `: ${item.maintenance_reason}` : ''}`
    : item.suppression_rule_active
      ? `Suppression rule${item.suppression_reason ? `: ${item.suppression_reason}` : ''}`
      : null;

  return (
    <li className="section-panel-tight">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Link
              href={`/assets/${encodeURIComponent(key)}`}
              className="text-base font-semibold text-[var(--text)] hover:text-[var(--green)]"
            >
              {item.asset_name || key}
            </Link>
            <span className="rounded-full border border-[var(--border)] px-2 py-0.5 font-mono text-[11px] text-[var(--muted)]">
              {key}
            </span>
            {item.posture_status && (
              <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium uppercase ${badgeClass(item.posture_status)}`}>
                {item.posture_status}
              </span>
            )}
            {item.ai_recommended_action && (
              <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium uppercase ${badgeClass(item.ai_recommended_action)}`}>
                AI {labelize(item.ai_recommended_action)}
              </span>
            )}
            {item.ai_urgency && (
              <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium uppercase ${badgeClass(item.ai_urgency)}`}>
                {item.ai_urgency}
              </span>
            )}
          </div>

          <div className="mt-3 flex flex-wrap gap-2">
            {item.criticality && <span className="stat-chip">Criticality {item.criticality}</span>}
            {item.environment && <span className="stat-chip">{item.environment}</span>}
            {item.posture_score != null && <span className="stat-chip">Posture {item.posture_score}</span>}
            {item.asset_type && <span className="stat-chip">Type {item.asset_type}</span>}
            {item.verified != null && (
              <span className="stat-chip">{item.verified ? 'Verified asset' : 'Unverified asset'}</span>
            )}
            <span className="stat-chip">{formatLastSeen(item)}</span>
          </div>

          {(keySignals.length > 0 || maintenanceNote || item.assigned_to || item.ack_reason) && (
            <div className="mt-3 space-y-2 text-sm text-[var(--text-muted)]">
              {keySignals.length > 0 && <p>{keySignals.join(' | ')}</p>}
              {(item.assigned_to || item.ack_reason) && (
                <p>
                  {item.assigned_to ? `Assigned to ${item.assigned_to}` : 'Unassigned'}
                  {item.ack_reason ? ` | Ack reason: ${item.ack_reason}` : ''}
                </p>
              )}
              {maintenanceNote && <p className="text-[var(--amber)]">{maintenanceNote}</p>}
            </div>
          )}

          {item.open_incident_ids && item.open_incident_ids.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
              <span>Open incidents:</span>
              {item.open_incident_ids.map((incidentId) => (
                <Link
                  key={incidentId}
                  href={`/incidents/${incidentId}`}
                  className="rounded-full border border-[var(--border)] px-2 py-0.5 text-[var(--text)] hover:bg-[var(--surface-elevated)]"
                >
                  #{incidentId}
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2 xl:justify-end">
          <button type="button" onClick={toggleGuidance} className="btn-secondary text-sm">
            {guidanceOpen ? 'Hide AI' : 'AI guidance'}
          </button>
          {canMutate && (
            <>
              <button
                type="button"
                onClick={() => setActionMode(actionMode ? null : 'ack')}
                disabled={isBusy}
                className="btn-secondary text-sm"
              >
                Respond
              </button>
              <button
                type="button"
                onClick={() => onResolve(key)}
                disabled={isBusy}
                className="btn-secondary text-sm"
              >
                Resolve
              </button>
            </>
          )}
        </div>
      </div>

      {canMutate && actionMode && (
        <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface)]/85 p-4">
          <div className="mb-3 flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => setActionMode('ack')}
              className={actionMode === 'ack' ? 'btn-primary text-sm' : 'btn-secondary text-sm'}
            >
              Acknowledge
            </button>
            <button
              type="button"
              onClick={() => {
                setSuppressUntil(defaultSuppress());
                setActionMode('suppress');
              }}
              className={actionMode === 'suppress' ? 'btn-primary text-sm' : 'btn-secondary text-sm'}
            >
              Suppress
            </button>
            <button
              type="button"
              onClick={() => setActionMode('assign')}
              className={actionMode === 'assign' ? 'btn-primary text-sm' : 'btn-secondary text-sm'}
            >
              Assign
            </button>
            <button type="button" onClick={() => setActionMode(null)} className="btn-secondary text-sm">
              Close
            </button>
          </div>

          {actionMode === 'ack' && (
            <div className="flex flex-wrap items-end gap-3">
              <label className="text-sm text-[var(--muted)]">
                Reason
                <input
                  type="text"
                  placeholder="Optional acknowledgment note"
                  value={ackReason}
                  onChange={(e) => setAckReason(e.target.value)}
                  className="input mt-1 min-w-[240px]"
                />
              </label>
              <button
                type="button"
                onClick={() => {
                  onAck(key, ackReason || undefined);
                  setActionMode(null);
                }}
                disabled={isBusy}
                className="btn-primary text-sm"
              >
                Save acknowledgment
              </button>
            </div>
          )}

          {actionMode === 'suppress' && (
            <div className="flex flex-wrap items-end gap-3">
              <label className="text-sm text-[var(--muted)]">
                Until
                <input
                  type="datetime-local"
                  value={suppressUntil || defaultSuppress()}
                  onChange={(e) => setSuppressUntil(e.target.value)}
                  className="input mt-1"
                />
              </label>
              <button
                type="button"
                onClick={() => {
                  const until = suppressUntil || defaultSuppress();
                  onSuppress(key, new Date(until).toISOString());
                  setActionMode(null);
                }}
                disabled={isBusy}
                className="btn-primary text-sm"
              >
                Save suppression
              </button>
            </div>
          )}

          {actionMode === 'assign' && (
            <div className="flex flex-wrap items-end gap-3">
              <label className="text-sm text-[var(--muted)]">
                Assignee
                <input
                  type="text"
                  placeholder="Assign to analyst"
                  value={assignTo}
                  onChange={(e) => setAssignTo(e.target.value)}
                  className="input mt-1 min-w-[220px]"
                />
              </label>
              <button
                type="button"
                onClick={() => {
                  onAssign(key, assignTo);
                  setActionMode(null);
                }}
                disabled={isBusy}
                className="btn-primary text-sm"
              >
                Save assignment
              </button>
            </div>
          )}
        </div>
      )}

      {guidanceOpen && (
        <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface)]/85 p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-[var(--text)]">AI response guidance</h3>
              <p className="text-xs text-[var(--muted)]">
                Recommended next move based on posture, active findings, incidents, and suppression context.
              </p>
            </div>
            {canMutate && (
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => handleGenerateGuidance(false)}
                  disabled={guidanceGenerating}
                  className="btn-primary text-sm"
                >
                  {guidanceGenerating ? 'Generating...' : guidance ? 'Refresh guidance' : 'Generate guidance'}
                </button>
                {guidance && (
                  <button
                    type="button"
                    onClick={() => handleGenerateGuidance(true)}
                    disabled={guidanceGenerating}
                    className="btn-secondary text-sm"
                  >
                    Force regenerate
                  </button>
                )}
              </div>
            )}
          </div>

          {guidanceLoading ? (
            <p className="mt-3 text-sm text-[var(--muted)]">Loading stored guidance...</p>
          ) : guidance?.guidance_text ? (
            <div className="mt-4">
              <div className="mb-3 flex flex-wrap items-center gap-2">
                {guidance.recommended_action && (
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium uppercase ${badgeClass(guidance.recommended_action)}`}>
                    {labelize(guidance.recommended_action)}
                  </span>
                )}
                {guidance.urgency && (
                  <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium uppercase ${badgeClass(guidance.urgency)}`}>
                    {guidance.urgency}
                  </span>
                )}
                {guidance.stale && (
                  <span className="rounded-full border border-[var(--amber)]/30 bg-[var(--amber)]/15 px-2 py-0.5 text-[11px] text-[var(--amber)]">
                    stale
                  </span>
                )}
              </div>
              <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">
                {guidance.guidance_text}
              </p>
              <p className="mt-3 text-xs text-[var(--muted)]">
                Generated {formatDateTime(guidance.generated_at)} via {guidance.provider}/{guidance.model}
              </p>
            </div>
          ) : (
            <p className="mt-3 text-sm text-[var(--muted)]">No AI guidance generated yet for this alert.</p>
          )}

          {guidanceMessage && (
            <p
              className={`mt-3 text-xs ${
                guidanceMessage.toLowerCase().includes('failed') ||
                guidanceMessage.toLowerCase().includes('unavailable')
                  ? 'text-[var(--red)]'
                  : 'text-[var(--muted)]'
              }`}
            >
              {friendlyApiMessage(guidanceMessage)}
            </p>
          )}
        </div>
      )}
    </li>
  );
}

export default function AlertsPage() {
  const { canMutate } = useAuth();
  const [data, setData] = useState<AlertsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('firing');
  const [loading, setLoading] = useState<string | null>(null);

  const load = useCallback(() => {
    getAlerts()
      .then((result) => {
        setData(result);
        setError(null);
      })
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
    const timer = setInterval(load, 30000);
    return () => clearInterval(timer);
  }, [load]);

  const withMutation = async (assetKey: string, fn: () => Promise<unknown>) => {
    setLoading(assetKey);
    try {
      await fn();
      await load();
    } finally {
      setLoading(null);
    }
  };

  const handleAck = async (asset_key: string, reason?: string) => {
    await withMutation(asset_key, () => postAlertAck(asset_key, reason));
  };

  const handleSuppress = async (asset_key: string, until_iso: string) => {
    await withMutation(asset_key, () => postAlertSuppress(asset_key, until_iso));
  };

  const handleResolve = async (asset_key: string) => {
    await withMutation(asset_key, () => postAlertResolve(asset_key));
  };

  const handleAssign = async (asset_key: string, assigned_to: string) => {
    await withMutation(asset_key, () => postAlertAssign(asset_key, assigned_to));
  };

  const grafanaUrl = process.env.NEXT_PUBLIC_GRAFANA_URL || 'http://localhost:3001';
  const list = data ? data[activeTab] : [];

  return (
    <main className="page-shell">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-[var(--text-muted)]">
          Prioritized alert queue with response guidance, suppression context, and linked risk
          signals.
        </p>
        {data && (
          <div className="flex flex-wrap gap-2 text-xs">
            <span className="stat-chip-strong">{data.firing.length} firing</span>
            <span className="stat-chip">{data.suppressed.length} suppressed</span>
            <span className="stat-chip">{data.acked.length} acknowledged</span>
            <span className="stat-chip">{data.resolved.length} resolved</span>
          </div>
        )}
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <div className="mb-6 flex flex-wrap gap-2">
        {TABS.map(({ id, label }) => (
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
            {data && data[id].length > 0 && (
              <span className="ml-2 rounded-full bg-black/15 px-2 py-0.5 text-[11px]">
                {data[id].length}
              </span>
            )}
          </button>
        ))}
      </div>

      <section className="mb-12 animate-in">
        {list.length === 0 ? (
          <div className="section-panel py-12 text-center">
            <p className="text-sm text-[var(--muted)]">
              {activeTab === 'firing'
                ? 'No firing alerts. All assets are up or suppressed.'
                : `No ${activeTab} alerts.`}
            </p>
          </div>
        ) : (
          <ul className="space-y-4">
            {list.map((item) => (
              <AlertRow
                key={item.asset_key}
                item={item}
                onAck={handleAck}
                onSuppress={handleSuppress}
                onResolve={handleResolve}
                onAssign={handleAssign}
                loading={loading}
                canMutate={canMutate}
              />
            ))}
          </ul>
        )}
      </section>

      <section className="animate-in">
        <div className="section-panel">
          <h2 className="section-title">Grafana</h2>
          <p className="mb-4 text-sm text-[var(--muted)]">
            Use Grafana for raw alert rules and history. Use this page for response workflow and SecPlat context.
          </p>
          <a
            href={`${grafanaUrl}/alerting/list`}
            target="_blank"
            rel="noopener noreferrer"
            className="btn-secondary inline-flex"
          >
            Open Grafana alert rules
          </a>
        </div>
      </section>
    </main>
  );
}
