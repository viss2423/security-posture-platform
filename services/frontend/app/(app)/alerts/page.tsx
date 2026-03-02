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
  const [ackReason, setAckReason] = useState('');
  const [showAck, setShowAck] = useState(false);
  const [suppressUntil, setSuppressUntil] = useState('');
  const [showSuppress, setShowSuppress] = useState(false);
  const [assignTo, setAssignTo] = useState(item.assigned_to ?? '');
  const [showAssign, setShowAssign] = useState(false);
  const [guidanceOpen, setGuidanceOpen] = useState(false);
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

  const contextNotes = useMemo(() => {
    const notes: string[] = [];
    if (item.reason) notes.push(`reason ${labelize(item.reason)}`);
    if (item.active_finding_count) notes.push(`${item.active_finding_count} active findings`);
    if (item.top_risk_score != null) notes.push(`top risk ${item.top_risk_score}`);
    if (item.open_incident_count) notes.push(`${item.open_incident_count} open incidents`);
    if (item.maintenance_active) notes.push(`maintenance until ${formatDateTime(item.maintenance_end_at)}`);
    if (item.suppression_rule_active) notes.push(`suppression rule until ${formatDateTime(item.suppression_end_at)}`);
    return notes;
  }, [item]);

  return (
    <li className="border-b border-[var(--border)] py-4 last:border-0">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <Link
              href={`/assets/${encodeURIComponent(key)}`}
              className="font-medium text-[var(--red)] hover:underline"
            >
              {item.asset_name || key}
            </Link>
            <span className="rounded bg-[var(--surface-elevated)] px-2 py-0.5 font-mono text-xs text-[var(--muted)]">
              {key}
            </span>
            {item.posture_status && (
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${badgeClass(item.posture_status)}`}>
                {item.posture_status}
              </span>
            )}
            {item.criticality && (
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${badgeClass(item.criticality)}`}>
                {item.criticality}
              </span>
            )}
            {item.environment && (
              <span className="rounded border border-[var(--border)] px-2 py-0.5 text-xs text-[var(--muted)]">
                {item.environment}
              </span>
            )}
            {item.ai_recommended_action && (
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${badgeClass(item.ai_recommended_action)}`}>
                AI: {labelize(item.ai_recommended_action)}
              </span>
            )}
            {item.ai_urgency && (
              <span className={`rounded px-2 py-0.5 text-xs font-medium ${badgeClass(item.ai_urgency)}`}>
                urgency {item.ai_urgency}
              </span>
            )}
          </div>

          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--muted)]">
            <span>{formatLastSeen(item)}</span>
            {item.posture_score != null && <span>Posture score {item.posture_score}</span>}
            {item.asset_type && <span>Type {item.asset_type}</span>}
            {item.verified != null && <span>{item.verified ? 'Verified asset' : 'Unverified asset'}</span>}
            {item.assigned_to && <span>Assigned to {item.assigned_to}</span>}
            {item.ack_reason && <span>Ack reason: {item.ack_reason}</span>}
            {item.suppressed_until && <span>Suppressed until {formatDateTime(item.suppressed_until)}</span>}
          </div>

          {contextNotes.length > 0 && (
            <p className="mt-2 text-sm text-[var(--muted)]">{contextNotes.join(' · ')}</p>
          )}

          {(item.maintenance_active || item.suppression_rule_active) && (
            <div className="mt-3 rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] px-3 py-2 text-xs text-[var(--muted)]">
              {item.maintenance_active && (
                <p>
                  Active maintenance window{item.maintenance_reason ? `: ${item.maintenance_reason}` : ''}.
                </p>
              )}
              {item.suppression_rule_active && (
                <p>
                  Active suppression rule{item.suppression_reason ? `: ${item.suppression_reason}` : ''}.
                </p>
              )}
            </div>
          )}

          {item.open_incident_ids && item.open_incident_ids.length > 0 && (
            <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
              <span>Open incidents:</span>
              {item.open_incident_ids.map((incidentId) => (
                <Link
                  key={incidentId}
                  href={`/incidents/${incidentId}`}
                  className="rounded border border-[var(--border)] px-2 py-0.5 text-[var(--text)] hover:bg-[var(--surface-elevated)]"
                >
                  #{incidentId}
                </Link>
              ))}
            </div>
          )}
        </div>

        <div className="flex flex-col gap-3 xl:items-end">
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={toggleGuidance} className="btn-secondary text-sm">
              {guidanceOpen ? 'Hide AI' : 'AI guidance'}
            </button>
            {canMutate && (
              <>
                {showAck ? (
                  <span className="flex items-center gap-2">
                    <input
                      type="text"
                      placeholder="Reason (optional)"
                      value={ackReason}
                      onChange={(e) => setAckReason(e.target.value)}
                      className="w-40 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        onAck(key, ackReason || undefined);
                        setShowAck(false);
                      }}
                      disabled={isBusy}
                      className="btn-primary text-sm"
                    >
                      Ack
                    </button>
                    <button type="button" onClick={() => setShowAck(false)} className="btn-secondary text-sm">
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => setShowAck(true)}
                    disabled={isBusy}
                    className="btn-secondary text-sm"
                  >
                    Ack
                  </button>
                )}

                {showSuppress ? (
                  <span className="flex items-center gap-2">
                    <input
                      type="datetime-local"
                      value={suppressUntil || defaultSuppress()}
                      onChange={(e) => setSuppressUntil(e.target.value)}
                      className="rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        const until = suppressUntil || defaultSuppress();
                        onSuppress(key, new Date(until).toISOString());
                        setShowSuppress(false);
                      }}
                      disabled={isBusy}
                      className="btn-secondary text-sm"
                    >
                      Suppress
                    </button>
                    <button type="button" onClick={() => setShowSuppress(false)} className="btn-secondary text-sm">
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => {
                      setSuppressUntil(defaultSuppress());
                      setShowSuppress(true);
                    }}
                    disabled={isBusy}
                    className="btn-secondary text-sm"
                  >
                    Suppress
                  </button>
                )}

                <button
                  type="button"
                  onClick={() => onResolve(key)}
                  disabled={isBusy}
                  className="btn-secondary text-sm"
                >
                  Resolve
                </button>

                {showAssign ? (
                  <span className="flex items-center gap-2">
                    <input
                      type="text"
                      placeholder="Assign to"
                      value={assignTo}
                      onChange={(e) => setAssignTo(e.target.value)}
                      className="w-32 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-sm"
                    />
                    <button
                      type="button"
                      onClick={() => {
                        onAssign(key, assignTo);
                        setShowAssign(false);
                      }}
                      disabled={isBusy}
                      className="btn-secondary text-sm"
                    >
                      Assign
                    </button>
                    <button type="button" onClick={() => setShowAssign(false)} className="btn-secondary text-sm">
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    type="button"
                    onClick={() => setShowAssign(true)}
                    disabled={isBusy}
                    className="btn-secondary text-sm"
                  >
                    Assign
                  </button>
                )}
              </>
            )}
          </div>

          {(item.ai_generated_at || guidance) && (
            <p className="text-xs text-[var(--muted)]">
              AI last generated {formatDateTime(guidance?.generated_at || item.ai_generated_at)}
            </p>
          )}
        </div>
      </div>

      {guidanceOpen && (
        <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-[var(--text)]">AI response guidance</h3>
              <p className="text-xs text-[var(--muted)]">
                Use this to decide whether to acknowledge, suppress, assign, escalate, resolve, or monitor.
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
                  <span className={`rounded px-2 py-0.5 text-xs font-medium ${badgeClass(guidance.recommended_action)}`}>
                    {labelize(guidance.recommended_action)}
                  </span>
                )}
                {guidance.urgency && (
                  <span className={`rounded px-2 py-0.5 text-xs font-medium ${badgeClass(guidance.urgency)}`}>
                    urgency {guidance.urgency}
                  </span>
                )}
                {guidance.stale && (
                  <span className="rounded border border-[var(--amber)]/30 bg-[var(--amber)]/15 px-2 py-0.5 text-xs text-[var(--amber)]">
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
            <p className="mt-3 text-sm text-[var(--muted)]">
              No AI guidance has been generated for this alert yet.
            </p>
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
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-10">Alerts</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <div className="mb-6 flex gap-1 border-b border-[var(--border)]">
        {TABS.map(({ id, label }) => (
          <button
            key={id}
            type="button"
            onClick={() => setActiveTab(id)}
            className={`rounded-t-lg px-4 py-2.5 text-sm font-medium transition ${
              activeTab === id
                ? 'border border-[var(--border)] border-b-0 -mb-px bg-[var(--surface-elevated)] text-[var(--text)]'
                : 'text-[var(--muted)] hover:bg-[var(--border)]/30'
            }`}
          >
            {label}
            {data && data[id].length > 0 && (
              <span className="ml-1.5 rounded-full bg-[var(--muted)]/30 px-1.5 text-xs">
                {data[id].length}
              </span>
            )}
          </button>
        ))}
      </div>

      <section className="mb-12 animate-in">
        <div className="card">
          {list.length === 0 ? (
            <div className="py-12 text-center">
              <p className="text-sm text-[var(--muted)]">
                {activeTab === 'firing'
                  ? 'No firing alerts. All assets are up or suppressed.'
                  : `No ${activeTab} alerts.`}
              </p>
            </div>
          ) : (
            <ul className="divide-y divide-[var(--border)]">
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
        </div>
      </section>

      <section className="animate-in">
        <h2 className="section-title">Grafana</h2>
        <p className="mb-4 text-sm text-[var(--muted)]">Alert rules and history are managed in Grafana.</p>
        <a
          href={`${grafanaUrl}/alerting/list`}
          target="_blank"
          rel="noopener noreferrer"
          className="btn-secondary inline-flex"
        >
          Open Grafana - Alert rules
        </a>
      </section>
    </main>
  );
}
