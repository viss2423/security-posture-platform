'use client';

import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import {
  getAlerts,
  postAlertAck,
  postAlertSuppress,
  postAlertResolve,
  postAlertAssign,
  type AlertsResponse,
  type AlertItem,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';

type TabId = 'firing' | 'acked' | 'suppressed' | 'resolved';

const TABS: { id: TabId; label: string }[] = [
  { id: 'firing', label: 'Firing' },
  { id: 'acked', label: 'Acknowledged' },
  { id: 'suppressed', label: 'Suppressed' },
  { id: 'resolved', label: 'Resolved' },
];

function AlertRow({
  item,
  onAck,
  onSuppress,
  onResolve,
  onAssign,
  loading,
}: {
  item: AlertItem;
  onAck: (key: string, reason?: string) => void;
  onSuppress: (key: string, until: string) => void;
  onResolve: (key: string) => void;
  onAssign: (key: string, who: string) => void;
  loading: string | null;
}) {
  const [ackReason, setAckReason] = useState('');
  const [showAck, setShowAck] = useState(false);
  const [suppressUntil, setSuppressUntil] = useState('');
  const [showSuppress, setShowSuppress] = useState(false);
  const [assignTo, setAssignTo] = useState(item.assigned_to ?? '');
  const [showAssign, setShowAssign] = useState(false);
  const key = item.asset_key;
  const isBusy = loading === key;

  const defaultSuppress = () => {
    const d = new Date();
    d.setHours(d.getHours() + 2);
    return d.toISOString().slice(0, 16);
  };

  return (
    <li className="flex flex-wrap items-center justify-between gap-2 border-b border-[var(--border)] py-3 last:border-0">
      <div>
        <Link href={`/assets/${encodeURIComponent(key)}`} className="font-medium text-[var(--red)] hover:underline">
          {key}
        </Link>
        {item.ack_reason && <span className="ml-2 text-sm text-[var(--muted)]">({item.ack_reason})</span>}
        {item.assigned_to && <span className="ml-2 text-xs text-[var(--muted)]">assigned to {item.assigned_to}</span>}
        {item.suppressed_until && <span className="ml-2 text-xs text-[var(--muted)]">until {formatDateTime(item.suppressed_until)}</span>}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        {showAck && (
          <span className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Reason (optional)"
              value={ackReason}
              onChange={(e) => setAckReason(e.target.value)}
              className="w-40 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-sm"
            />
            <button type="button" onClick={() => { onAck(key, ackReason || undefined); setShowAck(false); }} disabled={isBusy} className="btn-primary text-sm">Ack</button>
            <button type="button" onClick={() => setShowAck(false)} className="btn-secondary text-sm">Cancel</button>
          </span>
        )}
        {!showAck && (
          <button type="button" onClick={() => setShowAck(true)} disabled={isBusy} className="btn-secondary text-sm">Ack</button>
        )}
        {showSuppress && (
          <span className="flex items-center gap-2">
            <input
              type="datetime-local"
              value={suppressUntil || defaultSuppress()}
              onChange={(e) => setSuppressUntil(e.target.value)}
              className="rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-sm"
            />
            <button type="button" onClick={() => { const u = suppressUntil || defaultSuppress(); onSuppress(key, new Date(u).toISOString()); setShowSuppress(false); }} disabled={isBusy} className="btn-secondary text-sm">Suppress</button>
            <button type="button" onClick={() => setShowSuppress(false)} className="btn-secondary text-sm">Cancel</button>
          </span>
        )}
        {!showSuppress && (
          <button type="button" onClick={() => { setSuppressUntil(defaultSuppress()); setShowSuppress(true); }} disabled={isBusy} className="btn-secondary text-sm">Suppress</button>
        )}
        <button type="button" onClick={() => onResolve(key)} disabled={isBusy} className="btn-secondary text-sm">Resolve</button>
        {showAssign && (
          <span className="flex items-center gap-2">
            <input
              type="text"
              placeholder="Assign to"
              value={assignTo}
              onChange={(e) => setAssignTo(e.target.value)}
              className="w-32 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-sm"
            />
            <button type="button" onClick={() => { onAssign(key, assignTo); setShowAssign(false); }} disabled={isBusy} className="btn-secondary text-sm">Assign</button>
            <button type="button" onClick={() => setShowAssign(false)} className="btn-secondary text-sm">Cancel</button>
          </span>
        )}
        {!showAssign && (
          <button type="button" onClick={() => setShowAssign(true)} disabled={isBusy} className="btn-secondary text-sm">Assign</button>
        )}
      </div>
    </li>
  );
}

export default function AlertsPage() {
  const [data, setData] = useState<AlertsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('firing');
  const [loading, setLoading] = useState<string | null>(null);

  const load = useCallback(() => {
    getAlerts()
      .then(setData)
      .catch((e) => setError(e.message));
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 30000);
    return () => clearInterval(t);
  }, [load]);

  const handleAck = async (asset_key: string, reason?: string) => {
    setLoading(asset_key);
    try {
      await postAlertAck(asset_key, reason);
      load();
    } finally {
      setLoading(null);
    }
  };
  const handleSuppress = async (asset_key: string, until_iso: string) => {
    setLoading(asset_key);
    try {
      await postAlertSuppress(asset_key, until_iso);
      load();
    } finally {
      setLoading(null);
    }
  };
  const handleResolve = async (asset_key: string) => {
    setLoading(asset_key);
    try {
      await postAlertResolve(asset_key);
      load();
    } finally {
      setLoading(null);
    }
  };
  const handleAssign = async (asset_key: string, assigned_to: string) => {
    setLoading(asset_key);
    try {
      await postAlertAssign(asset_key, assigned_to);
      load();
    } finally {
      setLoading(null);
    }
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
                ? 'bg-[var(--surface-elevated)] text-[var(--text)] border border-[var(--border)] border-b-0 -mb-px'
                : 'text-[var(--muted)] hover:bg-[var(--border)]/30'
            }`}
          >
            {label}
            {data && data[id].length > 0 && (
              <span className="ml-1.5 rounded-full bg-[var(--muted)]/30 px-1.5 text-xs">{data[id].length}</span>
            )}
          </button>
        ))}
      </div>

      <section className="mb-12 animate-in">
        <div className="card">
          {list.length === 0 ? (
            <div className="py-12 text-center">
              <p className="text-sm text-[var(--muted)]">
                {activeTab === 'firing' ? 'No firing alerts. All assets are up or suppressed.' : `No ${activeTab} alerts.`}
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
                />
              ))}
            </ul>
          )}
        </div>
      </section>

      <section className="animate-in">
        <h2 className="section-title">Grafana</h2>
        <p className="mb-4 text-sm text-[var(--muted)]">Alert rules and history are managed in Grafana.</p>
        <a href={`${grafanaUrl}/alerting/list`} target="_blank" rel="noopener noreferrer" className="btn-secondary inline-flex">
          Open Grafana - Alert rules
        </a>
      </section>
    </main>
  );
}