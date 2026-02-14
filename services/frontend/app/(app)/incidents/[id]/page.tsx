'use client';

import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  getIncident,
  updateIncidentStatus,
  addIncidentNote,
  linkIncidentAlert,
  unlinkIncidentAlert,
  createIncidentJiraTicket,
  type Incident,
  type IncidentStatus,
  type IncidentTimelineEntry,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

const STATUS_FLOW: IncidentStatus[] = ['new', 'triaged', 'contained', 'resolved', 'closed'];

function severityColor(s: string): string {
  switch (s) {
    case 'critical':
    case 'high':
      return 'var(--red)';
    case 'medium':
      return 'var(--amber)';
    case 'low':
    case 'info':
      return 'var(--green)';
    default:
      return 'var(--muted)';
  }
}

function TimelineEntry({ entry }: { entry: IncidentTimelineEntry }) {
  if (entry.event_type === 'note') {
    return (
      <div className="border-l-2 border-[var(--border)] pl-4 py-2">
        <p className="text-sm text-[var(--text)] whitespace-pre-wrap">{entry.body || '–'}</p>
        <p className="text-xs text-[var(--muted)] mt-1">
          {entry.author ?? 'System'} · {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }
  if (entry.event_type === 'state_change') {
    const from = (entry.details?.from as string) ?? '?';
    const to = (entry.details?.to as string) ?? '?';
    return (
      <div className="border-l-2 border-[var(--green)]/50 pl-4 py-2">
        <p className="text-sm text-[var(--muted)]">
          Status: <span className="capitalize">{from}</span> → <span className="capitalize text-[var(--text)]">{to}</span>
        </p>
        <p className="text-xs text-[var(--muted)] mt-1">
          {entry.author ?? 'System'} · {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }
  if (entry.event_type === 'alert_added') {
    const keys = (entry.details?.asset_keys as string[]) ?? (entry.details?.asset_key ? [entry.details.asset_key] : []);
    return (
      <div className="border-l-2 border-[var(--amber)]/50 pl-4 py-2">
        <p className="text-sm text-[var(--muted)]">
          Alert(s) linked: {keys.length ? keys.join(', ') : '–'}
        </p>
        <p className="text-xs text-[var(--muted)] mt-1">
          {entry.author ?? 'System'} · {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }
  return (
    <div className="border-l-2 border-[var(--border)] pl-4 py-2">
      <p className="text-xs text-[var(--muted)]">{formatDateTime(entry.created_at)} · {entry.event_type}</p>
    </div>
  );
}

export default function IncidentDetailPage() {
  const params = useParams();
  const id = params.id != null ? Number(params.id) : NaN;
  const { canMutate } = useAuth();
  const [incident, setIncident] = useState<Incident | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [noteBody, setNoteBody] = useState('');
  const [linkAssetKey, setLinkAssetKey] = useState('');
  const [loadingStatus, setLoadingStatus] = useState(false);
  const [loadingNote, setLoadingNote] = useState(false);
  const [loadingLink, setLoadingLink] = useState(false);
  const [loadingJira, setLoadingJira] = useState(false);
  const [jiraProjectKey, setJiraProjectKey] = useState('');
  const [actionError, setActionError] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!Number.isInteger(id) || id < 1) return;
    getIncident(id)
      .then(setIncident)
      .catch((e) => setError(e.message));
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  const handleStatusChange = async (newStatus: IncidentStatus) => {
    setActionError(null);
    setLoadingStatus(true);
    try {
      await updateIncidentStatus(id, newStatus);
      load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Update failed');
    } finally {
      setLoadingStatus(false);
    }
  };

  const handleAddNote = async () => {
    setActionError(null);
    setLoadingNote(true);
    try {
      await addIncidentNote(id, noteBody);
      setNoteBody('');
      load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Failed to add note');
    } finally {
      setLoadingNote(false);
    }
  };

  const handleLinkAlert = async () => {
    const key = linkAssetKey.trim();
    if (!key) return;
    setActionError(null);
    setLoadingLink(true);
    try {
      await linkIncidentAlert(id, key);
      setLinkAssetKey('');
      load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Failed to link alert');
    } finally {
      setLoadingLink(false);
    }
  };

  const handleUnlink = async (asset_key: string) => {
    setActionError(null);
    try {
      await unlinkIncidentAlert(id, asset_key);
      load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Failed to unlink');
    }
  };

  const handleCreateJira = async () => {
    setActionError(null);
    setLoadingJira(true);
    try {
      await createIncidentJiraTicket(id, jiraProjectKey.trim() || undefined);
      load();
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Failed to create Jira ticket');
    } finally {
      setLoadingJira(false);
    }
  };

  if (!Number.isInteger(id) || id < 1) {
    return (
      <main className="mx-auto max-w-4xl px-4 py-10">
        <p className="text-[var(--red)]">Invalid incident ID</p>
      </main>
    );
  }

  if (error && !incident) {
    return (
      <main className="mx-auto max-w-4xl px-4 py-10">
        <div className="alert-error" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      </main>
    );
  }

  if (!incident) {
    return (
      <main className="mx-auto max-w-4xl px-4 py-10">
        <p className="text-[var(--muted)]">Loading incident…</p>
      </main>
    );
  }

  const currentStatusIndex = STATUS_FLOW.indexOf(incident.status);
  const canProgress = currentStatusIndex >= 0 && currentStatusIndex < STATUS_FLOW.length - 1;
  const nextStatus = canProgress ? STATUS_FLOW[currentStatusIndex + 1] : null;

  return (
    <main className="mx-auto max-w-4xl px-4 py-10 sm:px-6 lg:px-8">
      <nav className="mb-6 flex items-center gap-2 text-sm" aria-label="Breadcrumb">
        <Link href="/incidents" className="font-medium text-[var(--muted)] hover:text-[var(--text)]">
          Incidents
        </Link>
        <span className="text-[var(--border)]">/</span>
        <span className="font-medium text-[var(--text)]">#{incident.id}</span>
      </nav>

      <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="page-title mb-2">{incident.title}</h1>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <span
              className="inline-block rounded px-2 py-0.5 text-xs font-medium capitalize"
              style={{ backgroundColor: `${severityColor(incident.severity)}20`, color: severityColor(incident.severity) }}
            >
              {incident.severity}
            </span>
            <span className="text-[var(--muted)] capitalize">Status: {incident.status}</span>
            {incident.assigned_to && (
              <span className="text-[var(--muted)]">Assigned: {incident.assigned_to}</span>
            )}
            {incident.sla_due_at && (
              <span className="text-[var(--muted)]">SLA due: {formatDateTime(incident.sla_due_at)}</span>
            )}
          </div>
        </div>
        {canMutate && (
          <div className="flex flex-wrap gap-2">
            {STATUS_FLOW.map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => handleStatusChange(s)}
                disabled={loadingStatus || incident.status === s}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                  incident.status === s
                    ? 'bg-[var(--green)] text-white'
                    : 'bg-[var(--border)]/50 text-[var(--muted)] hover:bg-[var(--border)]'
                }`}
              >
                {s}
              </button>
            ))}
          </div>
        )}
      </div>

      {actionError && (
        <div className="mb-4 alert-error animate-in" role="alert">
          {actionError}
        </div>
      )}

      <section className="mb-8">
        <h2 className="section-title mb-3">Linked alerts</h2>
        <div className="card">
          {incident.alerts.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No alerts linked. Add one below.</p>
          ) : (
            <ul className="space-y-2">
              {incident.alerts.map((a) => (
                <li key={a.asset_key} className="flex items-center justify-between gap-2">
                  <Link
                    href={`/assets/${encodeURIComponent(a.asset_key)}`}
                    className="font-medium text-[var(--red)] hover:underline"
                  >
                    {a.asset_key}
                  </Link>
                  {canMutate && (
                    <button
                      type="button"
                      onClick={() => handleUnlink(a.asset_key)}
                      className="text-xs text-[var(--muted)] underline hover:text-[var(--red)]"
                    >
                      Unlink
                    </button>
                  )}
                </li>
              ))}
            </ul>
          )}
          {canMutate && (
            <div className="mt-4 flex gap-2">
              <input
                type="text"
                value={linkAssetKey}
                onChange={(e) => setLinkAssetKey(e.target.value)}
                placeholder="Asset key (e.g. secplat-api)"
                className="input flex-1 max-w-xs"
              />
              <button
                type="button"
                onClick={handleLinkAlert}
                disabled={loadingLink || !linkAssetKey.trim()}
                className="btn-secondary text-sm"
              >
                {loadingLink ? 'Linking…' : 'Link alert'}
              </button>
            </div>
          )}
        </div>
      </section>

      <section className="mb-8">
        <h2 className="section-title mb-3">Timeline</h2>
        <div className="card">
          {incident.timeline.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No timeline entries yet. Add a note below.</p>
          ) : (
            <div className="space-y-0">
              {incident.timeline.map((entry) => (
                <TimelineEntry key={entry.id} entry={entry} />
              ))}
            </div>
          )}
          {canMutate && (
            <div className="mt-4 border-t border-[var(--border)] pt-4">
              <label className="mb-2 block text-sm font-medium text-[var(--muted)]">Add note</label>
              <textarea
                value={noteBody}
                onChange={(e) => setNoteBody(e.target.value)}
                placeholder="Note or update…"
                rows={3}
                className="input w-full"
              />
              <button
                type="button"
                onClick={handleAddNote}
                disabled={loadingNote}
                className="mt-2 btn-primary text-sm"
              >
                {loadingNote ? 'Adding…' : 'Add note'}
              </button>
            </div>
          )}
        </div>
      </section>

      {(incident.metadata?.jira_issue_key || canMutate) && (
        <section className="mb-8">
          <h2 className="section-title mb-3">Jira</h2>
          <div className="card">
            {incident.metadata?.jira_issue_key ? (
              <p className="text-sm">
                <a
                  href={incident.metadata.jira_issue_url as string}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-[var(--green)] hover:underline"
                >
                  View in Jira: {String(incident.metadata.jira_issue_key)}
                </a>
              </p>
            ) : (
              <div className="flex flex-wrap items-end gap-3">
                <label className="text-sm text-[var(--muted)]">
                  Project key (optional if set in env)
                  <input
                    type="text"
                    value={jiraProjectKey}
                    onChange={(e) => setJiraProjectKey(e.target.value)}
                    placeholder="e.g. SEC"
                    className="ml-2 w-24 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5 text-sm text-[var(--text)]"
                  />
                </label>
                <button
                  type="button"
                  onClick={handleCreateJira}
                  disabled={loadingJira}
                  className="btn-primary text-sm"
                >
                  {loadingJira ? 'Creating…' : 'Create Jira ticket'}
                </button>
              </div>
            )}
          </div>
        </section>
      )}

      <section>
        <h2 className="section-title mb-2">Details</h2>
        <dl className="card grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-[var(--muted)]">Created</dt>
          <dd>{formatDateTime(incident.created_at)}</dd>
          <dt className="text-[var(--muted)]">Updated</dt>
          <dd>{formatDateTime(incident.updated_at)}</dd>
          {incident.resolved_at && (
            <>
              <dt className="text-[var(--muted)]">Resolved</dt>
              <dd>{formatDateTime(incident.resolved_at)}</dd>
            </>
          )}
          {incident.closed_at && (
            <>
              <dt className="text-[var(--muted)]">Closed</dt>
              <dd>{formatDateTime(incident.closed_at)}</dd>
            </>
          )}
        </dl>
      </section>
    </main>
  );
}
