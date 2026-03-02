'use client';

import { useCallback, useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  getIncident,
  getIncidentAISummary,
  updateIncidentStatus,
  addIncidentNote,
  linkIncidentAlert,
  unlinkIncidentAlert,
  createIncidentJiraTicket,
  generateIncidentAISummary,
  type AIIncidentSummary,
  type Finding,
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

function riskBadgeClass(level?: string | null): string {
  switch ((level || '').toLowerCase()) {
    case 'critical':
      return 'bg-[var(--red)] text-white';
    case 'high':
      return 'bg-orange-600 text-white';
    case 'medium':
      return 'bg-yellow-500 text-black';
    case 'low':
      return 'bg-blue-500 text-white';
    default:
      return 'bg-[var(--muted)]/20 text-[var(--muted)]';
  }
}

function isFallbackProvider(provider?: string | null): boolean {
  return (provider || '').toLowerCase().includes('fallback');
}

function riskDrivers(finding: Finding): string[] {
  const raw = finding.risk_factors_json;
  if (!raw || typeof raw !== 'object') return [];
  const drivers = (raw as Record<string, unknown>).drivers;
  if (!Array.isArray(drivers)) return [];
  return drivers.filter((x): x is string => typeof x === 'string').slice(0, 2);
}

function formatRiskDriverLabel(driver: string): string {
  return driver.replace(/_/g, ' ');
}

function TimelineEntry({ entry }: { entry: IncidentTimelineEntry }) {
  if (entry.event_type === 'note') {
    return (
      <div className="border-l-2 border-[var(--border)] pl-4 py-2">
        <p className="text-sm text-[var(--text)] whitespace-pre-wrap">{entry.body || '-'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
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
          Status: <span className="capitalize">{from}</span> -{' '}
          <span className="capitalize text-[var(--text)]">{to}</span>
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  if (entry.event_type === 'alert_added') {
    const keys =
      (entry.details?.asset_keys as string[]) ??
      (entry.details?.asset_key ? [entry.details.asset_key as string] : []);
    return (
      <div className="border-l-2 border-[var(--amber)]/50 pl-4 py-2">
        <p className="text-sm text-[var(--muted)]">
          Alert(s) linked: {keys.length ? keys.join(', ') : '-'}
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  return (
    <div className="border-l-2 border-[var(--border)] pl-4 py-2">
      <p className="text-xs text-[var(--muted)]">
        {formatDateTime(entry.created_at)} | {entry.event_type}
      </p>
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
  const [aiSummary, setAiSummary] = useState<AIIncidentSummary | null>(null);
  const [loadingSummary, setLoadingSummary] = useState(false);
  const [generatingSummary, setGeneratingSummary] = useState(false);
  const [summaryMessage, setSummaryMessage] = useState<string | null>(null);

  const load = useCallback(() => {
    if (!Number.isInteger(id) || id < 1) return;

    setError(null);
    getIncident(id)
      .then(setIncident)
      .catch((e) => setError(e.message));

    setLoadingSummary(true);
    getIncidentAISummary(id)
      .then((out) => {
        setAiSummary(out);
        setSummaryMessage(null);
      })
      .catch(() => setAiSummary(null))
      .finally(() => setLoadingSummary(false));
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

  const handleUnlink = async (assetKey: string) => {
    setActionError(null);
    try {
      await unlinkIncidentAlert(id, assetKey);
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

  const handleGenerateSummary = async (force: boolean = false) => {
    setActionError(null);
    setSummaryMessage(null);
    setGeneratingSummary(true);
    try {
      const out = await generateIncidentAISummary(id, force);
      setAiSummary(out);
      if (isFallbackProvider(out.provider)) {
        setSummaryMessage(
          'Summary generated with fallback template due to temporary AI provider slowness or unavailability.'
        );
      } else {
        setSummaryMessage('Summary generated successfully.');
      }
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to generate AI summary';
      setActionError(msg);
      setSummaryMessage(msg);
    } finally {
      setGeneratingSummary(false);
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
        <p className="text-[var(--muted)]">Loading incident...</p>
      </main>
    );
  }

  const linkedRisk = incident.linked_risk;
  const linkedRiskFindings = linkedRisk?.items ?? [];

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
              style={{
                backgroundColor: `${severityColor(incident.severity)}20`,
                color: severityColor(incident.severity),
              }}
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
            {STATUS_FLOW.map((status) => (
              <button
                key={status}
                type="button"
                onClick={() => handleStatusChange(status)}
                disabled={loadingStatus || incident.status === status}
                className={`rounded-lg px-3 py-1.5 text-sm font-medium transition ${
                  incident.status === status
                    ? 'bg-[var(--green)] text-white'
                    : 'bg-[var(--border)]/50 text-[var(--muted)] hover:bg-[var(--border)]'
                }`}
              >
                {status}
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
              {incident.alerts.map((alert) => (
                <li key={alert.asset_key} className="flex items-center justify-between gap-2">
                  <Link
                    href={`/assets/${encodeURIComponent(alert.asset_key)}`}
                    className="font-medium text-[var(--red)] hover:underline"
                  >
                    {alert.asset_key}
                  </Link>
                  {canMutate && (
                    <button
                      type="button"
                      onClick={() => handleUnlink(alert.asset_key)}
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
                className="input max-w-xs flex-1"
              />
              <button
                type="button"
                onClick={handleLinkAlert}
                disabled={loadingLink || !linkAssetKey.trim()}
                className="btn-secondary text-sm"
              >
                {loadingLink ? 'Linking...' : 'Link alert'}
              </button>
            </div>
          )}
        </div>
      </section>

      <section className="mb-8">
        <div className="mb-3 flex flex-wrap items-center justify-between gap-3">
          <h2 className="section-title">Linked finding risk</h2>
          {linkedRiskFindings.length > 0 && (
            <Link href="/findings" className="text-xs font-medium text-[var(--green)] hover:underline">
              View all findings
            </Link>
          )}
        </div>
        <div className="card">
          {incident.alerts.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">Link alerts to see the highest-risk related findings.</p>
          ) : linkedRiskFindings.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No findings are currently associated with the linked assets.</p>
          ) : (
            <div>
              <p className="mb-3 text-xs text-[var(--muted)]">
                {linkedRisk?.asset_count ?? 0} linked asset{linkedRisk?.asset_count === 1 ? '' : 's'} |{' '}
                {linkedRisk?.finding_count ?? 0} finding{linkedRisk?.finding_count === 1 ? '' : 's'} |{' '}
                {linkedRisk?.active_finding_count ?? 0} active | top risk{' '}
                {linkedRisk?.top_risk_level || 'unscored'}{' '}
                {linkedRisk?.top_risk_score != null ? Math.round(Number(linkedRisk.top_risk_score)) : '-'}
              </p>
              <ul className="space-y-3">
                {linkedRiskFindings.map((finding) => (
                  <li
                    key={finding.finding_id}
                    className="flex flex-wrap items-start justify-between gap-3 rounded border border-[var(--border)] p-3"
                  >
                    <div className="min-w-0 flex-1">
                      <p className="font-medium text-[var(--text)]">{finding.title}</p>
                      <p className="mt-1 text-xs text-[var(--muted)]">
                        {finding.asset_key ? (
                          <Link
                            href={`/assets/${encodeURIComponent(finding.asset_key)}`}
                            className="hover:text-[var(--green)] hover:underline"
                          >
                            {finding.asset_name || finding.asset_key}
                          </Link>
                        ) : (
                          'Unlinked asset'
                        )}
                        {finding.category ? ` / ${finding.category}` : ''}
                      </p>
                      {riskDrivers(finding).length > 0 && (
                        <p className="mt-1 text-[11px] text-[var(--muted)]">
                          {riskDrivers(finding).map(formatRiskDriverLabel).join(' / ')}
                        </p>
                      )}
                    </div>
                    <div className="text-right">
                      <span
                        className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${riskBadgeClass(
                          finding.risk_level
                        )}`}
                      >
                        {finding.risk_level || 'risk'} {Math.round(Number(finding.risk_score ?? 0))}
                      </span>
                      <p className="mt-1 text-[11px] text-[var(--muted)] capitalize">
                        {finding.status.replace('_', ' ')}
                      </p>
                    </div>
                  </li>
                ))}
              </ul>
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
                placeholder="Note or update..."
                rows={3}
                className="input w-full"
              />
              <button
                type="button"
                onClick={handleAddNote}
                disabled={loadingNote}
                className="mt-2 btn-primary text-sm"
              >
                {loadingNote ? 'Adding...' : 'Add note'}
              </button>
            </div>
          )}
        </div>
      </section>

      <section className="mb-8">
        <h2 className="section-title mb-3">AI executive summary</h2>
        <div className="card">
          {loadingSummary ? (
            <p className="text-sm text-[var(--muted)]">Loading summary...</p>
          ) : aiSummary?.summary_text ? (
            <>
              <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">{aiSummary.summary_text}</p>
              <p className="mt-3 text-xs text-[var(--muted)]">
                Generated {formatDateTime(aiSummary.generated_at)} via {aiSummary.provider}/{aiSummary.model}
              </p>
              {isFallbackProvider(aiSummary.provider) && (
                <p className="mt-2 text-xs text-[var(--amber)]">
                  Showing fallback summary. Use Force regenerate to retry with full model output.
                </p>
              )}
            </>
          ) : (
            <p className="text-sm text-[var(--muted)]">No AI summary generated yet for this incident.</p>
          )}
          {summaryMessage && (
            <p
              className={`mt-3 text-xs ${
                summaryMessage.toLowerCase().includes('failed')
                  ? 'text-[var(--red)]'
                  : 'text-[var(--muted)]'
              }`}
            >
              {summaryMessage}
            </p>
          )}
          {canMutate && (
            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() => handleGenerateSummary(false)}
                disabled={generatingSummary}
                className="btn-primary text-sm"
              >
                {generatingSummary ? 'Generating...' : aiSummary ? 'Refresh summary' : 'Generate summary'}
              </button>
              {aiSummary && (
                <button
                  type="button"
                  onClick={() => handleGenerateSummary(true)}
                  disabled={generatingSummary}
                  className="btn-secondary text-sm"
                >
                  Force regenerate
                </button>
              )}
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
                  {loadingJira ? 'Creating...' : 'Create Jira ticket'}
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
