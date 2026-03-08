'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  compareAISummaryVersions,
  createAIFeedback,
  createAISummaryVersion,
  getAttackGraphIncident,
  getIncident,
  getIncidentAISummary,
  listAISummaryVersions,
  updateIncidentStatus,
  addIncidentNote,
  linkIncidentAlert,
  unlinkIncidentAlert,
  createIncidentJiraTicket,
  generateIncidentAISummary,
  type AIFeedbackValue,
  type AttackGraph,
  type AIIncidentSummary,
  type AISummaryVersion,
  type AISummaryVersionCompare,
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
type GuardrailSectionKey = 'facts' | 'inference' | 'recommendations';
type GuardrailItem = { statement: string; evidence: string[] };

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

function parseGuardrailItems(raw: unknown): GuardrailItem[] {
  if (!Array.isArray(raw)) return [];
  const out: GuardrailItem[] = [];
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object') continue;
    const statement = String((entry as Record<string, unknown>).statement || '').trim();
    if (!statement) continue;
    const evidenceRaw = (entry as Record<string, unknown>).evidence;
    const evidence = Array.isArray(evidenceRaw)
      ? evidenceRaw
          .map((value) => String(value || '').trim().toUpperCase())
          .filter((value) => value.length > 0)
      : [];
    out.push({ statement, evidence });
  }
  return out;
}

function parseIncidentGuardrails(ai?: AIIncidentSummary | null): {
  mode: string;
  usedFallbackSections: boolean;
  sections: Record<GuardrailSectionKey, GuardrailItem[]>;
  evidenceMap: Record<string, string>;
} | null {
  if (!ai?.context_json || typeof ai.context_json !== 'object') return null;
  const guardrails = (ai.context_json as Record<string, unknown>).guardrails;
  if (!guardrails || typeof guardrails !== 'object') return null;

  const guardrailObj = guardrails as Record<string, unknown>;
  const mode = String(guardrailObj.mode || '').trim();
  const usedFallbackSections = Boolean(guardrailObj.used_fallback_sections);
  const sectionsRaw = guardrailObj.sections;
  const sectionsObj =
    sectionsRaw && typeof sectionsRaw === 'object'
      ? (sectionsRaw as Record<string, unknown>)
      : {};
  const sections: Record<GuardrailSectionKey, GuardrailItem[]> = {
    facts: parseGuardrailItems(sectionsObj.facts),
    inference: parseGuardrailItems(sectionsObj.inference),
    recommendations: parseGuardrailItems(sectionsObj.recommendations),
  };

  if (
    sections.facts.length === 0 &&
    sections.inference.length === 0 &&
    sections.recommendations.length === 0
  ) {
    return null;
  }

  const evidenceMap: Record<string, string> = {};
  const catalog = guardrailObj.evidence_catalog;
  if (Array.isArray(catalog)) {
    for (const item of catalog) {
      if (!item || typeof item !== 'object') continue;
      const row = item as Record<string, unknown>;
      const id = String(row.id || '').trim().toUpperCase();
      if (!id) continue;
      const kind = String(row.kind || '').trim();
      const value = String(row.value ?? '').trim();
      const label = kind && value ? `${kind}: ${value}` : kind || value || id;
      evidenceMap[id] = label.slice(0, 140);
    }
  }

  return { mode, usedFallbackSections, sections, evidenceMap };
}

function TimelineEntry({ entry }: { entry: IncidentTimelineEntry }) {
  const sourceType = String(entry.source_type || 'event');

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

  if (entry.event_type === 'alert_activity') {
    const assetKey = (entry.details?.asset_key as string) ?? '-';
    const severity = (entry.details?.severity as string) ?? 'medium';
    const status = (entry.details?.status as string) ?? 'firing';
    return (
      <div className="border-l-2 border-[var(--amber)]/60 pl-4 py-2">
        <p className="text-sm text-[var(--text)]">{entry.body || 'Alert activity'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          Asset {assetKey} | Severity {severity} | Status {status}
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  if (entry.event_type === 'finding_activity') {
    const assetKey = (entry.details?.asset_key as string) ?? '-';
    const severity = (entry.details?.severity as string) ?? 'medium';
    const status = (entry.details?.status as string) ?? 'open';
    return (
      <div className="border-l-2 border-orange-500/50 pl-4 py-2">
        <p className="text-sm text-[var(--text)]">{entry.body || 'Finding activity'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          Asset {assetKey} | Severity {severity} | Status {status}
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  if (entry.event_type === 'telemetry_event') {
    const src = (entry.details?.src_ip as string) ?? '-';
    const domain = (entry.details?.domain as string) ?? '-';
    const process = (entry.details?.process as string) ?? '-';
    return (
      <div className="border-l-2 border-sky-500/50 pl-4 py-2">
        <p className="text-sm text-[var(--text)]">{entry.body || 'Telemetry event'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          Src IP {src} | Domain {domain} | Process {process}
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          Collector | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  if (entry.event_type === 'job_activity' || entry.event_type === 'job_linked') {
    const jobType = (entry.details?.job_type as string) ?? 'job';
    const status = (entry.details?.status as string) ?? 'queued';
    const jobId = (entry.details?.job_id as number | string | null) ?? null;
    return (
      <div className="border-l-2 border-indigo-500/50 pl-4 py-2">
        <p className="text-sm text-[var(--text)]">{entry.body || 'Job activity'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {jobId != null ? `Job #${jobId} | ` : ''}
          Type {jobType} | Status {status}
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  if (entry.event_type === 'automation_action' || entry.event_type === 'response_rollback') {
    const actionType =
      (entry.details?.action_type as string) ??
      (entry.details?.rollback_type as string) ??
      'action';
    const status = (entry.details?.status as string) ?? 'pending';
    return (
      <div className="border-l-2 border-violet-500/50 pl-4 py-2">
        <p className="text-sm text-[var(--text)]">{entry.body || 'Automation activity'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          Type {actionType} | Status {status}
        </p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'Automation'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  if (entry.event_type === 'decision') {
    return (
      <div className="border-l-2 border-[var(--green)]/40 pl-4 py-2">
        <p className="text-sm text-[var(--text)]">{entry.body || 'Decision logged'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  if (entry.event_type === 'evidence_linked') {
    return (
      <div className="border-l-2 border-[var(--border)] pl-4 py-2">
        <p className="text-sm text-[var(--text)]">{entry.body || 'Evidence linked'}</p>
        <p className="mt-1 text-xs text-[var(--muted)]">
          {entry.author ?? 'System'} | {formatDateTime(entry.created_at)}
        </p>
      </div>
    );
  }

  return (
    <div className="border-l-2 border-[var(--border)] pl-4 py-2">
      {entry.body && <p className="text-sm text-[var(--text)]">{entry.body}</p>}
      <p className="text-xs text-[var(--muted)]">
        {formatDateTime(entry.created_at)} | {entry.event_type} | {sourceType}
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
  const [savingVersion, setSavingVersion] = useState(false);
  const [feedbackBusy, setFeedbackBusy] = useState<AIFeedbackValue | null>(null);
  const [loadingVersions, setLoadingVersions] = useState(false);
  const [summaryVersions, setSummaryVersions] = useState<AISummaryVersion[]>([]);
  const [compareFrom, setCompareFrom] = useState<number | null>(null);
  const [compareTo, setCompareTo] = useState<number | null>(null);
  const [comparison, setComparison] = useState<AISummaryVersionCompare | null>(null);
  const [comparingVersions, setComparingVersions] = useState(false);
  const [summaryMessage, setSummaryMessage] = useState<string | null>(null);
  const [incidentGraph, setIncidentGraph] = useState<AttackGraph | null>(null);
  const [loadingGraph, setLoadingGraph] = useState(false);
  const [graphError, setGraphError] = useState<string | null>(null);
  const [graphLookbackHours, setGraphLookbackHours] = useState('72');

  const loadSummaryVersions = useCallback(() => {
    if (!Number.isInteger(id) || id < 1) return;
    setLoadingVersions(true);
    listAISummaryVersions('incident', id, 30)
      .then((out) => {
        const items = out.items || [];
        setSummaryVersions(items);
        const versionNos = items.map((item) => Number(item.version_no)).filter(Number.isFinite);
        setCompareTo((prev) => {
          if (versionNos.length === 0) return null;
          if (prev != null && versionNos.includes(prev)) return prev;
          return versionNos[0];
        });
        setCompareFrom((prev) => {
          if (versionNos.length === 0) return null;
          if (prev != null && versionNos.includes(prev)) return prev;
          return versionNos.length > 1 ? versionNos[1] : versionNos[0];
        });
      })
      .catch(() => setSummaryVersions([]))
      .finally(() => setLoadingVersions(false));
  }, [id]);

  const loadIncidentGraph = useCallback(
    async (lookbackOverride?: number) => {
      if (!Number.isInteger(id) || id < 1) return;
      const lookback = Math.max(
        1,
        Math.min(720, Number.isFinite(lookbackOverride) ? Number(lookbackOverride) : Number(graphLookbackHours || 72))
      );
      setLoadingGraph(true);
      setGraphError(null);
      try {
        const graph = await getAttackGraphIncident(id, lookback);
        setIncidentGraph(graph);
      } catch (e) {
        setIncidentGraph(null);
        const msg = e instanceof Error ? e.message : 'Failed to load incident graph';
        setGraphError(msg);
      } finally {
        setLoadingGraph(false);
      }
    },
    [graphLookbackHours, id]
  );

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
    loadSummaryVersions();
    void loadIncidentGraph();
  }, [id, loadIncidentGraph, loadSummaryVersions]);

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

  const handleSaveSummaryVersion = async () => {
    if (!aiSummary?.summary_text) {
      setSummaryMessage('Generate a summary first, then save a version.');
      return;
    }
    setActionError(null);
    setSummaryMessage(null);
    setSavingVersion(true);
    try {
      const created = await createAISummaryVersion('incident', id, {
        content_text: aiSummary.summary_text,
        provider: aiSummary.provider,
        model: aiSummary.model,
        source_type: generatingSummary ? 'regenerate' : 'generated',
        context_json: aiSummary.context_json || {},
        evidence_json: {
          generated_at: aiSummary.generated_at,
          generated_by: aiSummary.generated_by || null,
        },
      });
      await loadSummaryVersions();
      setSummaryMessage(`Saved version v${created.version_no}.`);
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save summary version';
      setActionError(msg);
      setSummaryMessage(msg);
    } finally {
      setSavingVersion(false);
    }
  };

  const handleSummaryFeedback = async (feedback: AIFeedbackValue) => {
    if (!aiSummary?.summary_text) {
      setSummaryMessage('Generate a summary first, then submit feedback.');
      return;
    }
    setActionError(null);
    setSummaryMessage(null);
    setFeedbackBusy(feedback);
    try {
      let latestVersionId = summaryVersions[0]?.version_id ?? null;
      if (!latestVersionId) {
        const created = await createAISummaryVersion('incident', id, {
          content_text: aiSummary.summary_text,
          provider: aiSummary.provider,
          model: aiSummary.model,
          source_type: 'feedback_seed',
          context_json: aiSummary.context_json || {},
          evidence_json: {
            generated_at: aiSummary.generated_at,
            generated_by: aiSummary.generated_by || null,
          },
        });
        latestVersionId = created.version_id;
        await loadSummaryVersions();
      }
      await createAIFeedback({
        entity_type: 'incident',
        entity_id: id,
        version_id: latestVersionId,
        feedback,
        context_json: { surface: 'incident_detail' },
      });
      setSummaryMessage(
        feedback === 'up'
          ? 'Feedback recorded: summary was useful.'
          : 'Feedback recorded: summary needs improvement.'
      );
    } catch (e) {
      const msg = e instanceof Error ? e.message : 'Failed to save feedback';
      setActionError(msg);
      setSummaryMessage(msg);
    } finally {
      setFeedbackBusy(null);
    }
  };

  const handleCompareVersions = async () => {
    if (compareFrom == null || compareTo == null || compareFrom === compareTo) return;
    setActionError(null);
    setComparingVersions(true);
    try {
      const out = await compareAISummaryVersions('incident', id, compareFrom, compareTo);
      setComparison(out);
    } catch (e) {
      setActionError(e instanceof Error ? e.message : 'Failed to compare versions');
      setComparison(null);
    } finally {
      setComparingVersions(false);
    }
  };

  const summaryGuardrails = useMemo(() => parseIncidentGuardrails(aiSummary), [aiSummary]);

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
        <div className="mb-3 flex flex-wrap items-end justify-between gap-3">
          <h2 className="section-title">Attack graph panel</h2>
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-xs text-[var(--muted)]">
              Lookback
              <input
                type="number"
                min={1}
                max={720}
                value={graphLookbackHours}
                onChange={(e) => setGraphLookbackHours(e.target.value)}
                className="ml-2 w-20 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1 text-xs text-[var(--text)]"
              />
            </label>
            <button
              type="button"
              onClick={() => void loadIncidentGraph()}
              disabled={loadingGraph}
              className="btn-secondary text-xs"
            >
              {loadingGraph ? 'Refreshing...' : 'Refresh graph'}
            </button>
            <Link href="/attack-graph" className="text-xs font-medium text-[var(--green)] hover:underline">
              Open full graph workspace
            </Link>
          </div>
        </div>
        <div className="card">
          {loadingGraph ? (
            <p className="text-sm text-[var(--muted)]">Loading attack graph...</p>
          ) : graphError ? (
            <p className="text-sm text-[var(--muted)]">{friendlyApiMessage(graphError)}</p>
          ) : !incidentGraph || incidentGraph.nodes.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">
              No graph data yet for this incident. Add alerts or telemetry and refresh.
            </p>
          ) : (
            <div className="space-y-4">
              <div className="grid gap-2 sm:grid-cols-4">
                <div className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] p-2 text-xs">
                  <p className="text-[var(--muted)] uppercase">Nodes</p>
                  <p className="text-base font-semibold text-[var(--text)]">{incidentGraph.nodes.length}</p>
                </div>
                <div className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] p-2 text-xs">
                  <p className="text-[var(--muted)] uppercase">Edges</p>
                  <p className="text-base font-semibold text-[var(--text)]">{incidentGraph.edges.length}</p>
                </div>
                <div className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] p-2 text-xs">
                  <p className="text-[var(--muted)] uppercase">Kill-chain phases</p>
                  <p className="text-base font-semibold text-[var(--text)]">{incidentGraph.kill_chain.length}</p>
                </div>
                <div className="rounded border border-[var(--border)] bg-[var(--surface-elevated)] p-2 text-xs">
                  <p className="text-[var(--muted)] uppercase">Incident</p>
                  <p className="text-base font-semibold text-[var(--text)]">#{incident.id}</p>
                </div>
              </div>

              {incidentGraph.kill_chain.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {incidentGraph.kill_chain.map((phase) => (
                    <span
                      key={phase.phase}
                      className="rounded-full border border-[var(--border)] bg-[var(--surface-elevated)] px-2 py-0.5 text-xs text-[var(--muted)]"
                    >
                      {phase.phase}: {phase.count}
                    </span>
                  ))}
                </div>
              )}

              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-[var(--border)] text-left uppercase tracking-[0.12em] text-[var(--muted)]">
                      <th className="px-2 py-2">Source</th>
                      <th className="px-2 py-2">Relation</th>
                      <th className="px-2 py-2">Target</th>
                      <th className="px-2 py-2">Weight</th>
                    </tr>
                  </thead>
                  <tbody>
                    {incidentGraph.edges.slice(0, 12).map((edge) => (
                      <tr key={edge.id} className="border-b border-[var(--border)]/40">
                        <td className="px-2 py-2 font-mono">{edge.source}</td>
                        <td className="px-2 py-2">{edge.relation}</td>
                        <td className="px-2 py-2 font-mono">{edge.target}</td>
                        <td className="px-2 py-2">{edge.weight ?? 1}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {incidentGraph.edges.length > 12 && (
                  <p className="mt-2 text-xs text-[var(--muted)]">
                    Showing 12 of {incidentGraph.edges.length} edges. Open the full workspace for the full path graph.
                  </p>
                )}
              </div>
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
              {summaryGuardrails && (
                <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                      Evidence-backed breakdown
                    </p>
                    {summaryGuardrails.mode && (
                      <span className="stat-chip">Mode: {summaryGuardrails.mode}</span>
                    )}
                    {summaryGuardrails.usedFallbackSections && (
                      <span className="rounded-full border border-[var(--amber)]/30 bg-[var(--amber)]/15 px-2 py-0.5 text-[11px] text-[var(--amber)]">
                        fallback sections used
                      </span>
                    )}
                  </div>
                  <div className="mt-3 grid gap-3 lg:grid-cols-3">
                    {(['facts', 'inference', 'recommendations'] as GuardrailSectionKey[]).map(
                      (key) => (
                        <div
                          key={key}
                          className="rounded-lg border border-[var(--border)] bg-[var(--surface)]/70 p-3"
                        >
                          <p className="text-xs font-semibold uppercase tracking-wide text-[var(--muted)]">
                            {key.replace('_', ' ')}
                          </p>
                          {summaryGuardrails.sections[key].length > 0 ? (
                            <ul className="mt-2 space-y-2">
                              {summaryGuardrails.sections[key].map((entry, idx) => (
                                <li key={`${key}-${idx}`} className="text-xs text-[var(--text)]">
                                  <p>{entry.statement}</p>
                                  {entry.evidence.length > 0 && (
                                    <div className="mt-1 flex flex-wrap gap-1">
                                      {entry.evidence.map((eid) => (
                                        <span
                                          key={`${key}-${idx}-${eid}`}
                                          className="rounded-full border border-[var(--border)] px-2 py-0.5 font-mono text-[10px] text-[var(--muted)]"
                                          title={summaryGuardrails.evidenceMap[eid] || eid}
                                        >
                                          {eid}
                                        </span>
                                      ))}
                                    </div>
                                  )}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <p className="mt-2 text-xs text-[var(--muted)]">No entries</p>
                          )}
                        </div>
                      )
                    )}
                  </div>
                </div>
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
              <button
                type="button"
                onClick={handleSaveSummaryVersion}
                disabled={savingVersion || !aiSummary?.summary_text}
                className="btn-secondary text-sm"
              >
                {savingVersion ? 'Saving...' : 'Save version'}
              </button>
              <button
                type="button"
                onClick={() => handleSummaryFeedback('up')}
                disabled={feedbackBusy != null || !aiSummary?.summary_text}
                className="btn-secondary text-sm"
              >
                {feedbackBusy === 'up' ? 'Saving...' : 'Thumbs up'}
              </button>
              <button
                type="button"
                onClick={() => handleSummaryFeedback('down')}
                disabled={feedbackBusy != null || !aiSummary?.summary_text}
                className="btn-secondary text-sm"
              >
                {feedbackBusy === 'down' ? 'Saving...' : 'Thumbs down'}
              </button>
            </div>
          )}
          <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                Summary versions
              </p>
              <span className="stat-chip">{summaryVersions.length} saved</span>
            </div>
            {loadingVersions ? (
              <p className="mt-3 text-xs text-[var(--muted)]">Loading version history...</p>
            ) : summaryVersions.length === 0 ? (
              <p className="mt-3 text-xs text-[var(--muted)]">
                No saved versions yet. Save the current summary to start change tracking.
              </p>
            ) : (
              <ul className="mt-3 space-y-2 text-xs text-[var(--muted)]">
                {summaryVersions.slice(0, 6).map((version) => (
                  <li key={version.version_id} className="flex items-center justify-between gap-3">
                    <span>
                      v{version.version_no} · {version.source_type || 'generated'}
                    </span>
                    <span>{formatDateTime(version.created_at)}</span>
                  </li>
                ))}
              </ul>
            )}
            {summaryVersions.length >= 2 && (
              <div className="mt-4 space-y-3 border-t border-[var(--border)] pt-4">
                <p className="text-xs font-semibold uppercase tracking-[0.12em] text-[var(--muted)]">
                  Compare versions
                </p>
                <div className="grid gap-2 sm:grid-cols-[1fr_1fr_auto]">
                  <select
                    value={compareFrom ?? ''}
                    onChange={(e) => setCompareFrom(e.target.value ? Number(e.target.value) : null)}
                    className="input py-2 text-sm"
                  >
                    {summaryVersions.map((version) => (
                      <option key={`from-${version.version_id}`} value={version.version_no}>
                        From v{version.version_no}
                      </option>
                    ))}
                  </select>
                  <select
                    value={compareTo ?? ''}
                    onChange={(e) => setCompareTo(e.target.value ? Number(e.target.value) : null)}
                    className="input py-2 text-sm"
                  >
                    {summaryVersions.map((version) => (
                      <option key={`to-${version.version_id}`} value={version.version_no}>
                        To v{version.version_no}
                      </option>
                    ))}
                  </select>
                  <button
                    type="button"
                    onClick={handleCompareVersions}
                    disabled={
                      comparingVersions ||
                      compareFrom == null ||
                      compareTo == null ||
                      compareFrom === compareTo
                    }
                    className="btn-secondary text-sm"
                  >
                    {comparingVersions ? 'Comparing...' : 'Compare'}
                  </button>
                </div>
                {comparison && (
                  <div className="rounded-lg border border-[var(--border)] bg-[var(--bg)] px-3 py-2 text-xs text-[var(--muted)]">
                    <p>
                      Word delta: {comparison.word_delta >= 0 ? '+' : ''}
                      {comparison.word_delta}
                    </p>
                    <p className="mt-1">
                      v{comparison.from_version}: {comparison.before_excerpt || '(empty)'}
                    </p>
                    <p className="mt-1">
                      v{comparison.to_version}: {comparison.after_excerpt || '(empty)'}
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>
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
