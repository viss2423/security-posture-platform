'use client';

import Link from 'next/link';
import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createAIFeedback,
  createAISummaryVersion,
  createJob,
  generateJobAITriage,
  getJob,
  getJobAITriage,
  getJobs,
  retryJob,
  type AIFeedbackValue,
  type AIJobTriage,
  type JobDetail,
  type JobItem,
  type JobProgress,
} from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { formatDateTime } from '@/lib/format';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';

type EnqueueJobType =
  | 'web_exposure'
  | 'score_recompute'
  | 'repository_scan'
  | 'threat_intel_refresh'
  | 'telemetry_import'
  | 'network_anomaly_score'
  | 'attack_lab_run'
  | 'detection_rule_test'
  | 'aws_iam_posture'
  | 'github_posture';

const JOB_LABELS: Record<EnqueueJobType, string> = {
  web_exposure: 'Web Exposure Scan',
  score_recompute: 'Score Recompute',
  repository_scan: 'Repository Scan',
  threat_intel_refresh: 'Threat Intel Refresh',
  telemetry_import: 'Telemetry Import',
  network_anomaly_score: 'Anomaly Scoring',
  attack_lab_run: 'Attack Lab Run',
  detection_rule_test: 'Detection Rule Test',
  aws_iam_posture: 'AWS IAM Posture',
  github_posture: 'GitHub Posture',
};

const JOB_DESCRIPTIONS: Record<EnqueueJobType, string> = {
  web_exposure: 'Check web-facing assets for open ports and exposed services.',
  score_recompute: 'Recalculate posture scores from current findings.',
  repository_scan: 'Run OSV and Trivy scanners against the configured repository.',
  threat_intel_refresh: 'Pull the latest IOC feeds and match against your assets.',
  telemetry_import: 'Parse log files and generate event-centric alerts.',
  network_anomaly_score: 'Detect per-asset deviations from the recent telemetry baseline.',
  attack_lab_run: 'Run a controlled attack simulation and generate incidents.',
  detection_rule_test: 'Evaluate detection rules against recent telemetry.',
  aws_iam_posture: 'Scan AWS IAM read-only for root MFA, password policy, stale keys, admin policies, and unused users.',
  github_posture: 'Scan a GitHub account or org read-only for security gaps (branch protection, 2FA, Dependabot, secret scanning, public repos).',
};

const DEFAULT_REPOSITORY_SCAN = {
  path: '/workspace',
  assetKey: 'secplat-repo',
  assetName: 'SecPlat repository',
  environment: 'dev',
  criticality: 'medium',
  trivyScanners: 'vuln,misconfig,secret',
};

const DEFAULT_JOB_PARAMS: Partial<Record<EnqueueJobType, string>> = {
  telemetry_import: JSON.stringify(
    { source: 'suricata', file_path: '/workspace/lab-data/suricata/eve.json', asset_key: 'secplat-api' },
    null,
    2
  ),
  network_anomaly_score: JSON.stringify({ lookback_hours: 24, threshold: 2.5 }, null, 2),
  attack_lab_run: JSON.stringify({ task_type: 'port_scan', target: 'verify-web', asset_key: 'verify-web' }, null, 2),
  detection_rule_test: JSON.stringify({ rule_id: 1, lookback_hours: 24 }, null, 2),
};

function jobLabel(type: string): string {
  return JOB_LABELS[type as EnqueueJobType] ?? type.replace(/_/g, ' ');
}

function formatJobParamValue(value: unknown): string {
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (value == null || value === '') return '-';
  return String(value);
}

function StatusDot({ status }: { status: string }) {
  if (status === 'done') return <span className="dot-online" style={{ width: 7, height: 7 }} />;
  if (status === 'running') return <span className="dot-warning" style={{ width: 7, height: 7 }} />;
  if (status === 'failed') return <span className="dot-critical" style={{ width: 7, height: 7 }} />;
  return <span className="inline-block h-1.5 w-1.5 rounded-full bg-[var(--text-subtle)]" />;
}

function ScanProgressBar({ progress, compact = false }: { progress: JobProgress; compact?: boolean }) {
  const total = Math.max(1, Number(progress.repos_total) || 0);
  const done = Math.min(total, Math.max(0, Number(progress.repos_done) || 0));
  const pct = Math.round((done / total) * 100);
  return (
    <div className={compact ? 'w-40 shrink-0' : 'w-full'}>
      <div className="flex items-center justify-between gap-2 text-[10px] text-[var(--text-subtle)]">
        <span className="tabular-nums">{done}/{total} repos</span>
        {progress.findings_so_far != null && (
          <span className="tabular-nums text-[var(--amber)]">{progress.findings_so_far} findings</span>
        )}
      </div>
      <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, background: 'var(--amber)', boxShadow: '0 0 8px rgba(251,191,36,0.4)' }}
        />
      </div>
      {!compact && progress.current && (
        <p className="mt-1 truncate font-mono text-[10px] text-[var(--text-subtle)]">scanning {progress.current}</p>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    done:    'bg-[var(--green)]/15 text-[var(--green)] border-[var(--green)]/20',
    failed:  'bg-[var(--red)]/15 text-[var(--red)] border-[var(--red)]/20',
    running: 'bg-[var(--amber)]/15 text-[var(--amber)] border-[var(--amber)]/20',
    queued:  'bg-[var(--surface-elevated)] text-[var(--muted)] border-[var(--border)]',
  };
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium ${map[status] ?? map.queued}`}>
      <StatusDot status={status} />
      {status}
    </span>
  );
}

export default function JobsPage() {
  const { canMutate } = useAuth();
  const [data, setData] = useState<{ items: JobItem[] } | null>(null);
  const [detail, setDetail] = useState<JobDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [retryingId, setRetryingId] = useState<number | null>(null);
  const [enqueueType, setEnqueueType] = useState<EnqueueJobType>('web_exposure');
  const [enqueueAssetId, setEnqueueAssetId] = useState('');
  const [repoPath, setRepoPath] = useState(DEFAULT_REPOSITORY_SCAN.path);
  const [repoAssetKey, setRepoAssetKey] = useState(DEFAULT_REPOSITORY_SCAN.assetKey);
  const [repoAssetName, setRepoAssetName] = useState(DEFAULT_REPOSITORY_SCAN.assetName);
  const [repoEnvironment, setRepoEnvironment] = useState(DEFAULT_REPOSITORY_SCAN.environment);
  const [repoCriticality, setRepoCriticality] = useState(DEFAULT_REPOSITORY_SCAN.criticality);
  const [repoTrivyScanners, setRepoTrivyScanners] = useState(DEFAULT_REPOSITORY_SCAN.trivyScanners);
  const [repoEnableOsv, setRepoEnableOsv] = useState(true);
  const [repoEnableTrivy, setRepoEnableTrivy] = useState(true);
  const [ghScopeType, setGhScopeType] = useState<'user' | 'org'>('user');
  const [ghScope, setGhScope] = useState('');
  const [ghMaxRepos, setGhMaxRepos] = useState('50');
  const [awsRegion, setAwsRegion] = useState('');
  const [enqueueing, setEnqueueing] = useState(false);
  const [customJobParams, setCustomJobParams] = useState<string>(DEFAULT_JOB_PARAMS.telemetry_import || '{}');
  const [aiTriage, setAiTriage] = useState<AIJobTriage | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageGenerating, setTriageGenerating] = useState(false);
  const [triageMessage, setTriageMessage] = useState<string | null>(null);
  const [savingTriageVersion, setSavingTriageVersion] = useState(false);
  const [triageFeedbackBusy, setTriageFeedbackBusy] = useState<AIFeedbackValue | null>(null);
  const [showForm, setShowForm] = useState(false);

  const load = useCallback(() => {
    getJobs(statusFilter || undefined)
      .then((result) => { setData(result); setError(null); })
      .catch((e) => setError(e.message));
  }, [statusFilter]);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (enqueueType in DEFAULT_JOB_PARAMS) {
      setCustomJobParams(DEFAULT_JOB_PARAMS[enqueueType] || '{}');
    }
  }, [enqueueType]);

  const openDetail = (id: number) => {
    setAiTriage(null);
    setTriageMessage(null);
    getJob(id).then(setDetail).catch((e) => setError(e.message));
  };

  useEffect(() => {
    if (!detail || (detail.status !== 'failed' && !detail.error)) {
      setAiTriage(null); setTriageLoading(false); setTriageMessage(null);
      return;
    }
    setTriageLoading(true);
    setTriageMessage(null);
    getJobAITriage(detail.job_id)
      .then(setAiTriage)
      .catch((e) => {
        const message = e instanceof Error ? e.message : 'Failed to load AI triage';
        if (!message.toLowerCase().includes('not found')) setTriageMessage(message);
        setAiTriage(null);
      })
      .finally(() => setTriageLoading(false));
  }, [detail]);

  const handleEnqueue = () => {
    if (enqueueType === 'repository_scan') {
      if (!repoEnableOsv && !repoEnableTrivy) { setError('Enable at least one repository scanner'); return; }
      setError(null); setEnqueueing(true);
      createJob({
        job_type: enqueueType,
        job_params_json: {
          path: repoPath.trim() || DEFAULT_REPOSITORY_SCAN.path,
          asset_key: repoAssetKey.trim() || DEFAULT_REPOSITORY_SCAN.assetKey,
          asset_name: repoAssetName.trim() || DEFAULT_REPOSITORY_SCAN.assetName,
          environment: repoEnvironment.trim() || DEFAULT_REPOSITORY_SCAN.environment,
          criticality: repoCriticality.trim() || DEFAULT_REPOSITORY_SCAN.criticality,
          trivy_scanners: repoTrivyScanners.trim() || DEFAULT_REPOSITORY_SCAN.trivyScanners,
          enable_osv: repoEnableOsv,
          enable_trivy: repoEnableTrivy,
        },
      }).then((job) => { load(); openDetail(job.job_id); setShowForm(false); })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }
    if (enqueueType === 'threat_intel_refresh') {
      setError(null); setEnqueueing(true);
      createJob({ job_type: enqueueType })
        .then((job) => { load(); openDetail(job.job_id); setShowForm(false); })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }
    if (enqueueType === 'github_posture') {
      if (ghScopeType === 'org' && !ghScope.trim()) { setError('Organization name is required for org scans'); return; }
      const maxRepos = parseInt(ghMaxRepos, 10);
      if (Number.isNaN(maxRepos) || maxRepos < 1 || maxRepos > 500) { setError('Max repositories must be between 1 and 500'); return; }
      setError(null); setEnqueueing(true);
      createJob({
        job_type: enqueueType,
        job_params_json: {
          scope_type: ghScopeType,
          scope: ghScope.trim(),
          max_repos: maxRepos,
        },
      }).then((job) => { load(); openDetail(job.job_id); setShowForm(false); })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }
    if (enqueueType === 'aws_iam_posture') {
      setError(null); setEnqueueing(true);
      createJob({
        job_type: enqueueType,
        job_params_json: awsRegion.trim() ? { region: awsRegion.trim() } : {},
      }).then((job) => { load(); openDetail(job.job_id); setShowForm(false); })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }
    if (['telemetry_import', 'network_anomaly_score', 'attack_lab_run', 'detection_rule_test'].includes(enqueueType)) {
      let parsedParams: Record<string, unknown> = {};
      try { parsedParams = customJobParams.trim() ? JSON.parse(customJobParams) : {}; }
      catch { setError('Job params must be valid JSON'); return; }
      setError(null); setEnqueueing(true);
      createJob({ job_type: enqueueType, job_params_json: parsedParams })
        .then((job) => { load(); openDetail(job.job_id); setShowForm(false); })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }
    const assetId = enqueueAssetId.trim() ? parseInt(enqueueAssetId, 10) : undefined;
    if (assetId != null && Number.isNaN(assetId)) { setError('Asset ID must be a number'); return; }
    setError(null); setEnqueueing(true);
    createJob({ job_type: enqueueType, target_asset_id: assetId })
      .then(() => { load(); setEnqueueAssetId(''); setShowForm(false); })
      .catch((e) => setError(e.message))
      .finally(() => setEnqueueing(false));
  };

  const handleRetry = (id: number) => {
    setError(null); setRetryingId(id);
    retryJob(id)
      .then(() => { load(); if (detail?.job_id === id) openDetail(id); })
      .catch((e) => setError(e.message))
      .finally(() => setRetryingId(null));
  };

  const handleGenerateTriage = async (force: boolean) => {
    if (!detail) return;
    setTriageGenerating(true); setTriageMessage(null);
    try {
      const out = await generateJobAITriage(detail.job_id, force);
      setAiTriage(out);
      setTriageMessage(out.cached ? 'Showing cached AI triage.' : 'AI triage generated.');
    } catch (e) {
      setTriageMessage(e instanceof Error ? e.message : 'AI triage generation failed');
    } finally { setTriageGenerating(false); }
  };

  const handleSaveTriageVersion = async () => {
    if (!detail || !aiTriage?.triage_text) { setTriageMessage('Generate AI triage before saving a version.'); return; }
    setSavingTriageVersion(true); setTriageMessage(null);
    try {
      const created = await createAISummaryVersion('job', detail.job_id, {
        content_text: aiTriage.triage_text,
        provider: aiTriage.provider,
        model: aiTriage.model,
        source_type: aiTriage.cached ? 'cached' : 'generated',
        context_json: aiTriage.context_json || {},
        evidence_json: { generated_at: aiTriage.generated_at, generated_by: aiTriage.generated_by || null },
      });
      setTriageMessage(`Saved version v${created.version_no}.`);
    } catch (e) { setTriageMessage(e instanceof Error ? e.message : 'Saving triage version failed'); }
    finally { setSavingTriageVersion(false); }
  };

  const handleTriageFeedback = async (feedback: AIFeedbackValue) => {
    if (!detail || !aiTriage?.triage_text) { setTriageMessage('Generate AI triage before submitting feedback.'); return; }
    setTriageFeedbackBusy(feedback); setTriageMessage(null);
    try {
      await createAIFeedback({ entity_type: 'job', entity_id: detail.job_id, feedback, context_json: { surface: 'jobs_page' } });
      setTriageMessage(feedback === 'up' ? 'Feedback recorded: triage was useful.' : 'Feedback recorded: triage needs improvement.');
    } catch (e) { setTriageMessage(e instanceof Error ? e.message : 'Saving triage feedback failed'); }
    finally { setTriageFeedbackBusy(null); }
  };

  const statusCounts = useMemo(() => {
    const counts = { queued: 0, running: 0, done: 0, failed: 0 };
    for (const job of data?.items ?? []) {
      if (job.status in counts) counts[job.status as keyof typeof counts] += 1;
    }
    return counts;
  }, [data]);

  const activeJobs = statusCounts.queued + statusCounts.running;
  const terminalJobs = statusCounts.done + statusCounts.failed;
  const successRate = terminalJobs > 0 ? Math.round((statusCounts.done / terminalJobs) * 100) : null;
  const successRateColor =
    successRate == null ? 'var(--text-subtle)' :
    successRate >= 80 ? 'var(--green)' :
    successRate >= 50 ? 'var(--amber)' :
    'var(--red)';

  const fieldClass = 'w-full rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-3 py-2 text-sm text-[var(--text)] placeholder:text-[var(--text-subtle)] transition focus:outline-none focus:ring-2 focus:ring-[var(--accent-ring)] focus:border-[var(--accent)]';

  const filteredItems = data?.items ?? [];

  useEffect(() => {
    if (activeJobs <= 0) return;
    const poll = window.setInterval(load, 4500);
    return () => window.clearInterval(poll);
  }, [activeJobs, load]);

  // Keep an open detail panel live while its job is queued/running so the
  // progress bar advances without the user re-clicking the row.
  useEffect(() => {
    if (!detail || (detail.status !== 'running' && detail.status !== 'queued')) return;
    const poll = window.setInterval(() => {
      getJob(detail.job_id).then(setDetail).catch(() => {});
    }, 4500);
    return () => window.clearInterval(poll);
  }, [detail]);

  return (
    <main className="page-shell space-y-5">

      {/* ── Hero ──────────────────────────────────────────── */}
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <h1 className="sr-only">Scan jobs</h1>
            <span className="live-pill">
              <span className={activeJobs > 0 ? 'dot-warning' : 'dot-online'} />
              {activeJobs > 0 ? `${activeJobs} running` : 'Idle'}
            </span>

            <div className="mt-5 flex items-end gap-4">
              <span
                className="text-[5.5rem] font-black leading-none tabular-nums animate-count"
                style={{ color: successRateColor, textShadow: `0 0 40px ${successRateColor}55, 0 0 80px ${successRateColor}22` }}
              >
                {successRate != null ? `${successRate}%` : '--'}
              </span>
              <div className="mb-4 flex flex-col gap-1">
                <span className="text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--text-subtle)]">
                  Success rate
                </span>
                <span className="text-sm text-[var(--text-muted)]">
                  {statusCounts.done} done · {statusCounts.failed} failed
                </span>
              </div>
            </div>

            <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full" style={{ background: 'rgba(255,255,255,0.06)' }}>
              <div
                className="h-full rounded-full transition-all duration-1000"
                style={{ width: `${successRate ?? 0}%`, background: successRateColor, boxShadow: `0 0 8px ${successRateColor}66` }}
              />
            </div>

            <div className="mt-4 flex flex-wrap gap-2">
              {statusCounts.failed > 0 && (
                <span
                  className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-bold"
                  style={{ color: 'var(--red)', borderColor: 'rgba(248,113,113,0.42)', background: 'rgba(248,113,113,0.14)' }}
                >
                  ⚡ {statusCounts.failed} failed — needs triage
                </span>
              )}
              {statusCounts.running > 0 && (
                <span
                  className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold"
                  style={{ color: 'var(--amber)', borderColor: 'rgba(251,191,36,0.28)', background: 'rgba(251,191,36,0.08)' }}
                >
                  <span className="dot-warning" />
                  {statusCounts.running} running
                </span>
              )}
              {statusCounts.queued > 0 && (
                <span className="inline-flex items-center gap-1.5 rounded-full border border-[var(--border)] px-2.5 py-1 text-xs text-[var(--text-muted)]">
                  {statusCounts.queued} queued
                </span>
              )}
              {statusCounts.failed === 0 && activeJobs === 0 && (
                <span
                  className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold"
                  style={{ color: 'var(--green)', borderColor: 'rgba(52,211,153,0.28)', background: 'rgba(52,211,153,0.08)' }}
                >
                  <span className="dot-online" />
                  All clear
                </span>
              )}
            </div>

            {canMutate && (
              <div className="mt-5 flex flex-wrap gap-2">
                <button type="button" onClick={() => setShowForm((v) => !v)} className="btn-primary text-sm">
                  {showForm ? 'Close launcher' : 'Run a scan'}
                </button>
                <button type="button" onClick={load} className="btn-secondary text-sm">
                  Refresh
                </button>
              </div>
            )}
          </div>

          {/* Right: quick stat tiles */}
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Queued + running</p>
              <p className="hero-stat-value" style={{ color: activeJobs > 0 ? 'var(--amber)' : 'var(--text-strong)' }}>
                {activeJobs}
              </p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">In progress now</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Failed</p>
              <p className="hero-stat-value" style={{ color: statusCounts.failed > 0 ? 'var(--red)' : 'var(--text-strong)' }}>
                {statusCounts.failed}
              </p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Click to triage</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Completed</p>
              <p className="hero-stat-value" style={{ color: 'var(--green)' }}>
                {statusCounts.done}
              </p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">Successful runs</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Total tracked</p>
              <p className="hero-stat-value">{data?.items.length ?? 0}</p>
              <p className="mt-1 text-[11px] text-[var(--text-subtle)]">All activities</p>
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

      {/* ── Run a scan (collapsible launcher) ─────────────── */}
      {canMutate && showForm && (
        <section className="section-panel animate-in">
          <div className="mb-4 flex items-center justify-between gap-3">
            <div>
              <h2 className="section-title">Scan launcher</h2>
              <p className="text-sm text-[var(--text-muted)]">
                {JOB_DESCRIPTIONS[enqueueType]}
              </p>
            </div>
          </div>

          <div className="grid gap-4">
            {/* Job type picker */}
            <div className="grid gap-2 sm:grid-cols-4">
              {(Object.keys(JOB_LABELS) as EnqueueJobType[]).map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setEnqueueType(type)}
                  className={`rounded-lg border px-3 py-2.5 text-left text-xs transition ${
                    enqueueType === type
                      ? 'border-[var(--accent)]/40 bg-[var(--accent-dim)] text-[var(--accent)]'
                      : 'border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text-muted)] hover:border-[var(--border-strong)] hover:text-[var(--text)]'
                  }`}
                >
                  <span className="block font-semibold">{JOB_LABELS[type]}</span>
                </button>
              ))}
            </div>

            {/* Type-specific params */}
            {enqueueType === 'repository_scan' && (
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                <div className="grid gap-4 lg:grid-cols-3">
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Scan path</span>
                    <input type="text" value={repoPath} onChange={(e) => setRepoPath(e.target.value)} className={fieldClass} />
                  </label>
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Asset key</span>
                    <input type="text" value={repoAssetKey} onChange={(e) => setRepoAssetKey(e.target.value)} className={fieldClass} />
                  </label>
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Display name</span>
                    <input type="text" value={repoAssetName} onChange={(e) => setRepoAssetName(e.target.value)} className={fieldClass} />
                  </label>
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Environment</span>
                    <input type="text" value={repoEnvironment} onChange={(e) => setRepoEnvironment(e.target.value)} className={fieldClass} />
                  </label>
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Criticality</span>
                    <select value={repoCriticality} onChange={(e) => setRepoCriticality(e.target.value)} className={fieldClass}>
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </label>
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Trivy scanners</span>
                    <input type="text" value={repoTrivyScanners} onChange={(e) => setRepoTrivyScanners(e.target.value)} className={fieldClass} />
                  </label>
                </div>
                <div className="mt-4 flex flex-wrap gap-5 text-sm text-[var(--text)]">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={repoEnableOsv} onChange={(e) => setRepoEnableOsv(e.target.checked)} />
                    <span>OSV scanner</span>
                  </label>
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input type="checkbox" checked={repoEnableTrivy} onChange={(e) => setRepoEnableTrivy(e.target.checked)} />
                    <span>Trivy filesystem scan</span>
                  </label>
                </div>
              </div>
            )}

            {enqueueType === 'threat_intel_refresh' && (
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                <p className="text-sm text-[var(--text)]">
                  Pulls the latest IOC feeds and recomputes matches against your asset inventory.
                  No additional configuration needed.
                </p>
              </div>
            )}

            {enqueueType === 'github_posture' && (
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                <div className="grid gap-4 lg:grid-cols-3">
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Scan scope</span>
                    <select value={ghScopeType} onChange={(e) => setGhScopeType(e.target.value as 'user' | 'org')} className={fieldClass}>
                      <option value="user">User account</option>
                      <option value="org">Organization</option>
                    </select>
                  </label>
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">
                      {ghScopeType === 'org' ? 'Organization name' : 'Username (optional)'}
                    </span>
                    <input
                      type="text"
                      value={ghScope}
                      onChange={(e) => setGhScope(e.target.value)}
                      placeholder={ghScopeType === 'org' ? 'my-company' : 'Leave blank to scan the token owner'}
                      className={fieldClass}
                    />
                  </label>
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">Max repositories</span>
                    <input type="number" min={1} max={500} value={ghMaxRepos} onChange={(e) => setGhMaxRepos(e.target.value)} className={fieldClass} />
                  </label>
                </div>
                <p className="mt-4 text-xs text-[var(--text-subtle)]">
                  Read-only scan using the GitHub token configured on the server (GITHUB_TOKEN).
                  Checks branch protection, 2FA enforcement, Dependabot alerts, secret scanning and
                  public repos, then maps results to SOC 2 controls on the Compliance page.
                </p>
              </div>
            )}

            {enqueueType === 'aws_iam_posture' && (
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                <div className="grid gap-4 lg:grid-cols-3">
                  <label className="space-y-1.5 text-sm text-[var(--muted)]">
                    <span className="block text-[11px] font-semibold uppercase tracking-widest">AWS region override</span>
                    <input
                      type="text"
                      value={awsRegion}
                      onChange={(e) => setAwsRegion(e.target.value)}
                      placeholder="Leave blank to use AWS_REGION"
                      className={fieldClass}
                    />
                  </label>
                </div>
                <p className="mt-4 text-xs text-[var(--text-subtle)]">
                  Read-only scan using AWS credentials configured on the server. Access keys are never entered in the browser.
                </p>
              </div>
            )}

            {['telemetry_import', 'network_anomaly_score', 'attack_lab_run', 'detection_rule_test'].includes(enqueueType) && (
              <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                <label className="space-y-1.5 text-sm text-[var(--muted)]">
                  <span className="block text-[11px] font-semibold uppercase tracking-widest">Parameters (JSON)</span>
                  <textarea value={customJobParams} onChange={(e) => setCustomJobParams(e.target.value)} rows={6} className={`${fieldClass} font-mono text-xs`} />
                </label>
              </div>
            )}

            {enqueueType !== 'repository_scan' && enqueueType !== 'threat_intel_refresh' && enqueueType !== 'github_posture' && enqueueType !== 'aws_iam_posture' &&
             !['telemetry_import', 'network_anomaly_score', 'attack_lab_run', 'detection_rule_test'].includes(enqueueType) && (
              <label className="space-y-1.5 text-sm text-[var(--muted)]">
                <span className="block text-[11px] font-semibold uppercase tracking-widest">Asset ID (optional)</span>
                <input type="text" value={enqueueAssetId} onChange={(e) => setEnqueueAssetId(e.target.value)} placeholder="Leave blank to run globally" className={fieldClass} />
              </label>
            )}

            <div className="flex justify-end gap-2 border-t border-[var(--border)] pt-3">
              <button type="button" onClick={() => setShowForm(false)} className="btn-secondary text-sm">Cancel</button>
              <button type="button" onClick={handleEnqueue} disabled={enqueueing} className="btn-primary text-sm">
                {enqueueing ? 'Starting...' : `Run ${JOB_LABELS[enqueueType]}`}
              </button>
            </div>
          </div>
        </section>
      )}

      {/* ── Activity stream ────────────────────────────────── */}
      {filteredItems.length === 0 && !error ? (
        <EmptyState
          title="No activities yet"
          description={canMutate ? 'Use "Run a scan" above to start your first job.' : 'Jobs appear here when scans are enqueued.'}
        />
      ) : (
        <section className="section-panel animate-in">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="section-title">Activity stream</h2>
              <p className="text-sm text-[var(--text-muted)]">Click any row to inspect details and get AI triage for failures.</p>
            </div>
            {/* Status filter tabs */}
            <div className="flex flex-wrap gap-1.5">
              {[
                { key: '', label: 'All', count: data?.items.length ?? 0 },
                { key: 'running', label: 'Running', count: statusCounts.running },
                { key: 'queued', label: 'Queued', count: statusCounts.queued },
                { key: 'done', label: 'Done', count: statusCounts.done },
                { key: 'failed', label: 'Failed', count: statusCounts.failed },
              ].map((item) => (
                <button
                  key={item.key}
                  type="button"
                  onClick={() => setStatusFilter(item.key)}
                  className={`inline-flex items-center gap-1.5 rounded-full border px-3 py-1 text-xs font-medium transition ${
                    statusFilter === item.key
                      ? 'border-[var(--accent)]/30 bg-[var(--accent-dim)] text-[var(--accent)]'
                      : 'border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text-muted)] hover:border-[var(--border-strong)] hover:text-[var(--text)]'
                  }`}
                >
                  {item.label}
                  <span className="rounded-full bg-black/20 px-1.5 py-0.5 text-[9px]">{item.count}</span>
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-1.5">
            {filteredItems.map((job) => {
              const borderColor =
                job.status === 'failed' ? 'var(--red)' :
                job.status === 'running' ? 'var(--amber)' :
                job.status === 'done' ? 'var(--green)' :
                'transparent';
              return (
                <div
                  key={job.job_id}
                  onClick={() => openDetail(job.job_id)}
                  className="flex cursor-pointer flex-wrap items-center gap-3 rounded-lg border border-[var(--border)] bg-[var(--surface-soft)] px-4 py-3 transition hover:bg-[var(--surface-elevated)] hover:border-[var(--border-strong)]"
                  style={{ borderLeft: `3px solid ${borderColor}` }}
                >
                  <span className="font-mono text-xs text-[var(--text-subtle)] shrink-0">#{job.job_id}</span>
                  <span className="flex-1 min-w-0 text-sm font-medium text-[var(--text)]">{jobLabel(job.job_type)}</span>
                  {job.asset_key && (
                    <span className="hidden truncate text-xs text-[var(--text-muted)] sm:block max-w-[160px]">
                      {job.asset_name || job.asset_key}
                    </span>
                  )}
                  {job.status === 'running' && job.progress_json && (
                    <ScanProgressBar progress={job.progress_json} compact />
                  )}
                  <StatusBadge status={job.status} />
                  <span className="text-xs text-[var(--text-subtle)] shrink-0">{formatDateTime(job.created_at)}</span>
                  {canMutate && (job.status === 'failed' || job.status === 'done') && (
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); handleRetry(job.job_id); }}
                      disabled={retryingId === job.job_id}
                      className="text-xs font-medium text-[var(--green)] hover:underline disabled:opacity-50"
                    >
                      {retryingId === job.job_id ? 'Retrying…' : 'Retry'}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* ── Job detail panel ───────────────────────────────── */}
      {detail && (
        <section className="animate-in grid gap-5 xl:grid-cols-[minmax(0,1fr)_340px]">
          <div className="space-y-5">
            <div className="section-panel">
              <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-lg font-bold text-[var(--text-strong)]">
                    {jobLabel(detail.job_type)}
                    <span className="ml-2 font-mono text-sm font-normal text-[var(--text-subtle)]">#{detail.job_id}</span>
                  </h2>
                  <p className="mt-0.5 text-sm text-[var(--text-muted)]">{JOB_DESCRIPTIONS[detail.job_type as EnqueueJobType] ?? detail.job_type}</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  <StatusBadge status={detail.status} />
                  {canMutate && (detail.status === 'failed' || detail.status === 'done') && (
                    <button type="button" onClick={() => handleRetry(detail.job_id)} disabled={retryingId === detail.job_id} className="btn-secondary text-sm">
                      {retryingId === detail.job_id ? 'Retrying…' : 'Retry'}
                    </button>
                  )}
                  <button type="button" onClick={() => { setDetail(null); setAiTriage(null); setTriageMessage(null); }} className="btn-secondary text-sm">
                    Close
                  </button>
                </div>
              </div>

              <div className="meta-grid">
                {[
                  { label: 'Requested by', value: detail.requested_by ?? '-' },
                  { label: 'Created', value: formatDateTime(detail.created_at) },
                  { label: 'Started', value: formatDateTime(detail.started_at) },
                  { label: 'Finished', value: formatDateTime(detail.finished_at) },
                  { label: 'Retries', value: detail.retry_count ?? 0 },
                  { label: 'Target asset', value: detail.asset_key ? `${detail.asset_name || detail.asset_key} (${detail.asset_key})` : detail.target_asset_id ?? '-' },
                  ...(detail.asset_environment ? [{ label: 'Environment', value: detail.asset_environment }] : []),
                  ...(detail.asset_criticality ? [{ label: 'Criticality', value: detail.asset_criticality }] : []),
                ].map(({ label, value }) => (
                  <div key={label} className="kv-item">
                    <span className="kv-label">{label}</span>
                    <div className="kv-value">{String(value)}</div>
                  </div>
                ))}
              </div>

              {detail.status === 'running' && detail.progress_json && (
                <div className="mt-4 rounded-xl border border-[var(--amber)]/25 bg-[var(--amber)]/08 px-4 py-3">
                  <p className="mb-2 text-[11px] font-semibold uppercase tracking-[0.14em] text-[var(--amber)]">
                    Scan in progress
                  </p>
                  <ScanProgressBar progress={detail.progress_json} />
                </div>
              )}

              {detail.error && (
                <div className="mt-4 rounded-xl border border-[var(--red)]/25 bg-[var(--red)]/08 px-4 py-3 text-sm text-[var(--red)]">
                  {detail.error}
                </div>
              )}

              {(detail.job_type === 'github_posture' || detail.job_type === 'aws_iam_posture') && detail.status === 'done' && (
                <div className="mt-4 flex flex-wrap items-center gap-3 rounded-xl border border-[var(--green)]/25 bg-[var(--green)]/08 px-4 py-3 text-sm">
                  <span className="text-[var(--text)]">Scan complete — results are ready.</span>
                  <Link href="/findings" className="font-medium text-[var(--accent)] hover:underline">
                    View findings
                  </Link>
                  <Link href="/compliance" className="font-medium text-[var(--accent)] hover:underline">
                    SOC 2 compliance report
                  </Link>
                </div>
              )}

              {detail.job_params_json && Object.keys(detail.job_params_json).length > 0 && (
                <div className="mt-4 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/50 p-4">
                  <h3 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--text-subtle)]">Parameters</h3>
                  <div className="grid gap-3 sm:grid-cols-2">
                    {Object.entries(detail.job_params_json).map(([key, value]) => (
                      <div key={key} className="kv-item">
                        <span className="kv-label">{key.replace(/_/g, ' ')}</span>
                        <div className="kv-value">{formatJobParamValue(value)}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {detail.log_output != null && detail.log_output !== '' && (
              <details className="disclosure animate-in">
                <summary className="px-4 py-3 text-sm font-medium text-[var(--text)]">Raw worker log</summary>
                <div className="disclosure-body">
                  <pre className="max-h-80 overflow-auto rounded-lg border border-[var(--border)] bg-[var(--bg)] p-4 font-mono text-xs text-[var(--text)]">
                    {detail.log_output}
                  </pre>
                </div>
              </details>
            )}
          </div>

          {/* AI Triage sidebar */}
          <aside className="section-panel animate-in">
            <h2 className="section-title">AI triage</h2>
            <p className="mb-4 text-sm text-[var(--text-muted)]">
              Get an instant explanation of why this job failed and what to do next.
            </p>

            {detail.status !== 'failed' && !detail.error ? (
              <div className="rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)]/40 px-4 py-3 text-sm text-[var(--text-subtle)]">
                Only available for failed jobs.
              </div>
            ) : triageLoading ? (
              <div className="flex items-center gap-2 text-sm text-[var(--muted)]">
                <div className="loading-dots"><span /><span /><span /></div>
                Loading triage…
              </div>
            ) : aiTriage?.triage_text ? (
              <>
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/70 p-4">
                  <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">{aiTriage.triage_text}</p>
                </div>
                <p className="mt-2 text-xs text-[var(--text-subtle)]">
                  Generated {formatDateTime(aiTriage.generated_at)} via {aiTriage.provider}/{aiTriage.model}
                </p>
                {canMutate && (
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button type="button" onClick={handleSaveTriageVersion} disabled={savingTriageVersion || triageGenerating || triageFeedbackBusy != null} className="btn-secondary text-xs">
                      {savingTriageVersion ? 'Saving…' : 'Save version'}
                    </button>
                    <button type="button" onClick={() => handleTriageFeedback('up')} disabled={triageGenerating || savingTriageVersion || triageFeedbackBusy != null} className="btn-secondary text-xs">
                      {triageFeedbackBusy === 'up' ? 'Saving…' : '👍 Helpful'}
                    </button>
                    <button type="button" onClick={() => handleTriageFeedback('down')} disabled={triageGenerating || savingTriageVersion || triageFeedbackBusy != null} className="btn-secondary text-xs">
                      {triageFeedbackBusy === 'down' ? 'Saving…' : '👎 Not helpful'}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <p className="text-sm text-[var(--muted)]">No AI triage generated yet.</p>
            )}

            {triageMessage && (
              <p className={`mt-3 text-xs ${triageMessage.toLowerCase().includes('failed') ? 'text-[var(--red)]' : 'text-[var(--muted)]'}`}>
                {friendlyApiMessage(triageMessage)}
              </p>
            )}

            {canMutate && (detail.status === 'failed' || detail.error) && (
              <div className="mt-4 flex flex-wrap gap-2">
                <button type="button" onClick={() => handleGenerateTriage(false)} disabled={triageGenerating} className="btn-primary text-sm">
                  {triageGenerating ? 'Generating…' : aiTriage ? 'Refresh triage' : 'Generate triage'}
                </button>
                {aiTriage && (
                  <button type="button" onClick={() => handleGenerateTriage(true)} disabled={triageGenerating} className="btn-secondary text-sm">
                    Force refresh
                  </button>
                )}
              </div>
            )}
          </aside>
        </section>
      )}
    </main>
  );
}
