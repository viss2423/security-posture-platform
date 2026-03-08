'use client';

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
  | 'detection_rule_test';

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
    {
      source: 'suricata',
      file_path: '/workspace/lab-data/suricata/eve.json',
      asset_key: 'secplat-api',
    },
    null,
    2
  ),
  network_anomaly_score: JSON.stringify({ lookback_hours: 24, threshold: 2.5 }, null, 2),
  attack_lab_run: JSON.stringify(
    { task_type: 'port_scan', target: 'verify-web', asset_key: 'verify-web' },
    null,
    2
  ),
  detection_rule_test: JSON.stringify({ rule_id: 1, lookback_hours: 24 }, null, 2),
};

function formatJobParamValue(value: unknown): string {
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (value == null || value === '') return '-';
  return String(value);
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
  const [repoTrivyScanners, setRepoTrivyScanners] = useState(
    DEFAULT_REPOSITORY_SCAN.trivyScanners
  );
  const [repoEnableOsv, setRepoEnableOsv] = useState(true);
  const [repoEnableTrivy, setRepoEnableTrivy] = useState(true);
  const [enqueueing, setEnqueueing] = useState(false);
  const [customJobParams, setCustomJobParams] = useState<string>(
    DEFAULT_JOB_PARAMS.telemetry_import || '{}'
  );
  const [aiTriage, setAiTriage] = useState<AIJobTriage | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageGenerating, setTriageGenerating] = useState(false);
  const [triageMessage, setTriageMessage] = useState<string | null>(null);
  const [savingTriageVersion, setSavingTriageVersion] = useState(false);
  const [triageFeedbackBusy, setTriageFeedbackBusy] = useState<AIFeedbackValue | null>(null);

  const load = useCallback(() => {
    getJobs(statusFilter || undefined)
      .then((result) => {
        setData(result);
        setError(null);
      })
      .catch((e) => setError(e.message));
  }, [statusFilter]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    if (enqueueType in DEFAULT_JOB_PARAMS) {
      setCustomJobParams(DEFAULT_JOB_PARAMS[enqueueType] || '{}');
    }
  }, [enqueueType]);

  const openDetail = (id: number) => {
    setAiTriage(null);
    setTriageMessage(null);
    getJob(id)
      .then(setDetail)
      .catch((e) => setError(e.message));
  };

  useEffect(() => {
    if (!detail || (detail.status !== 'failed' && !detail.error)) {
      setAiTriage(null);
      setTriageLoading(false);
      setTriageMessage(null);
      return;
    }
    setTriageLoading(true);
    setTriageMessage(null);
    getJobAITriage(detail.job_id)
      .then(setAiTriage)
      .catch((e) => {
        const message = e instanceof Error ? e.message : 'Failed to load AI triage';
        if (!message.toLowerCase().includes('not found')) {
          setTriageMessage(message);
        }
        setAiTriage(null);
      })
      .finally(() => setTriageLoading(false));
  }, [detail]);

  const handleEnqueue = () => {
    if (enqueueType === 'repository_scan') {
      if (!repoEnableOsv && !repoEnableTrivy) {
        setError('Enable at least one repository scanner');
        return;
      }
      setError(null);
      setEnqueueing(true);
      createJob({
        job_type: enqueueType,
        job_params_json: {
          path: repoPath.trim() || DEFAULT_REPOSITORY_SCAN.path,
          asset_key: repoAssetKey.trim() || DEFAULT_REPOSITORY_SCAN.assetKey,
          asset_name: repoAssetName.trim() || DEFAULT_REPOSITORY_SCAN.assetName,
          environment: repoEnvironment.trim() || DEFAULT_REPOSITORY_SCAN.environment,
          criticality: repoCriticality.trim() || DEFAULT_REPOSITORY_SCAN.criticality,
          trivy_scanners:
            repoTrivyScanners.trim() || DEFAULT_REPOSITORY_SCAN.trivyScanners,
          enable_osv: repoEnableOsv,
          enable_trivy: repoEnableTrivy,
        },
      })
        .then((job) => {
          load();
          openDetail(job.job_id);
        })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }
    if (enqueueType === 'threat_intel_refresh') {
      setError(null);
      setEnqueueing(true);
      createJob({ job_type: enqueueType })
        .then((job) => {
          load();
          openDetail(job.job_id);
        })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }
    if (
      enqueueType === 'telemetry_import' ||
      enqueueType === 'network_anomaly_score' ||
      enqueueType === 'attack_lab_run' ||
      enqueueType === 'detection_rule_test'
    ) {
      let parsedParams: Record<string, unknown> = {};
      try {
        parsedParams = customJobParams.trim() ? JSON.parse(customJobParams) : {};
      } catch {
        setError('Job params must be valid JSON');
        return;
      }
      setError(null);
      setEnqueueing(true);
      createJob({ job_type: enqueueType, job_params_json: parsedParams })
        .then((job) => {
          load();
          openDetail(job.job_id);
        })
        .catch((e) => setError(e.message))
        .finally(() => setEnqueueing(false));
      return;
    }

    const assetId = enqueueAssetId.trim() ? parseInt(enqueueAssetId, 10) : undefined;
    if (assetId != null && Number.isNaN(assetId)) {
      setError('Asset ID must be a number');
      return;
    }
    setError(null);
    setEnqueueing(true);
    createJob({ job_type: enqueueType, target_asset_id: assetId })
      .then(() => {
        load();
        setEnqueueAssetId('');
      })
      .catch((e) => setError(e.message))
      .finally(() => setEnqueueing(false));
  };

  const handleRetry = (id: number) => {
    setError(null);
    setRetryingId(id);
    retryJob(id)
      .then(() => {
        load();
        if (detail?.job_id === id) openDetail(id);
      })
      .catch((e) => setError(e.message))
      .finally(() => setRetryingId(null));
  };

  const handleGenerateTriage = async (force: boolean) => {
    if (!detail) return;
    setTriageGenerating(true);
    setTriageMessage(null);
    try {
      const out = await generateJobAITriage(detail.job_id, force);
      setAiTriage(out);
      setTriageMessage(out.cached ? 'Showing cached AI triage.' : 'AI triage generated.');
    } catch (e) {
      setTriageMessage(e instanceof Error ? e.message : 'AI triage generation failed');
    } finally {
      setTriageGenerating(false);
    }
  };

  const handleSaveTriageVersion = async () => {
    if (!detail || !aiTriage?.triage_text) {
      setTriageMessage('Generate AI triage before saving a version.');
      return;
    }
    setSavingTriageVersion(true);
    setTriageMessage(null);
    try {
      const created = await createAISummaryVersion('job', detail.job_id, {
        content_text: aiTriage.triage_text,
        provider: aiTriage.provider,
        model: aiTriage.model,
        source_type: aiTriage.cached ? 'cached' : 'generated',
        context_json: aiTriage.context_json || {},
        evidence_json: {
          generated_at: aiTriage.generated_at,
          generated_by: aiTriage.generated_by || null,
        },
      });
      setTriageMessage(`Saved version v${created.version_no}.`);
    } catch (e) {
      setTriageMessage(e instanceof Error ? e.message : 'Saving triage version failed');
    } finally {
      setSavingTriageVersion(false);
    }
  };

  const handleTriageFeedback = async (feedback: AIFeedbackValue) => {
    if (!detail || !aiTriage?.triage_text) {
      setTriageMessage('Generate AI triage before submitting feedback.');
      return;
    }
    setTriageFeedbackBusy(feedback);
    setTriageMessage(null);
    try {
      await createAIFeedback({
        entity_type: 'job',
        entity_id: detail.job_id,
        feedback,
        context_json: { surface: 'jobs_page' },
      });
      setTriageMessage(
        feedback === 'up'
          ? 'Feedback recorded: triage was useful.'
          : 'Feedback recorded: triage needs improvement.'
      );
    } catch (e) {
      setTriageMessage(e instanceof Error ? e.message : 'Saving triage feedback failed');
    } finally {
      setTriageFeedbackBusy(null);
    }
  };

  const statusBadge = (status: string) => {
    const classes =
      status === 'done'
        ? 'bg-[var(--green)]/20 text-[var(--green)] border border-[var(--green)]/20'
        : status === 'failed'
          ? 'bg-[var(--red)]/20 text-[var(--red)] border border-[var(--red)]/20'
          : status === 'running'
            ? 'bg-[var(--amber)]/20 text-[var(--amber)] border border-[var(--amber)]/20'
            : 'bg-[var(--surface-elevated)] text-[var(--muted)] border border-[var(--border)]';
    return <span className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase ${classes}`}>{status}</span>;
  };

  const statusCounts = useMemo(() => {
    const counts = { queued: 0, running: 0, done: 0, failed: 0 };
    for (const job of data?.items ?? []) {
      if (job.status in counts) {
        counts[job.status as keyof typeof counts] += 1;
      }
    }
    return counts;
  }, [data]);

  const activeJobs = statusCounts.queued + statusCounts.running;
  const terminalJobs = statusCounts.done + statusCounts.failed;
  const successRate = terminalJobs > 0 ? Math.round((statusCounts.done / terminalJobs) * 100) : null;

  return (
    <main className="page-shell space-y-6">
      <section className="page-hero">
        <div className="hero-grid">
          <div>
            <span className="stat-chip-strong">Jobs Command Center</span>
            <h1 className="hero-title mt-3">Security Workload Orchestration</h1>
            <p className="hero-copy">
              Queue operations, inspect failed runs, and use AI triage without reading raw worker
              logs first.
            </p>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Active</p>
              <p className="hero-stat-value">{activeJobs}</p>
              <p className="mt-1 text-xs text-[var(--text-muted)]">Queued + running</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Failed</p>
              <p className="hero-stat-value">{statusCounts.failed}</p>
              <p className="mt-1 text-xs text-[var(--text-muted)]">Needs triage</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Completed</p>
              <p className="hero-stat-value">{statusCounts.done}</p>
              <p className="mt-1 text-xs text-[var(--text-muted)]">Successful runs</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Success Rate</p>
              <p className="hero-stat-value">{successRate != null ? `${successRate}%` : '--'}</p>
              <p className="mt-1 text-xs text-[var(--text-muted)]">Done vs failed</p>
            </div>
          </div>
        </div>
      </section>

      <div className="flex flex-wrap items-center justify-between gap-3">
        {data && <span className="stat-chip-strong">{data.items.length} jobs in view</span>}
        <span className="stat-chip">
          Running {statusCounts.running} • Queued {statusCounts.queued} • Failed {statusCounts.failed}
        </span>
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <div className="mb-6 grid gap-4 lg:grid-cols-[minmax(0,1.4fr)_minmax(280px,0.8fr)]">
        {canMutate && (
          <section className="section-panel">
            <h2 className="section-title">Enqueue job</h2>
            <div className="grid gap-4">
              <div className="grid gap-4 sm:grid-cols-[220px_minmax(0,1fr)]">
                <label className="text-sm text-[var(--muted)]">
                  Type
                  <select
                    value={enqueueType}
                    onChange={(e) => setEnqueueType(e.target.value as EnqueueJobType)}
                    className="input mt-1"
                  >
                    <option value="web_exposure">web_exposure</option>
                    <option value="score_recompute">score_recompute</option>
                    <option value="repository_scan">repository_scan</option>
                    <option value="threat_intel_refresh">threat_intel_refresh</option>
                    <option value="telemetry_import">telemetry_import</option>
                    <option value="network_anomaly_score">network_anomaly_score</option>
                    <option value="attack_lab_run">attack_lab_run</option>
                    <option value="detection_rule_test">detection_rule_test</option>
                  </select>
                </label>
                {enqueueType !== 'repository_scan' &&
                  enqueueType !== 'threat_intel_refresh' &&
                  enqueueType !== 'telemetry_import' &&
                  enqueueType !== 'network_anomaly_score' &&
                  enqueueType !== 'attack_lab_run' &&
                  enqueueType !== 'detection_rule_test' && (
                  <label className="text-sm text-[var(--muted)]">
                    Asset ID
                    <input
                      type="text"
                      value={enqueueAssetId}
                      onChange={(e) => setEnqueueAssetId(e.target.value)}
                      placeholder="Optional for web_exposure"
                      className="input mt-1"
                    />
                  </label>
                )}
              </div>

              {enqueueType === 'repository_scan' ? (
                <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                  <div className="grid gap-4 lg:grid-cols-2">
                    <label className="text-sm text-[var(--muted)]">
                      Scan path
                      <input
                        type="text"
                        value={repoPath}
                        onChange={(e) => setRepoPath(e.target.value)}
                        className="input mt-1"
                      />
                    </label>
                    <label className="text-sm text-[var(--muted)]">
                      Repository asset key
                      <input
                        type="text"
                        value={repoAssetKey}
                        onChange={(e) => setRepoAssetKey(e.target.value)}
                        className="input mt-1"
                      />
                    </label>
                    <label className="text-sm text-[var(--muted)]">
                      Display name
                      <input
                        type="text"
                        value={repoAssetName}
                        onChange={(e) => setRepoAssetName(e.target.value)}
                        className="input mt-1"
                      />
                    </label>
                    <label className="text-sm text-[var(--muted)]">
                      Environment
                      <input
                        type="text"
                        value={repoEnvironment}
                        onChange={(e) => setRepoEnvironment(e.target.value)}
                        className="input mt-1"
                      />
                    </label>
                    <label className="text-sm text-[var(--muted)]">
                      Criticality
                      <select
                        value={repoCriticality}
                        onChange={(e) => setRepoCriticality(e.target.value)}
                        className="input mt-1"
                      >
                        <option value="high">high</option>
                        <option value="medium">medium</option>
                        <option value="low">low</option>
                      </select>
                    </label>
                    <label className="text-sm text-[var(--muted)]">
                      Trivy scanners
                      <input
                        type="text"
                        value={repoTrivyScanners}
                        onChange={(e) => setRepoTrivyScanners(e.target.value)}
                        className="input mt-1"
                      />
                    </label>
                  </div>
                  <div className="mt-4 flex flex-wrap gap-5 text-sm text-[var(--text)]">
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={repoEnableOsv}
                        onChange={(e) => setRepoEnableOsv(e.target.checked)}
                      />
                      <span>Run OSV scanner</span>
                    </label>
                    <label className="flex items-center gap-2">
                      <input
                        type="checkbox"
                        checked={repoEnableTrivy}
                        onChange={(e) => setRepoEnableTrivy(e.target.checked)}
                      />
                      <span>Run Trivy filesystem scan</span>
                    </label>
                  </div>
                </div>
              ) : enqueueType === 'threat_intel_refresh' ? (
                <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                  <p className="text-sm text-[var(--text)]">
                    Refreshes configured IOC feeds and recomputes matches against known assets.
                  </p>
                  <p className="mt-2 text-xs text-[var(--muted)]">
                    Feed URLs come from API configuration. Use this to update the
                    Threat intelligence panel in Overview.
                  </p>
                </div>
              ) : enqueueType === 'telemetry_import' ||
                enqueueType === 'network_anomaly_score' ||
                enqueueType === 'attack_lab_run' ||
                enqueueType === 'detection_rule_test' ? (
                <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                  <label className="text-sm text-[var(--muted)]">
                    Job params JSON
                    <textarea
                      value={customJobParams}
                      onChange={(e) => setCustomJobParams(e.target.value)}
                      rows={8}
                      className="input mt-1 font-mono text-xs"
                    />
                  </label>
                  <p className="mt-2 text-xs text-[var(--muted)]">
                    Use this for telemetry imports, anomaly scoring, attack-lab execution, and detection rule tests.
                  </p>
                </div>
              ) : null}

              <div className="flex flex-wrap items-end justify-between gap-3">
                <p className="text-xs text-[var(--muted)]">
                  {enqueueType === 'repository_scan'
                    ? 'Repository scans run inside the API container and can take several minutes on /workspace.'
                    : enqueueType === 'threat_intel_refresh'
                      ? 'Threat-intel refresh runs inside the API container and updates IOC summaries plus asset matches.'
                      : enqueueType === 'telemetry_import'
                        ? 'Telemetry imports parse log files and generate event-centric alerts.'
                        : enqueueType === 'network_anomaly_score'
                          ? 'Network anomaly scoring computes per-asset deviations from recent telemetry baseline.'
                          : enqueueType === 'attack_lab_run'
                            ? 'Attack-lab runs controlled simulations and auto-generates incidents from resulting alerts.'
                            : enqueueType === 'detection_rule_test'
                              ? 'Detection rule tests evaluate rules against recent telemetry and can emit rule-match alerts.'
                    : 'Process queued jobs with docker compose up -d worker-web.'}
                </p>
                <button
                  type="button"
                  onClick={handleEnqueue}
                  disabled={enqueueing}
                  className="btn-primary"
                >
                  {enqueueing ? 'Enqueueing...' : 'Enqueue'}
                </button>
              </div>
            </div>
          </section>
        )}

        <section className="section-panel">
          <h2 className="section-title">Filters</h2>
          <div className="mb-3 flex flex-wrap gap-2">
            {[
              { key: '', label: 'All', count: data?.items.length ?? 0 },
              { key: 'queued', label: 'Queued', count: statusCounts.queued },
              { key: 'running', label: 'Running', count: statusCounts.running },
              { key: 'done', label: 'Done', count: statusCounts.done },
              { key: 'failed', label: 'Failed', count: statusCounts.failed },
            ].map((item) => (
              <button
                key={item.label}
                type="button"
                onClick={() => setStatusFilter(item.key)}
                className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition ${
                  statusFilter === item.key
                    ? 'border-cyan-300/35 bg-cyan-300/14 text-cyan-100'
                    : 'border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text-muted)] hover:border-cyan-300/30 hover:text-[var(--text)]'
                }`}
              >
                {item.label}
                <span className="rounded-full bg-black/25 px-1.5 py-0.5 text-[10px]">{item.count}</span>
              </button>
            ))}
          </div>
          <label className="text-sm text-[var(--muted)]">
            Status
            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              className="input mt-1"
            >
              <option value="">All jobs</option>
              <option value="queued">Queued</option>
              <option value="running">Running</option>
              <option value="done">Done</option>
              <option value="failed">Failed</option>
            </select>
          </label>
        </section>
      </div>

      {data?.items.length === 0 ? (
        <EmptyState
          title="No jobs"
          description={
            canMutate
              ? 'Enqueue a job, then start the worker to process it. Failed runs will expose AI triage and raw logs.'
              : 'Jobs appear here when analysts or admins enqueue scans.'
          }
        />
      ) : (
        <section className="section-panel">
          <div className="section-head">
            <div>
              <h2 className="text-lg font-semibold text-[var(--text)]">Queue Stream</h2>
              <p className="section-head-copy">Select a row to inspect execution detail and AI triage.</p>
            </div>
            <span className="stat-chip">{data?.items.length ?? 0} records</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">ID</th>
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Target</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3">Retries</th>
                  <th className="px-4 py-3 text-right">Action</th>
                </tr>
              </thead>
              <tbody>
                {data?.items.map((job) => (
                  <tr
                    key={job.job_id}
                    className="cursor-pointer border-b border-[var(--border)]/50 transition hover:bg-[var(--surface-elevated)]/30"
                    onClick={() => openDetail(job.job_id)}
                  >
                    <td className="px-4 py-3 font-mono text-[var(--text)]">{job.job_id}</td>
                    <td className="px-4 py-3 text-[var(--text)]">{job.job_type}</td>
                    <td className="px-4 py-3 text-[var(--muted)]">
                      {job.asset_key ? (
                        <div>
                          <div className="text-[var(--text)]">{job.asset_name || job.asset_key}</div>
                          <div className="text-xs font-mono text-[var(--muted)]">{job.asset_key}</div>
                        </div>
                      ) : (
                        job.target_asset_id ?? '-'
                      )}
                    </td>
                    <td className="px-4 py-3">{statusBadge(job.status)}</td>
                    <td className="px-4 py-3 text-[var(--muted)]">{formatDateTime(job.created_at)}</td>
                    <td className="px-4 py-3 text-[var(--muted)]">{job.retry_count ?? 0}</td>
                    <td className="px-4 py-3 text-right" onClick={(e) => e.stopPropagation()}>
                      {canMutate && (job.status === 'failed' || job.status === 'done') && (
                        <button
                          type="button"
                          onClick={() => handleRetry(job.job_id)}
                          disabled={retryingId === job.job_id}
                          className="text-xs font-medium text-[var(--green)] hover:underline disabled:opacity-50"
                        >
                          {retryingId === job.job_id ? 'Retrying...' : 'Retry'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {detail && (
        <section className="mt-8 grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px]">
          <div className="space-y-6">
            <div className="section-panel animate-in">
              <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                <div>
                  <h2 className="text-xl font-semibold text-[var(--text)]">
                    Job {detail.job_id}
                  </h2>
                  <p className="mt-1 text-sm text-[var(--text-muted)]">{detail.job_type}</p>
                </div>
                <div className="flex flex-wrap items-center gap-2">
                  {statusBadge(detail.status)}
                  {canMutate && (detail.status === 'failed' || detail.status === 'done') && (
                    <button
                      type="button"
                      onClick={() => handleRetry(detail.job_id)}
                      disabled={retryingId === detail.job_id}
                      className="btn-secondary text-sm"
                    >
                      {retryingId === detail.job_id ? 'Retrying...' : 'Retry'}
                    </button>
                  )}
                  <button
                    type="button"
                    onClick={() => {
                      setDetail(null);
                      setAiTriage(null);
                      setTriageMessage(null);
                    }}
                    className="btn-secondary text-sm"
                  >
                    Close
                  </button>
                </div>
              </div>

              <div className="meta-grid">
                <div className="kv-item">
                  <span className="kv-label">Requested by</span>
                  <div className="kv-value">{detail.requested_by ?? '-'}</div>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Created</span>
                  <div className="kv-value">{formatDateTime(detail.created_at)}</div>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Started</span>
                  <div className="kv-value">{formatDateTime(detail.started_at)}</div>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Finished</span>
                  <div className="kv-value">{formatDateTime(detail.finished_at)}</div>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Retries</span>
                  <div className="kv-value">{detail.retry_count ?? 0}</div>
                </div>
                <div className="kv-item">
                  <span className="kv-label">Target asset</span>
                  <div className="kv-value">
                    {detail.asset_key
                      ? `${detail.asset_name || detail.asset_key} (${detail.asset_key})`
                      : detail.target_asset_id ?? '-'}
                  </div>
                </div>
                {detail.asset_type && (
                  <div className="kv-item">
                    <span className="kv-label">Asset type</span>
                    <div className="kv-value">{detail.asset_type}</div>
                  </div>
                )}
                {detail.asset_environment && (
                  <div className="kv-item">
                    <span className="kv-label">Environment</span>
                    <div className="kv-value">{detail.asset_environment}</div>
                  </div>
                )}
                {detail.asset_criticality && (
                  <div className="kv-item">
                    <span className="kv-label">Criticality</span>
                    <div className="kv-value">{detail.asset_criticality}</div>
                  </div>
                )}
                {detail.asset_verified != null && (
                  <div className="kv-item">
                    <span className="kv-label">Verified</span>
                    <div className="kv-value">{detail.asset_verified ? 'Yes' : 'No'}</div>
                  </div>
                )}
              </div>

              {detail.error && (
                <div className="mt-5 rounded-xl border border-[var(--red)]/20 bg-[var(--red)]/10 px-4 py-3 text-sm text-[var(--red)]">
                  {detail.error}
                </div>
              )}

              {detail.job_params_json &&
                Object.keys(detail.job_params_json).length > 0 && (
                  <div className="mt-5 rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/50 p-4">
                    <h3 className="text-sm font-semibold uppercase tracking-[0.16em] text-[var(--muted)]">
                      Parameters
                    </h3>
                    <div className="mt-4 grid gap-3 sm:grid-cols-2">
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
                <summary>Raw worker log output</summary>
                <div className="disclosure-body">
                  <pre className="max-h-96 overflow-x-auto overflow-y-auto whitespace-pre-wrap rounded-lg border border-[var(--border)] bg-[var(--bg)] p-4 font-mono text-xs text-[var(--text)]">
                    {detail.log_output}
                  </pre>
                </div>
              </details>
            )}
          </div>

          <aside className="section-panel animate-in">
            <h2 className="section-title">AI triage</h2>
            <p className="mb-4 text-sm text-[var(--text-muted)]">
              Use this when a job fails and you need the likely cause and the next operator step.
            </p>
            {detail.status !== 'failed' && !detail.error ? (
              <p className="text-sm text-[var(--muted)]">AI triage is available for failed jobs.</p>
            ) : triageLoading ? (
              <p className="text-sm text-[var(--muted)]">Loading triage...</p>
            ) : aiTriage?.triage_text ? (
              <>
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/70 p-4">
                  <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">
                    {aiTriage.triage_text}
                  </p>
                </div>
                <p className="mt-3 text-xs text-[var(--muted)]">
                  Generated {formatDateTime(aiTriage.generated_at)} via {aiTriage.provider}/{aiTriage.model}
                </p>
                {canMutate && (
                  <div className="mt-3 flex flex-wrap gap-2">
                    <button
                      type="button"
                      onClick={handleSaveTriageVersion}
                      disabled={savingTriageVersion || triageGenerating || triageFeedbackBusy != null}
                      className="btn-secondary text-xs"
                    >
                      {savingTriageVersion ? 'Saving...' : 'Save version'}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleTriageFeedback('up')}
                      disabled={triageGenerating || savingTriageVersion || triageFeedbackBusy != null}
                      className="btn-secondary text-xs"
                    >
                      {triageFeedbackBusy === 'up' ? 'Saving...' : 'Thumbs up'}
                    </button>
                    <button
                      type="button"
                      onClick={() => handleTriageFeedback('down')}
                      disabled={triageGenerating || savingTriageVersion || triageFeedbackBusy != null}
                      className="btn-secondary text-xs"
                    >
                      {triageFeedbackBusy === 'down' ? 'Saving...' : 'Thumbs down'}
                    </button>
                  </div>
                )}
              </>
            ) : (
              <p className="text-sm text-[var(--muted)]">No AI triage generated yet for this job.</p>
            )}

            {triageMessage && (
              <p
                className={`mt-3 text-xs ${
                  triageMessage.toLowerCase().includes('failed')
                    ? 'text-[var(--red)]'
                    : 'text-[var(--muted)]'
                }`}
              >
                {friendlyApiMessage(triageMessage)}
              </p>
            )}

            {canMutate && (detail.status === 'failed' || detail.error) && (
              <div className="mt-4 flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => handleGenerateTriage(false)}
                  disabled={triageGenerating}
                  className="btn-primary text-sm"
                >
                  {triageGenerating ? 'Generating...' : aiTriage ? 'Refresh triage' : 'Generate triage'}
                </button>
                {aiTriage && (
                  <button
                    type="button"
                    onClick={() => handleGenerateTriage(true)}
                    disabled={triageGenerating}
                    className="btn-secondary text-sm"
                  >
                    Force regenerate
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
