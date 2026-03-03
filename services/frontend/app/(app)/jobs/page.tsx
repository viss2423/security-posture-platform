'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  createJob,
  generateJobAITriage,
  getJob,
  getJobAITriage,
  getJobs,
  retryJob,
  type AIJobTriage,
  type JobDetail,
  type JobItem,
} from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { formatDateTime } from '@/lib/format';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';

export default function JobsPage() {
  const { canMutate } = useAuth();
  const [data, setData] = useState<{ items: JobItem[] } | null>(null);
  const [detail, setDetail] = useState<JobDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [retryingId, setRetryingId] = useState<number | null>(null);
  const [enqueueType, setEnqueueType] = useState<'web_exposure' | 'score_recompute'>(
    'web_exposure'
  );
  const [enqueueAssetId, setEnqueueAssetId] = useState('');
  const [enqueueing, setEnqueueing] = useState(false);
  const [aiTriage, setAiTriage] = useState<AIJobTriage | null>(null);
  const [triageLoading, setTriageLoading] = useState(false);
  const [triageGenerating, setTriageGenerating] = useState(false);
  const [triageMessage, setTriageMessage] = useState<string | null>(null);

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

  return (
    <main className="page-shell">
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <p className="max-w-2xl text-sm text-[var(--text-muted)]">
          Queue operations, inspect failed runs, and use AI triage without reading raw worker logs
          first.
        </p>
        {data && <span className="stat-chip-strong">{data.items.length} jobs in view</span>}
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
            <div className="grid gap-4 sm:grid-cols-[180px_minmax(0,1fr)_auto] sm:items-end">
              <label className="text-sm text-[var(--muted)]">
                Type
                <select
                  value={enqueueType}
                  onChange={(e) =>
                    setEnqueueType(e.target.value as 'web_exposure' | 'score_recompute')
                  }
                  className="input mt-1"
                >
                  <option value="web_exposure">web_exposure</option>
                  <option value="score_recompute">score_recompute</option>
                </select>
              </label>
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
              <button
                type="button"
                onClick={handleEnqueue}
                disabled={enqueueing}
                className="btn-primary"
              >
                {enqueueing ? 'Enqueueing...' : 'Enqueue'}
              </button>
            </div>
            <p className="mt-3 text-xs text-[var(--muted)]">
              Process queued jobs with <code className="rounded bg-[var(--bg)] px-1">docker compose up -d worker-web</code>.
            </p>
          </section>
        )}

        <section className="section-panel">
          <h2 className="section-title">Filters</h2>
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
