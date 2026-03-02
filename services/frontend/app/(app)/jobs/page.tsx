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

function isFallbackProvider(provider: string | null | undefined): boolean {
  return (provider || '').toLowerCase().includes('fallback');
}

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
      .then(setData)
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
      setTriageMessage(
        isFallbackProvider(out.provider)
          ? 'Triage generated with fallback guidance because the AI provider was temporarily slow or unavailable.'
          : out.cached
            ? 'Showing cached AI triage.'
            : 'AI triage generated.'
      );
    } catch (e) {
      setTriageMessage(e instanceof Error ? e.message : 'AI triage generation failed');
    } finally {
      setTriageGenerating(false);
    }
  };

  const statusBadge = (status: string) => {
    const c =
      status === 'done'
        ? 'bg-[var(--green)]/20 text-[var(--green)]'
        : status === 'failed'
          ? 'bg-[var(--red)]/20 text-[var(--red)]'
          : status === 'running'
            ? 'bg-[var(--amber)]/20 text-[var(--amber)]'
            : 'bg-[var(--muted)]/20 text-[var(--muted)]';
    return <span className={`rounded px-2 py-0.5 text-xs font-medium ${c}`}>{status}</span>;
  };

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-8">Jobs</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {canMutate && (
        <div className="card-glass mb-6 p-4">
          <h2 className="mb-3 text-sm font-semibold text-[var(--text)]">Enqueue job</h2>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm text-[var(--muted)]">
              Type
              <select
                value={enqueueType}
                onChange={(e) =>
                  setEnqueueType(e.target.value as 'web_exposure' | 'score_recompute')
                }
                className="ml-2 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5 text-sm text-[var(--text)]"
              >
                <option value="web_exposure">web_exposure</option>
                <option value="score_recompute">score_recompute</option>
              </select>
            </label>
            <label className="text-sm text-[var(--muted)]">
              Asset ID (optional for web_exposure; use an asset with type external_web)
              <input
                type="text"
                value={enqueueAssetId}
                onChange={(e) => setEnqueueAssetId(e.target.value)}
                placeholder="e.g. 1"
                className="ml-2 w-20 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5 text-sm text-[var(--text)]"
              />
            </label>
            <button type="button" onClick={handleEnqueue} disabled={enqueueing} className="btn-primary">
              {enqueueing ? 'Enqueueing...' : 'Enqueue'}
            </button>
          </div>
          <p className="mt-2 text-xs text-[var(--muted)]">
            Run the worker to process queued jobs:{' '}
            <code className="rounded bg-[var(--bg)] px-1">docker compose up -d worker-web</code>{' '}
            (see README).
          </p>
        </div>
      )}

      <div className="mb-4 flex flex-wrap items-center gap-3">
        <label className="text-sm text-[var(--muted)]">
          Status
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="ml-2 rounded border border-[var(--border)] bg-[var(--bg)] px-2 py-1.5 text-sm text-[var(--text)]"
          >
            <option value="">All</option>
            <option value="queued">Queued</option>
            <option value="running">Running</option>
            <option value="done">Done</option>
            <option value="failed">Failed</option>
          </select>
        </label>
      </div>

      {data?.items.length === 0 ? (
        <EmptyState
          title="No jobs"
          description={
            canMutate
              ? 'Enqueue a job above (web_exposure or score_recompute), then start the worker to process them. Click a job to see logs; use Retry on failed jobs.'
              : 'Jobs are created when an analyst or admin enqueues a scan. Run the worker to process queued jobs.'
          }
        />
      ) : (
        <div className="card-glass overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="px-4 py-3 text-left font-medium text-[var(--muted)]">ID</th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--muted)]">Type</th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--muted)]">Asset</th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--muted)]">Status</th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--muted)]">Created</th>
                  <th className="px-4 py-3 text-left font-medium text-[var(--muted)]">Retries</th>
                  <th className="w-20" />
                </tr>
              </thead>
              <tbody>
                {data?.items.map((j) => (
                  <tr
                    key={j.job_id}
                    className="cursor-pointer border-b border-[var(--border)]/50 hover:bg-[var(--surface-elevated)]/50"
                    onClick={() => openDetail(j.job_id)}
                  >
                    <td className="px-4 py-2 font-mono text-[var(--text)]">{j.job_id}</td>
                    <td className="px-4 py-2 text-[var(--text)]">{j.job_type}</td>
                    <td className="px-4 py-2 text-[var(--muted)]">
                      {j.asset_key ? (
                        <div>
                          <div className="text-[var(--text)]">{j.asset_name || j.asset_key}</div>
                          <div className="text-xs font-mono text-[var(--muted)]">{j.asset_key}</div>
                        </div>
                      ) : (
                        j.target_asset_id ?? '-'
                      )}
                    </td>
                    <td className="px-4 py-2">{statusBadge(j.status)}</td>
                    <td className="px-4 py-2 text-[var(--muted)]">{formatDateTime(j.created_at)}</td>
                    <td className="px-4 py-2 text-[var(--muted)]">{j.retry_count ?? 0}</td>
                    <td className="px-4 py-2" onClick={(e) => e.stopPropagation()}>
                      {canMutate && (j.status === 'failed' || j.status === 'done') && (
                        <button
                          type="button"
                          onClick={() => handleRetry(j.job_id)}
                          disabled={retryingId === j.job_id}
                          className="text-xs text-[var(--green)] hover:underline disabled:opacity-50"
                        >
                          {retryingId === j.job_id ? '...' : 'Retry'}
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {detail && (
        <div className="card-glass mt-8 p-6 animate-in">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-4">
            <h2 className="text-lg font-semibold text-[var(--text)]">
              Job {detail.job_id} - {detail.job_type}
            </h2>
            <div className="flex items-center gap-2">
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
          <dl className="mb-4 grid grid-cols-2 gap-x-4 gap-y-1 text-sm">
            <dt className="text-[var(--muted)]">Requested by</dt>
            <dd className="text-[var(--text)]">{detail.requested_by ?? '-'}</dd>
            <dt className="text-[var(--muted)]">Created</dt>
            <dd className="text-[var(--text)]">{formatDateTime(detail.created_at)}</dd>
            <dt className="text-[var(--muted)]">Started</dt>
            <dd className="text-[var(--text)]">{formatDateTime(detail.started_at)}</dd>
            <dt className="text-[var(--muted)]">Finished</dt>
            <dd className="text-[var(--text)]">{formatDateTime(detail.finished_at)}</dd>
            <dt className="text-[var(--muted)]">Retries</dt>
            <dd className="text-[var(--text)]">{detail.retry_count ?? 0}</dd>
            <dt className="text-[var(--muted)]">Asset</dt>
            <dd className="text-[var(--text)]">
              {detail.asset_key
                ? `${detail.asset_name || detail.asset_key} (${detail.asset_key})`
                : (detail.target_asset_id ?? '-')}
            </dd>
            {detail.asset_type && (
              <>
                <dt className="text-[var(--muted)]">Asset type</dt>
                <dd className="text-[var(--text)]">{detail.asset_type}</dd>
              </>
            )}
            {detail.asset_environment && (
              <>
                <dt className="text-[var(--muted)]">Environment</dt>
                <dd className="text-[var(--text)]">{detail.asset_environment}</dd>
              </>
            )}
            {detail.asset_criticality && (
              <>
                <dt className="text-[var(--muted)]">Criticality</dt>
                <dd className="text-[var(--text)]">{detail.asset_criticality}</dd>
              </>
            )}
            {detail.asset_verified != null && (
              <>
                <dt className="text-[var(--muted)]">Verified</dt>
                <dd className="text-[var(--text)]">{detail.asset_verified ? 'yes' : 'no'}</dd>
              </>
            )}
          </dl>
          {detail.error && (
            <div className="mb-4 rounded-lg bg-[var(--red)]/10 p-3 text-sm text-[var(--red)]">
              {detail.error}
            </div>
          )}
          {(detail.status === 'failed' || detail.error) && (
            <div className="mb-4 rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] p-4">
              <h3 className="mb-2 text-sm font-semibold text-[var(--text)]">AI triage</h3>
              {triageLoading ? (
                <p className="text-sm text-[var(--muted)]">Loading triage...</p>
              ) : aiTriage?.triage_text ? (
                <>
                  <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">
                    {aiTriage.triage_text}
                  </p>
                  <p className="mt-3 text-xs text-[var(--muted)]">
                    Generated {formatDateTime(aiTriage.generated_at)} via {aiTriage.provider}/
                    {aiTriage.model}
                  </p>
                  {isFallbackProvider(aiTriage.provider) && (
                    <p className="mt-2 text-xs text-[var(--amber)]">
                      Showing fallback triage. Use Force regenerate to retry with full model
                      output.
                    </p>
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
              {canMutate && (
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
            </div>
          )}
          {detail.log_output != null && detail.log_output !== '' && (
            <div>
              <h3 className="mb-2 text-sm font-medium text-[var(--muted)]">Log output</h3>
              <pre className="max-h-80 overflow-x-auto overflow-y-auto whitespace-pre-wrap rounded-lg border border-[var(--border)] bg-[var(--bg)] p-4 font-mono text-xs text-[var(--text)]">
                {detail.log_output}
              </pre>
            </div>
          )}
        </div>
      )}
    </main>
  );
}
