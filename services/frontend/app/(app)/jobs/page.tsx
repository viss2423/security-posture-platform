'use client';

import { useCallback, useEffect, useState } from 'react';
import { getJobs, getJob, retryJob, createJob, type JobItem, type JobDetail } from '@/lib/api';
import { useAuth } from '@/contexts/AuthContext';
import { formatDateTime } from '@/lib/format';
import { ApiDownHint, EmptyState } from '@/components/EmptyState';

export default function JobsPage() {
  const { canMutate } = useAuth();
  const [data, setData] = useState<{ items: JobItem[] } | null>(null);
  const [detail, setDetail] = useState<JobDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState('');
  const [retryingId, setRetryingId] = useState<number | null>(null);
  const [enqueueType, setEnqueueType] = useState<'web_exposure' | 'score_recompute'>('web_exposure');
  const [enqueueAssetId, setEnqueueAssetId] = useState('');
  const [enqueueing, setEnqueueing] = useState(false);

  const load = useCallback(() => {
    getJobs(statusFilter || undefined)
      .then(setData)
      .catch((e) => setError(e.message));
  }, [statusFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const openDetail = (id: number) => {
    getJob(id)
      .then(setDetail)
      .catch((e) => setError(e.message));
  };

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
          {error}
          <ApiDownHint />
        </div>
      )}

      {canMutate && (
        <div className="card-glass mb-6 p-4">
          <h2 className="text-sm font-semibold text-[var(--text)] mb-3">Enqueue job</h2>
          <div className="flex flex-wrap items-end gap-3">
            <label className="text-sm text-[var(--muted)]">
              Type
              <select
                value={enqueueType}
                onChange={(e) => setEnqueueType(e.target.value as 'web_exposure' | 'score_recompute')}
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
              {enqueueing ? 'Enqueueing…' : 'Enqueue'}
            </button>
          </div>
          <p className="mt-2 text-xs text-[var(--muted)]">
            Run the worker to process queued jobs: <code className="rounded bg-[var(--bg)] px-1">docker compose up -d worker-web</code> (see README).
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
          description={canMutate ? 'Enqueue a job above (web_exposure or score_recompute), then start the worker to process them. Click a job to see logs; use Retry on failed jobs.' : 'Jobs are created when an analyst or admin enqueues a scan. Run the worker to process queued jobs.'}
        />
      ) : (
        <div className="card-glass overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)]">
                  <th className="text-left py-3 px-4 font-medium text-[var(--muted)]">ID</th>
                  <th className="text-left py-3 px-4 font-medium text-[var(--muted)]">Type</th>
                  <th className="text-left py-3 px-4 font-medium text-[var(--muted)]">Asset</th>
                  <th className="text-left py-3 px-4 font-medium text-[var(--muted)]">Status</th>
                  <th className="text-left py-3 px-4 font-medium text-[var(--muted)]">Created</th>
                  <th className="text-left py-3 px-4 font-medium text-[var(--muted)]">Retries</th>
                  <th className="w-20" />
                </tr>
              </thead>
              <tbody>
                {data?.items.map((j) => (
                  <tr
                    key={j.job_id}
                    className="border-b border-[var(--border)]/50 hover:bg-[var(--surface-elevated)]/50 cursor-pointer"
                    onClick={() => openDetail(j.job_id)}
                  >
                    <td className="py-2 px-4 font-mono text-[var(--text)]">{j.job_id}</td>
                    <td className="py-2 px-4 text-[var(--text)]">{j.job_type}</td>
                    <td className="py-2 px-4 text-[var(--muted)]">{j.target_asset_id ?? '–'}</td>
                    <td className="py-2 px-4">{statusBadge(j.status)}</td>
                    <td className="py-2 px-4 text-[var(--muted)]">{formatDateTime(j.created_at)}</td>
                    <td className="py-2 px-4 text-[var(--muted)]">{j.retry_count ?? 0}</td>
                    <td className="py-2 px-4" onClick={(e) => e.stopPropagation()}>
                      {canMutate && (j.status === 'failed' || j.status === 'done') && (
                        <button
                          type="button"
                          onClick={() => handleRetry(j.job_id)}
                          disabled={retryingId === j.job_id}
                          className="text-xs text-[var(--green)] hover:underline disabled:opacity-50"
                        >
                          {retryingId === j.job_id ? '…' : 'Retry'}
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
          <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
            <h2 className="text-lg font-semibold text-[var(--text)]">
              Job {detail.job_id} · {detail.job_type}
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
                  {retryingId === detail.job_id ? 'Retrying…' : 'Retry'}
                </button>
              )}
              <button type="button" onClick={() => setDetail(null)} className="btn-secondary text-sm">
                Close
              </button>
            </div>
          </div>
          <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-sm mb-4">
            <dt className="text-[var(--muted)]">Requested by</dt>
            <dd className="text-[var(--text)]">{detail.requested_by ?? '–'}</dd>
            <dt className="text-[var(--muted)]">Created</dt>
            <dd className="text-[var(--text)]">{formatDateTime(detail.created_at)}</dd>
            <dt className="text-[var(--muted)]">Started</dt>
            <dd className="text-[var(--text)]">{formatDateTime(detail.started_at)}</dd>
            <dt className="text-[var(--muted)]">Finished</dt>
            <dd className="text-[var(--text)]">{formatDateTime(detail.finished_at)}</dd>
            <dt className="text-[var(--muted)]">Retries</dt>
            <dd className="text-[var(--text)]">{detail.retry_count ?? 0}</dd>
          </dl>
          {detail.error && (
            <div className="mb-4 p-3 rounded-lg bg-[var(--red)]/10 text-[var(--red)] text-sm">
              {detail.error}
            </div>
          )}
          {detail.log_output != null && detail.log_output !== '' && (
            <div>
              <h3 className="text-sm font-medium text-[var(--muted)] mb-2">Log output</h3>
              <pre className="rounded-lg border border-[var(--border)] bg-[var(--bg)] p-4 text-xs overflow-x-auto whitespace-pre-wrap font-mono text-[var(--text)] max-h-80 overflow-y-auto">
                {detail.log_output}
              </pre>
            </div>
          )}
        </div>
      )}
    </main>
  );
}
