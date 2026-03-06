'use client';

import { useEffect, useState } from 'react';
import { useParams } from 'next/navigation';
import Link from 'next/link';
import {
  generateAssetAIDiagnosis,
  getAssetAIDiagnosis,
  getAssetDetail,
  getRepositoryScanSummary,
  getTelemetryAssetLogs,
  getThreatIntelAssetMatches,
  updateAssetByKey,
  type AIAssetDiagnosis,
  type AssetDetail,
  type RepositoryScanSummary,
  type TelemetryEvent,
  type ThreatIntelAssetMatches,
} from '@/lib/api';
import { AssetDetailSkeleton } from '@/components/Skeleton';
import { ApiDownHint } from '@/components/EmptyState';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

type TabId = 'summary' | 'timeline' | 'zeek' | 'evidence' | 'config';

function lastUpdatedAgo(lastSeen: string | null | undefined): string {
  if (!lastSeen) return '—';
  const sec = Math.floor((Date.now() - new Date(lastSeen).getTime()) / 1000);
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  return `${Math.floor(sec / 3600)}h ago`;
}

const ALL_TABS: { id: TabId; label: string; mutateOnly?: boolean }[] = [
  { id: 'summary', label: 'Summary' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'zeek', label: 'Zeek logs' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'config', label: 'Config', mutateOnly: true },
];

function isOptionalRepositorySummaryError(message: string | null): boolean {
  const normalized = (message || '').toLowerCase();
  return normalized.includes('asset not found') || normalized.includes('404');
}

function severityBadgeClass(value?: string | null): string {
  switch ((value || '').toLowerCase()) {
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

export default function AssetDetailPage() {
  const params = useParams();
  const assetKey = params.assetKey as string;
  const { canMutate } = useAuth();
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('summary');
  const [editOwner, setEditOwner] = useState('');
  const [editCriticality, setEditCriticality] = useState<'high' | 'medium' | 'low'>('medium');
  const [editName, setEditName] = useState('');
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);
  const [aiDiagnosis, setAiDiagnosis] = useState<AIAssetDiagnosis | null>(null);
  const [loadingDiagnosis, setLoadingDiagnosis] = useState(false);
  const [generatingDiagnosis, setGeneratingDiagnosis] = useState(false);
  const [diagnosisMessage, setDiagnosisMessage] = useState<string | null>(null);
  const [repositorySummary, setRepositorySummary] = useState<RepositoryScanSummary | null>(
    null
  );
  const [repositoryError, setRepositoryError] = useState<string | null>(null);
  const [threatIntelMatches, setThreatIntelMatches] = useState<ThreatIntelAssetMatches | null>(
    null
  );
  const [threatIntelError, setThreatIntelError] = useState<string | null>(null);
  const [zeekLogs, setZeekLogs] = useState<TelemetryEvent[]>([]);
  const [zeekError, setZeekError] = useState<string | null>(null);

  useEffect(() => {
    if (!assetKey) return;
    setDiagnosisMessage(null);
    setRepositoryError(null);
    setThreatIntelError(null);
    setZeekError(null);
    Promise.allSettled([
      getAssetDetail(assetKey),
      getRepositoryScanSummary(assetKey),
      getThreatIntelAssetMatches(assetKey),
      getTelemetryAssetLogs(assetKey, { source: 'zeek', limit: 150 }),
    ]).then(([detailResult, repositoryResult, threatIntelResult, zeekResult]) => {
        if (detailResult.status === 'fulfilled') {
          const d = detailResult.value;
          setDetail(d);
          setEditOwner(d?.state?.owner?.trim() ?? '');
          setEditCriticality(
            (d?.state?.criticality as 'high' | 'medium' | 'low') ?? 'medium'
          );
          setEditName(d?.state?.name?.trim() ?? '');
          setError(null);
        } else {
          setError(
            detailResult.reason instanceof Error
              ? detailResult.reason.message
              : 'Failed to load asset'
          );
        }

        if (repositoryResult.status === 'fulfilled') {
          setRepositorySummary(repositoryResult.value);
          setRepositoryError(null);
        } else {
          const message =
            repositoryResult.reason instanceof Error
              ? repositoryResult.reason.message
              : 'Failed to load repository summary';
          if (isOptionalRepositorySummaryError(message)) {
            setRepositorySummary(null);
            setRepositoryError(null);
          } else {
            setRepositorySummary(null);
            setRepositoryError(message);
          }
        }

        if (threatIntelResult.status === 'fulfilled') {
          setThreatIntelMatches(threatIntelResult.value);
          setThreatIntelError(null);
        } else {
          const message =
            threatIntelResult.reason instanceof Error
              ? threatIntelResult.reason.message
              : 'Failed to load threat-intel matches';
          if (isOptionalRepositorySummaryError(message)) {
            setThreatIntelMatches(null);
            setThreatIntelError(null);
          } else {
            setThreatIntelMatches(null);
            setThreatIntelError(message);
          }
        }

        if (zeekResult.status === 'fulfilled') {
          setZeekLogs(zeekResult.value.items || []);
          setZeekError(null);
        } else {
          const message =
            zeekResult.reason instanceof Error
              ? zeekResult.reason.message
              : 'Failed to load Zeek logs';
          if (isOptionalRepositorySummaryError(message)) {
            setZeekLogs([]);
            setZeekError(null);
          } else {
            setZeekLogs([]);
            setZeekError(message);
          }
        }
      });

    setLoadingDiagnosis(true);
    getAssetAIDiagnosis(assetKey)
      .then((out) => setAiDiagnosis(out))
      .catch((e) => {
        const message = e instanceof Error ? e.message : 'Failed to load AI diagnosis';
        if (!message.toLowerCase().includes('not found')) {
          setDiagnosisMessage(message);
        }
        setAiDiagnosis(null);
      })
      .finally(() => setLoadingDiagnosis(false));
  }, [assetKey]);

  const openEdit = () => {
    if (detail?.state) {
      setEditOwner(detail.state.owner?.trim() ?? '');
      setEditCriticality((detail.state.criticality as 'high' | 'medium' | 'low') ?? 'medium');
      setEditName(detail.state.name?.trim() ?? '');
    }
    setSaveError(null);
    setActiveTab('config');
  };
  const saveEdit = async () => {
    setSaveError(null);
    setSaving(true);
    try {
      await updateAssetByKey(assetKey, {
        owner: editOwner,
        criticality: editCriticality,
        name: editName || assetKey,
      });
      const d = await getAssetDetail(assetKey);
      setDetail(d);
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  const asset = detail?.state;
  const isRepositoryAsset =
    detail?.reason_display === 'repository_scan' ||
    detail?.state?.reason === 'repository_findings' ||
    repositorySummary != null;
  const latencySloMs = detail?.latency_slo_ms ?? 200;
  const isSpike = (ms: number | undefined) => typeof ms === 'number' && ms > latencySloMs;

  const copyEvidence = () => {
    if (!detail?.evidence) return;
    navigator.clipboard.writeText(JSON.stringify(detail.evidence, null, 2));
  };
  const openSearchUrl = process.env.NEXT_PUBLIC_OPENSEARCH_DASHBOARDS_URL;

  const handleGenerateDiagnosis = async (force: boolean) => {
    setGeneratingDiagnosis(true);
    setDiagnosisMessage(null);
    try {
      const out = await generateAssetAIDiagnosis(assetKey, force);
      setAiDiagnosis(out);
      setDiagnosisMessage(out.cached ? 'Showing cached AI diagnosis.' : 'AI diagnosis generated.');
    } catch (e) {
      setDiagnosisMessage(e instanceof Error ? e.message : 'AI diagnosis generation failed');
    } finally {
      setGeneratingDiagnosis(false);
    }
  };

  return (
    <main className="page-shell">
      <nav className="mb-6 flex items-center gap-2 text-sm" aria-label="Breadcrumb">
        <Link href="/assets" className="font-medium text-[var(--muted)] transition hover:text-[var(--text)]">
          Assets
        </Link>
        <span className="text-[var(--border)]">/</span>
        <span className="font-medium text-[var(--text)] truncate max-w-[200px] sm:max-w-none" title={assetKey}>
          {assetKey}
        </span>
      </nav>
      <h1 className="page-title mb-2 animate-in truncate" title={assetKey}>{assetKey}</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {error}
          <ApiDownHint />
        </div>
      )}
      {asset && detail && (
        <>
          <p className="mb-6 max-w-3xl text-sm text-[var(--text-muted)] animate-in">
            {isRepositoryAsset ? 'Repository scan refreshed' : 'Last updated'}{' '}
            {lastUpdatedAgo(asset.last_seen)}
            {detail.expected_interval_sec != null && (
              <>
                {' '}
                | Expected {isRepositoryAsset ? 'scan' : 'interval'} every{' '}
                {detail.expected_interval_sec}s
              </>
            )}
            {detail.data_completeness?.label_24h != null && (
              <> | Data completeness (24h): {detail.data_completeness.label_24h}{detail.data_completeness.pct_24h != null ? ` (${detail.data_completeness.pct_24h}%)` : ''}</>
            )}
          </p>

          <div className="mb-6 flex flex-wrap gap-2">
            {ALL_TABS.filter((t) => !t.mutateOnly || canMutate).map(({ id, label }) => (
              <button
                key={id}
                type="button"
                onClick={() => setActiveTab(id)}
                className={`rounded-full px-4 py-2 text-sm font-medium transition ${
                  activeTab === id
                    ? 'bg-[var(--green)] text-white shadow-lg shadow-[var(--green-glow)]'
                    : 'border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--muted)] hover:bg-[var(--surface)]'
                }`}
              >
                {label}
              </button>
            ))}
          </div>

          {activeTab === 'summary' && (
            <div className="grid gap-6 xl:grid-cols-[minmax(0,1fr)_360px] animate-in">
              <div className="space-y-6">
                <section className="section-panel">
                  <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                    <div className="flex flex-wrap gap-2">
                      <span className={`badge ${(asset.status || 'unknown').toLowerCase()}`}>{asset.status || 'unknown'}</span>
                      {asset.criticality && <span className="stat-chip capitalize">{asset.criticality}</span>}
                      {asset.environment && <span className="stat-chip">{asset.environment}</span>}
                      {asset.posture_score != null && <span className="stat-chip">Posture {asset.posture_score}</span>}
                    </div>
                    {canMutate && (
                      <button type="button" onClick={openEdit} className="btn-secondary text-sm">
                        Edit metadata
                      </button>
                    )}
                  </div>
                  <div className="meta-grid">
                    <div className="kv-item">
                      <span className="kv-label">Reason</span>
                      <div className="kv-value">{detail.reason_display ?? asset.reason ?? '-'}</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Last seen</span>
                      <div className="kv-value">{asset.last_seen ? formatDateTime(asset.last_seen) : '-'}</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Staleness</span>
                      <div className="kv-value">{asset.staleness_seconds ?? '-'}s</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Owner</span>
                      <div className="kv-value">{asset.owner?.trim() || 'Unassigned'}</div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">Latency SLO</span>
                      <div className="kv-value">
                        {detail.latency_slo_ok ? `Passing < ${detail.latency_slo_ms}ms` : `Over ${detail.latency_slo_ms}ms`}
                      </div>
                    </div>
                    <div className="kv-item">
                      <span className="kv-label">24h error rate</span>
                      <div className="kv-value">{detail.error_rate_24h ?? 0}%</div>
                    </div>
                  </div>
                </section>

                {detail.recommendations.length > 0 && (
                  <section className="section-panel">
                    <h2 className="section-title">Recommended actions</h2>
                    <ul className="space-y-3">
                      {detail.recommendations.map((recommendation, index) => (
                        <li key={index} className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/60 px-4 py-3 text-sm text-[var(--text)]">
                          {recommendation}
                        </li>
                      ))}
                    </ul>
                  </section>
                )}

                {repositoryError && (
                  <section className="section-panel">
                    <p className="text-sm text-[var(--red)]">{repositoryError}</p>
                  </section>
                )}

                {threatIntelError && (
                  <section className="section-panel">
                    <p className="text-sm text-[var(--red)]">{threatIntelError}</p>
                  </section>
                )}

                {zeekError && (
                  <section className="section-panel">
                    <p className="text-sm text-[var(--red)]">{zeekError}</p>
                  </section>
                )}

                {zeekLogs.length > 0 && (
                  <section className="section-panel">
                    <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <h2 className="section-title">Zeek logs</h2>
                        <p className="text-sm text-[var(--text-muted)]">
                          Recent network telemetry for this asset from Zeek protocol analysis.
                        </p>
                      </div>
                      <button
                        type="button"
                        onClick={() => setActiveTab('zeek')}
                        className="btn-secondary text-sm"
                      >
                        Open Zeek tab
                      </button>
                    </div>
                    <ul className="space-y-3">
                      {zeekLogs.slice(0, 5).map((event) => (
                        <li
                          key={event.event_id}
                          className="rounded-xl border border-[var(--border)] p-3"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <div>
                              <p className="font-medium text-[var(--text)]">
                                {event.event_type} {event.domain ? `| ${event.domain}` : ''}
                              </p>
                              <p className="mt-1 text-xs text-[var(--muted)]">
                                {event.src_ip || '-'}:{event.src_port ?? '-'} →{' '}
                                {event.dst_ip || '-'}:{event.dst_port ?? '-'}
                                {event.protocol ? ` | ${event.protocol}` : ''}
                              </p>
                            </div>
                            <span className="stat-chip">
                              {event.event_time ? formatDateTime(event.event_time) : '-'}
                            </span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </section>
                )}

                {threatIntelMatches && threatIntelMatches.total > 0 && (
                  <section className="section-panel">
                      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                        <div>
                          <h2 className="section-title">Threat-intel matches</h2>
                          <p className="text-sm text-[var(--text-muted)]">
                            This asset currently matches indicators from configured IOC feeds.
                          </p>
                        </div>
                        <Link href="/threat-intel" className="btn-secondary text-sm">
                          Open intel
                        </Link>
                      </div>
                    <ul className="space-y-3">
                      {threatIntelMatches.items.map((item, index) => (
                        <li
                          key={`${item.source}-${item.indicator}-${index}`}
                          className="rounded-xl border border-[var(--border)] p-3"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-3">
                            <div>
                              <p className="font-medium text-[var(--text)]">
                                {item.indicator}
                              </p>
                              <p className="mt-1 text-xs text-[var(--muted)]">
                                {item.source} | matched on {item.match_field}:{' '}
                                {item.matched_value}
                              </p>
                            </div>
                            <span
                              className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${severityBadgeClass('high')}`}
                            >
                              {item.indicator_type}
                            </span>
                          </div>
                        </li>
                      ))}
                    </ul>
                  </section>
                )}

                {repositorySummary && (
                  <section className="section-panel">
                    <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
                      <div>
                        <h2 className="section-title">Repository scan</h2>
                        <p className="text-sm text-[var(--text-muted)]">
                          OSV and Trivy findings mapped onto the repository asset.
                        </p>
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <Link href="/findings" className="btn-secondary text-sm">
                          Open findings
                        </Link>
                        <Link href="/jobs" className="btn-secondary text-sm">
                          Run another scan
                        </Link>
                      </div>
                    </div>

                    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
                      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                        <div className="text-3xl font-bold text-[var(--red)]">
                          {repositorySummary.open_findings}
                        </div>
                        <p className="mt-2 text-sm text-[var(--muted)]">Open findings</p>
                      </div>
                      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                        <div className="text-3xl font-bold text-[var(--amber)]">
                          {repositorySummary.in_progress_findings}
                        </div>
                        <p className="mt-2 text-sm text-[var(--muted)]">In progress</p>
                      </div>
                      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                        <div className="text-3xl font-bold text-[var(--text)]">
                          {repositorySummary.accepted_risk_findings}
                        </div>
                        <p className="mt-2 text-sm text-[var(--muted)]">Accepted risk</p>
                      </div>
                      <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/40 p-4">
                        <div className="text-3xl font-bold text-[var(--green)]">
                          {repositorySummary.remediated_findings}
                        </div>
                        <p className="mt-2 text-sm text-[var(--muted)]">Remediated</p>
                      </div>
                    </div>

                    <div className="mt-6 grid gap-6 xl:grid-cols-2">
                      <div>
                        <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                          Scanner sources
                        </h3>
                        <ul className="space-y-3">
                          {repositorySummary.sources.map((source) => (
                            <li
                              key={source.source}
                              className="rounded-xl border border-[var(--border)] p-3"
                            >
                              <div className="flex items-center justify-between gap-3">
                                <span className="font-medium text-[var(--text)]">
                                  {source.label}
                                </span>
                                <span className="stat-chip">{source.total} findings</span>
                              </div>
                              <p className="mt-2 text-xs text-[var(--muted)]">
                                Open {source.open} | In progress {source.in_progress} |
                                Accepted {source.accepted_risk} | Remediated{' '}
                                {source.remediated}
                              </p>
                              <div className="mt-3 flex flex-wrap gap-2">
                                {Object.entries(source.by_severity).map(
                                  ([severity, count]) => (
                                    <span
                                      key={`${source.source}-${severity}`}
                                      className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${severityBadgeClass(severity)}`}
                                    >
                                      {severity} {count}
                                    </span>
                                  )
                                )}
                              </div>
                            </li>
                          ))}
                        </ul>
                      </div>

                      <div>
                        <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                          Top packages
                        </h3>
                        {repositorySummary.top_packages.length === 0 ? (
                          <p className="text-sm text-[var(--muted)]">
                            No package inventory items are currently implicated.
                          </p>
                        ) : (
                          <ul className="space-y-3">
                            {repositorySummary.top_packages.map((pkg) => (
                              <li
                                key={pkg.package_name}
                                className="flex items-center justify-between gap-3 rounded-xl border border-[var(--border)] p-3"
                              >
                                <div>
                                  <p className="font-medium text-[var(--text)]">
                                    {pkg.package_name}
                                  </p>
                                  <p className="mt-1 text-xs text-[var(--muted)]">
                                    {pkg.active_count} active / {pkg.total_count} total
                                  </p>
                                </div>
                                <span
                                  className={`rounded px-2 py-0.5 text-xs font-semibold uppercase ${severityBadgeClass(pkg.max_severity)}`}
                                >
                                  {pkg.max_severity}
                                </span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    </div>

                    <div className="mt-6 grid gap-6 xl:grid-cols-2">
                      <div>
                        <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                          Recent findings
                        </h3>
                        {repositorySummary.recent_findings.length === 0 ? (
                          <p className="text-sm text-[var(--muted)]">
                            No repository findings recorded yet.
                          </p>
                        ) : (
                          <ul className="space-y-3">
                            {repositorySummary.recent_findings.map((finding) => (
                              <li
                                key={finding.finding_id}
                                className="rounded-xl border border-[var(--border)] p-3"
                              >
                                <div className="flex flex-wrap items-start justify-between gap-3">
                                  <div className="min-w-0 flex-1">
                                    <p className="font-medium text-[var(--text)]">
                                      {finding.title}
                                    </p>
                                    <p className="mt-1 text-xs text-[var(--muted)]">
                                      {finding.source || 'scanner'}
                                      {finding.package_name
                                        ? ` | ${finding.package_name}${
                                            finding.package_version
                                              ? `@${finding.package_version}`
                                              : ''
                                          }`
                                        : ''}
                                      {finding.vulnerability_id
                                        ? ` | ${finding.vulnerability_id}`
                                        : ''}
                                    </p>
                                  </div>
                                  <div className="text-right">
                                    <span
                                      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold uppercase ${severityBadgeClass(finding.risk_level || finding.severity)}`}
                                    >
                                      {finding.risk_level || finding.severity}
                                    </span>
                                    <p className="mt-1 text-[11px] capitalize text-[var(--muted)]">
                                      {finding.status.replace('_', ' ')}
                                    </p>
                                  </div>
                                </div>
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>

                      <div>
                        <h3 className="mb-3 text-sm font-medium text-[var(--muted)]">
                          Recent scan jobs
                        </h3>
                        {repositorySummary.latest_jobs.length === 0 ? (
                          <p className="text-sm text-[var(--muted)]">
                            No repository scan jobs have been recorded for this asset.
                          </p>
                        ) : (
                          <ul className="space-y-3">
                            {repositorySummary.latest_jobs.map((job) => (
                              <li
                                key={job.job_id}
                                className="rounded-xl border border-[var(--border)] p-3"
                              >
                                <div className="flex items-center justify-between gap-3">
                                  <span className="font-medium text-[var(--text)]">
                                    Job {job.job_id}
                                  </span>
                                  <span
                                    className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase ${
                                      job.status === 'done'
                                        ? 'bg-[var(--green)]/20 text-[var(--green)]'
                                        : job.status === 'failed'
                                          ? 'bg-[var(--red)]/20 text-[var(--red)]'
                                          : job.status === 'running'
                                            ? 'bg-[var(--amber)]/20 text-[var(--amber)]'
                                            : 'bg-[var(--surface-elevated)] text-[var(--muted)]'
                                    }`}
                                  >
                                    {job.status}
                                  </span>
                                </div>
                                <p className="mt-1 text-xs text-[var(--muted)]">
                                  Created {job.created_at ? formatDateTime(job.created_at) : '-'}
                                </p>
                                {job.error ? (
                                  <p className="mt-2 text-xs text-[var(--red)]">
                                    {job.error}
                                  </p>
                                ) : null}
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    </div>
                  </section>
                )}
              </div>

              <aside className="section-panel">
                <h2 className="section-title">AI diagnosis</h2>
                <p className="mb-4 text-sm text-[var(--text-muted)]">
                  Summarized operational diagnosis using current posture, recent events, and linked risk signals.
                </p>
                <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/60 p-4">
                  {loadingDiagnosis ? (
                    <p className="text-sm text-[var(--muted)]">Loading diagnosis...</p>
                  ) : aiDiagnosis?.diagnosis_text ? (
                    <>
                      <p className="whitespace-pre-wrap text-sm leading-6 text-[var(--text)]">
                        {aiDiagnosis.diagnosis_text}
                      </p>
                      <p className="mt-3 text-xs text-[var(--muted)]">
                        Generated {formatDateTime(aiDiagnosis.generated_at)} via {aiDiagnosis.provider}/
                        {aiDiagnosis.model}
                      </p>
                    </>
                  ) : (
                    <p className="text-sm text-[var(--muted)]">
                      No AI diagnosis generated yet for this asset.
                    </p>
                  )}
                  {diagnosisMessage && (
                    <p
                      className={`mt-3 text-xs ${
                        diagnosisMessage.toLowerCase().includes('failed')
                          ? 'text-[var(--red)]'
                          : 'text-[var(--muted)]'
                      }`}
                    >
                      {diagnosisMessage}
                    </p>
                  )}
                  {canMutate && (
                    <div className="mt-4 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => handleGenerateDiagnosis(false)}
                        disabled={generatingDiagnosis}
                        className="btn-primary text-sm"
                      >
                        {generatingDiagnosis
                          ? 'Generating...'
                          : aiDiagnosis
                            ? 'Refresh diagnosis'
                            : 'Generate diagnosis'}
                      </button>
                      {aiDiagnosis && (
                        <button
                          type="button"
                          onClick={() => handleGenerateDiagnosis(true)}
                          disabled={generatingDiagnosis}
                          className="btn-secondary text-sm"
                        >
                          Force regenerate
                        </button>
                        )}
                    </div>
                  )}
                </div>
              </aside>
            </div>
          )}

          {activeTab === 'timeline' && (
            <div className="animate-in">
              <h2 className="section-title">Timeline (last 24h)</h2>
              {detail.timeline.length === 0 ? (
                <div className="section-panel py-12 text-center text-sm text-[var(--muted)]">No events in the last 24h.</div>
              ) : (
                <div className="section-panel overflow-hidden p-0">
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse text-sm">
                      <thead>
                        <tr className="border-b border-[var(--border)] bg-[var(--bg)]/50">
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Time</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Status</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Code</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Latency (ms)</th>
                        </tr>
                      </thead>
                      <tbody>
                        {detail.timeline.slice(0, 50).map((ev, i) => {
                          const codeBad = ev.code != null && ev.code !== 200;
                          const latencySpike = isSpike(ev.latency_ms);
                          const isAnomaly = codeBad || latencySpike;
                          return (
                            <tr key={i} className={`border-b border-[var(--border)] ${isAnomaly ? 'bg-[var(--red)]/10' : ''}`}>
                              <td className="px-4 py-3">{ev['@timestamp'] ? formatDateTime(ev['@timestamp']) : '–'}</td>
                              <td className="px-4 py-3">{ev.status ?? '–'}</td>
                              <td className={`px-4 py-3 ${codeBad ? 'font-semibold text-[var(--red)]' : ''}`}>{ev.code ?? '–'}</td>
                              <td className={`px-4 py-3 ${latencySpike ? 'font-semibold text-[var(--amber)]' : ''}`}>
                                {ev.latency_ms ?? '–'}
                                {latencySpike && <span className="ml-1.5 text-xs text-[var(--amber)]">spike</span>}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                  {detail.timeline.length > 50 && <p className="px-4 py-2 text-xs text-[var(--muted)]">Showing latest 50 of {detail.timeline.length}</p>}
                </div>
              )}
            </div>
          )}

          {activeTab === 'zeek' && (
            <div className="animate-in">
              <h2 className="section-title">Zeek logs (network activity)</h2>
              {zeekLogs.length === 0 ? (
                <div className="section-panel py-12 text-center text-sm text-[var(--muted)]">
                  No Zeek logs are currently linked to this asset.
                </div>
              ) : (
                <div className="section-panel overflow-hidden p-0">
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse text-sm">
                      <thead>
                        <tr className="border-b border-[var(--border)] bg-[var(--bg)]/50">
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Time</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Type</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Flow</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">Domain/URL</th>
                          <th className="px-4 py-3 text-left text-xs font-medium uppercase tracking-wider text-[var(--muted)]">TI</th>
                        </tr>
                      </thead>
                      <tbody>
                        {zeekLogs.map((event) => (
                          <tr key={event.event_id} className="border-b border-[var(--border)]">
                            <td className="px-4 py-3">
                              {event.event_time ? formatDateTime(event.event_time) : '-'}
                            </td>
                            <td className="px-4 py-3">
                              <span className="stat-chip uppercase">{event.event_type}</span>
                            </td>
                            <td className="px-4 py-3">
                              {(event.src_ip || '-') + ':' + (event.src_port ?? '-')}
                              {' → '}
                              {(event.dst_ip || '-') + ':' + (event.dst_port ?? '-')}
                              {event.protocol ? ` (${event.protocol})` : ''}
                            </td>
                            <td className="px-4 py-3">
                              {event.domain || event.url || '-'}
                            </td>
                            <td className="px-4 py-3">
                              {event.ti_match ? (
                                <span className="rounded bg-[var(--red)]/20 px-2 py-0.5 text-xs text-[var(--red)]">
                                  matched {event.ti_source || 'feed'}
                                </span>
                              ) : (
                                <span className="text-xs text-[var(--muted)]">none</span>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'evidence' && (
            <div className="animate-in">
              <h2 className="section-title">Last check (evidence)</h2>
              {!detail.evidence ? (
                <div className="section-panel py-12 text-center text-sm text-[var(--muted)]">No evidence yet.</div>
              ) : (
                <section className="section-panel">
                  <div className="mb-2 flex flex-wrap gap-2">
                    <button type="button" onClick={copyEvidence} className="btn-secondary text-sm">Copy JSON</button>
                    {openSearchUrl && (
                      <a href={openSearchUrl} target="_blank" rel="noopener noreferrer" className="btn-secondary text-sm">View in OpenSearch</a>
                    )}
                  </div>
                  <details className="disclosure" open>
                    <summary>Raw evidence JSON</summary>
                    <div className="disclosure-body">
                      <pre className="overflow-auto rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] p-4 text-xs text-[var(--text-muted)]">{JSON.stringify(detail.evidence, null, 2)}</pre>
                    </div>
                  </details>
                </section>
              )}
            </div>
          )}

          {canMutate && activeTab === 'config' && (
            <div className="animate-in">
              <h2 className="section-title">Config</h2>
              <div className="section-panel">
                {saveError && <p className="mb-3 text-sm text-[var(--red)]">{saveError}</p>}
                <div className="flex max-w-sm flex-col gap-4">
                  <div>
                    <label className="mb-1.5 block text-sm font-medium text-[var(--muted)]">Owner</label>
                    <input type="text" value={editOwner} onChange={(e) => setEditOwner(e.target.value)} placeholder="e.g. Platform team" className="input" />
                  </div>
                  <div>
                    <label className="mb-1.5 block text-sm font-medium text-[var(--muted)]">Criticality</label>
                    <select value={editCriticality} onChange={(e) => setEditCriticality(e.target.value as 'high' | 'medium' | 'low')} className="input">
                      <option value="high">High</option>
                      <option value="medium">Medium</option>
                      <option value="low">Low</option>
                    </select>
                  </div>
                  <div>
                    <label className="mb-1.5 block text-sm font-medium text-[var(--muted)]">Name</label>
                    <input type="text" value={editName} onChange={(e) => setEditName(e.target.value)} placeholder="Display name" className="input" />
                  </div>
                  <div className="flex gap-2">
                    <button type="button" onClick={saveEdit} disabled={saving} className="btn-primary">{saving ? 'Saving...' : 'Save'}</button>
                    <button type="button" onClick={() => { setSaveError(null); }} disabled={saving} className="btn-secondary">Cancel</button>
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
      {!detail && !error && <AssetDetailSkeleton />}
    </main>
  );
}
