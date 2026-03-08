const API = '/api';

function redirectToLogin() {
  if (typeof window !== 'undefined') {
    window.location.replace('/login');
  }
}

function parseApiErrorMessage(status: number, text: string, fallback: string): string {
  const message = text || fallback;
  if (status === 502) {
    try {
      const data = JSON.parse(text);
      if (typeof data?.error?.message === 'string') return data.error.message;
      if (typeof data?.error === 'string') return data.error;
    } catch {
      return 'API unreachable';
    }
    return message;
  }

  try {
    const data = JSON.parse(text);
    if (typeof data?.error?.message === 'string') return data.error.message;
    if (typeof data?.detail === 'string') return data.detail;
    if (typeof data?.error === 'string') return data.error;
  } catch {
    return message;
  }

  return message;
}

async function tryRefreshSession(): Promise<boolean> {
  try {
    const res = await fetch(API + '/auth/session', {
      method: 'PATCH',
      cache: 'no-store',
    });
    return res.ok;
  } catch {
    return false;
  }
}

async function downloadFromApi(url: string, filename: string): Promise<void> {
  let res = await fetch(url, { cache: 'no-store' });
  if (res.status === 401) {
    const refreshed = await tryRefreshSession();
    if (refreshed) {
      res = await fetch(url, { cache: 'no-store' });
    }
  }
  if (res.status === 401) {
    redirectToLogin();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    throw new Error((await res.text()) || 'Download failed');
  }
  const blob = await res.blob();
  const objectUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = objectUrl;
  anchor.download = filename;
  anchor.click();
  URL.revokeObjectURL(objectUrl);
}

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const headers = new Headers(options?.headers);
  if (!headers.has('Accept')) {
    headers.set('Accept', 'application/json');
  }
  if (options?.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const requestInit: RequestInit = {
    ...options,
    headers,
    cache: options?.cache ?? 'no-store',
  };
  let res = await fetch(API + path, requestInit);
  if (res.status === 401 && path !== '/auth/session') {
    const refreshed = await tryRefreshSession();
    if (refreshed) {
      res = await fetch(API + path, requestInit);
    }
  }
  if (res.status === 401) {
    redirectToLogin();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const text = await res.text();
    throw new Error(parseApiErrorMessage(res.status, text, res.statusText || 'Request failed'));
  }
  return res.json();
}

export type AuthConfig = { oidc_enabled: boolean };

export async function getAuthConfig(): Promise<AuthConfig> {
  const res = await fetch(API + '/auth/config', { cache: 'no-store' });
  if (!res.ok) return { oidc_enabled: false };
  return res.json();
}

export async function login(username: string, password: string): Promise<{ access_token: string }> {
  const res = await fetch(API + '/auth/session', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
    cache: 'no-store',
  });
  const text = await res.text();
  if (!res.ok) {
    let msg = text || 'Login failed';
    try {
      const j = JSON.parse(text);
      if (j?.error) msg = j.error;
    } catch {
      /* use text as-is */
    }
    throw new Error(msg);
  }
  return { access_token: 'session' };
}

export async function logout(): Promise<void> {
  await fetch(API + '/auth/session', {
    method: 'DELETE',
    cache: 'no-store',
  });
}

export type Me = { username: string; role: string };

export async function getMe(): Promise<Me> {
  return apiFetch<Me>('/auth/me');
}

export type PostureSummary = {
  green: number;
  amber: number;
  red: number;
  posture_score_avg: number | null;
  down_assets?: string[];
};

export type AssetPosture = {
  asset_id: string;
  asset_key: string;
  status: 'green' | 'amber' | 'red';
  last_seen?: string | null;
  reason?: string | null;
  criticality?: 'high' | 'medium' | 'low';
  name?: string | null;
  owner?: string | null;
  environment?: string | null;
  posture_score?: number | null;
  staleness_seconds?: number | null;
};

export type PostureFilters = {
  environment?: string | null;
  criticality?: string | null;
  owner?: string | null;
  status?: string | null;
};

function filtersToParams(f: PostureFilters): string {
  const p = new URLSearchParams();
  if (f.environment) p.set('environment', f.environment);
  if (f.criticality) p.set('criticality', f.criticality);
  if (f.owner) p.set('owner', f.owner);
  if (f.status) p.set('status', f.status);
  const s = p.toString();
  return s ? `?${s}` : '';
}

export async function getPostureSummary(filters?: PostureFilters): Promise<PostureSummary> {
  return apiFetch<PostureSummary>('/posture/summary' + (filters ? filtersToParams(filters) : ''));
}

export async function getPostureList(filters?: PostureFilters): Promise<{ total: number; items: AssetPosture[] }> {
  return apiFetch<{ total: number; items: AssetPosture[] }>('/posture' + (filters ? filtersToParams(filters) : ''));
}

export type OverviewResponse = {
  executive_strip: {
    posture_score_avg: number | null;
    total_assets: number;
    alerts_firing: number;
    score_trend_vs_yesterday: 'up' | 'down' | 'same' | null;
    risk_change_24h: number | null;
    green: number;
    amber: number;
    red: number;
    down_assets: string[];
  };
  top_drivers: {
    worst_assets: Array<{ asset_id: string; name?: string | null; posture_score?: number | null; status?: string }>;
    by_reason: Array<{ reason: string; count: number }>;
    recently_updated: Array<{ asset_id: string; name?: string | null; last_seen?: string | null }>;
  };
};

export async function getPostureOverview(filters?: PostureFilters): Promise<OverviewResponse> {
  return apiFetch<OverviewResponse>('/posture/overview' + (filters ? filtersToParams(filters) : ''));
}

export type TrendPoint = {
  created_at: string;
  posture_score_avg: number | null;
  green: number;
  amber: number;
  red: number;
};

export async function getPostureTrend(range: '24h' | '7d' | '30d' = '7d'): Promise<{ range: string; points: TrendPoint[] }> {
  return apiFetch<{ range: string; points: TrendPoint[] }>(`/posture/trend?range=${range}`);
}

export async function getPosture(assetKey: string): Promise<AssetPosture> {
  return apiFetch<AssetPosture>(`/posture/${encodeURIComponent(assetKey)}`);
}

export type DataCompleteness = {
  checks: number;
  expected: number;
  label_24h: string;
  label_1h: string;
  pct_24h: number | null;
  pct_1h: number | null;
};

export type AssetDetail = {
  state: AssetPosture;
  timeline: Array<{ '@timestamp'?: string; status?: string; code?: number; latency_ms?: number; message?: string }>;
  evidence: Record<string, unknown> | null;
  recommendations: string[];
  expected_interval_sec: number;
  data_completeness: DataCompleteness;
  latency_slo_ms: number;
  latency_slo_ok: boolean;
  error_rate_24h: number;
  reason_display?: string | null;
};

export async function getAssetDetail(assetKey: string, hours: number = 24): Promise<AssetDetail> {
  return apiFetch<AssetDetail>(`/posture/${encodeURIComponent(assetKey)}/detail?hours=${hours}`);
}

export type ReportSummary = {
  period: string;
  uptime_pct: number;
  posture_score_avg: number | null;
  avg_latency_ms: number | null;
  top_incidents: string[];
  total_assets: number;
  green: number;
  amber: number;
  red: number;
};

export async function getReportSummary(period: string = '24h'): Promise<ReportSummary> {
  return apiFetch<ReportSummary>(`/posture/reports/summary?period=${period}`);
}

/** Stored report snapshot (from DB) */
export type ReportSnapshot = {
  id: number;
  period: string;
  created_at: string;
  uptime_pct: number;
  posture_score_avg: number | null;
  avg_latency_ms: number | null;
  total_assets: number;
  green: number;
  amber: number;
  red: number;
  top_incidents: string[];
};

export async function getReportHistory(limit: number = 20): Promise<{ items: ReportSnapshot[] }> {
  return apiFetch<{ items: ReportSnapshot[] }>(`/posture/reports/history?limit=${limit}`);
}

export async function getReportSnapshot(id: number): Promise<ReportSnapshot> {
  return apiFetch<ReportSnapshot>(`/posture/reports/history/${id}`);
}

export async function saveReportSnapshot(period: string = '24h'): Promise<ReportSnapshot> {
  return apiFetch<ReportSnapshot>(`/posture/reports/snapshot?period=${period}`, { method: 'POST' });
}

/** Download executive summary as PDF. Optional snapshotId to export that snapshot. */
export async function downloadExecutivePdf(snapshotId?: number): Promise<void> {
  const url =
    snapshotId != null
    ? `${API}/posture/reports/executive.pdf?snapshot_id=${snapshotId}`
    : `${API}/posture/reports/executive.pdf`;
  await downloadFromApi(url, 'secplat-executive.pdf');
}

export type MaintenanceWindow = {
  id: number;
  asset_key: string;
  start_at: string;
  end_at: string;
  reason?: string | null;
  created_by?: string | null;
  created_at?: string | null;
};

export type SuppressionRule = {
  id: number;
  scope: 'asset' | 'finding' | 'all';
  scope_value?: string | null;
  starts_at: string;
  ends_at: string;
  reason?: string | null;
  created_by?: string | null;
  created_at?: string | null;
};

export async function getMaintenanceWindows(opts?: {
  assetKey?: string;
  activeOnly?: boolean;
}): Promise<{ items: MaintenanceWindow[] }> {
  const p = new URLSearchParams();
  if (opts?.assetKey) p.set('asset_key', opts.assetKey);
  if (opts?.activeOnly) p.set('active_only', 'true');
  const qs = p.toString();
  return apiFetch<{ items: MaintenanceWindow[] }>(`/suppression/maintenance-windows${qs ? `?${qs}` : ''}`);
}

export async function createMaintenanceWindow(body: {
  asset_key: string;
  start_at: string;
  end_at: string;
  reason?: string | null;
}): Promise<MaintenanceWindow> {
  return apiFetch<MaintenanceWindow>('/suppression/maintenance-windows', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function deleteMaintenanceWindow(id: number): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/suppression/maintenance-windows/${id}`, { method: 'DELETE' });
}

export async function getSuppressionRules(opts?: {
  scope?: 'asset' | 'finding' | 'all';
  activeOnly?: boolean;
}): Promise<{ items: SuppressionRule[] }> {
  const p = new URLSearchParams();
  if (opts?.scope) p.set('scope', opts.scope);
  if (opts?.activeOnly) p.set('active_only', 'true');
  const qs = p.toString();
  return apiFetch<{ items: SuppressionRule[] }>(`/suppression/rules${qs ? `?${qs}` : ''}`);
}

export async function createSuppressionRule(body: {
  scope: 'asset' | 'finding' | 'all';
  scope_value?: string | null;
  starts_at: string;
  ends_at: string;
  reason?: string | null;
}): Promise<SuppressionRule> {
  return apiFetch<SuppressionRule>('/suppression/rules', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function deleteSuppressionRule(id: number): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>(`/suppression/rules/${id}`, { method: 'DELETE' });
}

export type ReportWhatChanged = {
  from: { period: string; uptime_pct: number; posture_score_avg: number | null; total_assets: number; green: number; amber: number; red: number; created_at?: string; id?: number };
  to: { period: string; uptime_pct: number; posture_score_avg: number | null; total_assets: number; green: number; amber: number; red: number; created_at?: string; id?: number | string };
  score_delta: number | null;
  green_delta: number;
  amber_delta: number;
  red_delta: number;
  incidents_added: string[];
  incidents_removed: string[];
};

export async function getReportWhatChanged(fromId: number, toId?: number): Promise<ReportWhatChanged> {
  const params = new URLSearchParams({ from_id: String(fromId) });
  if (toId != null) params.set('to_id', String(toId));
  return apiFetch<ReportWhatChanged>(`/posture/reports/what-changed?${params}`);
}

export type AuditEvent = {
  id: number;
  created_at: string;
  action: string;
  user_name: string | null;
  asset_key: string | null;
  details: Record<string, unknown>;
  request_id: string | null;
};

export type AuditFilters = {
  user?: string | null;
  action?: string | null;
  since?: string | null;
  limit?: number;
};

export async function getAuditLog(filters?: AuditFilters): Promise<{ items: AuditEvent[]; actions?: string[] }> {
  const p = new URLSearchParams();
  if (filters?.user) p.set('user', filters.user);
  if (filters?.action) p.set('action', filters.action);
  if (filters?.since) p.set('since', filters.since);
  if (filters?.limit != null) p.set('limit', String(filters.limit));
  const q = p.toString();
  return apiFetch<{ items: AuditEvent[]; actions?: string[] }>('/audit' + (q ? `?${q}` : ''));
}

export type User = {
  username: string;
  role: string;
  source: string;
  disabled?: boolean;
};

export async function getUsers(): Promise<{ items: User[] }> {
  return apiFetch<{ items: User[] }>('/auth/users');
}

// Policy bundles (Phase B.2)
export type PolicyBundle = {
  id: number;
  name: string;
  description: string | null;
  status: 'draft' | 'approved';
  created_at: string | null;
  updated_at: string | null;
  approved_at: string | null;
  approved_by: string | null;
};

export type PolicyBundleDetail = PolicyBundle & { definition: string };

export type PolicyViolation = {
  rule_id: string;
  rule_name: string;
  rule_type: string;
  asset_key: string;
  timestamp: string;
  bundle_approved_by?: string | null;
  evidence: Record<string, unknown>;
};

export type PolicyRuleResult = {
  id: string;
  name: string;
  type: string;
  passed: number;
  failed: number;
  total: number;
  pass_pct: number;
  violations?: PolicyViolation[];
};

export type PolicyEvaluateResult = {
  evaluation_id?: number;
  evaluated_at?: string | null;
  bundle_approved_by?: string | null;
  bundle_id: number;
  bundle_name: string;
  score: number;
  rules: PolicyRuleResult[];
  violations?: PolicyViolation[];
};

export type PolicyEvaluationSummary = {
  id: number;
  bundle_id: number;
  evaluated_at: string | null;
  evaluated_by?: string | null;
  bundle_approved_by?: string | null;
  score: number | null;
  violations_count: number;
};

export type PolicyEvaluationDetail = {
  id: number;
  bundle_id: number;
  evaluated_at: string | null;
  evaluated_by?: string | null;
  bundle_approved_by?: string | null;
  score: number | null;
  violations_count: number;
  result: PolicyEvaluateResult;
};

export async function getPolicyBundles(status?: string): Promise<{ items: PolicyBundle[] }> {
  const q = status ? `?status=${encodeURIComponent(status)}` : '';
  return apiFetch<{ items: PolicyBundle[] }>(`/policy/bundles${q}`);
}

export async function getPolicyBundle(id: number): Promise<PolicyBundleDetail> {
  return apiFetch<PolicyBundleDetail>(`/policy/bundles/${id}`);
}

export async function createPolicyBundle(body: { name: string; description?: string; definition: string }): Promise<{ id: number; name: string; status: string; created_at: string }> {
  return apiFetch(`/policy/bundles`, { method: 'POST', body: JSON.stringify(body) });
}

export async function updatePolicyBundle(id: number, body: { name?: string; description?: string; definition?: string }): Promise<PolicyBundleDetail> {
  return apiFetch<PolicyBundleDetail>(`/policy/bundles/${id}`, { method: 'PATCH', body: JSON.stringify(body) });
}

export async function approvePolicyBundle(id: number): Promise<{ ok: boolean; status: string }> {
  return apiFetch(`/policy/bundles/${id}/approve`, { method: 'POST' });
}

export async function evaluatePolicyBundle(id: number): Promise<PolicyEvaluateResult> {
  return apiFetch<PolicyEvaluateResult>(`/policy/bundles/${id}/evaluate`, { method: 'POST' });
}

export async function getPolicyEvaluationHistory(id: number, limit: number = 20): Promise<{ items: PolicyEvaluationSummary[] }> {
  return apiFetch<{ items: PolicyEvaluationSummary[] }>(`/policy/bundles/${id}/evaluations?limit=${limit}`);
}

export async function getPolicyEvaluation(id: number, evaluationId: number): Promise<PolicyEvaluationDetail> {
  return apiFetch<PolicyEvaluationDetail>(`/policy/bundles/${id}/evaluations/${evaluationId}`);
}

export async function deletePolicyBundle(id: number): Promise<{ ok: boolean }> {
  return apiFetch(`/policy/bundles/${id}`, { method: 'DELETE' });
}

// Jobs (Phase B.3)
export type JobItem = {
  job_id: number;
  job_type: string;
  target_asset_id: number | null;
  asset_key?: string | null;
  asset_name?: string | null;
  requested_by: string | null;
  status: string;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  retry_count?: number;
  job_params_json?: Record<string, unknown> | null;
};

export type JobDetail = JobItem & {
  log_output: string | null;
  asset_type?: string | null;
  asset_environment?: string | null;
  asset_criticality?: string | null;
  asset_verified?: boolean | null;
};

export async function getJobs(status?: string): Promise<{ items: JobItem[] }> {
  const q = status ? `?status=${encodeURIComponent(status)}&limit=100` : '?limit=100';
  return apiFetch<{ items: JobItem[] }>(`/jobs${q}`);
}

export async function getJob(id: number): Promise<JobDetail> {
  return apiFetch<JobDetail>(`/jobs/${id}`);
}

export async function createJob(payload: {
  job_type: string;
  target_asset_id?: number;
  requested_by?: string;
  job_params_json?: Record<string, unknown>;
}): Promise<JobItem> {
  return apiFetch<JobItem>('/jobs', { method: 'POST', body: JSON.stringify(payload) });
}

export async function retryJob(id: number): Promise<{ ok: boolean; status: string }> {
  return apiFetch(`/jobs/${id}/retry`, { method: 'POST' });
}

export type AIJobTriage = {
  job_id: number;
  triage_text: string;
  provider: string;
  model: string;
  generated_by?: string | null;
  generated_at: string;
  context_json?: Record<string, unknown>;
  cached?: boolean;
};

export async function getJobAITriage(jobId: number): Promise<AIJobTriage> {
  return apiFetch<AIJobTriage>(`/ai/jobs/${jobId}/triage`);
}

export async function generateJobAITriage(
  jobId: number,
  force: boolean = false
): Promise<AIJobTriage> {
  return apiFetch<AIJobTriage>(`/ai/jobs/${jobId}/triage/generate`, {
    method: 'POST',
    body: JSON.stringify({ force }),
  });
}

export type AlertItem = {
  asset_key: string;
  alert_id?: number;
  source?: string | null;
  title?: string | null;
  description?: string | null;
  event_count?: number | null;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  ti_match?: boolean;
  ti_source?: string | null;
  mitre_techniques?: string[];
  payload_json?: Record<string, unknown>;
  context_json?: Record<string, unknown>;
  state?: string;
  asset_name?: string | null;
  owner?: string | null;
  environment?: string | null;
  criticality?: 'high' | 'medium' | 'low' | null;
  asset_type?: string | null;
  verified?: boolean | null;
  posture_status?: 'green' | 'amber' | 'red' | null;
  posture_score?: number | null;
  reason?: string | null;
  last_seen?: string | null;
  staleness_seconds?: number | null;
  active_finding_count?: number;
  top_risk_score?: number | null;
  top_risk_level?: 'critical' | 'high' | 'medium' | 'low' | null;
  open_incident_count?: number;
  open_incident_ids?: number[];
  open_incident_severities?: string[];
  maintenance_active?: boolean;
  maintenance_reason?: string | null;
  maintenance_end_at?: string | null;
  suppression_rule_active?: boolean;
  suppression_reason?: string | null;
  suppression_end_at?: string | null;
  ai_recommended_action?: 'ack' | 'suppress' | 'assign' | 'escalate' | 'resolve' | 'monitor' | null;
  ai_urgency?: 'critical' | 'high' | 'medium' | 'low' | null;
  ai_generated_at?: string | null;
  effective_severity?: 'critical' | 'high' | 'medium' | 'low' | 'info' | null;
  effective_severity_score?: number | null;
  effective_severity_top_drivers?: Array<{
    code: string;
    delta: number;
    detail: string;
  }>;
  ack_reason?: string | null;
  acked_by?: string | null;
  acked_at?: string | null;
  suppressed_until?: string | null;
  assigned_to?: string | null;
  resolved_at?: string | null;
  updated_at?: string | null;
};

export type AlertsResponse = {
  firing: AlertItem[];
  acked: AlertItem[];
  suppressed: AlertItem[];
  resolved: AlertItem[];
};

export async function getAlerts(): Promise<AlertsResponse> {
  return apiFetch<AlertsResponse>('/alerts');
}

export type AlertRelatedEvent = {
  event_id: number;
  source: string;
  event_type: string;
  asset_key?: string | null;
  severity?: number | null;
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  domain?: string | null;
  protocol?: string | null;
  event_time?: string | null;
  ti_match?: boolean;
  ti_source?: string | null;
  anomaly_score?: number | null;
  payload_json?: Record<string, unknown>;
};

export type AlertEnrichment = {
  alert_id: number;
  alert_key?: string | null;
  source?: string | null;
  title?: string | null;
  description?: string | null;
  asset_key?: string | null;
  severity?: string | null;
  status?: string | null;
  ti_match?: boolean;
  ti_source?: string | null;
  mitre_techniques?: string[];
  event_count?: number;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  asset_context?: Record<string, unknown>;
  severity_analysis?: {
    base_severity?: string;
    effective_severity?: string;
    effective_score?: number;
    criticality?: string;
    recurrence_count?: number;
    drivers?: Array<{ code: string; delta: number; detail: string }>;
    top_drivers?: Array<{ code: string; delta: number; detail: string }>;
  };
  recurrence?: {
    dedupe_key?: string | null;
    event_count?: number;
    first_seen_at?: string | null;
    last_seen_at?: string | null;
    window_minutes?: number | null;
    recurrence_per_hour?: number | null;
    is_recurring?: boolean;
  };
  related_events?: AlertRelatedEvent[];
  dedupe_group?: Array<{
    alert_id: number;
    status?: string;
    severity?: string;
    event_count?: number;
    first_seen_at?: string | null;
    last_seen_at?: string | null;
  }>;
  recommended_next_steps?: string[];
  effective_severity?: string;
  effective_severity_score?: number;
};

export type AlertCluster = {
  cluster_key: string;
  cluster_type: 'asset' | 'source_ip' | 'technique' | 'campaign' | string;
  alert_count: number;
  event_count: number;
  first_seen_at?: string | null;
  last_seen_at?: string | null;
  max_severity?: string;
  asset_keys: string[];
  source_ips: string[];
  techniques: string[];
  campaigns: string[];
  alert_ids: number[];
};

export async function getAlertEnrichment(
  alertId: number,
  params?: { lookback_hours?: number; related_limit?: number }
): Promise<AlertEnrichment> {
  const query = new URLSearchParams();
  if (params?.lookback_hours != null) query.set('lookback_hours', String(params.lookback_hours));
  if (params?.related_limit != null) query.set('related_limit', String(params.related_limit));
  const suffix = query.toString();
  return apiFetch<AlertEnrichment>(
    `/alerts/${alertId}/enrichment${suffix ? `?${suffix}` : ''}`
  );
}

export async function getAlertRelatedEvents(
  alertId: number,
  params?: { lookback_hours?: number; limit?: number }
): Promise<{ alert_id: number; lookback_hours: number; items: AlertRelatedEvent[] }> {
  const query = new URLSearchParams();
  if (params?.lookback_hours != null) query.set('lookback_hours', String(params.lookback_hours));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ alert_id: number; lookback_hours: number; items: AlertRelatedEvent[] }>(
    `/alerts/${alertId}/related-events${suffix ? `?${suffix}` : ''}`
  );
}

export async function getAlertClusters(params?: {
  by?: 'asset' | 'source_ip' | 'technique' | 'campaign';
  status?: 'firing' | 'acked' | 'suppressed' | 'resolved';
  limit?: number;
}): Promise<{ cluster_by: string; status?: string | null; items: AlertCluster[] }> {
  const query = new URLSearchParams();
  if (params?.by) query.set('by', params.by);
  if (params?.status) query.set('status', params.status);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ cluster_by: string; status?: string | null; items: AlertCluster[] }>(
    `/alerts/clusters${suffix ? `?${suffix}` : ''}`
  );
}

export type AlertActionTarget = {
  asset_key?: string;
  alert_id?: number;
};

export async function postAlertAck(
  target: AlertActionTarget,
  reason?: string
): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/ack', {
    method: 'POST',
    body: JSON.stringify({ ...target, reason }),
  });
}

export async function postAlertSuppress(
  target: AlertActionTarget,
  until_iso: string
): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/suppress', {
    method: 'POST',
    body: JSON.stringify({ ...target, until_iso }),
  });
}

export async function postAlertResolve(target: AlertActionTarget): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/resolve', {
    method: 'POST',
    body: JSON.stringify({ ...target }),
  });
}

export async function postAlertAssign(
  target: AlertActionTarget,
  assigned_to: string
): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/assign', {
    method: 'POST',
    body: JSON.stringify({ ...target, assigned_to }),
  });
}

export type AutomationPlaybook = {
  playbook_id: number;
  title: string;
  description?: string | null;
  trigger: string;
  conditions_json: Array<Record<string, unknown>>;
  actions_json: Array<Record<string, unknown>>;
  approval_required: boolean;
  rollback_steps_json: Array<Record<string, unknown>>;
  enabled: boolean;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

export type AutomationRunAction = {
  run_action_id: number;
  run_id: number;
  action_index: number;
  action_type: string;
  risk_tier: 'low' | 'medium' | 'high' | string;
  status:
    | 'pending'
    | 'pending_approval'
    | 'approved'
    | 'rejected'
    | 'running'
    | 'done'
    | 'failed'
    | 'rolled_back'
    | string;
  params_json: Record<string, unknown>;
  result_json: Record<string, unknown>;
  error?: string | null;
  created_at?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
};

export type AutomationRun = {
  run_id: number;
  playbook_id: number;
  playbook_title?: string;
  trigger_source: string;
  trigger_payload_json: Record<string, unknown>;
  matched: boolean;
  status: 'running' | 'pending_approval' | 'done' | 'failed' | 'rejected' | string;
  requested_by?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  summary_json: Record<string, unknown>;
  actions?: AutomationRunAction[];
};

export type AutomationApproval = {
  approval_id: number;
  run_action_id: number;
  required_role: 'analyst' | 'admin' | string;
  risk_tier: 'medium' | 'high' | string;
  status: 'pending' | 'approved' | 'rejected' | string;
  requested_by?: string | null;
  approved_by?: string | null;
  rejected_by?: string | null;
  reason?: string | null;
  decision_note?: string | null;
  created_at?: string | null;
  decided_at?: string | null;
  run_id?: number;
  action_type?: string;
  params_json?: Record<string, unknown>;
};

export type AutomationRollback = {
  rollback_id: number;
  run_action_id: number;
  rollback_type: string;
  rollback_payload_json: Record<string, unknown>;
  status: 'pending' | 'executed' | 'failed' | string;
  requested_by?: string | null;
  executed_by?: string | null;
  created_at?: string | null;
  executed_at?: string | null;
  error?: string | null;
  run_id?: number;
  action_type?: string;
};

export async function getAutomationPlaybooks(params?: {
  include_disabled?: boolean;
}): Promise<{ items: AutomationPlaybook[] }> {
  const query = new URLSearchParams();
  if (params?.include_disabled != null) {
    query.set('include_disabled', params.include_disabled ? 'true' : 'false');
  }
  const suffix = query.toString();
  return apiFetch(`/automation/playbooks${suffix ? `?${suffix}` : ''}`);
}

export async function createAutomationPlaybook(body: {
  title: string;
  description?: string | null;
  trigger: string;
  conditions?: Array<Record<string, unknown>>;
  actions?: Array<Record<string, unknown>>;
  approval_required?: boolean;
  rollback_steps?: Array<Record<string, unknown>>;
  enabled?: boolean;
}): Promise<AutomationPlaybook> {
  return apiFetch('/automation/playbooks', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function updateAutomationPlaybook(
  playbook_id: number,
  body: {
    description?: string | null;
    trigger?: string;
    conditions?: Array<Record<string, unknown>>;
    actions?: Array<Record<string, unknown>>;
    approval_required?: boolean;
    rollback_steps?: Array<Record<string, unknown>>;
    enabled?: boolean;
  }
): Promise<AutomationPlaybook> {
  return apiFetch(`/automation/playbooks/${playbook_id}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function triggerAutomationRuns(body: {
  trigger: string;
  payload?: Record<string, unknown>;
  playbook_ids?: number[];
}): Promise<{ trigger: string; runs_created: number; items: AutomationRun[] }> {
  return apiFetch('/automation/runs/trigger', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function getAutomationRuns(params?: {
  status?: string;
  limit?: number;
}): Promise<{ items: AutomationRun[] }> {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/automation/runs${suffix ? `?${suffix}` : ''}`);
}

export async function getAutomationRun(run_id: number): Promise<AutomationRun> {
  return apiFetch(`/automation/runs/${run_id}`);
}

export async function getAutomationApprovals(params?: {
  limit?: number;
}): Promise<{ items: AutomationApproval[] }> {
  const query = new URLSearchParams();
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/automation/approvals${suffix ? `?${suffix}` : ''}`);
}

export async function approveAutomationApproval(
  approval_id: number,
  note?: string
): Promise<{
  approval: AutomationApproval;
  execution: Record<string, unknown>;
  run_status: string;
}> {
  return apiFetch(`/automation/approvals/${approval_id}/approve`, {
    method: 'POST',
    body: JSON.stringify({ note }),
  });
}

export async function rejectAutomationApproval(
  approval_id: number,
  note?: string
): Promise<{ approval: AutomationApproval; run_status: string }> {
  return apiFetch(`/automation/approvals/${approval_id}/reject`, {
    method: 'POST',
    body: JSON.stringify({ note }),
  });
}

export async function getAutomationRollbacks(params?: {
  status?: string;
  limit?: number;
}): Promise<{ items: AutomationRollback[] }> {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/automation/rollbacks${suffix ? `?${suffix}` : ''}`);
}

export async function executeAutomationRollback(
  rollback_id: number
): Promise<{ rollback: Record<string, unknown>; run_status: string }> {
  return apiFetch(`/automation/rollbacks/${rollback_id}/execute`, {
    method: 'POST',
  });
}

export type AttackSurfaceDiscoveryRun = {
  run_id: number;
  status: 'running' | 'done' | 'failed' | string;
  requested_by?: string | null;
  source_job_id?: number | null;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  metadata_json?: Record<string, unknown>;
  summary_json?: Record<string, unknown>;
};

export type AttackSurfaceHost = {
  host_id: number;
  run_id: number;
  asset_key?: string | null;
  hostname: string;
  ip_address?: string | null;
  internet_exposed: boolean;
  source?: string | null;
  discovered_at?: string | null;
};

export type AttackSurfaceService = {
  service_id: number;
  run_id: number;
  host_id: number;
  asset_key?: string | null;
  hostname?: string | null;
  port: number;
  protocol?: string | null;
  service_name?: string | null;
  service_version?: string | null;
  discovered_at?: string | null;
};

export type AttackSurfaceCertificate = {
  cert_id: number;
  run_id: number;
  host_id: number;
  asset_key?: string | null;
  hostname?: string | null;
  common_name?: string | null;
  issuer?: string | null;
  serial_number?: string | null;
  fingerprint_sha256?: string | null;
  not_before?: string | null;
  not_after?: string | null;
  discovered_at?: string | null;
};

export type AttackSurfaceExposure = {
  asset_key: string;
  asset_name?: string | null;
  environment?: string | null;
  criticality?: string | null;
  run_id?: number | null;
  internet_exposed: boolean;
  open_port_count: number;
  open_management_ports: string[];
  service_risk: number;
  exposure_score: number;
  exposure_level: 'critical' | 'high' | 'medium' | 'low' | string;
  details_json?: Record<string, unknown>;
  updated_at?: string | null;
};

export type AttackSurfaceDriftEvent = {
  event_id: number;
  run_id: number;
  event_type: 'new_host' | 'new_port' | 'new_subdomain' | 'unexpected_cert_change' | string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info' | string;
  asset_key?: string | null;
  hostname?: string | null;
  domain?: string | null;
  port?: number | null;
  details_json?: Record<string, unknown>;
  created_at?: string | null;
};

export type AttackSurfaceRelationship = {
  relationship_id: number;
  source_asset_key: string;
  target_asset_key: string;
  relation_type: string;
  confidence: number;
  details_json?: Record<string, unknown>;
  updated_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

export async function runAttackSurfaceDiscovery(body?: {
  domains?: string[];
  cert_salt?: string;
}): Promise<{
  run_id: number;
  status: string;
  requested_by?: string;
  source_job_id?: number | null;
  summary: Record<string, unknown>;
}> {
  return apiFetch('/attack-surface/discovery/run', {
    method: 'POST',
    body: JSON.stringify(body ?? {}),
  });
}

export async function getAttackSurfaceDiscoveryRuns(params?: {
  status?: string;
  limit?: number;
}): Promise<{ items: AttackSurfaceDiscoveryRun[] }> {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/attack-surface/discovery/runs${suffix ? `?${suffix}` : ''}`);
}

export async function getAttackSurfaceDiscoveryRun(
  run_id: number
): Promise<AttackSurfaceDiscoveryRun> {
  return apiFetch(`/attack-surface/discovery/runs/${run_id}`);
}

export async function getAttackSurfaceHosts(params?: {
  run_id?: number;
  limit?: number;
}): Promise<{ run_id: number | null; items: AttackSurfaceHost[] }> {
  const query = new URLSearchParams();
  if (params?.run_id != null) query.set('run_id', String(params.run_id));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/attack-surface/discovery/hosts${suffix ? `?${suffix}` : ''}`);
}

export async function getAttackSurfaceServices(params?: {
  run_id?: number;
  limit?: number;
}): Promise<{ run_id: number | null; items: AttackSurfaceService[] }> {
  const query = new URLSearchParams();
  if (params?.run_id != null) query.set('run_id', String(params.run_id));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/attack-surface/discovery/services${suffix ? `?${suffix}` : ''}`);
}

export async function getAttackSurfaceCertificates(params?: {
  run_id?: number;
  limit?: number;
}): Promise<{ run_id: number | null; items: AttackSurfaceCertificate[] }> {
  const query = new URLSearchParams();
  if (params?.run_id != null) query.set('run_id', String(params.run_id));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/attack-surface/discovery/certs${suffix ? `?${suffix}` : ''}`);
}

export async function getAttackSurfaceExposures(params?: {
  limit?: number;
}): Promise<{ items: AttackSurfaceExposure[] }> {
  const query = new URLSearchParams();
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/attack-surface/exposures${suffix ? `?${suffix}` : ''}`);
}

export async function getAttackSurfaceDrift(params?: {
  run_id?: number;
  event_type?: string;
  limit?: number;
}): Promise<{ items: AttackSurfaceDriftEvent[] }> {
  const query = new URLSearchParams();
  if (params?.run_id != null) query.set('run_id', String(params.run_id));
  if (params?.event_type) query.set('event_type', params.event_type);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/attack-surface/drift${suffix ? `?${suffix}` : ''}`);
}

export async function getAttackSurfaceRelationships(params?: {
  asset_key?: string;
  limit?: number;
}): Promise<{ items: AttackSurfaceRelationship[] }> {
  const query = new URLSearchParams();
  if (params?.asset_key) query.set('asset_key', params.asset_key);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/attack-surface/relationships${suffix ? `?${suffix}` : ''}`);
}

export async function upsertAttackSurfaceRelationship(body: {
  source_asset_key: string;
  target_asset_key: string;
  relation_type: string;
  confidence?: number;
  details?: Record<string, unknown>;
}): Promise<AttackSurfaceRelationship> {
  return apiFetch('/attack-surface/relationships', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export type AttackGraphNode = {
  id: string;
  type: string;
  label: string;
  metadata?: Record<string, unknown>;
};

export type AttackGraphEdge = {
  id: string;
  source: string;
  target: string;
  relation: string;
  weight?: number;
  first_seen?: string | null;
  last_seen?: string | null;
  metadata?: Record<string, unknown>;
};

export type AttackGraph = {
  nodes: AttackGraphNode[];
  edges: AttackGraphEdge[];
  kill_chain: Array<{ phase: string; count: number }>;
  summary: Record<string, unknown>;
};

export async function getAttackGraphIncident(
  incident_id: number,
  lookback_hours: number = 72
): Promise<AttackGraph> {
  return apiFetch(`/attack-graph/incidents/${incident_id}?lookback_hours=${lookback_hours}`);
}

export async function queryAttackGraph(body: {
  incident_id?: number;
  asset_key?: string;
  lookback_hours?: number;
}): Promise<AttackGraph> {
  return apiFetch('/attack-graph/query', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export type AIAlertGuidance = {
  asset_key: string;
  guidance_text: string;
  recommended_action?: 'ack' | 'suppress' | 'assign' | 'escalate' | 'resolve' | 'monitor' | null;
  urgency?: 'critical' | 'high' | 'medium' | 'low' | null;
  provider: string;
  model: string;
  generated_by?: string | null;
  generated_at: string;
  context_signature?: string;
  context_json?: Record<string, unknown>;
  cached?: boolean;
  stale?: boolean;
};

export async function getAlertAIGuidance(assetKey: string): Promise<AIAlertGuidance> {
  return apiFetch<AIAlertGuidance>(`/ai/alerts/${encodeURIComponent(assetKey)}/guidance`);
}

export async function generateAlertAIGuidance(
  assetKey: string,
  force: boolean = false
): Promise<AIAlertGuidance> {
  return apiFetch<AIAlertGuidance>(`/ai/alerts/${encodeURIComponent(assetKey)}/guidance/generate`, {
    method: 'POST',
    body: JSON.stringify({ force }),
  });
}

export type AssetMetadata = {
  asset_id: number;
  asset_key: string;
  type: string;
  name: string;
  owner?: string | null;
  owner_team?: string | null;
  owner_email?: string | null;
  environment?: string | null;
  criticality?: string | null;
};

export async function getAssetByKey(assetKey: string): Promise<AssetMetadata> {
  return apiFetch<AssetMetadata>(`/assets/by-key/${encodeURIComponent(assetKey)}`);
}

export async function updateAssetByKey(
  assetKey: string,
  body: { owner?: string; criticality?: string; name?: string; environment?: string }
): Promise<AssetMetadata> {
  return apiFetch<AssetMetadata>(`/assets/by-key/${encodeURIComponent(assetKey)}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

/** Download posture as CSV using the current cookie-backed session. */
export async function downloadPostureCsv(): Promise<void> {
  await downloadFromApi(API + '/posture?format=csv', 'secplat-posture.csv');
}

// Findings (Phase A.2: lifecycle + risk acceptance)
export type FindingStatus = 'open' | 'in_progress' | 'remediated' | 'accepted_risk';

export type Finding = {
  finding_id: number;
  finding_key: string | null;
  asset_id: number | null;
  asset_key: string | null;
  asset_name: string | null;
  first_seen: string | null;
  last_seen: string | null;
  status: string;
  source: string | null;
  category: string | null;
  title: string;
  severity: string;
  confidence: string;
  evidence: string | null;
  remediation: string | null;
  vulnerability_id?: string | null;
  package_ecosystem?: string | null;
  package_name?: string | null;
  package_version?: string | null;
  fixed_version?: string | null;
  scanner_metadata_json?: Record<string, unknown> | null;
  risk_score?: number | null;
  risk_level?: 'critical' | 'high' | 'medium' | 'low' | null;
  risk_factors_json?: Record<string, unknown> | null;
  risk_label?: 'incident_worthy' | 'benign' | null;
  risk_label_source?: string | null;
  risk_label_created_at?: string | null;
  risk_label_created_by?: string | null;
  accepted_risk_at?: string | null;
  accepted_risk_expires_at?: string | null;
  accepted_risk_reason?: string | null;
  accepted_risk_by?: string | null;
};

export type FindingRiskLabel = {
  id: number;
  finding_id: number;
  label: 'incident_worthy' | 'benign';
  source: string;
  note?: string | null;
  created_by?: string | null;
  created_at: string;
};

export type FindingsFilters = {
  status?: string | null;
  source?: string | null;
  risk_level?: 'critical' | 'high' | 'medium' | 'low' | 'unscored' | null;
  asset_key?: string | null;
  limit?: number;
};

export async function getFindings(filters?: FindingsFilters): Promise<Finding[]> {
  const p = new URLSearchParams();
  if (filters?.status) p.set('status', filters.status);
  if (filters?.source) p.set('source', filters.source);
  if (filters?.risk_level) p.set('risk_level', filters.risk_level);
  if (filters?.asset_key) p.set('asset_key', filters.asset_key);
  if (filters?.limit != null) p.set('limit', String(filters.limit));
  const q = p.toString();
  return apiFetch<Finding[]>('/findings/' + (q ? `?${q}` : ''));
}

export type RepositorySourceSummary = {
  source: string;
  label: string;
  total: number;
  open: number;
  in_progress: number;
  accepted_risk: number;
  remediated: number;
  by_severity: Record<string, number>;
  by_category: Record<string, number>;
};

export type RepositoryRecentFinding = {
  finding_id: number;
  finding_key: string | null;
  source: string | null;
  category: string | null;
  title: string;
  severity: string;
  status: FindingStatus;
  package_name?: string | null;
  package_version?: string | null;
  fixed_version?: string | null;
  vulnerability_id?: string | null;
  risk_score?: number | null;
  risk_level?: 'critical' | 'high' | 'medium' | 'low' | null;
  last_seen?: string | null;
};

export type RepositoryPackageSummary = {
  package_name: string;
  active_count: number;
  total_count: number;
  max_severity: string;
};

export type RepositoryScanSummary = {
  asset_key: string;
  asset_name?: string | null;
  asset_type?: string | null;
  environment?: string | null;
  criticality?: string | null;
  total_findings: number;
  open_findings: number;
  in_progress_findings: number;
  accepted_risk_findings: number;
  remediated_findings: number;
  sources: RepositorySourceSummary[];
  top_packages: RepositoryPackageSummary[];
  recent_findings: RepositoryRecentFinding[];
  latest_jobs: JobItem[];
};

export async function getRepositoryScanSummary(
  assetKey: string = 'secplat-repo'
): Promise<RepositoryScanSummary> {
  return apiFetch<RepositoryScanSummary>(
    `/findings/repository-summary?asset_key=${encodeURIComponent(assetKey)}`
  );
}

export type DependencyRiskSourceDistribution = {
  source: string;
  total: number;
  active: number;
  remediated: number;
  accepted_risk: number;
  by_severity: Record<string, number>;
};

export type DependencyRiskPackage = {
  package_name: string;
  package_ecosystem: string;
  active_count: number;
  total_count: number;
  max_risk_score: number;
  max_severity: string;
  last_seen?: string | null;
};

export type DependencyRiskRemediationItem = {
  finding_id: number;
  finding_key?: string | null;
  title: string;
  source?: string | null;
  status: FindingStatus;
  severity: string;
  vulnerability_id?: string | null;
  package_ecosystem?: string | null;
  package_name?: string | null;
  package_version?: string | null;
  fixed_version?: string | null;
  risk_score?: number | null;
  risk_level?: 'critical' | 'high' | 'medium' | 'low' | null;
  last_seen?: string | null;
};

export type DependencyRiskSummary = {
  asset_key: string;
  asset_name?: string | null;
  asset_type?: string | null;
  environment?: string | null;
  criticality?: string | null;
  total_findings: number;
  active_findings: number;
  remediated_findings: number;
  accepted_risk_findings: number;
  active_dependency_count: number;
  source_distribution: DependencyRiskSourceDistribution[];
  severity_distribution_active: Record<string, number>;
  ecosystem_distribution_active: Record<string, number>;
  dependency_distribution: DependencyRiskPackage[];
  remediation_queue: DependencyRiskRemediationItem[];
};

export async function getDependencyRiskSummary(
  assetKey: string = 'secplat-repo',
  remediationLimit: number = 20
): Promise<DependencyRiskSummary> {
  const query = new URLSearchParams({
    asset_key: assetKey,
    remediation_limit: String(remediationLimit),
  });
  return apiFetch<DependencyRiskSummary>(`/findings/dependency-risk?${query.toString()}`);
}

export type ThreatIntelSourceSummary = {
  source: string;
  feed_url?: string | null;
  indicator_count: number;
  by_type: { ip: number; domain: number };
  avg_confidence?: number;
  max_source_priority?: number;
  last_seen_at?: string | null;
};

export type ThreatIntelMatchedAsset = {
  asset_key: string;
  asset_name?: string | null;
  environment?: string | null;
  criticality?: string | null;
  match_count: number;
  indicators: string[];
  max_confidence?: number;
  campaign_tags?: string[];
};

export type ThreatIntelRecentIndicator = {
  source: string;
  indicator: string;
  indicator_type: 'ip' | 'domain';
  confidence_score?: number;
  confidence_label?: 'high' | 'medium' | 'low';
  campaign_tag?: string | null;
  last_match_count?: number;
  last_seen_at?: string | null;
};

export type ThreatIntelCampaign = {
  campaign_id: number;
  campaign_tag: string;
  title: string;
  description?: string | null;
  confidence_weight: number;
  source_priority: number;
  confidence_label: 'high' | 'medium' | 'low';
  is_active: boolean;
  ioc_count: number;
  matched_asset_count: number;
  updated_at?: string | null;
};

export type ThreatIntelSighting = {
  sighting_id: number;
  ioc_id: number;
  source: string;
  indicator: string;
  indicator_type: 'ip' | 'domain';
  confidence_score: number;
  confidence_label: 'high' | 'medium' | 'low';
  campaign_tag?: string | null;
  asset_key: string;
  asset_name?: string | null;
  match_field: string;
  matched_value: string;
  source_event_id?: number | null;
  source_event_ref?: string | null;
  source_tool?: string | null;
  last_match_count?: number;
  sighted_at: string;
};

export type ThreatIntelAssetMatch = {
  asset_key: string;
  asset_name?: string | null;
  match_field: string;
  matched_value: string;
  source: string;
  indicator: string;
  indicator_type: 'ip' | 'domain';
  last_seen_at?: string | null;
};

export type ThreatIntelAssetMatches = {
  asset_key: string;
  total: number;
  items: ThreatIntelAssetMatch[];
};

export type ThreatIntelSummary = {
  total_indicators: number;
  high_confidence_indicators?: number;
  source_count: number;
  total_asset_matches: number;
  matched_asset_count: number;
  campaign_count?: number;
  last_refreshed_at?: string | null;
  sources: ThreatIntelSourceSummary[];
  matched_assets: ThreatIntelMatchedAsset[];
  recent_indicators: ThreatIntelRecentIndicator[];
  top_sightings?: ThreatIntelSighting[];
  campaigns?: ThreatIntelCampaign[];
  latest_jobs: JobItem[];
};

export async function getThreatIntelSummary(): Promise<ThreatIntelSummary> {
  return apiFetch<ThreatIntelSummary>('/threat-intel/summary');
}

export async function getThreatIntelAssetMatches(
  assetKey: string
): Promise<ThreatIntelAssetMatches> {
  return apiFetch<ThreatIntelAssetMatches>(
    `/threat-intel/assets/${encodeURIComponent(assetKey)}`
  );
}

export async function getThreatIntelIOCs(params?: {
  q?: string;
  source?: string;
  indicator_type?: 'ip' | 'domain';
  campaign_tag?: string;
  min_confidence?: number;
  active_only?: boolean;
  limit?: number;
}): Promise<{ items: Array<Record<string, unknown>> }> {
  const query = new URLSearchParams();
  if (params?.q) query.set('q', params.q);
  if (params?.source) query.set('source', params.source);
  if (params?.indicator_type) query.set('indicator_type', params.indicator_type);
  if (params?.campaign_tag) query.set('campaign_tag', params.campaign_tag);
  if (params?.min_confidence != null) query.set('min_confidence', String(params.min_confidence));
  if (params?.active_only != null) query.set('active_only', String(params.active_only));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ items: Array<Record<string, unknown>> }>(
    `/threat-intel/iocs${suffix ? `?${suffix}` : ''}`
  );
}

export async function getThreatIntelSightings(params?: {
  asset_key?: string;
  source?: string;
  campaign_tag?: string;
  since_hours?: number;
  limit?: number;
}): Promise<{ items: ThreatIntelSighting[] }> {
  const query = new URLSearchParams();
  if (params?.asset_key) query.set('asset_key', params.asset_key);
  if (params?.source) query.set('source', params.source);
  if (params?.campaign_tag) query.set('campaign_tag', params.campaign_tag);
  if (params?.since_hours != null) query.set('since_hours', String(params.since_hours));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ items: ThreatIntelSighting[] }>(
    `/threat-intel/sightings${suffix ? `?${suffix}` : ''}`
  );
}

export type TelemetryEvent = {
  event_id: number;
  source: string;
  event_type: string;
  asset_id?: number | null;
  asset_key?: string | null;
  severity?: number | null;
  src_ip?: string | null;
  src_port?: number | null;
  dst_ip?: string | null;
  dst_port?: number | null;
  domain?: string | null;
  url?: string | null;
  protocol?: string | null;
  event_time?: string | null;
  ti_match?: boolean;
  ti_source?: string | null;
  mitre_techniques?: string[];
  anomaly_score?: number | null;
  payload_json?: Record<string, unknown>;
};

export type TelemetrySummary = {
  totals: {
    events: number;
    ti_matches: number;
    assets: number;
    sources: number;
  };
  sources: Array<{
    source: string;
    event_count: number;
    ti_matches: number;
    asset_count: number;
    last_event_at?: string | null;
    alerts: Record<string, number>;
  }>;
  recent_alerts: AlertItem[];
  latest_anomaly_scores: Array<{
    asset_key: string;
    anomaly_score: number;
    baseline_mean?: number | null;
    baseline_std?: number | null;
    current_value?: number | null;
    computed_at?: string | null;
  }>;
};

export async function getTelemetrySummary(): Promise<TelemetrySummary> {
  return apiFetch<TelemetrySummary>('/telemetry/summary');
}

export async function getTelemetryEvents(params?: {
  source?: string;
  asset_key?: string;
  ti_match?: boolean;
  limit?: number;
}): Promise<{ items: TelemetryEvent[] }> {
  const query = new URLSearchParams();
  if (params?.source) query.set('source', params.source);
  if (params?.asset_key) query.set('asset_key', params.asset_key);
  if (params?.ti_match != null) query.set('ti_match', params.ti_match ? 'true' : 'false');
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ items: TelemetryEvent[] }>(`/telemetry/events${suffix ? `?${suffix}` : ''}`);
}

export async function getTelemetryAssetLogs(
  assetKey: string,
  params?: { source?: string; limit?: number }
): Promise<{ asset_key: string; items: TelemetryEvent[] }> {
  const query = new URLSearchParams();
  if (params?.source) query.set('source', params.source);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ asset_key: string; items: TelemetryEvent[] }>(
    `/telemetry/assets/${encodeURIComponent(assetKey)}${suffix ? `?${suffix}` : ''}`
  );
}

export async function ingestTelemetry(body: {
  source: string;
  events: Array<Record<string, unknown>>;
  asset_key?: string;
  create_alerts?: boolean;
}): Promise<{
  ok: boolean;
  source: string;
  processed_events: number;
  alert_updates: number;
  ti_matches: number;
  ti_sources: Record<string, number>;
}> {
  return apiFetch('/telemetry/ingest', { method: 'POST', body: JSON.stringify(body) });
}

export type DetectionRule = {
  rule_id: number;
  name: string;
  description?: string | null;
  source?: string | null;
  rule_key?: string | null;
  version?: number | null;
  mitre_tactic?: string | null;
  mitre_technique?: string | null;
  parent_rule_id?: number | null;
  stage?: 'draft' | 'canary' | 'active' | string;
  rule_format: 'json' | 'yaml' | 'sigma';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  enabled: boolean;
  definition_yaml?: string | null;
  definition_json: Record<string, unknown>;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  last_tested_at?: string | null;
  last_test_matches?: number | null;
};

export type DetectionRun = {
  run_id: number;
  rule_id: number;
  rule_name: string;
  executed_by?: string | null;
  lookback_hours: number;
  status: 'running' | 'done' | 'failed';
  matches: number;
  run_mode?: 'test' | 'simulate' | 'scheduled' | string;
  trigger_source?: 'manual' | 'job' | 'scheduler' | string;
  schedule_ref?: string | null;
  create_alerts?: boolean;
  snapshot_hash?: string | null;
  snapshot_json?: Record<string, unknown>;
  rule_version?: number | null;
  rule_stage?: string | null;
  window_start?: string | null;
  window_end?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  results_json?: Record<string, unknown>;
};

export async function getDetectionRules(include_disabled: boolean = true): Promise<{ items: DetectionRule[] }> {
  const suffix = include_disabled ? '?include_disabled=true' : '';
  return apiFetch<{ items: DetectionRule[] }>(`/detections/rules${suffix}`);
}

export async function createDetectionRule(body: {
  name: string;
  description?: string | null;
  source?: string | null;
  rule_key?: string | null;
  version?: number;
  mitre_tactic?: string | null;
  mitre_technique?: string | null;
  parent_rule_id?: number | null;
  stage?: 'draft' | 'canary' | 'active';
  rule_format?: 'json' | 'yaml' | 'sigma';
  severity?: string;
  enabled?: boolean;
  definition_json?: Record<string, unknown>;
  definition_yaml?: string | null;
}): Promise<DetectionRule> {
  return apiFetch<DetectionRule>('/detections/rules', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function updateDetectionRule(
  ruleId: number,
  body: {
    description?: string | null;
    source?: string | null;
    rule_key?: string | null;
    version?: number | null;
    mitre_tactic?: string | null;
    mitre_technique?: string | null;
    parent_rule_id?: number | null;
    stage?: 'draft' | 'canary' | 'active' | null;
    rule_format?: 'json' | 'yaml' | 'sigma' | null;
    severity?: string | null;
    enabled?: boolean | null;
    definition_json?: Record<string, unknown>;
    definition_yaml?: string | null;
  }
): Promise<DetectionRule> {
  return apiFetch<DetectionRule>(`/detections/rules/${ruleId}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function cloneDetectionRule(ruleId: number): Promise<DetectionRule> {
  return apiFetch<DetectionRule>(`/detections/rules/${ruleId}/clone`, { method: 'POST' });
}

export async function testDetectionRule(
  ruleId: number,
  body?: { lookback_hours?: number; create_alerts?: boolean }
): Promise<{
  rule_id: number;
  run_id?: number | null;
  lookback_hours: number;
  candidate_events: number;
  matches: number;
  sample_matches: TelemetryEvent[];
  generated_alert?: AlertItem | null;
}> {
  return apiFetch(`/detections/rules/${ruleId}/test`, {
    method: 'POST',
    body: JSON.stringify(body ?? {}),
  });
}

export async function simulateDetectionRule(
  ruleId: number,
  body?: { lookback_hours?: number }
): Promise<{
  rule_id: number;
  run_id?: number | null;
  lookback_hours: number;
  run_mode: 'simulate' | string;
  trigger_source?: string;
  schedule_ref?: string | null;
  create_alerts?: boolean;
  candidate_events: number;
  matches: number;
  snapshot_hash?: string | null;
  snapshot_json?: Record<string, unknown>;
  sample_matches: TelemetryEvent[];
  generated_alert?: AlertItem | null;
}> {
  return apiFetch(`/detections/rules/${ruleId}/simulate`, {
    method: 'POST',
    body: JSON.stringify(body ?? {}),
  });
}

export async function getDetectionRuns(params?: {
  rule_id?: number;
  limit?: number;
}): Promise<{ items: DetectionRun[] }> {
  const query = new URLSearchParams();
  if (params?.rule_id != null) query.set('rule_id', String(params.rule_id));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ items: DetectionRun[] }>(`/detections/runs${suffix ? `?${suffix}` : ''}`);
}

export type DetectionMitreCoverage = {
  lookback_days: number;
  totals: {
    enabled_rules: number;
    mapped_rules: number;
    mapping_coverage_pct: number;
    covered_tactics: number;
    covered_techniques: number;
  };
  tactics: Array<{ mitre_tactic: string; rule_count: number }>;
  techniques: Array<{ mitre_technique: string; rule_count: number }>;
  top_detected_techniques: Array<{ mitre_technique: string; detections: number }>;
};

export async function getDetectionMitreCoverage(
  lookbackDays: number = 30
): Promise<DetectionMitreCoverage> {
  return apiFetch<DetectionMitreCoverage>(
    `/detections/coverage/mitre?lookback_days=${Math.max(1, Math.min(365, lookbackDays))}`
  );
}

export type AttackLabTask = {
  task_type: string;
  label: string;
  description: string;
};

export type AttackLabRun = {
  run_id: number;
  task_type: string;
  target_asset_id?: number | null;
  target_asset_key?: string | null;
  target?: string | null;
  status: 'queued' | 'running' | 'done' | 'failed';
  requested_by?: string | null;
  started_at?: string | null;
  finished_at?: string | null;
  error?: string | null;
  output_json?: Record<string, unknown>;
  created_at?: string | null;
};

export async function getAttackLabTasks(): Promise<{ items: AttackLabTask[] }> {
  return apiFetch<{ items: AttackLabTask[] }>('/attack-lab/tasks');
}

export async function runAttackLabTask(body: {
  task_type: string;
  target: string;
  asset_key?: string;
}): Promise<JobItem> {
  return apiFetch<JobItem>('/attack-lab/run', { method: 'POST', body: JSON.stringify(body) });
}

export async function runAttackLabAssetScan(body: {
  asset_key: string;
  task_type?: string;
}): Promise<JobItem> {
  return apiFetch<JobItem>('/attack-lab/scan-asset', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function getAttackLabRuns(params?: {
  status?: string;
  limit?: number;
}): Promise<{ items: AttackLabRun[] }> {
  const query = new URLSearchParams();
  if (params?.status) query.set('status', params.status);
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ items: AttackLabRun[] }>(`/attack-lab/runs${suffix ? `?${suffix}` : ''}`);
}

export type CyberRangeMission = {
  mission_id: string;
  title: string;
  description: string;
  asset_key: string;
  task_type: string;
  target: string;
  difficulty: 'beginner' | 'intermediate' | 'advanced' | string;
  focus: string;
  mitre_techniques: string[];
  asset?: {
    asset_key: string;
    name?: string | null;
    owner?: string | null;
    environment?: string | null;
    criticality?: string | null;
    asset_type?: string | null;
    verified?: boolean | null;
  } | null;
  asset_available: boolean;
  latest_job?: JobItem | null;
};

export async function getCyberRangeMissions(): Promise<{
  generated_at: string;
  items: CyberRangeMission[];
}> {
  return apiFetch('/cyber-range/missions');
}

export async function launchCyberRangeMission(missionId: string): Promise<{
  mission_id: string;
  job: JobItem;
}> {
  return apiFetch(`/cyber-range/missions/${encodeURIComponent(missionId)}/launch`, {
    method: 'POST',
  });
}

export async function updateFindingStatus(finding_id: number, status: FindingStatus): Promise<{ ok: boolean; finding_id: number; status: string }> {
  return apiFetch(`/findings/${finding_id}/status`, { method: 'PATCH', body: JSON.stringify({ status }) });
}

export async function acceptFindingRisk(
  finding_id: number,
  reason: string,
  expires_at: string
): Promise<{ ok: boolean; finding_id: number; status: string }> {
  return apiFetch(`/findings/${finding_id}/accept-risk`, {
    method: 'POST',
    body: JSON.stringify({ reason, expires_at }),
  });
}

export async function getFindingRiskLabels(
  finding_id: number
): Promise<{ items: FindingRiskLabel[] }> {
  return apiFetch(`/findings/${finding_id}/risk-labels`);
}

export async function createFindingRiskLabel(
  finding_id: number,
  body: { label: 'incident_worthy' | 'benign'; source?: string; note?: string | null }
): Promise<FindingRiskLabel> {
  return apiFetch(`/findings/${finding_id}/risk-labels`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export type RiskReadinessSummary = {
  total_findings: number;
  total_incidents: number;
  incident_linked_findings: number;
  total_labels: number;
  positive_labels: number;
  negative_labels: number;
  positive_ratio: number;
  positive_label_names: string[];
  labels_by_name: Record<string, number>;
  labels_by_source: Record<string, number>;
};

export type RiskReadinessCheck = {
  name: string;
  ok: boolean;
  current: number | string;
  required: number | string;
};

export type RiskModelStatus = {
  enabled: boolean;
  artifact_path: string;
  artifact_exists: boolean;
  artifact_loaded: boolean;
  current_scoring_mode: 'ml' | 'heuristic';
  scoring_signature: string;
  readiness: {
    status: 'ready' | 'not_ready';
    summary: RiskReadinessSummary;
    checks: RiskReadinessCheck[];
  };
  model_metadata?: {
    algorithm?: string;
    base_algorithm?: string;
    calibration_method?: string | null;
    calibration_folds?: number | null;
    target_name?: string;
    trained_at?: string;
    dataset_size?: number;
    feature_count?: number;
    train_auc?: number | null;
    test_auc?: number | null;
    train_accuracy?: number | null;
    test_accuracy?: number | null;
    train_accuracy_active_threshold?: number | null;
    test_accuracy_active_threshold?: number | null;
    brier_score?: number | null;
    recommended_threshold?: number | null;
    active_threshold?: number | null;
    threshold_source?: string | null;
    class_balance?: { positive: number; negative: number };
  } | null;
  latest_snapshot?: {
    id: number;
    created_at: string;
    event_type: 'train' | 'manual';
    threshold: number;
    f1?: number | null;
    auc?: number | null;
    drift_psi?: number | null;
  } | null;
};

export async function getRiskModelStatus(): Promise<RiskModelStatus> {
  return apiFetch('/ai/risk-scoring/status');
}

export async function bootstrapRiskModelLabels(): Promise<{
  inserted_positive: number;
  inserted_negative: number;
  inserted_total: number;
  summary: RiskReadinessSummary;
}> {
  return apiFetch('/ai/risk-scoring/bootstrap-labels', { method: 'POST' });
}

export async function trainRiskModel(body?: {
  random_state?: number;
  test_size?: number;
}): Promise<{
  artifact_path: string;
  artifact_exists: boolean;
  training_rows: number;
  rescored_findings?: number;
  snapshot_id?: number;
  metadata: NonNullable<RiskModelStatus['model_metadata']>;
}> {
  return apiFetch('/ai/risk-scoring/train', {
    method: 'POST',
    body: JSON.stringify(body ?? {}),
  });
}

export type RiskModelEvaluation = {
  artifact_path: string;
  trained_at?: string | null;
  threshold: number;
  recommended_threshold?: number | null;
  threshold_source?: string | null;
  labeled_evaluation: {
    rows: number;
    accuracy?: number | null;
    precision?: number | null;
    recall?: number | null;
    f1?: number | null;
    auc?: number | null;
    brier_score?: number | null;
    confusion_matrix: { tp: number; fp: number; tn: number; fn: number };
    label_counts: Record<string, number>;
    label_source_counts: Record<string, number>;
    prediction_buckets: Record<string, number>;
  };
  threshold_sweep: Array<{
    threshold: number;
    accuracy?: number | null;
    precision?: number | null;
    recall?: number | null;
    f1?: number | null;
    positive_predictions: number;
    confusion_matrix: { tp: number; fp: number; tn: number; fn: number };
  }>;
  calibration: {
    method?: string | null;
    brier_score?: number | null;
    bins: Array<{
      bucket: string;
      range_start: number;
      range_end: number;
      count: number;
      observed_positive_rate?: number | null;
      average_predicted_probability?: number | null;
    }>;
  };
  training_baseline: {
    dataset_size?: number | null;
    label_counts: Record<string, number>;
    label_source_counts: Record<string, number>;
    prediction_buckets: Record<string, number>;
    feature_distributions: Record<string, Record<string, number>>;
    test_auc?: number | null;
    test_accuracy?: number | null;
    test_accuracy_active_threshold?: number | null;
    recommended_threshold?: number | null;
    active_threshold?: number | null;
    threshold_source?: string | null;
    calibration_method?: string | null;
    brier_score?: number | null;
  };
  current_population: {
    total_findings: number;
    unlabeled_findings: number;
    predicted_positive_count: number;
    average_probability?: number | null;
    prediction_buckets: Record<string, number>;
    feature_distributions: Record<string, Record<string, number>>;
  };
  drift: {
    score_distribution_psi?: number | null;
    feature_shifts: Record<
      string,
      | {
          value: string;
          delta: number;
          training_share: number;
          current_share: number;
        }
      | null
    >;
    signals: Array<{
      metric: string;
      value: number;
      severity: 'low' | 'medium' | 'high';
      detail: string;
    }>;
  };
  review_queue: Array<{
    finding_id: number;
    finding_key?: string | null;
    title?: string | null;
    asset_key?: string | null;
    severity?: string | null;
    source?: string | null;
    predicted_probability: number;
    predicted_score: number;
    uncertainty: number;
    distance_from_threshold?: number;
    current_risk_score?: number | null;
    current_risk_level?: string | null;
  }>;
};

export async function getRiskModelEvaluation(
  params?: { threshold?: number; review_limit?: number }
): Promise<RiskModelEvaluation> {
  const query = new URLSearchParams();
  if (params?.threshold != null) query.set('threshold', String(params.threshold));
  if (params?.review_limit != null) query.set('review_limit', String(params.review_limit));
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return apiFetch(`/ai/risk-scoring/evaluation${suffix}`);
}

export async function setRiskModelThreshold(body: {
  threshold: number;
  source?: string;
}): Promise<{
  active_threshold: number;
  recommended_threshold?: number | null;
  threshold_source?: string | null;
  rescored_findings?: number;
  model_metadata?: NonNullable<RiskModelStatus['model_metadata']>;
}> {
  return apiFetch('/ai/risk-scoring/threshold', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export type RiskModelSnapshotSummary = {
  id: number;
  created_at: string;
  created_by?: string | null;
  event_type: 'train' | 'manual';
  model_signature?: string | null;
  artifact_path: string;
  threshold: number;
  recommended_threshold?: number | null;
  dataset_size?: number | null;
  positive_labels?: number | null;
  negative_labels?: number | null;
  accuracy?: number | null;
  precision?: number | null;
  recall?: number | null;
  f1?: number | null;
  auc?: number | null;
  brier_score?: number | null;
  test_auc?: number | null;
  drift_psi?: number | null;
};

export type RiskModelSnapshotDetail = RiskModelSnapshotSummary & {
  summary_json: RiskModelEvaluation;
};

export async function listRiskModelSnapshots(
  params?: { limit?: number }
): Promise<{ items: RiskModelSnapshotSummary[] }> {
  const query = new URLSearchParams();
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString() ? `?${query.toString()}` : '';
  return apiFetch(`/ai/risk-scoring/snapshots${suffix}`);
}

export async function createRiskModelSnapshot(body?: {
  threshold?: number;
}): Promise<{
  snapshot_id: number;
  created_at: string;
  event_type: 'train' | 'manual';
  threshold: number;
  recommended_threshold?: number | null;
  evaluation: RiskModelEvaluation;
}> {
  return apiFetch('/ai/risk-scoring/snapshots', {
    method: 'POST',
    body: JSON.stringify(body ?? {}),
  });
}

export async function getRiskModelSnapshot(
  snapshot_id: number
): Promise<RiskModelSnapshotDetail> {
  return apiFetch(`/ai/risk-scoring/snapshots/${snapshot_id}`);
}

// Incidents (Phase A.1)
export type IncidentSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IncidentStatus = 'new' | 'triaged' | 'contained' | 'resolved' | 'closed';

export type IncidentListItem = {
  id: number;
  title: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  assigned_to: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
  closed_at: string | null;
  sla_due_at: string | null;
  alert_count?: number;
};

export type IncidentAlertLink = {
  incident_id: number;
  asset_key: string;
  added_at: string;
  added_by: string | null;
};

export type IncidentTimelineEntry = {
  id: number | string;
  incident_id: number;
  event_type:
    | 'note'
    | 'state_change'
    | 'alert_added'
    | 'resolution'
    | 'checklist_added'
    | 'checklist_done'
    | 'decision'
    | 'evidence_linked'
    | 'alert_activity'
    | 'finding_activity'
    | 'telemetry_event'
    | 'job_activity'
    | 'job_linked'
    | 'automation_action'
    | 'response_rollback';
  author: string | null;
  body: string | null;
  details: Record<string, unknown>;
  created_at: string;
  source_type?:
    | 'note'
    | 'checklist'
    | 'decision'
    | 'evidence'
    | 'alert'
    | 'finding'
    | 'log'
    | 'job'
    | 'automation'
    | 'response'
    | string;
};

export type IncidentEvidenceItem = {
  evidence_id: number;
  incident_id: number;
  evidence_type: 'alert' | 'finding' | 'asset' | 'job' | 'ticket' | 'note' | 'event' | 'other';
  ref_id: string;
  relation: string;
  summary?: string | null;
  details: Record<string, unknown>;
  added_by?: string | null;
  created_at: string;
};

export type Incident = IncidentListItem & {
  metadata?: Record<string, unknown>;
  alerts: IncidentAlertLink[];
  timeline: IncidentTimelineEntry[];
  evidence?: IncidentEvidenceItem[];
  watchers?: IncidentWatcherItem[];
  checklist?: IncidentChecklistItem[];
  decisions?: IncidentDecisionItem[];
  linked_risk?: {
    asset_count: number;
    finding_count: number;
    active_finding_count: number;
    top_risk_score?: number | null;
    top_risk_level?: 'critical' | 'high' | 'medium' | 'low' | null;
    items: Finding[];
  };
};

export type IncidentsListResponse = { total: number; items: IncidentListItem[] };

export type CreateIncidentBody = {
  title: string;
  severity?: IncidentSeverity;
  assigned_to?: string | null;
  sla_due_at?: string | null;
  asset_keys?: string[] | null;
};

export async function getIncidents(params?: {
  status?: string;
  severity?: string;
  assigned_to?: string;
  limit?: number;
  offset?: number;
}): Promise<IncidentsListResponse> {
  const p = new URLSearchParams();
  if (params?.status) p.set('status', params.status);
  if (params?.severity) p.set('severity', params.severity);
  if (params?.assigned_to) p.set('assigned_to', params.assigned_to);
  if (params?.limit != null) p.set('limit', String(params.limit));
  if (params?.offset != null) p.set('offset', String(params.offset));
  const q = p.toString();
  return apiFetch<IncidentsListResponse>('/incidents' + (q ? `?${q}` : ''));
}

export async function getIncident(id: number): Promise<Incident> {
  return apiFetch<Incident>(`/incidents/${id}`);
}

export async function createIncident(body: CreateIncidentBody): Promise<IncidentListItem> {
  return apiFetch<IncidentListItem>('/incidents', { method: 'POST', body: JSON.stringify(body) });
}

export async function updateIncidentStatus(id: number, status: IncidentStatus): Promise<IncidentListItem> {
  return apiFetch<IncidentListItem>(`/incidents/${id}/status`, {
    method: 'PATCH',
    body: JSON.stringify({ status }),
  });
}

export async function addIncidentNote(id: number, body: string): Promise<IncidentTimelineEntry> {
  return apiFetch<IncidentTimelineEntry>(`/incidents/${id}/notes`, {
    method: 'POST',
    body: JSON.stringify({ body }),
  });
}

export async function linkIncidentAlert(id: number, asset_key: string): Promise<IncidentAlertLink & { message?: string }> {
  return apiFetch(`/incidents/${id}/alerts`, {
    method: 'POST',
    body: JSON.stringify({ asset_key }),
  });
}

export async function unlinkIncidentAlert(id: number, asset_key: string): Promise<{ ok: boolean }> {
  return apiFetch(`/incidents/${id}/alerts?asset_key=${encodeURIComponent(asset_key)}`, { method: 'DELETE' });
}

export type IncidentWatcherItem = {
  incident_id: number;
  username: string;
  added_by?: string | null;
  added_at: string;
};

export type IncidentChecklistItem = {
  item_id: number;
  incident_id: number;
  title: string;
  done: boolean;
  done_by?: string | null;
  done_at?: string | null;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
};

export type IncidentDecisionItem = {
  decision_id: number;
  incident_id: number;
  decision: string;
  rationale?: string | null;
  decided_by?: string | null;
  details: Record<string, unknown>;
  created_at: string;
};

export async function getIncidentTimeline(
  id: number,
  params?: {
    source_type?: string;
    event_type?: string;
    lookback_hours?: number;
    limit?: number;
  }
): Promise<{ items: IncidentTimelineEntry[] }> {
  const query = new URLSearchParams();
  if (params?.source_type) query.set('source_type', params.source_type);
  if (params?.event_type) query.set('event_type', params.event_type);
  if (params?.lookback_hours != null) query.set('lookback_hours', String(params.lookback_hours));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch(`/incidents/${id}/timeline${suffix ? `?${suffix}` : ''}`);
}

export async function getIncidentWatchers(id: number): Promise<{ items: IncidentWatcherItem[] }> {
  return apiFetch(`/incidents/${id}/watchers`);
}

export async function addIncidentWatcher(
  id: number,
  username: string
): Promise<IncidentWatcherItem> {
  return apiFetch(`/incidents/${id}/watchers`, {
    method: 'POST',
    body: JSON.stringify({ username }),
  });
}

export async function removeIncidentWatcher(
  id: number,
  username: string
): Promise<{ ok: boolean }> {
  return apiFetch(`/incidents/${id}/watchers?username=${encodeURIComponent(username)}`, {
    method: 'DELETE',
  });
}

export async function getIncidentChecklist(
  id: number
): Promise<{ items: IncidentChecklistItem[] }> {
  return apiFetch(`/incidents/${id}/checklist`);
}

export async function addIncidentChecklistItem(
  id: number,
  title: string
): Promise<IncidentChecklistItem> {
  return apiFetch(`/incidents/${id}/checklist`, {
    method: 'POST',
    body: JSON.stringify({ title }),
  });
}

export async function updateIncidentChecklistItem(
  id: number,
  item_id: number,
  done: boolean
): Promise<IncidentChecklistItem> {
  return apiFetch(`/incidents/${id}/checklist/${item_id}`, {
    method: 'PATCH',
    body: JSON.stringify({ done }),
  });
}

export async function getIncidentDecisions(
  id: number
): Promise<{ items: IncidentDecisionItem[] }> {
  return apiFetch(`/incidents/${id}/decisions`);
}

export async function addIncidentDecision(
  id: number,
  body: { decision: string; rationale?: string | null; details?: Record<string, unknown> }
): Promise<IncidentDecisionItem> {
  return apiFetch(`/incidents/${id}/decisions`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function getIncidentEvidence(id: number): Promise<{ items: IncidentEvidenceItem[] }> {
  return apiFetch(`/incidents/${id}/evidence`);
}

export async function addIncidentEvidence(
  id: number,
  body: {
    evidence_type: IncidentEvidenceItem['evidence_type'];
    ref_id: string;
    relation?: string;
    summary?: string | null;
    details?: Record<string, unknown>;
  }
): Promise<IncidentEvidenceItem> {
  return apiFetch(`/incidents/${id}/evidence`, {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export type IncidentAutoRule = {
  auto_rule_id: number;
  name: string;
  description?: string | null;
  enabled: boolean;
  severity_threshold: IncidentSeverity;
  window_minutes: number;
  min_alerts: number;
  require_distinct_sources: boolean;
  incident_severity: IncidentSeverity;
  created_by?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
};

export async function listIncidentAutoRules(): Promise<{ items: IncidentAutoRule[] }> {
  return apiFetch('/incidents/auto-rules/list');
}

export async function createIncidentAutoRule(body: {
  name: string;
  description?: string | null;
  enabled?: boolean;
  severity_threshold?: IncidentSeverity;
  window_minutes?: number;
  min_alerts?: number;
  require_distinct_sources?: boolean;
  incident_severity?: IncidentSeverity;
}): Promise<IncidentAutoRule> {
  return apiFetch('/incidents/auto-rules/create', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function updateIncidentAutoRule(
  autoRuleId: number,
  body: {
    description?: string | null;
    enabled?: boolean;
    severity_threshold?: IncidentSeverity;
    window_minutes?: number;
    min_alerts?: number;
    require_distinct_sources?: boolean;
    incident_severity?: IncidentSeverity;
  }
): Promise<IncidentAutoRule> {
  return apiFetch(`/incidents/auto-rules/${autoRuleId}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
}

export async function runIncidentAutoRules(): Promise<{
  rules_evaluated: number;
  incidents_created: number;
  incident_ids: number[];
  triggered: Array<{
    auto_rule_id: number;
    incident_id: number;
    asset_key: string;
    alert_ids: number[];
    source_count: number;
  }>;
}> {
  return apiFetch('/incidents/auto-rules/run', { method: 'POST' });
}

export type CreateJiraResponse = { issue_key: string; url: string; message?: string };

export async function createIncidentJiraTicket(
  incidentId: number,
  projectKey?: string
): Promise<CreateJiraResponse> {
  return apiFetch<CreateJiraResponse>(`/incidents/${incidentId}/jira`, {
    method: 'POST',
    body: JSON.stringify(projectKey != null ? { project_key: projectKey } : {}),
  });
}

// AI enrichments (Phase AI-1)
export type AIIncidentSummary = {
  incident_id: number;
  summary_text: string;
  provider: string;
  model: string;
  generated_by?: string | null;
  generated_at: string;
  context_json?: Record<string, unknown>;
  cached?: boolean;
};

export async function getIncidentAISummary(incidentId: number): Promise<AIIncidentSummary> {
  return apiFetch<AIIncidentSummary>(`/ai/incidents/${incidentId}/summary`);
}

export async function generateIncidentAISummary(
  incidentId: number,
  force: boolean = false
): Promise<AIIncidentSummary> {
  return apiFetch<AIIncidentSummary>(`/ai/incidents/${incidentId}/summary/generate`, {
    method: 'POST',
    body: JSON.stringify({ force }),
  });
}

export type AISummaryEntityType =
  | 'incident'
  | 'policy_evaluation'
  | 'alert'
  | 'job'
  | 'asset'
  | 'finding';

export type AISummaryVersion = {
  version_id: number;
  entity_type: AISummaryEntityType;
  entity_key: string;
  version_no: number;
  content_text: string;
  provider?: string | null;
  model?: string | null;
  generated_by?: string | null;
  source_type?: string | null;
  context_json?: Record<string, unknown>;
  evidence_json?: Record<string, unknown>;
  created_at: string;
};

export type AISummaryVersionCompare = {
  entity_type: AISummaryEntityType;
  entity_key: string;
  from_version: number;
  to_version: number;
  word_delta: number;
  before_excerpt: string;
  after_excerpt: string;
};

export type AIFeedbackValue = 'up' | 'down';

export type AIFeedbackItem = {
  feedback_id: number;
  entity_type: AISummaryEntityType;
  entity_key: string;
  version_id?: number | null;
  feedback: AIFeedbackValue;
  comment?: string | null;
  context_json?: Record<string, unknown>;
  created_by?: string | null;
  created_at: string;
};

export async function listAISummaryVersions(
  entityType: AISummaryEntityType,
  entityId: string | number,
  limit: number = 50
): Promise<{ items: AISummaryVersion[] }> {
  return apiFetch<{ items: AISummaryVersion[] }>(
    `/ai/summaries/${encodeURIComponent(entityType)}/${encodeURIComponent(String(entityId))}/versions?limit=${limit}`
  );
}

export async function createAISummaryVersion(
  entityType: AISummaryEntityType,
  entityId: string | number,
  body: {
    content_text?: string | null;
    provider?: string | null;
    model?: string | null;
    source_type?: string;
    context_json?: Record<string, unknown>;
    evidence_json?: Record<string, unknown>;
  }
): Promise<AISummaryVersion> {
  return apiFetch<AISummaryVersion>(
    `/ai/summaries/${encodeURIComponent(entityType)}/${encodeURIComponent(String(entityId))}/versions`,
    {
      method: 'POST',
      body: JSON.stringify(body),
    }
  );
}

export async function compareAISummaryVersions(
  entityType: AISummaryEntityType,
  entityId: string | number,
  fromVersion: number,
  toVersion: number
): Promise<AISummaryVersionCompare> {
  const params = new URLSearchParams({
    from_version: String(fromVersion),
    to_version: String(toVersion),
  });
  return apiFetch<AISummaryVersionCompare>(
    `/ai/summaries/${encodeURIComponent(entityType)}/${encodeURIComponent(String(entityId))}/versions/compare?${params.toString()}`
  );
}

export async function createAIFeedback(body: {
  entity_type: AISummaryEntityType;
  entity_id: string | number;
  version_id?: number | null;
  feedback: AIFeedbackValue;
  comment?: string | null;
  context_json?: Record<string, unknown>;
}): Promise<AIFeedbackItem> {
  return apiFetch<AIFeedbackItem>('/ai/feedback', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function listAIFeedback(params?: {
  entity_type?: AISummaryEntityType;
  entity_id?: string | number;
  limit?: number;
}): Promise<{ items: AIFeedbackItem[] }> {
  const query = new URLSearchParams();
  if (params?.entity_type) query.set('entity_type', params.entity_type);
  if (params?.entity_id != null) query.set('entity_id', String(params.entity_id));
  if (params?.limit != null) query.set('limit', String(params.limit));
  const suffix = query.toString();
  return apiFetch<{ items: AIFeedbackItem[] }>(`/ai/feedback${suffix ? `?${suffix}` : ''}`);
}

export async function getAIFeedback(feedbackId: number): Promise<AIFeedbackItem> {
  return apiFetch<AIFeedbackItem>(`/ai/feedback/${feedbackId}`);
}

export type AIPolicyEvaluationSummary = {
  evaluation_id: number;
  summary_text: string;
  provider: string;
  model: string;
  generated_by?: string | null;
  generated_at: string;
  context_json?: Record<string, unknown>;
  cached?: boolean;
};

export async function getPolicyEvaluationAISummary(
  evaluationId: number
): Promise<AIPolicyEvaluationSummary> {
  return apiFetch<AIPolicyEvaluationSummary>(`/ai/policy/evaluations/${evaluationId}/summary`);
}

export async function generatePolicyEvaluationAISummary(
  evaluationId: number,
  force: boolean = false
): Promise<AIPolicyEvaluationSummary> {
  return apiFetch<AIPolicyEvaluationSummary>(
    `/ai/policy/evaluations/${evaluationId}/summary/generate`,
    {
      method: 'POST',
      body: JSON.stringify({ force }),
    }
  );
}

export type AIAssetDiagnosis = {
  asset_key: string;
  diagnosis_text: string;
  provider: string;
  model: string;
  generated_by?: string | null;
  generated_at: string;
  context_json?: Record<string, unknown>;
  cached?: boolean;
};

export async function getAssetAIDiagnosis(assetKey: string): Promise<AIAssetDiagnosis> {
  return apiFetch<AIAssetDiagnosis>(`/ai/assets/${encodeURIComponent(assetKey)}/diagnosis`);
}

export async function generateAssetAIDiagnosis(
  assetKey: string,
  force: boolean = false
): Promise<AIAssetDiagnosis> {
  return apiFetch<AIAssetDiagnosis>(`/ai/assets/${encodeURIComponent(assetKey)}/diagnose`, {
    method: 'POST',
    body: JSON.stringify({ force }),
  });
}

export type AIFindingExplanation = {
  finding_id: number;
  explanation_text: string;
  remediation_patch?: string | null;
  provider: string;
  model: string;
  generated_by?: string | null;
  generated_at: string;
  context_json?: Record<string, unknown>;
  cached?: boolean;
};

export async function getFindingAIExplanation(findingId: number): Promise<AIFindingExplanation> {
  return apiFetch<AIFindingExplanation>(`/ai/findings/${findingId}/explanation`);
}

export async function generateFindingAIExplanation(
  findingId: number,
  force: boolean = false
): Promise<AIFindingExplanation> {
  return apiFetch<AIFindingExplanation>(`/ai/findings/${findingId}/explain`, {
    method: 'POST',
    body: JSON.stringify({ force }),
  });
}

export type PostureAnomaly = {
  id?: number;
  detected_at?: string;
  metric: string;
  severity: 'low' | 'medium' | 'high';
  current_value: number;
  baseline_mean: number;
  baseline_std: number;
  z_score: number | null;
  window_size: number;
  context_json?: Record<string, unknown>;
};

export async function listPostureAnomalies(limit: number = 20): Promise<{ items: PostureAnomaly[] }> {
  return apiFetch<{ items: PostureAnomaly[] }>(`/ai/posture/anomalies?limit=${limit}`);
}

export async function detectPostureAnomalies(persist: boolean = true): Promise<{
  detected_at: string;
  detected: number;
  persisted: number;
  items: PostureAnomaly[];
}> {
  return apiFetch(`/ai/posture/anomalies/detect`, {
    method: 'POST',
    body: JSON.stringify({ persist }),
  });
}
