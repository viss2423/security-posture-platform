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

async function downloadFromApi(url: string, filename: string): Promise<void> {
  const res = await fetch(url, { cache: 'no-store' });
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

  const res = await fetch(API + path, {
    ...options,
    headers,
    cache: options?.cache ?? 'no-store',
  });
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
  last_seen_at?: string | null;
};

export type ThreatIntelMatchedAsset = {
  asset_key: string;
  asset_name?: string | null;
  environment?: string | null;
  criticality?: string | null;
  match_count: number;
  indicators: string[];
};

export type ThreatIntelRecentIndicator = {
  source: string;
  indicator: string;
  indicator_type: 'ip' | 'domain';
  last_seen_at?: string | null;
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
  source_count: number;
  total_asset_matches: number;
  matched_asset_count: number;
  last_refreshed_at?: string | null;
  sources: ThreatIntelSourceSummary[];
  matched_assets: ThreatIntelMatchedAsset[];
  recent_indicators: ThreatIntelRecentIndicator[];
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
  rule_format: 'json' | 'sigma';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  enabled: boolean;
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
  severity?: string;
  enabled?: boolean;
  definition_json: Record<string, unknown>;
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
    severity?: string | null;
    enabled?: boolean | null;
    definition_json?: Record<string, unknown>;
  }
): Promise<DetectionRule> {
  return apiFetch<DetectionRule>(`/detections/rules/${ruleId}`, {
    method: 'PATCH',
    body: JSON.stringify(body),
  });
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
  id: number;
  incident_id: number;
  event_type: 'note' | 'state_change' | 'alert_added' | 'resolution';
  author: string | null;
  body: string | null;
  details: Record<string, unknown>;
  created_at: string;
};

export type Incident = IncidentListItem & {
  metadata?: Record<string, unknown>;
  alerts: IncidentAlertLink[];
  timeline: IncidentTimelineEntry[];
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
