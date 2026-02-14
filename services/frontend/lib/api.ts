const API = '/api';

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return localStorage.getItem('secplat_token');
}

export async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(API + path, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(token && { Authorization: `Bearer ${token}` }),
      ...options?.headers,
    },
  });
  if (res.status === 401) {
    localStorage.removeItem('secplat_token');
    if (typeof window !== 'undefined') window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    const text = await res.text();
    let msg = text || res.statusText;
    if (res.status === 502) {
      try {
        const j = JSON.parse(text);
        if (j?.error) msg = j.error;
      } catch {
        msg = 'API unreachable';
      }
    }
    throw new Error(msg);
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
  const res = await fetch(API + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password }),
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
  return JSON.parse(text);
}

export function setToken(token: string) {
  localStorage.setItem('secplat_token', token);
}

export function logout() {
  localStorage.removeItem('secplat_token');
  localStorage.removeItem('secplat_role');
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
  const token = getToken();
  const url = snapshotId != null
    ? `${API}/posture/reports/executive.pdf?snapshot_id=${snapshotId}`
    : `${API}/posture/reports/executive.pdf`;
  const res = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401) {
    localStorage.removeItem('secplat_token');
    if (typeof window !== 'undefined') window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error(await res.text() || 'Download failed');
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'secplat-executive.pdf';
  a.click();
  URL.revokeObjectURL(a.href);
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

export type PolicyEvaluateResult = {
  bundle_id: number;
  bundle_name: string;
  score: number;
  rules: { id: string; name: string; type: string; passed: number; failed: number; total: number; pass_pct: number }[];
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

export async function deletePolicyBundle(id: number): Promise<{ ok: boolean }> {
  return apiFetch(`/policy/bundles/${id}`, { method: 'DELETE' });
}

// Jobs (Phase B.3)
export type JobItem = {
  job_id: number;
  job_type: string;
  target_asset_id: number | null;
  requested_by: string | null;
  status: string;
  created_at: string | null;
  started_at: string | null;
  finished_at: string | null;
  error: string | null;
  retry_count?: number;
};

export type JobDetail = JobItem & { log_output: string | null };

export async function getJobs(status?: string): Promise<{ items: JobItem[] }> {
  const q = status ? `?status=${encodeURIComponent(status)}&limit=100` : '?limit=100';
  return apiFetch<{ items: JobItem[] }>(`/jobs${q}`);
}

export async function getJob(id: number): Promise<JobDetail> {
  return apiFetch<JobDetail>(`/jobs/${id}`);
}

export async function createJob(payload: { job_type: string; target_asset_id?: number; requested_by?: string }): Promise<JobItem> {
  return apiFetch<JobItem>('/jobs', { method: 'POST', body: JSON.stringify(payload) });
}

export async function retryJob(id: number): Promise<{ ok: boolean; status: string }> {
  return apiFetch(`/jobs/${id}/retry`, { method: 'POST' });
}

export type AlertItem = {
  asset_key: string;
  state?: string;
  ack_reason?: string | null;
  acked_by?: string | null;
  acked_at?: string | null;
  suppressed_until?: string | null;
  assigned_to?: string | null;
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

export async function postAlertAck(asset_key: string, reason?: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/ack', {
    method: 'POST',
    body: JSON.stringify({ asset_key, reason }),
  });
}

export async function postAlertSuppress(asset_key: string, until_iso: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/suppress', {
    method: 'POST',
    body: JSON.stringify({ asset_key, until_iso }),
  });
}

export async function postAlertResolve(asset_key: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/resolve', {
    method: 'POST',
    body: JSON.stringify({ asset_key }),
  });
}

export async function postAlertAssign(asset_key: string, assigned_to: string): Promise<{ ok: boolean }> {
  return apiFetch<{ ok: boolean }>('/alerts/assign', {
    method: 'POST',
    body: JSON.stringify({ asset_key, assigned_to }),
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

/** Download posture as CSV (uses token from localStorage). */
export async function downloadPostureCsv(): Promise<void> {
  const token = getToken();
  const res = await fetch(API + '/posture?format=csv', {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (res.status === 401) {
    localStorage.removeItem('secplat_token');
    if (typeof window !== 'undefined') window.location.href = '/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) throw new Error(await res.text() || 'Download failed');
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'secplat-posture.csv';
  a.click();
  URL.revokeObjectURL(url);
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
  accepted_risk_at?: string | null;
  accepted_risk_expires_at?: string | null;
  accepted_risk_reason?: string | null;
  accepted_risk_by?: string | null;
};

export type FindingsFilters = {
  status?: string | null;
  source?: string | null;
  asset_key?: string | null;
  limit?: number;
};

export async function getFindings(filters?: FindingsFilters): Promise<Finding[]> {
  const p = new URLSearchParams();
  if (filters?.status) p.set('status', filters.status);
  if (filters?.source) p.set('source', filters.source);
  if (filters?.asset_key) p.set('asset_key', filters.asset_key);
  if (filters?.limit != null) p.set('limit', String(filters.limit));
  const q = p.toString();
  return apiFetch<Finding[]>('/findings' + (q ? `?${q}` : ''));
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
