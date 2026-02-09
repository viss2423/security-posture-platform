const API = '/api';

function getToken(): string | null {
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
  if (!res.ok) throw new Error(await res.text() || res.statusText);
  return res.json();
}

export async function login(username: string, password: string): Promise<{ access_token: string }> {
  const res = await fetch(API + '/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ username, password }),
  });
  if (!res.ok) throw new Error(await res.text() || 'Login failed');
  return res.json();
}

export function setToken(token: string) {
  localStorage.setItem('secplat_token', token);
}

export function logout() {
  localStorage.removeItem('secplat_token');
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

export async function getPostureSummary(): Promise<PostureSummary> {
  return apiFetch<PostureSummary>('/posture/summary');
}

export async function getPostureList(): Promise<{ total: number; items: AssetPosture[] }> {
  return apiFetch<{ total: number; items: AssetPosture[] }>('/posture');
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
