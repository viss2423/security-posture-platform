/**
 * Turn raw API error (often JSON body like {"detail":"..."}) into a user-friendly message.
 * When the API returns 404 or "Asset not found in posture index", the backend may be running
 * old code without the new routes — suggest restarting the API.
 */
export function friendlyApiMessage(raw: string): string {
  let detail: string | undefined;
  try {
    const o = JSON.parse(raw);
    detail = typeof o.detail === 'string' ? o.detail : undefined;
  } catch {
    detail = raw;
  }
  const d = (detail || raw).toLowerCase();
  if (d.includes('not found') && (d.includes('asset') || d.includes('posture index') || d === 'not found')) {
    return 'This page needs the latest API routes. Restart the API service (e.g. docker compose restart api or restart the API process), then refresh.';
  }
  if (d === 'not found' || raw.trim() === '{"detail":"Not Found"}') {
    return 'Endpoint not found. Restart the API service to load the latest routes, then refresh.';
  }
  return detail || raw;
}
