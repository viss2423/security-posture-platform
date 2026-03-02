'use client';

const GRAFANA_URL = process.env.NEXT_PUBLIC_GRAFANA_URL || 'http://localhost:3001';

export default function DashboardsPage() {
  const embedUrl = `${GRAFANA_URL}/d/afbkybzs8bzeof/secplat-asset-posture?kiosk`;
  return (
    <main className="flex h-[calc(100vh-4rem)] flex-col animate-in">
      <iframe
        src={embedUrl}
        title="SecPlat Posture Dashboard"
        className="flex-1 w-full border-0 rounded-b-2xl"
      />
    </main>
  );
}
