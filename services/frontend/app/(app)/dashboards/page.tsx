'use client';

import { EmptyState } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';

const GRAFANA_URL = process.env.NEXT_PUBLIC_GRAFANA_URL || 'http://localhost:3001';

const DASHBOARD_SECTIONS = [
  {
    title: 'Asset Posture',
    description: 'Platform-wide security posture and health trend.',
    uid: 'afbkybzs8bzeof',
  },
  {
    title: 'Suricata IDS',
    description: 'Network IDS detections, signatures, and severity trends.',
    uid: 'secplat-suricata',
  },
  {
    title: 'Zeek Network Analytics',
    description: 'Protocol-level visibility for DNS, HTTP, and TLS context.',
    uid: 'secplat-zeek',
  },
  {
    title: 'Honeypot (Cowrie)',
    description: 'SSH/Telnet honeypot activity, brute-force attempts, and command telemetry.',
    uid: 'secplat-cowrie',
  },
];

export default function DashboardsPage() {
  const { canMutate } = useAuth();

  if (!canMutate) {
    return (
      <main className="page-shell space-y-6">
        <EmptyState
          title="Dashboards are limited to operator accounts"
          description="Viewer accounts stay on demo-scoped product tours and do not get direct access to live Grafana telemetry."
        />
      </main>
    );
  }

  return (
    <main className="page-shell space-y-6">
      <div>
        <h1 className="page-title">Dashboards</h1>
        <p className="mt-1 text-sm text-[var(--muted)]">
          Live Grafana dashboards for posture, IDS telemetry, network analytics, and honeypot data.
        </p>
      </div>
      {DASHBOARD_SECTIONS.map((section) => (
        <section key={section.uid} className="section-panel overflow-hidden p-0">
          <div className="border-b border-[var(--border)] px-5 py-4">
            <h2 className="section-title mb-1">{section.title}</h2>
            <p className="text-sm text-[var(--muted)]">{section.description}</p>
          </div>
          <iframe
            src={`${GRAFANA_URL}/d/${section.uid}?kiosk`}
            title={`${section.title} dashboard`}
            className="h-[32rem] w-full border-0"
          />
        </section>
      ))}
    </main>
  );
}
