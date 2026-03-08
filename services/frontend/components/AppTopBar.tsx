'use client';

import { ArrowRight, BriefcaseBusiness, Radar, Sparkles, Zap } from 'lucide-react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useAuth } from '@/contexts/AuthContext';
import { getActiveNavItem } from '@/lib/navigation';

const LazyCommandPalette = dynamic(() => import('@/components/CommandPalette'), {
  ssr: false,
  loading: () => (
    <button
      type="button"
      disabled
      className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-muted)] opacity-70"
    >
      Search
    </button>
  ),
});

function humanizeSegment(segment: string): string {
  return segment
    .replace(/\[|\]/g, '')
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function AppTopBar() {
  const pathname = usePathname();
  const { isAdmin, user } = useAuth();
  const active = getActiveNavItem(pathname, isAdmin);

  const parts = pathname.split('/').filter(Boolean);
  const breadcrumb = parts.map((segment, index) => {
    const href = `/${parts.slice(0, index + 1).join('/')}`;
    return { href, label: humanizeSegment(segment) };
  });

  return (
    <header className="mb-5">
      <div className="relative overflow-hidden rounded-3xl border border-[var(--border)] bg-[linear-gradient(168deg,rgba(15,31,50,0.96),rgba(8,19,34,0.9))] shadow-[0_28px_52px_-34px_rgba(0,0,0,0.95)] backdrop-blur-xl">
        <div className="pointer-events-none absolute -left-16 top-8 h-40 w-40 rounded-full bg-cyan-300/16 blur-3xl" />
        <div className="pointer-events-none absolute right-0 top-0 h-48 w-48 rounded-full bg-emerald-300/12 blur-3xl" />
        <div className="pointer-events-none absolute inset-x-10 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />

        <div className="relative border-b border-[var(--border)]/75 bg-gradient-to-r from-cyan-300/[0.16] via-transparent to-emerald-300/[0.14] px-4 py-2.5 sm:px-6">
          <div className="flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
            <span className="inline-flex items-center gap-2 rounded-full border border-cyan-300/35 bg-cyan-300/12 px-2.5 py-1 font-semibold uppercase tracking-[0.14em] text-cyan-100">
              <Sparkles size={12} />
              {active?.label ?? 'Workspace'}
            </span>
            {breadcrumb.map((item, index) => (
              <span key={item.href} className="inline-flex items-center gap-2">
                {index > 0 && <ArrowRight size={11} className="text-[var(--muted)]/80" />}
                <span>{item.label}</span>
              </span>
            ))}
          </div>
        </div>

        <div className="relative flex flex-wrap items-start justify-between gap-4 px-4 py-5 sm:px-6">
          <div className="min-w-0">
            <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-cyan-300/30 bg-cyan-300/10 px-3 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-100">
              <Radar size={11} />
              Security Operations Grid
            </div>
            <h2 className="mt-1 [font-family:var(--font-display)] text-[2rem] font-semibold tracking-tight text-[var(--text)] sm:text-[2.35rem]">
              {active?.label ?? 'Security Workspace'}
            </h2>
            <p className="mt-2 max-w-3xl text-sm leading-6 text-[var(--text-muted)]">
              {active?.description ??
                'Operate, govern, and report posture with enterprise-grade controls.'}
            </p>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <span className="stat-chip">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-300" />
                Telemetry stream online
              </span>
              <span className="stat-chip">
                <Zap size={12} className="text-cyan-100" />
                Low-latency command path
              </span>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <LazyCommandPalette isAdmin={isAdmin} />
            <Link
              href="/incidents"
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3.5 py-2 text-sm text-[var(--text-muted)] transition hover:border-cyan-300/40 hover:bg-cyan-300/[0.08] hover:text-[var(--text)]"
            >
              <BriefcaseBusiness size={14} />
              Incident Desk
            </Link>
            <div className="hidden rounded-xl border border-[var(--border)] bg-[linear-gradient(165deg,rgba(13,30,48,0.92),rgba(8,19,33,0.84))] px-3 py-2 text-right shadow-inner shadow-black/25 sm:block">
              <p className="text-[11px] uppercase tracking-[0.14em] text-[var(--muted)]">
                {user?.role || 'viewer'}
              </p>
              <p className="max-w-[11rem] truncate text-sm font-medium text-[var(--text)]">
                {user?.username || 'Analyst'}
              </p>
            </div>
          </div>
        </div>
      </div>
    </header>
  );
}
