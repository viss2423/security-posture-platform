'use client';

import { motion } from 'framer-motion';
import { ArrowRight, BriefcaseBusiness } from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import CommandPalette from '@/components/CommandPalette';
import { useAuth } from '@/contexts/AuthContext';
import { getActiveNavItem } from '@/lib/navigation';

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
    <motion.header
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.28, ease: 'easeOut' }}
      className="mb-4"
    >
      <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)]/92 px-4 py-4 shadow-lg shadow-black/15 backdrop-blur-xl sm:px-5 sm:py-4.5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-[var(--muted)]">
              <span className="inline-flex items-center gap-2 rounded-full border border-[var(--border)] bg-white/[0.03] px-2.5 py-1 font-semibold uppercase tracking-[0.14em] text-[var(--text-muted)]">
                {active?.label ?? 'Workspace'}
              </span>
              {breadcrumb.map((item, index) => (
                <span key={item.href} className="inline-flex items-center gap-2">
                  {index > 0 && <ArrowRight size={11} className="text-[var(--muted)]/80" />}
                  <span>{item.label}</span>
                </span>
              ))}
            </div>
            <h2 className="[font-family:var(--font-display)] text-[1.75rem] font-semibold tracking-tight text-[var(--text)]">
              {active?.label ?? 'Security Workspace'}
            </h2>
            <p className="mt-1 max-w-2xl text-sm text-[var(--text-muted)]">
              {active?.description ?? 'Operate, govern, and report posture with enterprise-grade controls.'}
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <CommandPalette isAdmin={isAdmin} />
            <Link
              href="/incidents"
              className="inline-flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-[var(--green)]/25 hover:bg-white/[0.03] hover:text-[var(--text)]"
            >
              <BriefcaseBusiness size={14} />
              Incident Desk
            </Link>
            <div className="hidden rounded-xl border border-[var(--border)] bg-white/[0.03] px-3 py-2 text-right sm:block">
              <p className="text-[11px] uppercase tracking-[0.14em] text-[var(--muted)]">{user?.role || 'viewer'}</p>
              <p className="max-w-[11rem] truncate text-sm font-medium text-[var(--text)]">{user?.username || 'Analyst'}</p>
            </div>
          </div>
        </div>
      </div>
    </motion.header>
  );
}
