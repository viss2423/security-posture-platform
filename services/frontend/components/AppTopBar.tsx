'use client';

import {
  ArrowRight,
  BriefcaseBusiness,
  Check,
  Copy,
  Search,
  Sparkles,
} from 'lucide-react';
import dynamic from 'next/dynamic';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useMemo, useState } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/cn';
import { getActiveNavItem, getVisibleNavGroups } from '@/lib/navigation';

const LazyCommandPalette = dynamic(() => import('@/components/CommandPalette'), {
  ssr: false,
  loading: () => (
    <button
      type="button"
      disabled
      className="inline-flex items-center gap-2 rounded-[1rem] border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--text-muted)] opacity-70"
    >
      <Search size={15} />
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
  const { canMutate, user } = useAuth();
  const role = user?.role ?? 'viewer';
  const active = getActiveNavItem(pathname, role);
  const [copied, setCopied] = useState(false);

  const parts = pathname.split('/').filter(Boolean);
  const breadcrumb = parts.map((segment, index) => {
    const href = `/${parts.slice(0, index + 1).join('/')}`;
    return { href, label: humanizeSegment(segment) };
  });

  const commandRoutes = useMemo(
    () =>
      getVisibleNavGroups(role)
        .flatMap((group) => group.items)
        .slice(0, 5),
    [role]
  );

  useEffect(() => {
    if (!copied) return;
    const timeout = window.setTimeout(() => setCopied(false), 1600);
    return () => window.clearTimeout(timeout);
  }, [copied]);

  const handleCopyLink = async () => {
    try {
      await navigator.clipboard.writeText(window.location.href);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  };

  return (
    <header className="space-y-3">
      <section className="relative overflow-hidden rounded-[1.45rem] border border-[var(--border)] bg-[rgba(255,255,255,0.82)] px-4 py-3 shadow-[var(--shadow-soft)] backdrop-blur-xl">
        <div className="pointer-events-none absolute inset-x-8 top-0 h-px bg-gradient-to-r from-transparent via-cyan-200/28 to-transparent" />
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2 text-[11px] uppercase tracking-[0.16em] text-[var(--muted)]">
              <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-300/18 bg-cyan-300/08 px-2.5 py-1 font-semibold text-[var(--cyan-strong)]">
                <Sparkles size={10} />
                Live context
              </span>
              {breadcrumb.map((item, index) => (
                <span key={item.href} className="inline-flex items-center gap-2">
                  {index > 0 && <ArrowRight size={11} className="text-[var(--muted)]/80" />}
                  <span>{item.label}</span>
                </span>
              ))}
            </div>
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-2">
              <p className="text-xl font-semibold tracking-[-0.03em] text-[var(--text)]">
                {active?.label ?? 'Customer Platform'}
              </p>
              <p className="max-w-3xl text-sm leading-6 text-[var(--text-muted)]">
                {active?.description ??
                  'Track coverage, priorities, and outcomes from one customer-facing platform.'}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <LazyCommandPalette />
            <button
              type="button"
              onClick={handleCopyLink}
              className={cn(
                'inline-flex items-center gap-2 rounded-[1rem] border px-3 py-2 text-sm transition',
                copied
                  ? 'border-emerald-300/24 bg-emerald-300/10 text-[var(--green)]'
                  : 'border-[var(--border)] bg-white text-[var(--text-muted)] hover:border-cyan-300/18 hover:text-[var(--text)]'
              )}
            >
              {copied ? <Check size={14} /> : <Copy size={14} />}
              {copied ? 'Copied' : 'Copy link'}
            </button>
            {canMutate && (
              <Link
                href="/incidents"
                className="inline-flex items-center gap-2 rounded-[1rem] border border-[var(--border)] bg-white px-3 py-2 text-sm text-[var(--text-muted)] transition hover:border-cyan-300/18 hover:text-[var(--text)]"
              >
                <BriefcaseBusiness size={14} />
                Response center
              </Link>
            )}
            <div className="rounded-[1rem] border border-[var(--border)] bg-white px-3 py-2 text-right">
              <p className="text-[10px] uppercase tracking-[0.16em] text-[var(--muted)]">
                {user?.role || 'viewer'}
              </p>
              <p className="max-w-[10rem] truncate text-sm font-semibold text-[var(--text)]">
                {user?.username || 'Analyst'}
              </p>
            </div>
          </div>
        </div>
      </section>

      <section className="relative overflow-hidden rounded-[1.25rem] border border-[var(--border)] bg-[rgba(255,255,255,0.78)] px-4 py-3 shadow-[var(--shadow-soft)]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="inline-flex items-center gap-1.5 rounded-full border border-cyan-300/18 bg-cyan-300/08 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--cyan-strong)]">
            Popular pages
          </span>
          {commandRoutes.map((route) => (
            <Link
              key={route.href}
              href={route.href}
              className={cn(
                'inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs transition',
                pathname === route.href || pathname.startsWith(`${route.href}/`)
                  ? 'border-cyan-300/20 bg-cyan-300/08 text-[var(--cyan-strong)]'
                  : 'border-[var(--border)] bg-white/86 text-[var(--text-muted)] hover:border-cyan-300/18 hover:text-[var(--text)]'
              )}
            >
              {route.label}
            </Link>
          ))}
        </div>
      </section>
    </header>
  );
}
