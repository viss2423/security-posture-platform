'use client';

import {
  Activity,
  Archive,
  BarChart2,
  Bell,
  BrainCircuit,
  Briefcase,
  Bug,
  Radar,
  Scale,
  ScrollText,
  Shield,
  ShieldAlert,
  Users,
  type LucideIcon,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useMemo } from 'react';
import { useAuth } from '@/contexts/AuthContext';
import { type PostureSummary } from '@/lib/api';
import { getActiveNavItem, getVisibleNavGroups, isActivePath, type NavIconKey } from '@/lib/navigation';
import { cn } from '@/lib/cn';

const ICONS: Record<NavIconKey, LucideIcon> = {
  activity: Activity,
  dashboard: BarChart2,
  assets: Archive,
  surface: Radar,
  graph: Radar,
  intel: Radar,
  telemetry: Activity,
  detections: ScrollText,
  automation: Briefcase,
  attack: ShieldAlert,
  range: Shield,
  findings: Bug,
  alerts: Bell,
  incidents: ShieldAlert,
  suppression: Shield,
  jobs: Briefcase,
  reports: BarChart2,
  policy: Scale,
  audit: ScrollText,
  users: Users,
  ml: BrainCircuit,
};

const QUICK_HREFS = ['/overview', '/assets', '/findings', '/alerts', '/incidents', '/reports'];

export default function WorkspaceRail({ summary }: { summary: PostureSummary | null }) {
  const pathname = usePathname();
  const { user } = useAuth();
  const role = user?.role ?? 'viewer';
  const groups = useMemo(() => getVisibleNavGroups(role), [role]);
  const active = useMemo(() => getActiveNavItem(pathname, role), [pathname, role]);

  const quickLinks = useMemo(
    () => groups.flatMap((g) => g.items).filter((i) => QUICK_HREFS.includes(i.href)),
    [groups]
  );

  const score =
    summary?.posture_score_avg != null ? Math.round(Number(summary.posture_score_avg)) : null;
  const scoreColor =
    score == null ? 'var(--text-subtle)' :
    score >= 75 ? 'var(--green)' :
    score >= 50 ? 'var(--amber)' :
    'var(--red)';
  const scoreW = `${Math.max(4, Math.min(score ?? 0, 100))}%`;

  const green = summary?.green ?? 0;
  const amber = summary?.amber ?? 0;
  const red   = summary?.red   ?? 0;

  return (
    <aside className="hidden xl:block xl:w-64 xl:shrink-0">
      <div className="sticky top-6 space-y-3">

        {/* ── Posture score ─────────────────────────────── */}
        <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4">
          <p className="mb-3 text-[10px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
            Posture score
          </p>
          <div className="flex items-end justify-between gap-3">
            <span
              className="text-4xl font-bold tabular-nums leading-none"
              style={{ color: scoreColor }}
            >
              {score ?? '--'}
            </span>
            <div className="space-y-1.5 text-right">
              <div className="flex items-center justify-end gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--green)]" />
                <span className="text-xs tabular-nums text-[var(--text-muted)]">
                  {green} clear
                </span>
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--amber)]" />
                <span className="text-xs tabular-nums text-[var(--text-muted)]">
                  {amber} watch
                </span>
              </div>
              <div className="flex items-center justify-end gap-1.5">
                <span className="h-1.5 w-1.5 rounded-full bg-[var(--red)]" />
                <span className="text-xs tabular-nums text-[var(--text-muted)]">
                  {red} critical
                </span>
              </div>
            </div>
          </div>
          {/* Score bar */}
          <div className="mt-4 h-1 overflow-hidden rounded-full bg-[var(--surface-elevated)]">
            <div
              className="h-full rounded-full transition-all duration-700"
              style={{ width: scoreW, background: scoreColor }}
            />
          </div>
        </div>

        {/* ── Current page ──────────────────────────────── */}
        {active && (
          <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4">
            <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
              Current view
            </p>
            <p className="text-base font-semibold text-[var(--text)]">{active.label}</p>
            <p className="mt-1.5 text-xs leading-relaxed text-[var(--text-muted)]">
              {active.description}
            </p>
          </div>
        )}

        {/* ── Quick jump ────────────────────────────────── */}
        <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4">
          <p className="mb-3 text-[10px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
            Quick jump
          </p>
          <div className="space-y-0.5">
            {quickLinks.map((item) => {
              const Icon = ICONS[item.icon];
              const isActive = isActivePath(pathname, item.href);
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={cn(
                    'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium transition-colors',
                    isActive
                      ? 'bg-[var(--accent-dim)] text-[var(--accent)]'
                      : 'text-[var(--text-muted)] hover:bg-white/[0.05] hover:text-[var(--text)]'
                  )}
                >
                  <Icon size={13} className="shrink-0 opacity-70" />
                  {item.label}
                  {isActive && (
                    <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--accent)]" />
                  )}
                </Link>
              );
            })}
          </div>
        </div>

        {/* ── User context ──────────────────────────────── */}
        <div className="rounded-lg border border-[var(--border)] bg-[var(--surface)] p-4">
          <p className="mb-2 text-[10px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
            Signed in as
          </p>
          <div className="flex items-center gap-2.5">
            <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-[var(--surface-soft)] text-[11px] font-bold uppercase text-[var(--text-muted)]">
              {(user?.username ?? 'U').charAt(0)}
            </span>
            <div className="min-w-0">
              <p className="truncate text-sm font-medium text-[var(--text)]">
                {user?.username ?? 'operator'}
              </p>
              <p className="text-[10px] uppercase tracking-widest text-[var(--text-subtle)]">
                {user?.role ?? 'viewer'}
              </p>
            </div>
          </div>
          <p className="mt-3 text-xs leading-relaxed text-[var(--text-subtle)]">
            Tip: press <kbd className="rounded border border-[var(--border)] bg-[var(--surface-soft)] px-1 py-0.5 text-[10px] font-mono text-[var(--text-muted)]">1</kbd>–<kbd className="rounded border border-[var(--border)] bg-[var(--surface-soft)] px-1 py-0.5 text-[10px] font-mono text-[var(--text-muted)]">4</kbd> to open nav groups, <kbd className="rounded border border-[var(--border)] bg-[var(--surface-soft)] px-1 py-0.5 text-[10px] font-mono text-[var(--text-muted)]">Ctrl K</kbd> to search.
          </p>
        </div>

      </div>
    </aside>
  );
}
