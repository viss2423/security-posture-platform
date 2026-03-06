'use client';

import {
  Activity,
  Archive,
  BarChart3,
  Bell,
  BrainCircuit,
  Briefcase,
  Bug,
  ChevronRight,
  FileText,
  Gamepad2,
  LogOut,
  Menu,
  Radar,
  Scale,
  ScrollText,
  Shield,
  ShieldAlert,
  Users,
  X,
  type LucideIcon,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useMemo, useState } from 'react';
import { logout, type PostureSummary } from '@/lib/api';
import { cn } from '@/lib/cn';
import {
  getVisibleNavGroups,
  isActivePath,
  type NavGroup,
  type NavIconKey,
} from '@/lib/navigation';
import { useAuth } from '@/contexts/AuthContext';

const ICONS: Record<NavIconKey, LucideIcon> = {
  activity: Activity,
  dashboard: BarChart3,
  assets: Archive,
  intel: Radar,
  telemetry: Activity,
  detections: ScrollText,
  attack: ShieldAlert,
  range: Gamepad2,
  findings: Bug,
  alerts: Bell,
  incidents: ShieldAlert,
  suppression: Shield,
  jobs: Briefcase,
  reports: FileText,
  policy: Scale,
  audit: ScrollText,
  users: Users,
  ml: BrainCircuit,
};

function Brand({ compact = false }: { compact?: boolean }) {
  return (
    <Link
      href="/overview"
      className="flex items-center gap-3 rounded-2xl px-2 py-1.5 text-[var(--text)] transition hover:bg-white/[0.03]"
    >
      <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-300 to-teal-300 text-sm font-black text-slate-950 shadow-[0_10px_30px_rgba(52,211,153,0.18)]">
        SP
      </span>
      {!compact && (
        <span className="flex flex-col">
          <span className="[font-family:var(--font-display)] text-sm font-semibold uppercase tracking-[0.08em] text-[var(--text)]">SecPlat</span>
          <span className="text-xs tracking-[0.06em] text-[var(--muted)]">Security operations</span>
        </span>
      )}
    </Link>
  );
}

function PulseCard({ summary }: { summary: PostureSummary | null }) {
  const score = summary?.posture_score_avg != null ? Math.round(Number(summary.posture_score_avg)) : null;

  return (
    <div className="rounded-2xl border border-[var(--border)] bg-white/[0.025] p-3.5">
      <div className="flex items-center justify-between gap-3">
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--muted)]">Operational pulse</p>
          <div className="mt-2 flex items-end gap-3">
            <p className="[font-family:var(--font-display)] text-4xl font-semibold leading-none text-[var(--text)]">{score ?? '--'}</p>
            <div className="pb-1 text-xs text-[var(--muted)]">Posture score</div>
          </div>
        </div>
        <span className="rounded-full border border-emerald-400/20 bg-emerald-400/10 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-emerald-300">
          Live
        </span>
      </div>
      <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-[var(--surface)]">
        <div
          className="h-full rounded-full bg-gradient-to-r from-emerald-400 to-teal-300 transition-all"
          style={{ width: `${Math.max(6, Math.min(100, score ?? 6))}%` }}
        />
      </div>
      <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)]/92 p-2.5">
          <p className="text-[var(--muted)]">Green</p>
          <p className="mt-1 font-semibold text-emerald-300">{summary?.green ?? '--'}</p>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)]/92 p-2.5">
          <p className="text-[var(--muted)]">Amber</p>
          <p className="mt-1 font-semibold text-amber-300">{summary?.amber ?? '--'}</p>
        </div>
        <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)]/92 p-2.5">
          <p className="text-[var(--muted)]">Red</p>
          <p className="mt-1 font-semibold text-rose-300">{summary?.red ?? '--'}</p>
        </div>
      </div>
    </div>
  );
}

function SidebarPanel({
  pathname,
  groups,
  username,
  role,
  summary,
  onSignOut,
  onNavigate,
}: {
  pathname: string;
  groups: NavGroup[];
  username?: string;
  role?: string;
  summary: PostureSummary | null;
  onSignOut: () => void | Promise<void>;
  onNavigate?: () => void;
}) {
  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-[var(--border)]/80 p-4">
        <Brand />
      </div>
      <div className="space-y-4 border-b border-[var(--border)]/80 px-3 py-4">
        <PulseCard summary={summary} />
      </div>
      <div className="flex-1 space-y-5 overflow-y-auto px-3 py-4">
        {groups.map((group) => (
          <section key={group.title}>
            <h2 className="px-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">{group.title}</h2>
            <div className="mt-2 space-y-1">
              {group.items.map((item) => {
                const Icon = ICONS[item.icon];
                const active = isActivePath(pathname, item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={onNavigate}
                    className={cn(
                      'group flex items-center gap-3 rounded-xl px-3 py-2 text-sm font-medium transition',
                      active
                        ? 'bg-emerald-400/[0.08] text-[var(--text)] ring-1 ring-emerald-400/18'
                        : 'text-[var(--text-muted)] hover:bg-white/[0.035] hover:text-[var(--text)]'
                    )}
                  >
                    <Icon
                      size={16}
                      className={cn(
                        'shrink-0 transition',
                        active ? 'text-[var(--green)]' : 'text-[var(--muted)] group-hover:text-[var(--text)]'
                      )}
                    />
                    <span className="flex-1 truncate">{item.label}</span>
                    <ChevronRight
                      size={14}
                      className={cn('transition', active ? 'text-[var(--green)]' : 'text-[var(--muted)]/70')}
                    />
                  </Link>
                );
              })}
            </div>
          </section>
        ))}
      </div>
      <div className="border-t border-[var(--border)]/80 p-4">
        <div className="mb-3 rounded-2xl border border-[var(--border)] bg-white/[0.03] px-3 py-3">
          <p className="truncate text-sm font-medium text-[var(--text)]">{username || 'Signed in'}</p>
          <p className="mt-1 text-[11px] uppercase tracking-[0.14em] text-[var(--muted)]">{role || 'viewer'}</p>
        </div>
        <button
          type="button"
          onClick={onSignOut}
          className="flex w-full items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2.5 text-sm font-medium text-[var(--text-muted)] transition hover:border-[var(--green)]/25 hover:bg-white/[0.025] hover:text-[var(--text)]"
        >
          <LogOut size={15} />
          Sign out
        </button>
      </div>
    </div>
  );
}

export default function Nav({ initialSummary }: { initialSummary: PostureSummary | null }) {
  const pathname = usePathname();
  const { isAdmin, user } = useAuth();
  const [mobileOpen, setMobileOpen] = useState(false);

  const visibleGroups = useMemo(() => getVisibleNavGroups(isAdmin), [isAdmin]);

  const handleSignOut = async () => {
    try {
      await logout();
    } finally {
      window.location.href = '/login';
    }
  };

  return (
    <>
      <div className="sticky top-2 z-40 mb-4 lg:hidden">
        <div className="rounded-2xl border border-[var(--border)] bg-[var(--surface)]/92 shadow-xl shadow-black/25 backdrop-blur-xl">
          <div className="flex items-center justify-between px-3 py-2.5">
            <Brand compact />
            <button
              type="button"
              aria-label="Open menu"
              onClick={() => setMobileOpen(true)}
              className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text)] transition hover:border-[var(--green)]/50"
            >
              <Menu size={18} />
            </button>
          </div>
        </div>
      </div>

      {mobileOpen && (
        <>
          <button
            type="button"
            aria-label="Close menu"
            onClick={() => setMobileOpen(false)}
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
          />
          <div className="fixed inset-y-0 left-0 z-[60] w-[min(88vw,22rem)] border-r border-[var(--border)] bg-[var(--surface)] shadow-2xl shadow-black/60 focus:outline-none lg:hidden">
            <button
              type="button"
              aria-label="Close menu"
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-3 inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text)]"
            >
              <X size={16} />
            </button>
            <SidebarPanel
              pathname={pathname}
              groups={visibleGroups}
              username={user?.username}
              role={user?.role}
              summary={initialSummary}
              onSignOut={handleSignOut}
              onNavigate={() => setMobileOpen(false)}
            />
          </div>
        </>
      )}

      <aside className="hidden lg:block lg:w-[17.5rem] lg:shrink-0">
        <div className="sticky top-4 h-[calc(100vh-2rem)] overflow-hidden rounded-[1.75rem] border border-[var(--border)] bg-[var(--surface)]/94 shadow-xl shadow-black/25 backdrop-blur-xl">
          <SidebarPanel
            pathname={pathname}
            groups={visibleGroups}
            username={user?.username}
            role={user?.role}
            summary={initialSummary}
            onSignOut={handleSignOut}
          />
        </div>
      </aside>
    </>
  );
}
