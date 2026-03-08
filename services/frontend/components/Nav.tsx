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
  Cpu,
  FileText,
  Gamepad2,
  LogOut,
  Menu,
  Radar,
  Scale,
  ScrollText,
  Shield,
  ShieldAlert,
  Signal,
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
  surface: Radar,
  graph: Radar,
  intel: Radar,
  telemetry: Activity,
  detections: ScrollText,
  automation: Briefcase,
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
      className="group relative flex items-center gap-3 rounded-2xl border border-[var(--border)] bg-[linear-gradient(165deg,rgba(13,28,45,0.92),rgba(8,19,33,0.84))] px-2.5 py-2 transition duration-300 hover:border-cyan-300/45 hover:bg-[linear-gradient(165deg,rgba(14,34,55,0.94),rgba(8,19,33,0.88))]"
    >
      <span className="pointer-events-none absolute inset-x-4 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/70 to-transparent" />
      <span className="relative flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl border border-cyan-200/35 bg-[radial-gradient(circle_at_35%_25%,rgba(136,248,255,0.55),rgba(28,180,218,0.16)_58%,rgba(5,18,32,0.95)_100%)] text-sm font-black text-cyan-50 shadow-[0_14px_34px_-16px_rgba(50,215,255,0.85)]">
        <span className="absolute inset-0 rounded-2xl border border-cyan-100/20" />
        <span className="relative">SP</span>
      </span>
      {!compact && (
        <span className="flex min-w-0 flex-1 flex-col">
          <span className="[font-family:var(--font-display)] text-sm font-semibold uppercase tracking-[0.14em] text-[var(--text)]">
            SecPlat
          </span>
          <span className="truncate text-[11px] tracking-[0.12em] text-[var(--muted)]">
            Quantum SOC Console
          </span>
        </span>
      )}
      {!compact && (
        <span className="inline-flex items-center gap-1 rounded-full border border-cyan-300/35 bg-cyan-300/12 px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-100">
          <Signal size={10} />
          Sync
        </span>
      )}
    </Link>
  );
}

function PulseCard({ summary }: { summary: PostureSummary | null }) {
  const score = summary?.posture_score_avg != null ? Math.round(Number(summary.posture_score_avg)) : null;
  const scoreWidth = Math.max(6, Math.min(100, score ?? 6));

  return (
    <div className="relative overflow-hidden rounded-2xl border border-cyan-300/30 bg-[linear-gradient(170deg,rgba(14,31,51,0.96),rgba(9,20,36,0.88))] p-4 shadow-[0_18px_32px_-24px_rgba(50,215,255,0.72)]">
      <div className="pointer-events-none absolute -right-10 -top-14 h-28 w-28 rounded-full bg-cyan-300/20 blur-2xl" />
      <div className="pointer-events-none absolute -left-10 -bottom-12 h-24 w-24 rounded-full bg-emerald-300/15 blur-2xl" />
      <div className="relative">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-[var(--muted)]">
              Neural posture pulse
            </p>
            <div className="mt-2 flex items-end gap-3">
              <p className="[font-family:var(--font-display)] text-4xl font-semibold leading-none text-[var(--text)]">
                {score ?? '--'}
              </p>
              <div className="pb-1 text-xs text-[var(--muted)]">Score index</div>
            </div>
          </div>
          <span className="relative inline-flex h-8 items-center gap-2 rounded-full border border-emerald-300/35 bg-emerald-300/12 px-3 text-[10px] font-semibold uppercase tracking-[0.14em] text-emerald-100">
            <span className="relative h-2 w-2 rounded-full bg-emerald-300">
              <span className="absolute inset-0 rounded-full bg-emerald-300/70 animate-[pulse-ring_2s_ease-out_infinite]" />
            </span>
            Live
          </span>
        </div>

        <div className="mt-4 h-2 overflow-hidden rounded-full border border-cyan-300/25 bg-[var(--surface)]/95">
          <div
            className="h-full rounded-full bg-[linear-gradient(90deg,#32d7ff,#3ef3db,#9dff81)] transition-all duration-500"
            style={{ width: `${scoreWidth}%` }}
          />
        </div>

        <div className="mt-4 grid grid-cols-3 gap-2 text-xs">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)]/90 p-2.5 shadow-inner shadow-black/20">
            <p className="text-[var(--muted)]">Green</p>
            <p className="mt-1 font-semibold text-emerald-300">{summary?.green ?? '--'}</p>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)]/90 p-2.5 shadow-inner shadow-black/20">
            <p className="text-[var(--muted)]">Amber</p>
            <p className="mt-1 font-semibold text-amber-300">{summary?.amber ?? '--'}</p>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface)]/90 p-2.5 shadow-inner shadow-black/20">
            <p className="text-[var(--muted)]">Red</p>
            <p className="mt-1 font-semibold text-rose-300">{summary?.red ?? '--'}</p>
          </div>
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
    <div className="relative flex h-full flex-col overflow-hidden">
      <div className="pointer-events-none absolute -left-20 top-20 h-40 w-40 rounded-full bg-cyan-300/16 blur-3xl" />
      <div className="pointer-events-none absolute -right-12 bottom-24 h-36 w-36 rounded-full bg-emerald-300/14 blur-3xl" />

      <div className="relative border-b border-[var(--border)]/80 p-4">
        <Brand />
      </div>

      <div className="relative space-y-4 border-b border-[var(--border)]/80 px-3 py-4">
        <PulseCard summary={summary} />
      </div>

      <div className="relative flex-1 space-y-5 overflow-y-auto px-3 py-4">
        {groups.map((group) => (
          <section key={group.title}>
            <div className="mb-2 flex items-center gap-2 px-2">
              <span className="h-px flex-1 bg-gradient-to-r from-cyan-300/35 to-transparent" />
              <h2 className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[var(--muted)]">
                {group.title}
              </h2>
              <span className="h-px flex-1 bg-gradient-to-l from-emerald-300/35 to-transparent" />
            </div>
            <div className="space-y-1.5">
              {group.items.map((item) => {
                const Icon = ICONS[item.icon];
                const active = isActivePath(pathname, item.href);
                return (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={onNavigate}
                    className={cn(
                      'group relative flex items-center gap-3 overflow-hidden rounded-xl border px-3 py-2.5 text-sm font-medium transition duration-200',
                      active
                        ? 'border-cyan-300/45 bg-[linear-gradient(90deg,rgba(50,215,255,0.18),rgba(62,243,219,0.1))] text-[var(--text)] shadow-[0_12px_22px_-16px_rgba(50,215,255,0.75)]'
                        : 'border-transparent text-[var(--text-muted)] hover:border-cyan-300/20 hover:bg-cyan-300/[0.08] hover:text-[var(--text)]'
                    )}
                  >
                    <span
                      className={cn(
                        'absolute bottom-2 left-1 top-2 w-[2px] rounded-full transition',
                        active ? 'bg-[linear-gradient(180deg,#32d7ff,#3ef3db)]' : 'bg-transparent'
                      )}
                    />
                    <Icon
                      size={16}
                      className={cn(
                        'relative z-[1] shrink-0 transition',
                        active ? 'text-cyan-100' : 'text-[var(--muted)] group-hover:text-cyan-100'
                      )}
                    />
                    <span className="relative z-[1] flex-1 truncate">{item.label}</span>
                    <ChevronRight
                      size={14}
                      className={cn(
                        'relative z-[1] transition',
                        active ? 'translate-x-0.5 text-cyan-100' : 'text-[var(--muted)]/70'
                      )}
                    />
                  </Link>
                );
              })}
            </div>
          </section>
        ))}
      </div>

      <div className="relative border-t border-[var(--border)]/80 p-4">
        <div className="mb-3 rounded-2xl border border-[var(--border)] bg-[linear-gradient(165deg,rgba(14,30,47,0.92),rgba(8,19,34,0.82))] px-3 py-3">
          <div className="mb-2 inline-flex items-center gap-2 rounded-full border border-cyan-300/30 bg-cyan-300/12 px-2.5 py-1 text-[10px] font-semibold uppercase tracking-[0.14em] text-cyan-100">
            <Cpu size={10} />
            Operator
          </div>
          <p className="truncate text-sm font-medium text-[var(--text)]">{username || 'Signed in'}</p>
          <p className="mt-1 text-[11px] uppercase tracking-[0.14em] text-[var(--muted)]">{role || 'viewer'}</p>
        </div>
        <button
          type="button"
          onClick={onSignOut}
          className="flex w-full items-center justify-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2.5 text-sm font-medium text-[var(--text-muted)] transition hover:border-cyan-300/40 hover:bg-cyan-300/[0.08] hover:text-[var(--text)]"
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
      <div className="sticky top-2 z-40 mb-5 lg:hidden">
        <div className="overflow-hidden rounded-2xl border border-[var(--border)] bg-[linear-gradient(165deg,rgba(14,30,48,0.95),rgba(8,19,34,0.9))] shadow-[0_20px_30px_-24px_rgba(0,0,0,0.9)] backdrop-blur-xl">
          <div className="flex items-center justify-between px-3 py-2.5">
            <Brand compact />
            <button
              type="button"
              aria-label="Open menu"
              onClick={() => setMobileOpen(true)}
              className="inline-flex h-10 w-10 items-center justify-center rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text)] transition hover:border-cyan-300/55 hover:text-cyan-100"
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
            className="fixed inset-0 z-50 bg-[radial-gradient(circle_at_30%_20%,rgba(50,215,255,0.14),rgba(0,0,0,0.82))] backdrop-blur-md"
          />
          <div className="fixed inset-y-0 left-0 z-[60] w-[min(88vw,22rem)] border-r border-[var(--border)] bg-[linear-gradient(180deg,rgba(14,31,51,0.98),rgba(8,19,34,0.96))] shadow-[0_28px_48px_-22px_rgba(0,0,0,0.96)] focus:outline-none lg:hidden">
            <button
              type="button"
              aria-label="Close menu"
              onClick={() => setMobileOpen(false)}
              className="absolute right-3 top-3 inline-flex h-9 w-9 items-center justify-center rounded-lg border border-[var(--border)] bg-[var(--surface-elevated)] text-[var(--text)] transition hover:border-cyan-300/45"
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

      <aside className="hidden lg:block lg:w-[20rem] lg:shrink-0">
        <div className="relative sticky top-4 h-[calc(100vh-2rem)] overflow-hidden rounded-[1.75rem] border border-[var(--border)] bg-[linear-gradient(180deg,rgba(14,31,51,0.98),rgba(8,19,34,0.94))] shadow-[0_30px_58px_-34px_rgba(0,0,0,0.95)] backdrop-blur-xl">
          <div className="pointer-events-none absolute inset-x-5 top-0 h-px bg-gradient-to-r from-transparent via-cyan-300/65 to-transparent" />
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
