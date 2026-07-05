'use client';

import {
  Activity,
  Archive,
  BarChart2,
  Bell,
  BrainCircuit,
  Briefcase,
  Bug,
  CheckCircle,
  Compass,
  Gamepad2,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  Scale,
  ScrollText,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  Users,
  X,
  type LucideIcon,
} from 'lucide-react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useEffect, useMemo, useRef, useState } from 'react';
import CommandPalette from '@/components/CommandPalette';
import { useAuth } from '@/contexts/AuthContext';
import { cn } from '@/lib/cn';
import { logout, type PostureSummary } from '@/lib/api';
import {
  countAdvancedNavItems,
  getAllVisibleNavItems,
  getVisibleNavGroups,
  isActivePath,
  isPreviewNavItem,
  type NavIconKey,
  type NavItem,
} from '@/lib/navigation';

const ADVANCED_NAV_STORAGE_KEY = 'secplat-nav-advanced';

function AdvancedToggle({
  visible,
  count,
  onToggle,
}: {
  visible: boolean;
  count: number;
  onToggle: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-[12px] font-medium text-[var(--text-subtle)] transition-colors hover:bg-white/[0.05] hover:text-[var(--text-muted)]"
    >
      <Settings size={13} className="shrink-0 opacity-70" />
      {visible ? 'Hide advanced tools' : `Show advanced tools (${count})`}
    </button>
  );
}

/* ── Icon map ──────────────────────────────────────────────── */
const ICONS: Record<NavIconKey, LucideIcon> = {
  activity: Activity,
  dashboard: LayoutDashboard,
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
  reports: BarChart2,
  policy: Scale,
  audit: ScrollText,
  users: Users,
  ml: BrainCircuit,
};

/* One icon per nav group shown in the rail */
const GROUP_ICONS: Record<string, LucideIcon> = {
  'Start Here': Compass,
  'Operate':    Shield,
  'Assure':     CheckCircle,
  'Admin':      Settings,
};

/* ── Posture score ring ────────────────────────────────────── */
function ScoreRing({ score }: { score: number | string }) {
  const num = score === '--' ? null : Number(score);
  const valid = num != null && !isNaN(num);
  const r = 11;
  const circ = 2 * Math.PI * r;
  const fill = valid ? Math.max(0, Math.min(1, num! / 100)) * circ : 0;
  const color = !valid ? '#475569' : num! >= 75 ? '#4ade80' : num! >= 50 ? '#fbbf24' : '#f87171';

  return (
    <div className="relative inline-flex h-8 w-8 shrink-0 items-center justify-center">
      <svg width="32" height="32" viewBox="0 0 32 32" className="-rotate-90">
        <circle cx="16" cy="16" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="2.5" />
        {valid && (
          <circle
            cx="16" cy="16" r={r}
            fill="none"
            stroke={color}
            strokeWidth="2.5"
            strokeDasharray={`${fill} ${circ}`}
            strokeLinecap="round"
          />
        )}
      </svg>
      <span className="absolute text-[9px] font-bold tabular-nums leading-none" style={{ color }}>
        {score}
      </span>
    </div>
  );
}

/* ── Secondary panel nav item ──────────────────────────────── */
function PanelItem({
  item,
  active,
  preview,
  onClick,
}: {
  item: NavItem;
  active: boolean;
  preview?: boolean;
  onClick: () => void;
}) {
  const Icon = ICONS[item.icon];
  return (
    <Link
      href={item.href}
      onClick={onClick}
      className={cn(
        'group flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium transition-colors duration-100',
        active
          ? 'bg-[var(--accent-dim)] text-[var(--accent)]'
          : 'text-[var(--text-muted)] hover:bg-white/[0.05] hover:text-[var(--text)]'
      )}
    >
      <Icon size={14} className="shrink-0 opacity-70" />
      <span className="min-w-0 truncate">{item.label}</span>
      {preview && !active && (
        <span className="ml-auto shrink-0 rounded border border-[var(--border)] px-1 py-px text-[8px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
          Demo
        </span>
      )}
      {active && (
        <span className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--accent)]" />
      )}
    </Link>
  );
}

/* ── Rail icon button ──────────────────────────────────────── */
function RailBtn({
  icon: Icon,
  label,
  active,
  badge,
  shortcut,
  onClick,
}: {
  icon: LucideIcon;
  label: string;
  active: boolean;
  badge?: number;
  shortcut?: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      title={shortcut ? `${label} (${shortcut})` : label}
      onClick={onClick}
      className={cn(
        'group/rail relative flex h-9 w-9 items-center justify-center rounded-md transition-colors duration-100',
        active
          ? 'bg-[var(--accent-dim)] text-[var(--accent)]'
          : 'text-[var(--text-subtle)] hover:bg-white/[0.06] hover:text-[var(--text-muted)]'
      )}
    >
      {active && (
        <span className="absolute left-0 top-2 bottom-2 w-0.5 rounded-r-sm bg-[var(--accent)]" />
      )}
      <Icon size={16} />
      {badge != null && badge > 0 && (
        <span className="absolute -right-0.5 -top-0.5 flex h-3.5 min-w-[14px] items-center justify-center rounded-full bg-[var(--red)] px-0.5 text-[8px] font-bold leading-none text-white">
          {badge > 99 ? '99+' : badge}
        </span>
      )}
    </button>
  );
}

/* ── Main component ────────────────────────────────────────── */
export default function Nav({ initialSummary }: { initialSummary: PostureSummary | null }) {
  const pathname = usePathname();
  const { user } = useAuth();
  const role = user?.role ?? 'viewer';
  const [mobileOpen, setMobileOpen] = useState(false);
  const [expandedGroup, setExpandedGroup] = useState<string | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const panelRef = useRef<HTMLDivElement>(null);
  const panelBodyRef = useRef<HTMLDivElement>(null);

  /* Restore the advanced-tools preference (defaults off so new users see a focused nav) */
  useEffect(() => {
    try {
      if (window.localStorage.getItem(ADVANCED_NAV_STORAGE_KEY) === '1') setShowAdvanced(true);
    } catch {
      /* storage unavailable */
    }
  }, []);

  const toggleAdvanced = () => {
    setShowAdvanced((current) => {
      const next = !current;
      try {
        window.localStorage.setItem(ADVANCED_NAV_STORAGE_KEY, next ? '1' : '0');
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  };

  /* Never hide the page the user is currently on: force-reveal when on an advanced page */
  const onAdvancedPage = useMemo(
    () =>
      getAllVisibleNavItems(role).some(
        (item) => item.advanced && isActivePath(pathname, item.href)
      ),
    [pathname, role]
  );
  const advancedVisible = showAdvanced || onAdvancedPage;
  const advancedCount = useMemo(() => countAdvancedNavItems(role), [role]);
  const visibleGroups = useMemo(
    () => getVisibleNavGroups(role, advancedVisible),
    [advancedVisible, role]
  );

  const score =
    initialSummary?.posture_score_avg != null
      ? Math.round(Number(initialSummary.posture_score_avg))
      : '--';

  /* Close secondary panel on route change */
  useEffect(() => { setExpandedGroup(null); }, [pathname]);

  /* Close secondary panel on outside click (checks both rail and panel body) */
  useEffect(() => {
    if (!expandedGroup) return;
    function handle(e: MouseEvent) {
      const inRail = panelRef.current?.contains(e.target as Node);
      const inPanel = panelBodyRef.current?.contains(e.target as Node);
      if (!inRail && !inPanel) setExpandedGroup(null);
    }
    document.addEventListener('mousedown', handle);
    return () => document.removeEventListener('mousedown', handle);
  }, [expandedGroup]);

  /* Keyboard shortcuts: 1–4 toggle nav groups, Escape closes panel */
  useEffect(() => {
    function handle(e: KeyboardEvent) {
      const target = e.target as HTMLElement;
      if (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable) return;
      if (e.key === 'Escape') { setExpandedGroup(null); return; }
      const idx = parseInt(e.key, 10) - 1;
      if (idx >= 0 && idx < visibleGroups.length && !e.ctrlKey && !e.metaKey && !e.altKey) {
        e.preventDefault();
        setExpandedGroup((prev) => (prev === visibleGroups[idx].title ? null : visibleGroups[idx].title));
      }
    }
    window.addEventListener('keydown', handle);
    return () => window.removeEventListener('keydown', handle);
  }, [visibleGroups]);

  const toggleGroup = (title: string) =>
    setExpandedGroup((prev) => (prev === title ? null : title));

  const openSearch = () =>
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', ctrlKey: true, bubbles: true }));

  const handleSignOut = async () => {
    try { await logout(); } finally { window.location.href = '/login'; }
  };

  const selectedGroup = visibleGroups.find((g) => g.title === expandedGroup);

  return (
    <>
      {/* ── Desktop icon rail (fixed 48px) ─────────────────── */}
      <div
        ref={panelRef}
        className="fixed inset-y-0 left-0 z-40 hidden w-12 flex-col items-center border-r border-[var(--border)] bg-[var(--surface)] py-3 lg:flex"
      >
        {/* Logo */}
        <Link
          href="/overview"
          className="mb-3 flex h-8 w-8 shrink-0 items-center justify-center rounded-md bg-[var(--accent)] text-[10px] font-black text-[#09090b] transition-opacity hover:opacity-80"
          title="Overview"
        >
          SP
        </Link>

        <div className="mb-1 h-px w-6 bg-[var(--border)]" />

        {/* Group icons */}
        <div className="flex flex-1 flex-col items-center gap-1 py-2">
          {visibleGroups.map((group, idx) => {
            const Icon = GROUP_ICONS[group.title] ?? Shield;
            const isActive = expandedGroup === group.title;
            const alertBadge = group.title === 'Operate' ? (initialSummary?.red ?? 0) : undefined;
            return (
              <RailBtn
                key={group.title}
                icon={Icon}
                label={group.title}
                active={isActive}
                badge={alertBadge}
                shortcut={String(idx + 1)}
                onClick={() => toggleGroup(group.title)}
              />
            );
          })}

          {/* Search */}
          <div className="mt-2 h-px w-6 bg-[var(--border)]" />
          <button
            type="button"
            title="Search (Ctrl K)"
            aria-label="Search and jump to a page"
            onClick={openSearch}
            className="flex h-9 w-9 items-center justify-center rounded-md text-[var(--text-subtle)] transition-colors hover:bg-white/[0.06] hover:text-[var(--text-muted)]"
          >
            <Search size={16} />
          </button>
        </div>

        {/* Bottom — score + user + sign out */}
        <div className="flex flex-col items-center gap-2 border-t border-[var(--border)] pt-3">
          <div title={`Posture score: ${score}`}>
            <ScoreRing score={score} />
          </div>

          <div
            title={`${user?.username ?? 'User'} (${user?.role ?? 'viewer'})`}
            className="flex h-8 w-8 items-center justify-center rounded-md bg-[var(--surface-soft)] text-[11px] font-bold uppercase text-[var(--text-muted)] transition-colors hover:bg-[var(--surface-elevated)]"
          >
            {(user?.username ?? 'U').charAt(0)}
          </div>

          <button
            type="button"
            title="Sign out"
            aria-label="Sign out"
            onClick={handleSignOut}
            className="flex h-8 w-8 items-center justify-center rounded-md text-[var(--text-subtle)] transition-colors hover:bg-[rgba(248,113,113,0.1)] hover:text-[var(--red)]"
          >
            <LogOut size={15} />
          </button>
        </div>
      </div>

      {/* ── Secondary panel (fixed, overlaps content) ──────── */}
      {expandedGroup && selectedGroup && (
        <div ref={panelBodyRef} className="fixed inset-y-0 left-12 z-30 hidden w-52 flex-col border-r border-[var(--border)] bg-[var(--surface)] lg:flex">
          {/* Panel header */}
          <div className="flex h-12 shrink-0 items-center justify-between border-b border-[var(--border)] px-3">
            <div className="flex items-center gap-2">
              <span className="text-[11px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
                {selectedGroup.title}
              </span>
              <kbd className="rounded border border-[var(--border)] bg-[var(--surface-soft)] px-1 py-0.5 text-[9px] font-mono text-[var(--text-subtle)]">
                {visibleGroups.findIndex((g) => g.title === selectedGroup.title) + 1}
              </kbd>
            </div>
            <button
              type="button"
              onClick={() => setExpandedGroup(null)}
              className="flex h-6 w-6 items-center justify-center rounded text-[var(--text-subtle)] transition-colors hover:bg-white/[0.05] hover:text-[var(--text-muted)]"
            >
              <X size={13} />
            </button>
          </div>

          {/* Nav items */}
          <div className="flex-1 overflow-y-auto p-2 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
            {selectedGroup.items.map((item) => (
              <PanelItem
                key={item.href}
                item={item}
                active={isActivePath(pathname, item.href)}
                preview={isPreviewNavItem(item, role)}
                onClick={() => setExpandedGroup(null)}
              />
            ))}
            {advancedCount > 0 &&
              (selectedGroup.title === 'Operate' || selectedGroup.title === 'Assure') && (
              <div className="mt-1 border-t border-[var(--border)] pt-1">
                <AdvancedToggle
                  visible={advancedVisible}
                  count={advancedCount}
                  onToggle={toggleAdvanced}
                />
              </div>
              )}
          </div>

          {/* Panel footer */}
          <div className="shrink-0 border-t border-[var(--border)] p-3">
            <div className="flex items-center gap-2 px-1">
              <span className="inline-flex h-6 w-6 shrink-0 items-center justify-center rounded bg-[var(--surface-soft)] text-[10px] font-bold uppercase text-[var(--text-subtle)]">
                {(user?.username ?? 'U').charAt(0)}
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-medium text-[var(--text)]">
                  {user?.username ?? 'operator'}
                </p>
                <p className="text-[10px] uppercase tracking-widest text-[var(--text-subtle)]">
                  {user?.role ?? 'viewer'}
                </p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ── Mobile top bar ─────────────────────────────────── */}
      <div className="fixed inset-x-0 top-0 z-40 flex h-12 items-center justify-between border-b border-[var(--border)] bg-[var(--surface)] px-4 lg:hidden">
        <Link href="/overview" className="flex items-center gap-2">
          <span className="flex h-7 w-7 items-center justify-center rounded-md bg-[var(--accent)] text-[10px] font-black text-[#09090b]">
            SP
          </span>
          <span className="text-sm font-semibold text-[var(--text)]">SecPlat</span>
        </Link>
        <div className="flex items-center gap-1.5">
          <button
            type="button"
            aria-label="Search and jump to a page"
            onClick={openSearch}
            className="flex h-8 w-8 items-center justify-center rounded-md text-[var(--text-muted)] transition-colors hover:bg-white/[0.05]"
          >
            <Search size={16} />
          </button>
          <button
            type="button"
            aria-label="Open navigation"
            onClick={() => setMobileOpen(true)}
            className="flex h-8 w-8 items-center justify-center rounded-md text-[var(--text-muted)] transition-colors hover:bg-white/[0.05]"
          >
            <Menu size={17} />
          </button>
        </div>
      </div>

      {/* ── Mobile drawer ──────────────────────────────────── */}
      {mobileOpen && (
        <>
          <button
            type="button"
            aria-label="Close navigation"
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
            onClick={() => setMobileOpen(false)}
          />
          <aside className="fixed inset-y-0 left-0 z-[60] flex w-72 flex-col border-r border-[var(--border)] bg-[var(--surface)]">
            {/* Drawer header */}
            <div className="flex h-12 shrink-0 items-center justify-between border-b border-[var(--border)] px-4">
              <Link
                href="/overview"
                className="flex items-center gap-2"
                onClick={() => setMobileOpen(false)}
              >
                <span className="flex h-7 w-7 items-center justify-center rounded-md bg-[var(--accent)] text-[10px] font-black text-[#09090b]">
                  SP
                </span>
                <span className="text-sm font-semibold text-[var(--text)]">SecPlat</span>
              </Link>
              <button
                type="button"
                aria-label="Close navigation"
                onClick={() => setMobileOpen(false)}
                className="flex h-8 w-8 items-center justify-center rounded-md text-[var(--text-muted)] transition-colors hover:bg-white/[0.05]"
              >
                <X size={16} />
              </button>
            </div>

            {/* Score strip */}
            <div className="flex shrink-0 items-center gap-3 border-b border-[var(--border)] px-4 py-2.5">
              <ScoreRing score={score} />
              <div>
                <p className="text-[10px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
                  Posture score
                </p>
                <p className="text-sm font-bold tabular-nums text-[var(--text)]">{score}</p>
              </div>
            </div>

            {/* Nav groups */}
            <div className="flex-1 overflow-y-auto p-2">
              {visibleGroups.map((group) => (
                <div key={group.title} className="mb-4 last:mb-0">
                  <p className="mb-1 px-2.5 text-[10px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
                    {group.title}
                  </p>
                  <div className="space-y-0.5">
                    {group.items.map((item) => {
                      const Icon = ICONS[item.icon];
                      const active = isActivePath(pathname, item.href);
                      const preview = isPreviewNavItem(item, role);
                      return (
                        <Link
                          key={item.href}
                          href={item.href}
                          onClick={() => setMobileOpen(false)}
                          className={cn(
                            'flex items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium transition-colors',
                            active
                              ? 'bg-[var(--accent-dim)] text-[var(--accent)]'
                              : 'text-[var(--text-muted)] hover:bg-white/[0.05] hover:text-[var(--text)]'
                          )}
                        >
                          <Icon size={14} className="shrink-0 opacity-70" />
                          <span className="min-w-0 flex-1 truncate">{item.label}</span>
                          {preview && !active && (
                            <span className="shrink-0 rounded border border-[var(--border)] px-1 py-px text-[8px] font-semibold uppercase tracking-widest text-[var(--text-subtle)]">
                              Demo
                            </span>
                          )}
                        </Link>
                      );
                    })}
                  </div>
                </div>
              ))}
              {advancedCount > 0 && <div className="border-t border-[var(--border)] pt-1">
                <AdvancedToggle
                  visible={advancedVisible}
                  count={advancedCount}
                  onToggle={toggleAdvanced}
                />
              </div>}
            </div>

            {/* Footer */}
            <div className="shrink-0 border-t border-[var(--border)] p-3 space-y-1">
              <div className="flex items-center gap-2.5 px-2.5 py-1.5">
                <span className="flex h-7 w-7 shrink-0 items-center justify-center rounded-md bg-[var(--surface-soft)] text-[11px] font-bold uppercase text-[var(--text-muted)]">
                  {(user?.username ?? 'U').charAt(0)}
                </span>
                <div className="min-w-0">
                  <p className="truncate text-xs font-medium text-[var(--text)]">
                    {user?.username ?? 'operator'}
                  </p>
                  <p className="text-[10px] uppercase tracking-widest text-[var(--text-subtle)]">
                    {user?.role ?? 'viewer'}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={handleSignOut}
                className="flex w-full items-center gap-2.5 rounded-md px-2.5 py-2 text-[13px] font-medium text-[var(--text-muted)] transition-colors hover:bg-[rgba(248,113,113,0.08)] hover:text-[var(--red)]"
              >
                <LogOut size={14} />
                Sign out
              </button>
            </div>
          </aside>
        </>
      )}

      {/* Command palette — triggered by Ctrl K */}
      <CommandPalette showTrigger={false} />
    </>
  );
}
