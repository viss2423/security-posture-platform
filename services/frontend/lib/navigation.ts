export type NavIconKey =
  | 'activity'
  | 'dashboard'
  | 'assets'
  | 'surface'
  | 'graph'
  | 'intel'
  | 'telemetry'
  | 'detections'
  | 'automation'
  | 'attack'
  | 'range'
  | 'findings'
  | 'alerts'
  | 'incidents'
  | 'suppression'
  | 'jobs'
  | 'reports'
  | 'policy'
  | 'audit'
  | 'users'
  | 'ml';

export type NavItem = {
  href: string;
  label: string;
  icon: NavIconKey;
  adminOnly?: boolean;
  operatorOnly?: boolean;
  /** Specialist tooling hidden from the nav by default so new users see a focused set of pages. */
  advanced?: boolean;
  description: string;
};

export type NavGroup = {
  title: string;
  items: NavItem[];
};

export const NAV_GROUPS: NavGroup[] = [
  {
    title: 'Start Here',
    items: [
      {
        href: '/onboarding',
        label: 'Launch Checklist',
        icon: 'activity',
        description: 'Go from sign-in to first value with a guided customer setup flow.',
      },
      {
        href: '/overview',
        label: 'Executive Overview',
        icon: 'activity',
        description: 'See security health, risk movement, and next priorities at a glance.',
      },
      {
        href: '/dashboards',
        label: 'Dashboards',
        icon: 'dashboard',
        operatorOnly: true,
        description: 'Open analytics boards and customer-facing reporting views.',
      },
    ],
  },
  {
    title: 'Operate',
    items: [
      {
        href: '/assets',
        label: 'Asset Inventory',
        icon: 'assets',
        description: 'Track monitored assets, ownership, health, and posture in one place.',
      },
      {
        href: '/attack-surface',
        advanced: true,
        operatorOnly: true,
        label: 'External Exposure',
        icon: 'surface',
        description: 'Understand internet-facing exposure, drift, and service relationships.',
      },
      {
        href: '/threat-intel',
        advanced: true,
        operatorOnly: true,
        label: 'Threat Intelligence',
        icon: 'intel',
        description: 'Review IOC feeds, matched assets, and refresh health.',
      },
      {
        href: '/telemetry',
        advanced: true,
        operatorOnly: true,
        label: 'Signals',
        icon: 'telemetry',
        description: 'Inspect live network, endpoint, and deception signals in one place.',
      },
      {
        href: '/detections',
        advanced: true,
        operatorOnly: true,
        label: 'Detection Rules',
        icon: 'detections',
        description: 'Build, test, and tune the rules that generate alerts.',
      },
      {
        href: '/automation',
        advanced: true,
        operatorOnly: true,
        label: 'Workflows',
        icon: 'automation',
        description: 'Design response workflows, approvals, and rollback safety in one place.',
      },
      {
        href: '/attack-lab',
        advanced: true,
        operatorOnly: true,
        label: 'Detection Validation',
        icon: 'attack',
        description: 'Run safe simulations to verify your detections fire correctly.',
      },
      {
        href: '/attack-graph',
        advanced: true,
        operatorOnly: true,
        label: 'Path Explorer',
        icon: 'graph',
        description: 'Trace likely attacker paths and connect incidents back to exposure.',
      },
      {
        href: '/cyber-range',
        advanced: true,
        operatorOnly: true,
        label: 'Security Drills',
        icon: 'range',
        description: 'Guided training exercises that generate real detections and incidents.',
      },
      {
        href: '/findings',
        label: 'Risk Review',
        icon: 'findings',
        description: 'Prioritize vulnerabilities and track remediation progress.',
      },
      {
        href: '/alerts',
        label: 'Alerts',
        icon: 'alerts',
        operatorOnly: true,
        description: 'Manage firing, acknowledged, and resolved alerts.',
      },
      {
        href: '/incidents',
        label: 'Incident Response',
        icon: 'incidents',
        operatorOnly: true,
        description: 'Coordinate investigation, ownership, and response timelines.',
      },
      {
        href: '/suppression',
        advanced: true,
        operatorOnly: true,
        label: 'Maintenance Rules',
        icon: 'suppression',
        description: 'Set maintenance windows and noise-reduction rules with clear scope.',
      },
      {
        href: '/jobs',
        label: 'Activity Center',
        icon: 'jobs',
        operatorOnly: true,
        description: 'Monitor queued work, retries, and platform maintenance runs.',
      },
    ],
  },
  {
    title: 'Assure',
    items: [
      {
        href: '/compliance',
        label: 'Compliance Evidence',
        icon: 'reports',
        operatorOnly: true,
        description: 'SOC 2 evidence report mapped from live posture findings.',
      },
      {
        href: '/reports',
        label: 'Reporting Center',
        icon: 'reports',
        operatorOnly: true,
        description: 'Create customer-ready snapshots, exports, and board-level summaries.',
      },
      {
        href: '/policy',
        advanced: true,
        operatorOnly: true,
        label: 'Policy & Controls',
        icon: 'policy',
        description: 'Review policy bundles, approvals, and control evaluation results.',
      },
      {
        href: '/ml-risk',
        advanced: true,
        operatorOnly: true,
        label: 'AI Risk Engine',
        icon: 'ml',
        description: 'AI that learns from your team to automatically prioritize real threats.',
      },
      {
        href: '/audit',
        advanced: true,
        operatorOnly: true,
        label: 'Audit Trail',
        icon: 'audit',
        description: 'Trace who changed what and when across the platform.',
      },
    ],
  },
  {
    title: 'Admin',
    items: [
      {
        href: '/users',
        label: 'Team Access',
        icon: 'users',
        description: 'Manage roles, customer access, and operational permissions.',
        adminOnly: true,
      },
    ],
  },
];

function normalizeRole(role?: string | null): string {
  return (role || '').trim().toLowerCase();
}

function isOperatorRole(role?: string | null): boolean {
  const normalized = normalizeRole(role);
  return normalized === 'admin' || normalized === 'analyst';
}

function isAdminRole(role?: string | null): boolean {
  return normalizeRole(role) === 'admin';
}

export function getVisibleNavGroups(role: string | null, includeAdvanced = true): NavGroup[] {
  const isAdmin = isAdminRole(role);
  // Operator-only items stay visible to viewers so the full product surface is
  // discoverable — those routes render a static read-only preview for viewers
  // (see ViewerPreviewGate). Only admin tooling is hidden outright.
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter(
      (item) => (!item.adminOnly || isAdmin) && (includeAdvanced || !item.advanced)
    ),
  })).filter((group) => group.items.length > 0);
}

/** True when this nav item renders as a read-only preview for the given role. */
export function isPreviewNavItem(item: NavItem, role: string | null): boolean {
  return Boolean(item.operatorOnly) && !isOperatorRole(role);
}

export function countAdvancedNavItems(role: string | null): number {
  return getVisibleNavGroups(role).reduce((total, group) => {
    return total + group.items.filter((item) => item.advanced).length;
  }, 0);
}

export function getAllVisibleNavItems(role: string | null, includeAdvanced = true): NavItem[] {
  return getVisibleNavGroups(role, includeAdvanced).flatMap((group) => group.items);
}

export function isActivePath(pathname: string, href: string): boolean {
  if (href === '/overview') return pathname === '/overview';
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function getActiveNavItem(pathname: string, role: string | null): NavItem | null {
  const all = getAllVisibleNavItems(role);
  const matches = all.filter((item) => isActivePath(pathname, item.href));
  if (matches.length === 0) return null;
  return matches.sort((a, b) => b.href.length - a.href.length)[0];
}
