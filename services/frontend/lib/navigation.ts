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
        label: 'External Exposure',
        icon: 'surface',
        description: 'Understand internet-facing exposure, drift, and service relationships.',
      },
      {
        href: '/threat-intel',
        label: 'Threat Intelligence',
        icon: 'intel',
        description: 'Review IOC feeds, matched assets, and refresh health.',
      },
      {
        href: '/telemetry',
        label: 'Signals',
        icon: 'telemetry',
        description: 'Inspect live network, endpoint, and deception signals in one place.',
      },
      {
        href: '/detections',
        label: 'Detection Rules',
        icon: 'detections',
        description: 'Build, test, and tune the rules that generate alerts.',
      },
      {
        href: '/automation',
        label: 'Workflows',
        icon: 'automation',
        description: 'Design response workflows, approvals, and rollback safety in one place.',
      },
      {
        href: '/attack-lab',
        label: 'Attack Lab',
        icon: 'attack',
        description: 'Run controlled attack simulations for validation and demos.',
        adminOnly: true,
      },
      {
        href: '/attack-graph',
        label: 'Path Explorer',
        icon: 'graph',
        description: 'Trace likely attacker paths and connect incidents back to exposure.',
      },
      {
        href: '/cyber-range',
        label: 'Training Range',
        icon: 'range',
        description: 'Practice workflows with guided missions and live telemetry.',
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
        description: 'Manage firing, acknowledged, and resolved alerts.',
      },
      {
        href: '/incidents',
        label: 'Incident Response',
        icon: 'incidents',
        description: 'Coordinate investigation, ownership, and response timelines.',
      },
      {
        href: '/suppression',
        label: 'Maintenance Rules',
        icon: 'suppression',
        description: 'Set maintenance windows and noise-reduction rules with clear scope.',
      },
      {
        href: '/jobs',
        label: 'Activity Center',
        icon: 'jobs',
        description: 'Monitor queued work, retries, and platform maintenance runs.',
      },
    ],
  },
  {
    title: 'Assure',
    items: [
      {
        href: '/reports',
        label: 'Reporting Center',
        icon: 'reports',
        description: 'Create customer-ready snapshots, exports, and board-level summaries.',
      },
      {
        href: '/policy',
        label: 'Policy & Controls',
        icon: 'policy',
        description: 'Review policy bundles, approvals, and control evaluation results.',
      },
      {
        href: '/ml-risk',
        label: 'Scoring Studio',
        icon: 'ml',
        description: 'Inspect scoring quality, drift, and analyst labeling coverage.',
      },
      {
        href: '/audit',
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

export function getVisibleNavGroups(isAdmin: boolean): NavGroup[] {
  return NAV_GROUPS.map((group) => ({
    ...group,
    items: group.items.filter((item) => !item.adminOnly || isAdmin),
  })).filter((group) => group.items.length > 0);
}

export function getAllVisibleNavItems(isAdmin: boolean): NavItem[] {
  return getVisibleNavGroups(isAdmin).flatMap((group) => group.items);
}

export function isActivePath(pathname: string, href: string): boolean {
  if (href === '/overview') return pathname === '/overview';
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function getActiveNavItem(pathname: string, isAdmin: boolean): NavItem | null {
  const all = getAllVisibleNavItems(isAdmin);
  const matches = all.filter((item) => isActivePath(pathname, item.href));
  if (matches.length === 0) return null;
  return matches.sort((a, b) => b.href.length - a.href.length)[0];
}
