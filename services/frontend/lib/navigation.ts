export type NavIconKey =
  | 'activity'
  | 'dashboard'
  | 'assets'
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
    title: 'Command Center',
    items: [
      {
        href: '/overview',
        label: 'Overview',
        icon: 'activity',
        description: 'Executive summary and posture trend.',
      },
      {
        href: '/dashboards',
        label: 'Dashboards',
        icon: 'dashboard',
        description: 'Analytics dashboards and external views.',
      },
    ],
  },
  {
    title: 'Security Ops',
    items: [
      {
        href: '/assets',
        label: 'Assets',
        icon: 'assets',
        description: 'Asset inventory, status and ownership.',
      },
      {
        href: '/findings',
        label: 'Findings',
        icon: 'findings',
        description: 'Vulnerabilities and remediation tracking.',
      },
      {
        href: '/alerts',
        label: 'Alerts',
        icon: 'alerts',
        description: 'Firing, acknowledged and resolved alerts.',
      },
      {
        href: '/incidents',
        label: 'Incidents',
        icon: 'incidents',
        description: 'Incident lifecycle and response timeline.',
      },
      {
        href: '/suppression',
        label: 'Suppression',
        icon: 'suppression',
        description: 'Maintenance windows and suppression rules.',
      },
      {
        href: '/jobs',
        label: 'Jobs',
        icon: 'jobs',
        description: 'Background job queue and retries.',
      },
    ],
  },
  {
    title: 'Governance',
    items: [
      {
        href: '/reports',
        label: 'Reports',
        icon: 'reports',
        description: 'Executive snapshots and exports.',
      },
      {
        href: '/policy',
        label: 'Policy',
        icon: 'policy',
        description: 'Policy bundles, approvals and evaluations.',
      },
      {
        href: '/ml-risk',
        label: 'ML Risk',
        icon: 'ml',
        description: 'Model evaluation, drift tracking and label review.',
      },
      {
        href: '/audit',
        label: 'Audit',
        icon: 'audit',
        description: 'Traceability across platform actions.',
      },
    ],
  },
  {
    title: 'Administration',
    items: [
      {
        href: '/users',
        label: 'Users',
        icon: 'users',
        description: 'Role-based access and account management.',
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
