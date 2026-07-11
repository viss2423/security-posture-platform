/**
 * Static, read-only feature previews shown to viewer-role users on operator pages.
 * All content here is fabricated sample data — nothing is fetched from the API, so
 * a demo account can see what every feature does without touching real data.
 */

export type PreviewTone = 'green' | 'amber' | 'red' | 'accent' | 'muted';

export type PreviewStat = { label: string; value: string; tone?: PreviewTone };
export type PreviewCard = { title: string; body: string; badge?: string; tone?: PreviewTone };
export type PreviewTable = { columns: string[]; rows: string[][] };

export type FeaturePreview = {
  title: string;
  tagline: string;
  stats: PreviewStat[];
  /** Optional highlight cards (e.g. alert sources) rendered above the table. */
  cards?: PreviewCard[];
  cardsHeading?: string;
  table?: PreviewTable;
  tableHeading?: string;
  capabilities: string[];
};

export const DEMO_PREVIEWS: Record<string, FeaturePreview> = {
  '/alerts': {
    title: 'Alerts',
    tagline:
      'Every signal source lands in one triage queue with severity, asset context, and AI-assisted recommendations.',
    stats: [
      { label: 'Firing', value: '7', tone: 'red' },
      { label: 'Acknowledged', value: '12', tone: 'amber' },
      { label: 'Resolved (7d)', value: '54', tone: 'green' },
      { label: 'Mean time to ack', value: '11m', tone: 'accent' },
    ],
    cardsHeading: 'Where alerts come from',
    cards: [
      { title: 'Network IDS (Suricata)', body: 'Signature hits on live traffic — exploit attempts, C2 beacons, policy violations.', badge: 'network', tone: 'red' },
      { title: 'Network analytics (Zeek)', body: 'Protocol-level anomalies: odd DNS patterns, rare JA3 fingerprints, TLS oddities.', badge: 'network', tone: 'accent' },
      { title: 'Honeypot (Cowrie)', body: 'SSH/Telnet deception — brute-force attempts and attacker command capture.', badge: 'deception', tone: 'amber' },
      { title: 'Detection rules', body: 'Your own rules evaluated continuously against incoming telemetry.', badge: 'rules', tone: 'accent' },
      { title: 'Threat-intel match', body: 'An asset talked to a known-bad IOC from your enabled intel feeds.', badge: 'intel', tone: 'red' },
      { title: 'ML anomaly', body: 'Per-asset behavioural baselines flag deviations no rule anticipated.', badge: 'ml', tone: 'amber' },
      { title: 'Posture change', body: 'An asset drops to red — service down, port newly exposed, score collapse.', badge: 'posture', tone: 'amber' },
      { title: 'Repository scan', body: 'New critical vulnerability or exposed secret found in a connected repo.', badge: 'code', tone: 'red' },
    ],
    tableHeading: 'Sample queue',
    table: {
      columns: ['Severity', 'Alert', 'Source', 'Asset', 'Status'],
      rows: [
        ['critical', 'ET EXPLOIT Apache Struts RCE attempt', 'Suricata', 'edge-gateway', 'firing'],
        ['high', 'SSH brute-force: 240 attempts / 5 min', 'Cowrie honeypot', 'honeypot-01', 'firing'],
        ['high', 'Outbound connection to known C2 (feed: abuse.ch)', 'Threat intel', 'app-server-02', 'acknowledged'],
        ['medium', 'DNS query volume 6x baseline', 'ML anomaly', 'workstation-17', 'acknowledged'],
        ['medium', 'Posture dropped to red: port 9200 exposed', 'Posture', 'search-cluster', 'resolved'],
        ['low', 'New medium CVE in requests 2.28.0', 'Repo scan', 'payments-api', 'resolved'],
      ],
    },
    capabilities: [
      'Acknowledge, resolve, and assign alerts with a full audit trail',
      'AI triage suggests probable cause and next action — operators approve or reject',
      'One-click pivot to the asset, related telemetry, or a new incident',
      'Noise controls: suppression rules and maintenance windows',
    ],
  },

  '/incidents': {
    title: 'Incident Response',
    tagline: 'Coordinate investigation, ownership, and SLA timers from declaration to post-mortem.',
    stats: [
      { label: 'Open', value: '2', tone: 'red' },
      { label: 'Within SLA', value: '100%', tone: 'green' },
      { label: 'Median resolution', value: '4.2h', tone: 'accent' },
      { label: 'Closed (30d)', value: '17', tone: 'muted' },
    ],
    tableHeading: 'Sample incidents',
    table: {
      columns: ['Sev', 'Incident', 'Owner', 'SLA', 'Status'],
      rows: [
        ['SEV-1', 'Suspected C2 beaconing from app-server-02', 'j.ramos', '2h 14m left', 'investigating'],
        ['SEV-2', 'Credential stuffing against customer portal', 'a.chen', '6h 40m left', 'mitigating'],
        ['SEV-3', 'Expired TLS cert on internal API', 'unassigned', 'met', 'resolved'],
      ],
    },
    capabilities: [
      'Timeline view: every alert, action, and note in one thread',
      'SLA timers by severity with breach warnings',
      'AI incident summaries for handoffs and post-mortems',
      'Link alerts, assets, and attack paths as evidence',
    ],
  },

  '/telemetry': {
    title: 'Signals',
    tagline: 'Live network, endpoint, and deception telemetry — searchable in one place.',
    stats: [
      { label: 'Events (24h)', value: '48.2k', tone: 'accent' },
      { label: 'Sources', value: '4', tone: 'muted' },
      { label: 'IDS detections', value: '86', tone: 'amber' },
      { label: 'Honeypot sessions', value: '31', tone: 'red' },
    ],
    tableHeading: 'Sample event stream',
    table: {
      columns: ['Time', 'Source', 'Event', 'Asset'],
      rows: [
        ['14:32:07', 'suricata', 'ET SCAN Nmap OS detection probe', 'edge-gateway'],
        ['14:31:52', 'zeek', 'TLS: self-signed cert on outbound 443', 'app-server-02'],
        ['14:30:18', 'cowrie', 'login attempt root:123456 (rejected)', 'honeypot-01'],
        ['14:28:44', 'suricata', 'HTTP suspicious user-agent: sqlmap', 'customer-portal'],
      ],
    },
    capabilities: [
      'Suricata, Zeek, and Cowrie pipelines ingested and normalised automatically',
      'Filter by source, asset, severity, and time range',
      'Feed detection rules and ML baselines from the same stream',
    ],
  },

  '/detections': {
    title: 'Detection Rules',
    tagline: 'Author, test, and tune the rules that turn raw telemetry into alerts.',
    stats: [
      { label: 'Active rules', value: '133', tone: 'accent' },
      { label: 'Fired (7d)', value: '41', tone: 'amber' },
      { label: 'Precision (labelled)', value: '93%', tone: 'green' },
    ],
    tableHeading: 'Sample rules',
    table: {
      columns: ['Rule', 'Source', 'Severity', 'Hits (7d)'],
      rows: [
        ['SSH brute-force threshold', 'cowrie', 'high', '12'],
        ['Outbound traffic to TOR exit node', 'zeek', 'high', '3'],
        ['New admin user created outside change window', 'audit', 'critical', '0'],
        ['DNS tunneling heuristic', 'zeek', 'medium', '7'],
      ],
    },
    capabilities: [
      'Rule editor with dry-run backtesting against recent telemetry',
      'Per-rule hit history and precision tracking',
      'Promote noisy rules to suppression or tune thresholds in place',
    ],
  },

  '/automation': {
    title: 'Workflows',
    tagline: 'Response automation with human approval gates and rollback safety.',
    stats: [
      { label: 'Playbooks', value: '9', tone: 'accent' },
      { label: 'Runs (30d)', value: '64', tone: 'muted' },
      { label: 'Auto-resolved', value: '38%', tone: 'green' },
    ],
    tableHeading: 'Sample playbooks',
    table: {
      columns: ['Playbook', 'Trigger', 'Approval', 'Last run'],
      rows: [
        ['Isolate host on C2 match', 'threat-intel alert', 'required', '2d ago'],
        ['Rotate exposed secret', 'repo scan finding', 'required', '6d ago'],
        ['Auto-ack known-noisy IDS sig', 'alert pattern', 'auto', '3h ago'],
      ],
    },
    capabilities: [
      'Policy-as-code triggers with approval steps for destructive actions',
      'Every run logged with inputs, outputs, and rollback point',
      'Start from templates or compose custom steps',
    ],
  },

  '/attack-surface': {
    title: 'External Exposure',
    tagline: 'What the internet sees: open ports, services, certificates, and drift over time.',
    stats: [
      { label: 'Internet-facing assets', value: '14', tone: 'accent' },
      { label: 'Open services', value: '31', tone: 'muted' },
      { label: 'New this week', value: '2', tone: 'amber' },
      { label: 'Expiring certs (30d)', value: '1', tone: 'red' },
    ],
    tableHeading: 'Sample exposure',
    table: {
      columns: ['Host', 'Service', 'Port', 'Risk'],
      rows: [
        ['edge-gateway', 'nginx 1.24', '443', 'ok'],
        ['search-cluster', 'OpenSearch 2.14', '9200', 'exposed — should be internal'],
        ['legacy-ftp', 'vsftpd 3.0.3', '21', 'deprecated protocol'],
      ],
    },
    capabilities: [
      'Scheduled discovery scans with diff-based drift alerts',
      'Certificate inventory with expiry tracking',
      'Service-to-asset mapping feeds the attack graph',
    ],
  },

  '/attack-graph': {
    title: 'Path Explorer',
    tagline: 'Trace likely attacker paths from exposure to crown-jewel assets.',
    stats: [
      { label: 'Mapped assets', value: '42', tone: 'accent' },
      { label: 'Viable paths', value: '6', tone: 'amber' },
      { label: 'Choke points', value: '3', tone: 'green' },
    ],
    tableHeading: 'Sample paths',
    table: {
      columns: ['Path', 'Hops', 'Exploitability'],
      rows: [
        ['internet → edge-gateway → app-server-02 → customer-db', '3', 'high'],
        ['internet → legacy-ftp → file-share → domain-controller', '3', 'medium'],
        ['phish → workstation-17 → jump-host → search-cluster', '3', 'medium'],
      ],
    },
    capabilities: [
      'Graph built from live exposure, findings, and network relationships',
      'Rank paths by exploitability and business impact',
      'Simulate a fix to see which paths it cuts',
    ],
  },

  '/attack-lab': {
    title: 'Detection Validation',
    tagline: 'Run safe, controlled attack simulations and confirm your detections fire.',
    stats: [
      { label: 'Scenarios', value: '12', tone: 'accent' },
      { label: 'Runs (30d)', value: '18', tone: 'muted' },
      { label: 'Detection coverage', value: '83%', tone: 'green' },
    ],
    tableHeading: 'Sample scenarios',
    table: {
      columns: ['Scenario', 'Target', 'Detected by', 'Result'],
      rows: [
        ['Port scan sweep', 'verify sandbox', 'Suricata + rule', 'detected in 4s'],
        ['SSH brute force', 'honeypot', 'Cowrie + rule', 'detected in 2s'],
        ['SQLi probe', 'juice-shop sandbox', 'Suricata', 'detected in 6s'],
        ['Slow exfil over DNS', 'verify sandbox', '—', 'missed → rule suggested'],
      ],
    },
    capabilities: [
      'Sandboxed targets only — simulations never touch production',
      'Each run scores your detection pipeline end-to-end',
      'Missed techniques generate suggested detection rules',
    ],
  },

  '/cyber-range': {
    title: 'Security Drills',
    tagline: 'Guided training exercises that generate real signals, alerts, and incidents to practise on.',
    stats: [
      { label: 'Drills available', value: '8', tone: 'accent' },
      { label: 'Completed', value: '3', tone: 'green' },
      { label: 'Team best time', value: '22m', tone: 'muted' },
    ],
    tableHeading: 'Sample drills',
    table: {
      columns: ['Drill', 'Difficulty', 'Skills'],
      rows: [
        ['Ransomware precursor hunt', 'intermediate', 'triage, telemetry pivoting'],
        ['Compromised CI credential', 'advanced', 'audit trail, containment'],
        ['Noisy neighbour: tuning day', 'beginner', 'suppression, rule tuning'],
      ],
    },
    capabilities: [
      'Drills inject realistic signals into an isolated slice of the platform',
      'Scoreboards and step-by-step debriefs',
      'Great for onboarding new analysts',
    ],
  },

  '/suppression': {
    title: 'Maintenance Rules',
    tagline: 'Planned-work windows and noise-reduction rules with explicit scope and expiry.',
    stats: [
      { label: 'Active windows', value: '1', tone: 'amber' },
      { label: 'Suppression rules', value: '5', tone: 'accent' },
      { label: 'Alerts muted (7d)', value: '210', tone: 'muted' },
    ],
    tableHeading: 'Sample rules',
    table: {
      columns: ['Rule', 'Scope', 'Expires'],
      rows: [
        ['Patch window — web tier', 'env:prod, tier:web', 'tonight 02:00–04:00'],
        ['Mute known-noisy IDS sig 2210045', 'edge-gateway', 'in 12 days'],
        ['Ignore dev-environment posture flaps', 'env:dev', 'never (reviewed monthly)'],
      ],
    },
    capabilities: [
      'Every suppression has an owner, scope, and expiry — no permanent blind spots',
      'Suppressed alerts are still recorded and reviewable',
      'Calendar view of upcoming maintenance windows',
    ],
  },

  '/jobs': {
    title: 'Activity Center',
    tagline: 'Every scan, import, and background task — queued, running, and finished — with retries and AI failure triage.',
    stats: [
      { label: 'Running', value: '1', tone: 'amber' },
      { label: 'Success rate (7d)', value: '97%', tone: 'green' },
      { label: 'Job types', value: '10', tone: 'accent' },
    ],
    tableHeading: 'Sample activity',
    table: {
      columns: ['Job', 'Status', 'Duration', 'Result'],
      rows: [
        ['GitHub posture scan', 'done', '48s', '12 repos checked, 3 findings'],
        ['AWS IAM posture scan', 'done', '2s', 'Root MFA and stale key findings'],
        ['Web exposure scan', 'running', '2m 10s', '—'],
        ['Threat intel refresh', 'done', '12s', '1,840 IOCs updated'],
        ['Repository scan (OSV + Trivy)', 'done', '3m 41s', '2 new criticals'],
        ['Telemetry import', 'failed → retried', '55s', 'AI triage: malformed eve.json line 8,412'],
      ],
    },
    capabilities: [
      'Launch scans on demand or on a schedule',
      'Failed jobs get AI triage with a suggested fix',
      'Full parameter and output history per run',
    ],
  },

  '/compliance': {
    title: 'Compliance Evidence',
    tagline: 'Live SOC 2, ISO 27001, and CIS evidence mapped from real GitHub and AWS IAM posture findings — always current, never a screenshot folder.',
    stats: [
      { label: 'Controls tracked', value: '12', tone: 'accent' },
      { label: 'Passing', value: '9', tone: 'green' },
      { label: 'Needs action', value: '3', tone: 'red' },
    ],
    tableHeading: 'Sample controls',
    table: {
      columns: ['Control', 'Name', 'Status', 'Evidence'],
      rows: [
        ['SOC 2 CC6.1', 'Logical access controls', 'PASS', 'Org 2FA enforced; secret scanning on all repos'],
        ['ISO 27001 A.8.8', 'Vulnerability management', 'FAIL', 'Dependabot disabled on 2 repositories'],
        ['CIS 5.4', 'MFA for privileged access', 'FAIL', 'AWS root account MFA not enabled'],
      ],
    },
    capabilities: [
      'Each control links to the live findings that prove or break it',
      'One-click auditor-ready PDF or CSV export',
      'Evidence aggregates across connectors (GitHub, AWS) and updates automatically as scans run',
    ],
  },

  '/reports': {
    title: 'Reporting Center',
    tagline: 'Board-level summaries, posture snapshots, and what-changed comparisons.',
    stats: [
      { label: 'Snapshots', value: '30', tone: 'accent' },
      { label: 'Scheduled reports', value: '2', tone: 'muted' },
      { label: 'Score trend (30d)', value: '+6', tone: 'green' },
    ],
    tableHeading: 'Sample outputs',
    table: {
      columns: ['Report', 'Audience', 'Cadence'],
      rows: [
        ['Executive posture PDF', 'leadership', 'weekly'],
        ['What changed since last board meeting', 'board', 'monthly'],
        ['SOC 2 evidence pack', 'auditor', 'on demand'],
      ],
    },
    capabilities: [
      'Point-in-time snapshots you can diff: what improved, what regressed',
      'Executive PDF with score trend and top risks',
      'Snapshot on demand or on a schedule',
    ],
  },

  '/policy': {
    title: 'Policy & Controls',
    tagline: 'Security rules as versioned YAML with approvals, evaluation history, and rollback.',
    stats: [
      { label: 'Policy bundles', value: '4', tone: 'accent' },
      { label: 'Controls evaluated', value: '58', tone: 'muted' },
      { label: 'Compliance', value: '91%', tone: 'green' },
    ],
    tableHeading: 'Sample bundles',
    table: {
      columns: ['Bundle', 'Version', 'Last evaluation', 'Result'],
      rows: [
        ['Baseline hardening', 'v14', '1h ago', '54/58 pass'],
        ['PCI cardholder scope', 'v6', '1h ago', 'pass'],
        ['Internet-exposure guardrails', 'v9', '1h ago', '2 violations'],
      ],
    },
    capabilities: [
      'Versioned policy bundles with review-and-approve workflow',
      'Evaluations run continuously against live posture',
      'AI summary explains each violation in plain language',
    ],
  },

  '/ml-risk': {
    title: 'AI Risk Engine',
    tagline: 'A model that learns from your triage decisions to rank what actually matters.',
    stats: [
      { label: 'AI precision', value: '94%', tone: 'green' },
      { label: 'Labelled examples', value: '412', tone: 'accent' },
      { label: 'Alert noise cut', value: '-38%', tone: 'green' },
      { label: 'Drift (PSI)', value: '0.04', tone: 'muted' },
    ],
    tableHeading: 'Sample review queue',
    table: {
      columns: ['Finding', 'AI risk', 'Why'],
      rows: [
        ['Exposed OpenSearch port on search-cluster', '0.92', 'internet-facing + known exploit chatter'],
        ['Critical CVE in payments-api dependency', '0.87', 'crown-jewel asset + fix available'],
        ['Medium CVE in internal tool', '0.18', 'no exposure path, low criticality'],
      ],
    },
    capabilities: [
      'Every prediction is explained — no black-box scores',
      'Threshold tuning with live precision/recall preview',
      'Drift monitoring with automatic retrain suggestions',
    ],
  },

  '/audit': {
    title: 'Audit Trail',
    tagline: 'Who changed what, when — every login, config change, and action, immutably logged.',
    stats: [
      { label: 'Events (30d)', value: '3.1k', tone: 'accent' },
      { label: 'Actors', value: '6', tone: 'muted' },
      { label: 'Retention', value: '365d', tone: 'muted' },
    ],
    tableHeading: 'Sample trail',
    table: {
      columns: ['Time', 'Actor', 'Action', 'Detail'],
      rows: [
        ['09:14', 'a.chen', 'alert.resolve', 'alert #4812 — false positive'],
        ['08:52', 'j.ramos', 'policy.update', 'baseline-hardening v13 → v14'],
        ['08:30', 'system', 'job.run', 'scheduled GitHub posture scan'],
        ['07:58', 'admin', 'user.create', 'analyst account for new hire'],
      ],
    },
    capabilities: [
      'Filter by actor, action type, and time range',
      'Feeds SOC 2 change-management evidence automatically',
      'Service actions and human actions distinguished',
    ],
  },

  '/threat-intel': {
    title: 'Threat Intelligence',
    tagline: 'IOC feeds matched continuously against your assets and telemetry.',
    stats: [
      { label: 'Active IOCs', value: '18.4k', tone: 'accent' },
      { label: 'Feeds', value: '3', tone: 'muted' },
      { label: 'Matches (30d)', value: '4', tone: 'red' },
    ],
    tableHeading: 'Sample matches',
    table: {
      columns: ['IOC', 'Type', 'Feed', 'Matched asset'],
      rows: [
        ['185.220.x.x', 'ip', 'abuse.ch', 'app-server-02 (outbound)'],
        ['malware-cdn.example', 'domain', 'openphish', 'workstation-17 (DNS)'],
        ['9f86d08…', 'sha256', 'internal', 'file-share upload'],
      ],
    },
    capabilities: [
      'Feeds refresh on schedule with health monitoring',
      'Matches raise alerts with full context automatically',
      'Sightings history per indicator',
    ],
  },

  '/dashboards': {
    title: 'Dashboards',
    tagline: 'Live Grafana boards for posture, IDS telemetry, network analytics, and honeypot activity.',
    stats: [
      { label: 'Boards', value: '4', tone: 'accent' },
      { label: 'Data sources', value: '3', tone: 'muted' },
      { label: 'Refresh', value: '30s', tone: 'muted' },
    ],
    tableHeading: 'Available boards',
    table: {
      columns: ['Board', 'Shows'],
      rows: [
        ['Asset Posture', 'platform-wide health and score trend'],
        ['Suricata IDS', 'detections, signatures, severity over time'],
        ['Zeek Network Analytics', 'DNS, HTTP, and TLS protocol context'],
        ['Honeypot (Cowrie)', 'brute-force attempts and attacker commands'],
      ],
    },
    capabilities: [
      'Embedded Grafana with kiosk-mode boards',
      'Same telemetry pipeline that powers alerts',
      'Extend with your own panels',
    ],
  },
};

export function getDemoPreview(pathname: string): FeaturePreview | null {
  for (const [prefix, preview] of Object.entries(DEMO_PREVIEWS)) {
    if (pathname === prefix || pathname.startsWith(`${prefix}/`)) return preview;
  }
  return null;
}
