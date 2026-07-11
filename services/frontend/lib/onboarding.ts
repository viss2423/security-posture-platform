export type OnboardingInput = {
  authenticated: boolean;
  authConfigLoaded: boolean;
  oidcEnabled: boolean;
  assetCount: number;
  telemetryEventCount: number;
  detectionRuleCount: number;
  alertCount: number;
  incidentCount: number;
  githubScanRan?: boolean;
};

export type OnboardingStep = {
  id:
    | 'access'
    | 'identity'
    | 'github'
    | 'assets'
    | 'telemetry'
    | 'detections'
    | 'alerts'
    | 'incidents';
  title: string;
  description: string;
  detail: string;
  complete: boolean;
  ctaHref?: string;
  ctaLabel?: string;
};

export function deriveOnboardingSteps(input: OnboardingInput): OnboardingStep[] {
  return [
    {
      id: 'access',
      title: 'Platform access',
      description: 'Confirm the secure session is active for this customer account.',
      detail: input.authenticated ? 'Signed in and ready to continue.' : 'Sign in to continue.',
      complete: input.authenticated,
    },
    {
      id: 'identity',
      title: 'Identity path',
      description: 'Validate local login or optional SSO before broader rollout.',
      detail: !input.authConfigLoaded
        ? 'Auth config is still loading.'
        : input.oidcEnabled
          ? 'OIDC is configured for operator login.'
          : 'Local credential login is active; OIDC remains optional.',
      complete: input.authConfigLoaded,
    },
    {
      id: 'github',
      title: 'Connect GitHub',
      description: 'Run the read-only GitHub posture scan to unlock findings and evidence.',
      detail: input.githubScanRan
        ? 'GitHub posture evidence has been collected.'
        : 'No completed GitHub posture scan yet.',
      complete: Boolean(input.githubScanRan),
      ctaHref: '/jobs',
      ctaLabel: 'Run GitHub Posture',
    },
    {
      id: 'assets',
      title: 'Asset inventory',
      description: 'Register at least one monitored asset so telemetry and detections have scope.',
      detail:
        input.assetCount > 0
          ? `${input.assetCount} asset${input.assetCount === 1 ? '' : 's'} registered.`
          : 'No inventory records yet.',
      complete: input.assetCount > 0,
    },
    {
      id: 'telemetry',
      title: 'Signal connection',
      description: 'Ingest source events and prove they are visible inside the product.',
      detail:
        input.telemetryEventCount > 0
          ? `${input.telemetryEventCount} event${input.telemetryEventCount === 1 ? '' : 's'} visible.`
          : 'No telemetry events visible yet.',
      complete: input.telemetryEventCount > 0,
    },
    {
      id: 'detections',
      title: 'Baseline detections',
      description: 'Enable at least one baseline detection before moving into review workflows.',
      detail:
        input.detectionRuleCount > 0
          ? `${input.detectionRuleCount} rule${input.detectionRuleCount === 1 ? '' : 's'} available.`
          : 'No detection rules enabled yet.',
      complete: input.detectionRuleCount > 0,
    },
    {
      id: 'alerts',
      title: 'First alert',
      description: 'Generate an alert from live telemetry so triage workflows have a concrete signal.',
      detail:
        input.alertCount > 0
          ? `${input.alertCount} alert${input.alertCount === 1 ? '' : 's'} available for triage.`
          : 'No alerts created yet.',
      complete: input.alertCount > 0,
    },
    {
      id: 'incidents',
      title: 'First incident',
      description: 'Link alert evidence into an incident and verify the response surface is usable.',
      detail:
        input.incidentCount > 0
          ? `${input.incidentCount} incident${input.incidentCount === 1 ? '' : 's'} recorded.`
          : 'No incidents linked yet.',
      complete: input.incidentCount > 0,
    },
  ];
}

export function countCompletedOnboardingSteps(steps: OnboardingStep[]): number {
  return steps.filter((step) => step.complete).length;
}
