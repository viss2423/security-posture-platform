import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import OnboardingPageClient from '@/components/OnboardingPageClient';

const apiMocks = vi.hoisted(() => ({
  getAssets: vi.fn(),
  getTelemetrySummary: vi.fn(),
  getDetectionRules: vi.fn(),
  getAlerts: vi.fn(),
  getIncidents: vi.fn(),
  getPlatformDemoStatus: vi.fn(),
  createAsset: vi.fn(),
  ingestTelemetry: vi.fn(),
  createDetectionRule: vi.fn(),
  testDetectionRule: vi.fn(),
  createIncident: vi.fn(),
  seedDemoEnvironment: vi.fn(),
  resetDemoEnvironment: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    canMutate: true,
    isAdmin: true,
    user: { username: 'admin', role: 'admin' },
  }),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    ...apiMocks,
  };
});

describe('OnboardingPageClient', () => {
  beforeEach(() => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => ({ oidc_enabled: false }),
      })
    );
    apiMocks.getAssets.mockResolvedValue([]);
    apiMocks.getTelemetrySummary.mockResolvedValue({
      totals: { events: 0, ti_matches: 0, assets: 0, sources: 0 },
      sources: [],
      recent_alerts: [],
      latest_anomaly_scores: [],
    });
    apiMocks.getDetectionRules.mockResolvedValue({ items: [] });
    apiMocks.getAlerts.mockResolvedValue({
      firing: [],
      acked: [],
      suppressed: [],
      resolved: [],
    });
    apiMocks.getIncidents.mockResolvedValue({ total: 0, items: [] });
    apiMocks.getPlatformDemoStatus.mockResolvedValue({
      seed_version: 'v1',
      asset_key: 'cyberlab-demo-asset',
      repo_asset_key: 'cyberlab-demo-repo',
      ioc_source: 'cyberlab-demo',
      rule_name: 'cyberlab-demo-cowrie-login-failed-v1',
      seeded: false,
      assets_present: 0,
      assets: [],
      telemetry_events: 0,
      alerts: 0,
      incidents: 0,
      repository_findings: 0,
      attack_lab_runs: 0,
      detection_rule: null,
      latest_seed_at: null,
      latest_seed_details: null,
    });
    apiMocks.createAsset.mockResolvedValue({
      asset_id: 1,
      asset_key: 'onboarding-edge-gateway',
      type: 'external_web',
      name: 'Edge gateway',
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
    vi.unstubAllGlobals();
  });

  it('renders onboarding progress and can create an asset', async () => {
    render(<OnboardingPageClient />);

    await screen.findByText(/launch your account in one guided flow/i);
    expect(screen.getByText(/0 assets/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole('button', { name: /create asset/i }));

    await waitFor(() => {
      expect(apiMocks.createAsset).toHaveBeenCalledWith(
        expect.objectContaining({
          asset_key: 'onboarding-edge-gateway',
          type: 'external_web',
        })
      );
    });
  });
});
