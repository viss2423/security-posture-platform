import { fireEvent, render, screen, waitFor } from '@testing-library/react';

import AlertsPage from '@/app/(app)/alerts/page';

const apiMocks = vi.hoisted(() => ({
  getAlerts: vi.fn(),
  getAlertClusters: vi.fn(),
  getAlertAIGuidance: vi.fn(),
  generateAlertAIGuidance: vi.fn(),
  postAlertAck: vi.fn(),
  postAlertSuppress: vi.fn(),
  postAlertResolve: vi.fn(),
  postAlertAssign: vi.fn(),
  createAISummaryVersion: vi.fn(),
  createAIFeedback: vi.fn(),
}));

vi.mock('@/contexts/AuthContext', () => ({
  useAuth: () => ({
    canMutate: true,
    user: { username: 'analyst-1', role: 'analyst' },
  }),
}));

vi.mock('@/lib/api', async () => {
  const actual = await vi.importActual<typeof import('@/lib/api')>('@/lib/api');
  return {
    ...actual,
    ...apiMocks,
  };
});

describe('AlertsPage', () => {
  beforeEach(() => {
    apiMocks.getAlertClusters.mockResolvedValue({ cluster_by: 'asset', status: 'firing', items: [] });
    apiMocks.getAlerts.mockResolvedValue({
      firing: [
        {
          asset_key: 'gateway-1',
          source: 'cowrie',
          severity: 'high',
          description: 'Repeated failed login attempts',
          ai_recommended_action: 'ack',
          ai_requires_human_approval: true,
        },
      ],
      acked: [],
      suppressed: [],
      resolved: [],
    });
    apiMocks.getAlertAIGuidance.mockResolvedValue({
      asset_key: 'gateway-1',
      guidance_text: 'Acknowledge after analyst review and continue monitoring.',
      recommended_action: 'ack',
      requires_human_approval: true,
      approval_mode: 'manual_required',
      urgency: 'high',
      provider: 'ollama',
      model: 'llama3.1:8b',
      generated_at: '2026-03-31T20:00:00Z',
      context_json: {},
    });
    apiMocks.postAlertAck.mockResolvedValue({ ok: true });
    apiMocks.postAlertSuppress.mockResolvedValue({ ok: true });
    apiMocks.postAlertResolve.mockResolvedValue({ ok: true });
    apiMocks.postAlertAssign.mockResolvedValue({ ok: true });
    apiMocks.createAISummaryVersion.mockResolvedValue({ version_no: 1 });
    apiMocks.createAIFeedback.mockResolvedValue({ ok: true });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('requires operator acknowledgement before applying an AI recommendation', async () => {
    render(<AlertsPage />);

    await screen.findByText(/repeated failed login attempts/i);

    fireEvent.click(screen.getByRole('button', { name: /ai guidance/i }));

    await screen.findByText(/acknowledge after analyst review/i);

    const applyButton = await screen.findByRole('button', { name: /apply recommendation/i });
    expect(applyButton).toBeDisabled();

    fireEvent.click(
      screen.getByLabelText(
        /i reviewed the ai recommendation and accept responsibility for the resulting alert-state change/i
      )
    );

    await waitFor(() => expect(applyButton).not.toBeDisabled());

    fireEvent.click(applyButton);

    await waitFor(() => {
      expect(apiMocks.postAlertAck).toHaveBeenCalledWith(
        { asset_key: 'gateway-1' },
        'AI-guided acknowledgement'
      );
    });
  });
});
