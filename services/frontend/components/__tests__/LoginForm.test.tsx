import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import LoginForm from '@/components/LoginForm';

const replace = vi.fn();
const refresh = vi.fn();

vi.mock('next/navigation', () => ({
  useRouter: () => ({
    replace,
    refresh,
  }),
}));

describe('LoginForm', () => {
  beforeEach(() => {
    replace.mockReset();
    refresh.mockReset();
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        text: async () => JSON.stringify({ ok: true }),
      })
    );
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('submits credentials and redirects to the overview page', async () => {
    render(<LoginForm oidcEnabled={false} />);

    fireEvent.change(screen.getByLabelText(/username/i), {
      target: { value: 'admin' },
    });
    fireEvent.change(screen.getByLabelText(/password/i), {
      target: { value: 'admin' },
    });
    fireEvent.click(screen.getByRole('button', { name: /sign in/i }));

    await waitFor(() => {
      expect(fetch).toHaveBeenCalledWith(
        '/api/auth/session',
        expect.objectContaining({
          method: 'POST',
        })
      );
      expect(replace).toHaveBeenCalledWith('/overview');
      expect(refresh).toHaveBeenCalled();
    });
  });
});
