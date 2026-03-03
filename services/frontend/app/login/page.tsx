import { redirect } from 'next/navigation';
import LoginForm from '@/components/LoginForm';
import type { AuthConfig } from '@/lib/api';
import { serverApiFetch } from '@/lib/serverApi';
import { getServerSession } from '@/lib/session';

export default async function LoginPage() {
  const user = await getServerSession();
  if (user) {
    redirect('/overview');
  }

  let oidcEnabled = false;
  try {
    const config = await serverApiFetch<AuthConfig>('/auth/config', { cache: 'no-store' });
    oidcEnabled = Boolean(config.oidc_enabled);
  } catch {
    oidcEnabled = false;
  }

  return <LoginForm oidcEnabled={oidcEnabled} />;
}
