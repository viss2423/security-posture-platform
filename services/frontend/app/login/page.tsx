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
  let selfRegistration = false;
  try {
    const config = await serverApiFetch<AuthConfig>('/auth/config', { cache: 'no-store' });
    oidcEnabled = Boolean(config.oidc_enabled);
    selfRegistration = Boolean(config.self_registration);
  } catch {
    oidcEnabled = false;
    selfRegistration = false;
  }

  return <LoginForm oidcEnabled={oidcEnabled} selfRegistration={selfRegistration} />;
}
