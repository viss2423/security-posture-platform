import { cache } from 'react';
import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';
import type { Me } from '@/lib/api';
import { serverApiFetch, type ServerApiOptions } from '@/lib/serverApi';

export const SESSION_COOKIE_NAME = 'secplat_access_token';
const SESSION_MAX_AGE_SECONDS = 60 * 60 * 24;

export type SessionUser = Me & {
  canMutate: boolean;
  isAdmin: boolean;
};

export function sessionCookieOptions() {
  return {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: process.env.NODE_ENV === 'production',
    path: '/',
    maxAge: SESSION_MAX_AGE_SECONDS,
  };
}

export function roleCapabilities(role?: string | null) {
  const normalizedRole = (role || '').toLowerCase();
  return {
    isAdmin: normalizedRole === 'admin',
    canMutate: normalizedRole === 'admin' || normalizedRole === 'analyst',
  };
}

function toSessionUser(me: Me): SessionUser {
  return {
    ...me,
    ...roleCapabilities(me.role),
  };
}

export const getServerSession = cache(async (): Promise<SessionUser | null> => {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;
  if (!token) return null;

  try {
    const me = await serverApiFetch<Me>('/auth/me', {
      token,
      cache: 'no-store',
    });
    return toSessionUser(me);
  } catch {
    return null;
  }
});

export async function requireServerSession(): Promise<SessionUser> {
  const user = await getServerSession();
  if (!user) {
    redirect('/login');
  }
  return user;
}

export async function withServerSession<T>(
  path: string,
  options?: Omit<ServerApiOptions, 'token'>
): Promise<T> {
  const cookieStore = await cookies();
  const token = cookieStore.get(SESSION_COOKIE_NAME)?.value;
  if (!token) {
    redirect('/login');
  }
  try {
    return await serverApiFetch<T>(path, {
      ...options,
      token,
    });
  } catch (error) {
    if (error instanceof Error && error.message === 'Unauthorized') {
      redirect('/login');
    }
    throw error;
  }
}
