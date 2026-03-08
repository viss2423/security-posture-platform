import { NextRequest, NextResponse } from 'next/server';
import {
  REFRESH_SESSION_COOKIE_NAME,
  SESSION_COOKIE_NAME,
  refreshSessionCookieOptions,
  sessionCookieOptions,
} from '@/lib/session';

const API_URL = process.env.API_URL || 'http://127.0.0.1:8000';
type TokenPayload = {
  access_token?: string;
  refresh_token?: string;
};

function errorResponse(message: string, status: number) {
  return NextResponse.json({ error: message }, { status });
}

function parseErrorMessage(text: string, fallback: string): string {
  if (!text) return fallback;
  try {
    const data = JSON.parse(text);
    if (typeof data?.detail === 'string') return data.detail;
    if (typeof data?.error === 'string') return data.error;
  } catch {
    return text;
  }
  return fallback;
}

function clearSessionCookies(response: NextResponse) {
  response.cookies.set(SESSION_COOKIE_NAME, '', {
    ...sessionCookieOptions(),
    maxAge: 0,
  });
  response.cookies.set(REFRESH_SESSION_COOKIE_NAME, '', {
    ...refreshSessionCookieOptions(),
    maxAge: 0,
  });
}

export async function POST(request: NextRequest) {
  let accessToken: string | null = null;
  let refreshToken: string | null = null;

  try {
    const body = await request.json();
    if (typeof body?.access_token === 'string' && body.access_token.trim()) {
      accessToken = body.access_token.trim();
      if (typeof body?.refresh_token === 'string' && body.refresh_token.trim()) {
        refreshToken = body.refresh_token.trim();
      }
    } else {
      const username = String(body?.username || '').trim();
      const password = String(body?.password || '');
      if (!username || !password) {
        return errorResponse('Username and password are required', 400);
      }

      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Accept: 'application/json',
        },
        body: new URLSearchParams({ username, password }),
        cache: 'no-store',
      });
      const text = await response.text();
      if (!response.ok) {
        return errorResponse(
          parseErrorMessage(text, response.statusText || 'Login failed'),
          response.status
        );
      }
      const payload = JSON.parse(text) as TokenPayload;
      accessToken = payload.access_token?.trim() || null;
      refreshToken = payload.refresh_token?.trim() || null;
    }
  } catch {
    return errorResponse('Invalid login payload', 400);
  }

  if (!accessToken) {
    return errorResponse('Login failed', 401);
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(SESSION_COOKIE_NAME, accessToken, sessionCookieOptions());
  if (refreshToken) {
    response.cookies.set(
      REFRESH_SESSION_COOKIE_NAME,
      refreshToken,
      refreshSessionCookieOptions()
    );
  } else {
    response.cookies.set(REFRESH_SESSION_COOKIE_NAME, '', {
      ...refreshSessionCookieOptions(),
      maxAge: 0,
    });
  }
  return response;
}

export async function PATCH(request: NextRequest) {
  const refreshToken = request.cookies.get(REFRESH_SESSION_COOKIE_NAME)?.value?.trim();
  if (!refreshToken) {
    const response = errorResponse('Not authenticated', 401);
    clearSessionCookies(response);
    return response;
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}/auth/refresh`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ refresh_token: refreshToken }),
      cache: 'no-store',
    });
  } catch {
    return errorResponse('API unreachable', 502);
  }

  const text = await response.text();
  if (!response.ok) {
    const error = errorResponse(
      parseErrorMessage(text, response.statusText || 'Session refresh failed'),
      response.status
    );
    clearSessionCookies(error);
    return error;
  }

  let payload: TokenPayload;
  try {
    payload = JSON.parse(text) as TokenPayload;
  } catch {
    return errorResponse('Invalid refresh response', 502);
  }
  const accessToken = payload.access_token?.trim();
  const nextRefreshToken = payload.refresh_token?.trim();
  if (!accessToken || !nextRefreshToken) {
    return errorResponse('Invalid refresh response', 502);
  }

  const out = NextResponse.json({ ok: true });
  out.cookies.set(SESSION_COOKIE_NAME, accessToken, sessionCookieOptions());
  out.cookies.set(
    REFRESH_SESSION_COOKIE_NAME,
    nextRefreshToken,
    refreshSessionCookieOptions()
  );
  return out;
}

export async function DELETE() {
  const response = NextResponse.json({ ok: true });
  clearSessionCookies(response);
  return response;
}
