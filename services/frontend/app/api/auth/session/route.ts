import { NextRequest, NextResponse } from 'next/server';
import { SESSION_COOKIE_NAME, sessionCookieOptions } from '@/lib/session';

const API_URL = process.env.API_URL || 'http://127.0.0.1:8000';

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

export async function POST(request: NextRequest) {
  let accessToken: string | null = null;

  try {
    const body = await request.json();
    if (typeof body?.access_token === 'string' && body.access_token.trim()) {
      accessToken = body.access_token.trim();
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
      const payload = JSON.parse(text) as { access_token?: string };
      accessToken = payload.access_token?.trim() || null;
    }
  } catch {
    return errorResponse('Invalid login payload', 400);
  }

  if (!accessToken) {
    return errorResponse('Login failed', 401);
  }

  const response = NextResponse.json({ ok: true });
  response.cookies.set(SESSION_COOKIE_NAME, accessToken, sessionCookieOptions());
  return response;
}

export async function DELETE() {
  const response = NextResponse.json({ ok: true });
  response.cookies.set(SESSION_COOKIE_NAME, '', {
    ...sessionCookieOptions(),
    maxAge: 0,
  });
  return response;
}
