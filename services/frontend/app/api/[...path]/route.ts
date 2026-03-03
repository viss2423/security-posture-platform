import { NextRequest, NextResponse } from 'next/server';
import { SESSION_COOKIE_NAME } from '@/lib/session';

// When running frontend on host (npm run dev), "api" may not resolve; use localhost.
const API_URL = process.env.API_URL || 'http://127.0.0.1:8000';

type RouteContext = { params: Promise<{ path: string[] }> };

async function resolvePath(context: RouteContext): Promise<string> {
  const params = await context.params;
  return params.path.join('/');
}

function buildForwardHeaders(request: NextRequest): Record<string, string> {
  const headers: Record<string, string> = {};
  const authHeader = request.headers.get('authorization');
  const cookieToken = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  const token = authHeader || (cookieToken ? `Bearer ${cookieToken}` : null);
  if (token) headers.Authorization = token;
  const contentType = request.headers.get('content-type');
  if (contentType) headers['Content-Type'] = contentType;
  return headers;
}

export async function GET(request: NextRequest, context: RouteContext) {
  const path = await resolvePath(context);
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;

  const headers = buildForwardHeaders(request);
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';

  try {
    let res = await fetch(targetUrl, { headers, cache: 'no-store', redirect: 'manual' });
    // Follow redirects to the same API (e.g. FastAPI trailing-slash 307).
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('Location');
      if (location) {
        const isSameApi = location.startsWith('/') || location.startsWith(API_URL);
        if (isSameApi) {
          const nextUrl = location.startsWith('http') ? location : `${API_URL.replace(/\/$/, '')}${location}`;
          res = await fetch(nextUrl, { headers, cache: 'no-store', redirect: 'manual' });
        } else {
          return NextResponse.redirect(location, res.status as 301 | 302 | 303 | 307 | 308);
        }
      }
    }
    const contentType = res.headers.get('Content-Type') || 'application/json';
    if (contentType.startsWith('application/pdf') || contentType.startsWith('text/csv')) {
      const blob = await res.arrayBuffer();
      const outHeaders = new Headers({ 'Content-Type': contentType });
      const disp = res.headers.get('Content-Disposition');
      if (disp) outHeaders.set('Content-Disposition', disp);
      return new NextResponse(blob, { status: res.status, headers: outHeaders });
    }
    const data = await res.text();
    return new NextResponse(data, {
      status: res.status,
      headers: { 'Content-Type': contentType },
    });
  } catch (e) {
    console.error('API proxy error:', e);
    return NextResponse.json({ error: 'API unreachable' }, { status: 502 });
  }
}

export async function POST(request: NextRequest, context: RouteContext) {
  const path = await resolvePath(context);
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;

  const headers = buildForwardHeaders(request);
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';

  try {
    const body = await request.text();
    const res = await fetch(targetUrl, { method: 'POST', headers, body, cache: 'no-store' });
    const data = await res.text();
    return new NextResponse(data, {
      status: res.status,
      headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' },
    });
  } catch (e) {
    console.error('API proxy error:', e);
    return NextResponse.json({ error: 'API unreachable' }, { status: 502 });
  }
}

export async function PATCH(request: NextRequest, context: RouteContext) {
  const path = await resolvePath(context);
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;

  const headers = buildForwardHeaders(request);
  headers['Content-Type'] = headers['Content-Type'] || 'application/json';

  try {
    const body = await request.text();
    const res = await fetch(targetUrl, { method: 'PATCH', headers, body, cache: 'no-store' });
    const data = await res.text();
    return new NextResponse(data, {
      status: res.status,
      headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' },
    });
  } catch (e) {
    console.error('API proxy error:', e);
    return NextResponse.json({ error: 'API unreachable' }, { status: 502 });
  }
}

export async function DELETE(request: NextRequest, context: RouteContext) {
  const path = await resolvePath(context);
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;

  const headers = buildForwardHeaders(request);

  try {
    const res = await fetch(targetUrl, { method: 'DELETE', headers, cache: 'no-store' });
    const data = await res.text();
    return new NextResponse(data, {
      status: res.status,
      headers: { 'Content-Type': res.headers.get('Content-Type') || 'application/json' },
    });
  } catch (e) {
    console.error('API proxy error:', e);
    return NextResponse.json({ error: 'API unreachable' }, { status: 502 });
  }
}
