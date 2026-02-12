import { NextRequest, NextResponse } from 'next/server';

const API_URL = process.env.API_URL || 'http://api:8000';

export async function GET(request: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path.join('/');
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;
  
  const headers: Record<string, string> = {};
  const authHeader = request.headers.get('authorization');
  if (authHeader) headers['Authorization'] = authHeader;
  headers['Content-Type'] = 'application/json';

  try {
    const res = await fetch(targetUrl, { headers, cache: 'no-store' });
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

export async function POST(request: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path.join('/');
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;

  const headers: Record<string, string> = {};
  const authHeader = request.headers.get('authorization');
  if (authHeader) headers['Authorization'] = authHeader;
  headers['Content-Type'] = 'application/json';

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

export async function PATCH(request: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path.join('/');
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;

  const headers: Record<string, string> = {};
  const authHeader = request.headers.get('authorization');
  if (authHeader) headers['Authorization'] = authHeader;
  headers['Content-Type'] = 'application/json';

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

export async function DELETE(request: NextRequest, { params }: { params: { path: string[] } }) {
  const path = params.path.join('/');
  const url = new URL(request.url);
  const targetUrl = `${API_URL}/${path}${url.search}`;

  const headers: Record<string, string> = {};
  const authHeader = request.headers.get('authorization');
  if (authHeader) headers['Authorization'] = authHeader;

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
