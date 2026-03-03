const API_URL = process.env.API_URL || 'http://127.0.0.1:8000';

export type ServerApiOptions = RequestInit & {
  token?: string | null;
};

function parseErrorMessage(status: number, text: string, fallback: string): string {
  if (!text) return fallback;
  try {
    const data = JSON.parse(text);
    if (typeof data?.error?.message === 'string') return data.error.message;
    if (typeof data?.error === 'string') return data.error;
    if (typeof data?.detail === 'string') return data.detail;
  } catch {
    return text;
  }
  return fallback;
}

export async function serverApiFetch<T>(path: string, options?: ServerApiOptions): Promise<T> {
  const url = `${API_URL}${path}`;
  const res = await fetch(url, {
    ...options,
    headers: {
      Accept: 'application/json',
      ...(options?.body ? { 'Content-Type': 'application/json' } : {}),
      ...(options?.token ? { Authorization: `Bearer ${options.token}` } : {}),
      ...options?.headers,
    },
    cache: options?.cache ?? 'no-store',
  });

  if (res.status === 401) {
    throw new Error('Unauthorized');
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(parseErrorMessage(res.status, text, res.statusText || 'Request failed'));
  }

  return res.json();
}
