import type { PostureFilters } from '@/lib/api';

type SearchParamValue = string | string[] | undefined;
export type SearchParamsInput = Record<string, SearchParamValue>;

function firstValue(value: SearchParamValue): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function normalize(value: SearchParamValue): string | undefined {
  const normalized = (firstValue(value) || '').trim();
  return normalized ? normalized : undefined;
}

export function parsePostureFilters(searchParams: SearchParamsInput): PostureFilters {
  return {
    environment: normalize(searchParams.environment),
    criticality: normalize(searchParams.criticality),
    owner: normalize(searchParams.owner),
    status: normalize(searchParams.status),
  };
}

export function writePostureFilters(params: URLSearchParams, filters: PostureFilters): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const key of ['environment', 'criticality', 'owner', 'status'] as const) {
    const value = filters[key];
    if (value) next.set(key, value);
    else next.delete(key);
  }
  return next;
}
