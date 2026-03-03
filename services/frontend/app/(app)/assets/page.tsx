import AssetsPageClient from '@/components/AssetsPageClient';
import { EmptyState, ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import type { AssetPosture } from '@/lib/api';
import {
  parsePostureFilters,
  type SearchParamsInput,
  writePostureFilters,
} from '@/lib/postureFilters';
import { withServerSession } from '@/lib/session';

type PageProps = {
  searchParams?: Promise<SearchParamsInput>;
};

function filtersToSuffix(filters: ReturnType<typeof parsePostureFilters>): string {
  const params = writePostureFilters(new URLSearchParams(), filters);
  const query = params.toString();
  return query ? `?${query}` : '';
}

export default async function AssetsPage({ searchParams }: PageProps) {
  const resolvedSearchParams = (await searchParams) ?? {};
  const filters = parsePostureFilters(resolvedSearchParams);
  const filterSuffix = filtersToSuffix(filters);
  const result = await withServerSession<{ total: number; items: AssetPosture[] }>(
    `/posture${filterSuffix}`,
    {
      cache: 'no-store',
    }
  )
    .then((data) => ({ data, error: null as string | null }))
    .catch((error) => ({
      data: null as { total: number; items: AssetPosture[] } | null,
      error: error instanceof Error ? error.message : 'Request failed',
    }));

  if (result.error) {
    return (
      <main className="page-shell overflow-visible">
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(result.error)}
          <ApiDownHint />
        </div>
      </main>
    );
  }

  if (!result.data || result.data.items.length === 0) {
    return (
      <main className="page-shell overflow-visible">
        <EmptyState
          icon={<span className="text-2xl font-bold text-[var(--muted)]">0</span>}
          title="No assets yet"
          description="Assets appear here once posture data is ingested. Ingestion runs every 60s when the stack is up. Check that the ingestion container is running."
        />
      </main>
    );
  }

  return <AssetsPageClient items={result.data.items} />;
}
