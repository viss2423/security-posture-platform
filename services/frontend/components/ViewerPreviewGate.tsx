'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Eye, Lock } from 'lucide-react';
import { useAuth } from '@/contexts/AuthContext';
import { getDemoPreview, type FeaturePreview, type PreviewTone } from '@/lib/demoPreviews';

const TONE_CLASSES: Record<PreviewTone, string> = {
  green: 'text-[var(--green)]',
  amber: 'text-[var(--amber)]',
  red: 'text-[var(--red)]',
  accent: 'text-[var(--accent)]',
  muted: 'text-[var(--text-muted)]',
};

function severityCellClass(value: string): string {
  const v = value.toLowerCase();
  if (v.includes('critical') || v === 'sev-1' || v === 'fail') return 'text-[var(--red)] font-semibold';
  if (v.includes('high') || v === 'sev-2' || v === 'firing') return 'text-[var(--red)]';
  if (v.includes('medium') || v.includes('amber') || v === 'acknowledged' || v === 'running') return 'text-[var(--amber)]';
  if (v.includes('low') || v === 'pass' || v === 'done' || v === 'resolved' || v === 'detected in 2s') return 'text-[var(--green)]';
  return '';
}

function DemoPreviewView({ preview }: { preview: FeaturePreview }) {
  return (
    <main className="page-shell">
      {/* Read-only banner */}
      <div className="flex flex-wrap items-center gap-3 rounded-xl border border-[var(--accent)]/25 bg-[var(--accent-dim)] px-4 py-3">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-[var(--accent)]/15 text-[var(--accent)]">
          <Eye size={15} />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-[var(--text)]">Read-only preview with sample data</p>
          <p className="text-xs text-[var(--text-muted)]">
            This is what the feature looks like in operation. Operator accounts get the full
            interactive workspace — explore your live sandbox in{' '}
            <Link href="/assets" className="text-[var(--accent)] hover:underline">Assets</Link> and{' '}
            <Link href="/findings" className="text-[var(--accent)] hover:underline">Risk Review</Link>.
          </p>
        </div>
        <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-[var(--border)] bg-[var(--surface-elevated)] px-2.5 py-1 text-[10px] font-semibold uppercase tracking-widest text-[var(--text-muted)]">
          <Lock size={10} />
          Preview
        </span>
      </div>

      {/* Header + stats */}
      <section className="page-hero">
        <h1 className="page-title">{preview.title}</h1>
        <p className="hero-copy">{preview.tagline}</p>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {preview.stats.map((stat) => (
            <div key={stat.label} className="rounded-xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
              <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-[var(--text-subtle)]">
                {stat.label}
              </p>
              <p className={`mt-1 text-2xl font-bold tabular-nums ${TONE_CLASSES[stat.tone ?? 'muted']}`}>
                {stat.value}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* Highlight cards (e.g. alert sources) */}
      {preview.cards && preview.cards.length > 0 && (
        <section className="section-panel">
          {preview.cardsHeading && <h2 className="section-title">{preview.cardsHeading}</h2>}
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
            {preview.cards.map((card) => (
              <article key={card.title} className="rounded-xl border border-[var(--border)] bg-[var(--surface-soft)] p-4">
                <div className="flex items-center justify-between gap-2">
                  <h3 className="text-sm font-semibold text-[var(--text)]">{card.title}</h3>
                  {card.badge && (
                    <span className={`shrink-0 rounded px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-widest bg-[var(--surface-elevated)] ${TONE_CLASSES[card.tone ?? 'muted']}`}>
                      {card.badge}
                    </span>
                  )}
                </div>
                <p className="mt-1.5 text-xs leading-relaxed text-[var(--text-muted)]">{card.body}</p>
              </article>
            ))}
          </div>
        </section>
      )}

      {/* Sample table */}
      {preview.table && (
        <section className="section-panel">
          {preview.tableHeading && <h2 className="section-title">{preview.tableHeading}</h2>}
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="thead-row">
                  {preview.table.columns.map((column) => (
                    <th key={column} className="px-3 py-2 text-[11px] font-semibold uppercase tracking-[0.08em] text-[var(--text-subtle)]">
                      {column}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {preview.table.rows.map((row, rowIndex) => (
                  <tr key={rowIndex} className="border-t border-[var(--border)]">
                    {row.map((cell, cellIndex) => (
                      <td key={cellIndex} className={`px-3 py-2.5 text-[13px] text-[var(--text-muted)] ${severityCellClass(cell)}`}>
                        {cell}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* Capabilities */}
      <section className="section-panel">
        <h2 className="section-title">What operators can do here</h2>
        <ul className="grid gap-2 sm:grid-cols-2">
          {preview.capabilities.map((capability) => (
            <li key={capability} className="flex items-start gap-2 text-sm text-[var(--text-muted)]">
              <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--accent)]" />
              {capability}
            </li>
          ))}
        </ul>
        <p className="mt-4 text-xs text-[var(--text-subtle)]">
          Want full access? Ask your administrator to upgrade your account to analyst.
        </p>
      </section>
    </main>
  );
}

/**
 * For viewer-role users, operator-only routes render a static, read-only feature
 * preview (fabricated sample data) instead of the live page. Operators and admins
 * always get the real page.
 */
export default function ViewerPreviewGate({ children }: { children: React.ReactNode }) {
  const { user } = useAuth();
  const pathname = usePathname();
  const role = (user?.role ?? '').toLowerCase();
  const isOperator = role === 'admin' || role === 'analyst';

  if (!isOperator) {
    const preview = getDemoPreview(pathname);
    if (preview) return <DemoPreviewView preview={preview} />;
  }
  return <>{children}</>;
}
