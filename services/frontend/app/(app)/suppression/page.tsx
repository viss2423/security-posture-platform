'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  createMaintenanceWindow,
  createSuppressionRule,
  deleteMaintenanceWindow,
  deleteSuppressionRule,
  getMaintenanceWindows,
  getSuppressionRules,
  type MaintenanceWindow,
  type SuppressionRule,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

type Scope = 'asset' | 'finding' | 'all';

function toIso(value: string): string {
  if (!value) return '';
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return '';
  return d.toISOString();
}

function defaultTimeRange(hours: number = 2): { start: string; end: string } {
  const start = new Date();
  const end = new Date(start.getTime() + hours * 3600 * 1000);
  return {
    start: start.toISOString().slice(0, 16),
    end: end.toISOString().slice(0, 16),
  };
}

export default function SuppressionPage() {
  const { canMutate } = useAuth();
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [mwActiveOnly, setMwActiveOnly] = useState(false);
  const [rulesActiveOnly, setRulesActiveOnly] = useState(false);
  const [mwItems, setMwItems] = useState<MaintenanceWindow[]>([]);
  const [ruleItems, setRuleItems] = useState<SuppressionRule[]>([]);

  const defaultMw = useMemo(() => defaultTimeRange(2), []);
  const defaultRule = useMemo(() => defaultTimeRange(6), []);

  const [mwAssetKey, setMwAssetKey] = useState('');
  const [mwStart, setMwStart] = useState(defaultMw.start);
  const [mwEnd, setMwEnd] = useState(defaultMw.end);
  const [mwReason, setMwReason] = useState('');

  const [ruleScope, setRuleScope] = useState<Scope>('asset');
  const [ruleScopeValue, setRuleScopeValue] = useState('');
  const [ruleStart, setRuleStart] = useState(defaultRule.start);
  const [ruleEnd, setRuleEnd] = useState(defaultRule.end);
  const [ruleReason, setRuleReason] = useState('');

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    Promise.all([
      getMaintenanceWindows({ activeOnly: mwActiveOnly }),
      getSuppressionRules({ activeOnly: rulesActiveOnly }),
    ])
      .then(([mw, rules]) => {
        setMwItems(mw.items || []);
        setRuleItems(rules.items || []);
      })
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, [mwActiveOnly, rulesActiveOnly]);

  useEffect(() => {
    load();
  }, [load]);

  const createMw = async () => {
    setLoading(true);
    setError(null);
    try {
      await createMaintenanceWindow({
        asset_key: mwAssetKey.trim(),
        start_at: toIso(mwStart),
        end_at: toIso(mwEnd),
        reason: mwReason || undefined,
      });
      setMwAssetKey('');
      setMwReason('');
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const createRule = async () => {
    setLoading(true);
    setError(null);
    try {
      await createSuppressionRule({
        scope: ruleScope,
        scope_value: ruleScope === 'all' ? undefined : ruleScopeValue.trim(),
        starts_at: toIso(ruleStart),
        ends_at: toIso(ruleEnd),
        reason: ruleReason || undefined,
      });
      setRuleScopeValue('');
      setRuleReason('');
      load();
    } catch (e: any) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const canCreateMw = mwAssetKey.trim() && mwStart && mwEnd;
  const canCreateRule = ruleStart && ruleEnd && (ruleScope === 'all' || ruleScopeValue.trim());

  return (
    <main className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
      <h1 className="page-title mb-10">Suppression & Maintenance</h1>
      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      <section className="mb-10 grid gap-6 lg:grid-cols-2">
        <div className="card">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-[var(--text)]">Maintenance Windows</h2>
              <p className="text-sm text-[var(--muted)]">Suppress alerts/incidents for a specific asset.</p>
            </div>
            <label className="flex items-center gap-2 text-sm text-[var(--muted)]">
              <input
                type="checkbox"
                checked={mwActiveOnly}
                onChange={(e) => setMwActiveOnly(e.target.checked)}
                className="h-4 w-4"
              />
              Active only
            </label>
          </div>

          {canMutate ? (
            <div className="mt-6 grid gap-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <input
                  className="input"
                  placeholder="asset_key"
                  value={mwAssetKey}
                  onChange={(e) => setMwAssetKey(e.target.value)}
                />
                <input
                  className="input"
                  placeholder="Reason (optional)"
                  value={mwReason}
                  onChange={(e) => setMwReason(e.target.value)}
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <input className="input" type="datetime-local" value={mwStart} onChange={(e) => setMwStart(e.target.value)} />
                <input className="input" type="datetime-local" value={mwEnd} onChange={(e) => setMwEnd(e.target.value)} />
              </div>
              <div className="flex items-center gap-3">
                <button type="button" className="btn-primary" disabled={!canCreateMw || loading} onClick={createMw}>
                  Create window
                </button>
                <button type="button" className="btn-secondary" onClick={load} disabled={loading}>
                  Refresh
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-6 text-sm text-[var(--muted)]">You need analyst or admin rights to create windows.</div>
          )}

          <div className="mt-6 space-y-3">
            {mwItems.length === 0 && <div className="text-sm text-[var(--muted)]">No maintenance windows found.</div>}
            {mwItems.map((mw) => (
              <div key={mw.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-4 py-3">
                <div>
                  <div className="font-medium text-[var(--text)]">{mw.asset_key}</div>
                  <div className="text-xs text-[var(--muted)]">
                    {formatDateTime(mw.start_at)} → {formatDateTime(mw.end_at)}
                  </div>
                  {mw.reason && <div className="text-xs text-[var(--muted)]">Reason: {mw.reason}</div>}
                </div>
                {canMutate && (
                  <button
                    type="button"
                    className="btn-secondary text-sm"
                    onClick={() => deleteMaintenanceWindow(mw.id).then(load).catch((e) => setError(e.message))}
                  >
                    Delete
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>

        <div className="card">
          <div className="flex items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-[var(--text)]">Suppression Rules</h2>
              <p className="text-sm text-[var(--muted)]">Suppress findings or assets across a time window.</p>
            </div>
            <label className="flex items-center gap-2 text-sm text-[var(--muted)]">
              <input
                type="checkbox"
                checked={rulesActiveOnly}
                onChange={(e) => setRulesActiveOnly(e.target.checked)}
                className="h-4 w-4"
              />
              Active only
            </label>
          </div>

          {canMutate ? (
            <div className="mt-6 grid gap-3">
              <div className="grid gap-3 sm:grid-cols-2">
                <select className="input" value={ruleScope} onChange={(e) => setRuleScope(e.target.value as Scope)}>
                  <option value="asset">Asset</option>
                  <option value="finding">Finding</option>
                  <option value="all">All</option>
                </select>
                <input
                  className="input"
                  placeholder={ruleScope === 'finding' ? 'finding_key' : 'asset_key'}
                  value={ruleScopeValue}
                  onChange={(e) => setRuleScopeValue(e.target.value)}
                  disabled={ruleScope === 'all'}
                />
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <input className="input" type="datetime-local" value={ruleStart} onChange={(e) => setRuleStart(e.target.value)} />
                <input className="input" type="datetime-local" value={ruleEnd} onChange={(e) => setRuleEnd(e.target.value)} />
              </div>
              <input
                className="input"
                placeholder="Reason (optional)"
                value={ruleReason}
                onChange={(e) => setRuleReason(e.target.value)}
              />
              <div className="flex items-center gap-3">
                <button type="button" className="btn-primary" disabled={!canCreateRule || loading} onClick={createRule}>
                  Create rule
                </button>
                <button type="button" className="btn-secondary" onClick={load} disabled={loading}>
                  Refresh
                </button>
              </div>
            </div>
          ) : (
            <div className="mt-6 text-sm text-[var(--muted)]">You need analyst or admin rights to create rules.</div>
          )}

          <div className="mt-6 space-y-3">
            {ruleItems.length === 0 && <div className="text-sm text-[var(--muted)]">No suppression rules found.</div>}
            {ruleItems.map((rule) => (
              <div key={rule.id} className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface)] px-4 py-3">
                <div>
                  <div className="font-medium text-[var(--text)]">
                    {rule.scope}
                    {rule.scope_value ? `: ${rule.scope_value}` : ''}
                  </div>
                  <div className="text-xs text-[var(--muted)]">
                    {formatDateTime(rule.starts_at)} → {formatDateTime(rule.ends_at)}
                  </div>
                  {rule.reason && <div className="text-xs text-[var(--muted)]">Reason: {rule.reason}</div>}
                </div>
                {canMutate && (
                  <button
                    type="button"
                    className="btn-secondary text-sm"
                    onClick={() => deleteSuppressionRule(rule.id).then(load).catch((e) => setError(e.message))}
                  >
                    Delete
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      </section>
    </main>
  );
}
