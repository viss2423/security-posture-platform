'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  createDetectionRule,
  getDetectionRules,
  getDetectionRuns,
  testDetectionRule,
  updateDetectionRule,
  type DetectionRule,
  type DetectionRun,
} from '@/lib/api';
import { friendlyApiMessage } from '@/lib/apiError';
import { ApiDownHint } from '@/components/EmptyState';
import { formatDateTime } from '@/lib/format';
import { useAuth } from '@/contexts/AuthContext';

const DEFAULT_RULE_JSON = JSON.stringify(
  {
    source: 'suricata',
    condition_mode: 'all',
    conditions: [
      { field: 'event_type', op: 'eq', value: 'alert' },
      { field: 'ti_match', op: 'is_true' },
    ],
  },
  null,
  2
);

export default function DetectionsPage() {
  const { canMutate } = useAuth();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [runs, setRuns] = useState<DetectionRun[]>([]);
  const [selectedRuleId, setSelectedRuleId] = useState<number | null>(null);
  const [ruleName, setRuleName] = useState('');
  const [ruleDescription, setRuleDescription] = useState('');
  const [ruleSource, setRuleSource] = useState('suricata');
  const [ruleSeverity, setRuleSeverity] = useState<'critical' | 'high' | 'medium' | 'low' | 'info'>('medium');
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [ruleDefinition, setRuleDefinition] = useState(DEFAULT_RULE_JSON);
  const [lookbackHours, setLookbackHours] = useState(24);
  const [lastTestSummary, setLastTestSummary] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [ruleResult, runResult] = await Promise.all([
      getDetectionRules(true),
      getDetectionRuns({ limit: 40 }),
    ]);
    setRules(ruleResult.items || []);
    setRuns(runResult.items || []);
  }, []);

  useEffect(() => {
    void load().catch((loadError) => {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load detection rules');
    });
  }, [load]);

  const selectRule = (rule: DetectionRule) => {
    setSelectedRuleId(rule.rule_id);
    setRuleName(rule.name);
    setRuleDescription(rule.description || '');
    setRuleSource(rule.source || '');
    setRuleSeverity(rule.severity);
    setRuleEnabled(rule.enabled);
    setRuleDefinition(JSON.stringify(rule.definition_json || {}, null, 2));
    setLastTestSummary(null);
  };

  const resetForm = () => {
    setSelectedRuleId(null);
    setRuleName('');
    setRuleDescription('');
    setRuleSource('suricata');
    setRuleSeverity('medium');
    setRuleEnabled(true);
    setRuleDefinition(DEFAULT_RULE_JSON);
    setLastTestSummary(null);
  };

  const saveRule = async () => {
    if (!canMutate) return;
    let parsedDefinition: Record<string, unknown>;
    try {
      parsedDefinition = ruleDefinition.trim() ? JSON.parse(ruleDefinition) : {};
    } catch {
      setError('Rule definition must be valid JSON');
      return;
    }
    if (!ruleName.trim()) {
      setError('Rule name is required');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      if (selectedRuleId) {
        await updateDetectionRule(selectedRuleId, {
          description: ruleDescription || null,
          source: ruleSource || null,
          severity: ruleSeverity,
          enabled: ruleEnabled,
          definition_json: parsedDefinition,
        });
      } else {
        await createDetectionRule({
          name: ruleName.trim(),
          description: ruleDescription || null,
          source: ruleSource || null,
          severity: ruleSeverity,
          enabled: ruleEnabled,
          definition_json: parsedDefinition,
        });
      }
      await load();
      resetForm();
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Failed to save rule');
    } finally {
      setBusy(false);
    }
  };

  const runRuleTest = async (ruleId: number) => {
    if (!canMutate) return;
    setBusy(true);
    setError(null);
    try {
      const out = await testDetectionRule(ruleId, {
        lookback_hours: lookbackHours,
        create_alerts: true,
      });
      await load();
      setLastTestSummary(
        `Rule ${ruleId} matched ${out.matches} of ${out.candidate_events} events in ${out.lookback_hours}h.`
      );
    } catch (testError) {
      setError(testError instanceof Error ? testError.message : 'Detection test failed');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="page-shell">
      <div className="mb-6">
        <h1 className="page-title">Detections</h1>
        <p className="mt-2 max-w-3xl text-sm text-[var(--text-muted)]">
          Create custom detection rules and test them against telemetry history before promoting
          to production alerts.
        </p>
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {lastTestSummary && (
        <div className="mb-6 rounded-xl border border-[var(--green)]/30 bg-[var(--green)]/10 px-4 py-3 text-sm text-[var(--text)]">
          {lastTestSummary}
        </div>
      )}

      <section className="mb-8 grid gap-6 xl:grid-cols-[minmax(0,0.95fr)_minmax(360px,1.05fr)]">
        <div className="section-panel animate-in">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="section-title">Rule inventory</h2>
            <span className="stat-chip-strong">{rules.length} rules</span>
          </div>
          {rules.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">
              No rules yet. Create your first detection rule on the right.
            </p>
          ) : (
            <ul className="space-y-3">
              {rules.map((rule) => (
                <li
                  key={rule.rule_id}
                  className={`rounded-2xl border p-4 ${
                    selectedRuleId === rule.rule_id
                      ? 'border-[var(--green)]/45 bg-[var(--green)]/10'
                      : 'border-[var(--border)] bg-[var(--surface-elevated)]/40'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <button
                      type="button"
                      onClick={() => selectRule(rule)}
                      className="text-left font-medium text-[var(--text)] hover:text-[var(--green)]"
                    >
                      {rule.name}
                    </button>
                    <div className="flex items-center gap-2">
                      <span className="stat-chip uppercase">{rule.severity}</span>
                      <span className={`stat-chip ${rule.enabled ? '' : 'opacity-70'}`}>
                        {rule.enabled ? 'enabled' : 'disabled'}
                      </span>
                    </div>
                  </div>
                  <p className="mt-2 text-xs text-[var(--muted)]">
                    {rule.source || 'all sources'}
                    {rule.last_tested_at
                      ? ` | last tested ${formatDateTime(rule.last_tested_at)} (${rule.last_test_matches ?? 0} matches)`
                      : ' | not tested yet'}
                  </p>
                  {canMutate && (
                    <div className="mt-3">
                      <button
                        type="button"
                        onClick={() => void runRuleTest(rule.rule_id)}
                        disabled={busy}
                        className="btn-secondary text-sm"
                      >
                        Test rule
                      </button>
                    </div>
                  )}
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="section-panel animate-in">
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <h2 className="section-title">{selectedRuleId ? 'Edit rule' : 'Create rule'}</h2>
            {selectedRuleId && (
              <button type="button" onClick={resetForm} className="btn-secondary text-sm">
                New rule
              </button>
            )}
          </div>
          <div className="grid gap-4">
            <label className="text-sm text-[var(--muted)]">
              Name
              <input
                type="text"
                value={ruleName}
                onChange={(event) => setRuleName(event.target.value)}
                className="input mt-1"
                placeholder="Suricata IOC hit escalation"
              />
            </label>
            <label className="text-sm text-[var(--muted)]">
              Description
              <input
                type="text"
                value={ruleDescription}
                onChange={(event) => setRuleDescription(event.target.value)}
                className="input mt-1"
                placeholder="Escalate TI-backed IDS alerts"
              />
            </label>
            <div className="grid gap-4 md:grid-cols-3">
              <label className="text-sm text-[var(--muted)]">
                Source
                <input
                  type="text"
                  value={ruleSource}
                  onChange={(event) => setRuleSource(event.target.value)}
                  className="input mt-1"
                  placeholder="suricata"
                />
              </label>
              <label className="text-sm text-[var(--muted)]">
                Severity
                <select
                  value={ruleSeverity}
                  onChange={(event) =>
                    setRuleSeverity(
                      event.target.value as 'critical' | 'high' | 'medium' | 'low' | 'info'
                    )
                  }
                  className="input mt-1"
                >
                  <option value="critical">critical</option>
                  <option value="high">high</option>
                  <option value="medium">medium</option>
                  <option value="low">low</option>
                  <option value="info">info</option>
                </select>
              </label>
              <label className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] px-3 text-sm text-[var(--text)]">
                <input
                  type="checkbox"
                  checked={ruleEnabled}
                  onChange={(event) => setRuleEnabled(event.target.checked)}
                />
                Enabled
              </label>
            </div>
            <label className="text-sm text-[var(--muted)]">
              Rule definition (JSON)
              <textarea
                rows={12}
                value={ruleDefinition}
                onChange={(event) => setRuleDefinition(event.target.value)}
                className="input mt-1 font-mono text-xs"
              />
            </label>
            <div className="grid gap-4 md:grid-cols-[160px_1fr]">
              <label className="text-sm text-[var(--muted)]">
                Test lookback (h)
                <input
                  type="number"
                  min={1}
                  max={720}
                  value={lookbackHours}
                  onChange={(event) => setLookbackHours(Number(event.target.value || 24))}
                  className="input mt-1"
                />
              </label>
              {canMutate && (
                <div className="flex items-end gap-2">
                  <button
                    type="button"
                    onClick={() => void saveRule()}
                    disabled={busy}
                    className="btn-primary text-sm"
                  >
                    {busy ? 'Saving...' : selectedRuleId ? 'Update rule' : 'Create rule'}
                  </button>
                  {selectedRuleId && (
                    <button
                      type="button"
                      onClick={() => void runRuleTest(selectedRuleId)}
                      disabled={busy}
                      className="btn-secondary text-sm"
                    >
                      Test rule
                    </button>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="section-panel animate-in">
        <h2 className="section-title">Recent test runs</h2>
        {runs.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No detection test runs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">Run</th>
                  <th className="px-4 py-3">Rule</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Matches</th>
                  <th className="px-4 py-3">Lookback</th>
                  <th className="px-4 py-3">Started</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.run_id} className="border-b border-[var(--border)]/40">
                    <td className="px-4 py-3">{run.run_id}</td>
                    <td className="px-4 py-3">{run.rule_name}</td>
                    <td className="px-4 py-3 uppercase">{run.status}</td>
                    <td className="px-4 py-3">{run.matches}</td>
                    <td className="px-4 py-3">{run.lookback_hours}h</td>
                    <td className="px-4 py-3">
                      {run.started_at ? formatDateTime(run.started_at) : '-'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </main>
  );
}
