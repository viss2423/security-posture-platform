'use client';

import { useCallback, useEffect, useState } from 'react';
import {
  cloneDetectionRule,
  createDetectionRule,
  getDetectionMitreCoverage,
  getDetectionRules,
  getDetectionRuns,
  simulateDetectionRule,
  testDetectionRule,
  updateDetectionRule,
  type DetectionMitreCoverage,
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

const DEFAULT_RULE_YAML = `condition_mode: all
conditions:
  - field: event_type
    op: eq
    value: alert
  - field: ti_match
    op: is_true
`;

function shortHash(value?: string | null): string {
  const text = String(value || '').trim();
  return text ? `${text.slice(0, 12)}...` : '-';
}

export default function DetectionsPage() {
  const { canMutate } = useAuth();
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [runs, setRuns] = useState<DetectionRun[]>([]);
  const [coverage, setCoverage] = useState<DetectionMitreCoverage | null>(null);
  const [selectedRuleId, setSelectedRuleId] = useState<number | null>(null);
  const [ruleName, setRuleName] = useState('');
  const [ruleDescription, setRuleDescription] = useState('');
  const [ruleSource, setRuleSource] = useState('suricata');
  const [ruleKey, setRuleKey] = useState('');
  const [ruleVersion, setRuleVersion] = useState(1);
  const [ruleStage, setRuleStage] = useState<'draft' | 'canary' | 'active'>('active');
  const [ruleFormat, setRuleFormat] = useState<'json' | 'yaml' | 'sigma'>('json');
  const [mitreTactic, setMitreTactic] = useState('');
  const [mitreTechnique, setMitreTechnique] = useState('');
  const [ruleSeverity, setRuleSeverity] = useState<'critical' | 'high' | 'medium' | 'low' | 'info'>('medium');
  const [ruleEnabled, setRuleEnabled] = useState(true);
  const [ruleDefinitionJson, setRuleDefinitionJson] = useState(DEFAULT_RULE_JSON);
  const [ruleDefinitionYaml, setRuleDefinitionYaml] = useState(DEFAULT_RULE_YAML);
  const [lookbackHours, setLookbackHours] = useState(24);
  const [lastTestSummary, setLastTestSummary] = useState<string | null>(null);
  const [lastSimulationSummary, setLastSimulationSummary] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const [ruleResult, runResult, coverageResult] = await Promise.all([
      getDetectionRules(true),
      getDetectionRuns({ limit: 50 }),
      getDetectionMitreCoverage(30),
    ]);
    setRules(ruleResult.items || []);
    setRuns(runResult.items || []);
    setCoverage(coverageResult);
  }, []);

  useEffect(() => {
    void load().catch((loadError) => {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load detections');
    });
  }, [load]);

  const resetForm = () => {
    setSelectedRuleId(null);
    setRuleName('');
    setRuleDescription('');
    setRuleSource('suricata');
    setRuleKey('');
    setRuleVersion(1);
    setRuleStage('active');
    setRuleFormat('json');
    setMitreTactic('');
    setMitreTechnique('');
    setRuleSeverity('medium');
    setRuleEnabled(true);
    setRuleDefinitionJson(DEFAULT_RULE_JSON);
    setRuleDefinitionYaml(DEFAULT_RULE_YAML);
    setLastTestSummary(null);
    setLastSimulationSummary(null);
  };

  const selectRule = (rule: DetectionRule) => {
    setSelectedRuleId(rule.rule_id);
    setRuleName(rule.name);
    setRuleDescription(rule.description || '');
    setRuleSource(rule.source || '');
    setRuleKey(rule.rule_key || '');
    setRuleVersion(Math.max(1, Number(rule.version || 1)));
    setRuleStage((rule.stage as 'draft' | 'canary' | 'active') || 'active');
    setRuleFormat((rule.rule_format as 'json' | 'yaml' | 'sigma') || 'json');
    setMitreTactic(rule.mitre_tactic || '');
    setMitreTechnique(rule.mitre_technique || '');
    setRuleSeverity(rule.severity);
    setRuleEnabled(rule.enabled);
    setRuleDefinitionJson(JSON.stringify(rule.definition_json || {}, null, 2));
    setRuleDefinitionYaml(rule.definition_yaml || DEFAULT_RULE_YAML);
    setLastTestSummary(null);
    setLastSimulationSummary(null);
  };

  const saveRule = async () => {
    if (!canMutate) return;
    if (!ruleName.trim()) {
      setError('Rule name is required');
      return;
    }
    let parsedDefinition: Record<string, unknown> | undefined = undefined;
    if (ruleFormat === 'json') {
      try {
        parsedDefinition = ruleDefinitionJson.trim() ? JSON.parse(ruleDefinitionJson) : {};
      } catch {
        setError('Rule definition JSON is invalid');
        return;
      }
    }

    setBusy(true);
    setError(null);
    try {
      if (selectedRuleId) {
        await updateDetectionRule(selectedRuleId, {
          description: ruleDescription || null,
          source: ruleSource || null,
          rule_key: ruleKey || null,
          version: ruleVersion,
          mitre_tactic: mitreTactic || null,
          mitre_technique: mitreTechnique || null,
          stage: ruleStage,
          rule_format: ruleFormat,
          severity: ruleSeverity,
          enabled: ruleEnabled,
          definition_json: parsedDefinition,
          definition_yaml: ruleFormat === 'json' ? null : ruleDefinitionYaml,
        });
      } else {
        await createDetectionRule({
          name: ruleName.trim(),
          description: ruleDescription || null,
          source: ruleSource || null,
          rule_key: ruleKey || null,
          version: ruleVersion,
          mitre_tactic: mitreTactic || null,
          mitre_technique: mitreTechnique || null,
          stage: ruleStage,
          rule_format: ruleFormat,
          severity: ruleSeverity,
          enabled: ruleEnabled,
          definition_json: parsedDefinition,
          definition_yaml: ruleFormat === 'json' ? null : ruleDefinitionYaml,
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
      setLastSimulationSummary(null);
      setLastTestSummary(
        `Test run matched ${out.matches} of ${out.candidate_events} events over ${out.lookback_hours}h.`
      );
    } catch (testError) {
      setError(testError instanceof Error ? testError.message : 'Detection test failed');
    } finally {
      setBusy(false);
    }
  };

  const runRuleSimulation = async (ruleId: number) => {
    if (!canMutate) return;
    setBusy(true);
    setError(null);
    try {
      const out = await simulateDetectionRule(ruleId, {
        lookback_hours: lookbackHours,
      });
      await load();
      setLastTestSummary(null);
      setLastSimulationSummary(
        `Simulation matched ${out.matches} of ${out.candidate_events} events over ${out.lookback_hours}h (no alerts created).`
      );
    } catch (simulationError) {
      setError(simulationError instanceof Error ? simulationError.message : 'Simulation failed');
    } finally {
      setBusy(false);
    }
  };

  const cloneRule = async (ruleId: number) => {
    if (!canMutate) return;
    setBusy(true);
    setError(null);
    try {
      const cloned = await cloneDetectionRule(ruleId);
      await load();
      selectRule(cloned);
      setLastTestSummary(`Cloned rule ${ruleId} into draft rule ${cloned.rule_id}.`);
      setLastSimulationSummary(null);
    } catch (cloneError) {
      setError(cloneError instanceof Error ? cloneError.message : 'Failed to clone rule');
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="page-shell">
      <div className="mb-6">
        <h1 className="page-title">Detections</h1>
        <p className="mt-2 max-w-3xl text-sm text-[var(--text-muted)]">
          Manage versioned detection content, run dry-run simulations, and track ATT&CK coverage.
        </p>
      </div>

      {error && (
        <div className="mb-6 alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}

      {lastTestSummary && (
        <div className="mb-3 rounded-xl border border-[var(--green)]/30 bg-[var(--green)]/10 px-4 py-3 text-sm text-[var(--text)]">
          {lastTestSummary}
        </div>
      )}
      {lastSimulationSummary && (
        <div className="mb-6 rounded-xl border border-cyan-300/35 bg-cyan-300/10 px-4 py-3 text-sm text-[var(--text)]">
          {lastSimulationSummary}
        </div>
      )}

      <section className="mb-8 section-panel animate-in">
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <h2 className="section-title">ATT&CK coverage</h2>
          <span className="stat-chip-strong">
            {coverage?.totals.mapping_coverage_pct?.toFixed(1) || '0.0'}% mapped
          </span>
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
            <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">Enabled rules</p>
            <p className="mt-1 text-2xl font-semibold text-[var(--text)]">
              {coverage?.totals.enabled_rules ?? 0}
            </p>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
            <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">Covered tactics</p>
            <p className="mt-1 text-2xl font-semibold text-[var(--text)]">
              {coverage?.totals.covered_tactics ?? 0}
            </p>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
            <p className="text-xs uppercase tracking-[0.12em] text-[var(--muted)]">Covered techniques</p>
            <p className="mt-1 text-2xl font-semibold text-[var(--text)]">
              {coverage?.totals.covered_techniques ?? 0}
            </p>
          </div>
        </div>
        <div className="mt-4 grid gap-4 md:grid-cols-2">
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
            <p className="mb-2 text-xs uppercase tracking-[0.12em] text-[var(--muted)]">Top tactics</p>
            <ul className="space-y-1 text-sm text-[var(--text)]">
              {(coverage?.tactics || []).slice(0, 6).map((row) => (
                <li key={row.mitre_tactic} className="flex items-center justify-between">
                  <span>{row.mitre_tactic}</span>
                  <span className="stat-chip">{row.rule_count}</span>
                </li>
              ))}
              {(coverage?.tactics || []).length === 0 && (
                <li className="text-[var(--muted)]">No tactic mappings yet.</li>
              )}
            </ul>
          </div>
          <div className="rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-3">
            <p className="mb-2 text-xs uppercase tracking-[0.12em] text-[var(--muted)]">
              Top detected techniques
            </p>
            <ul className="space-y-1 text-sm text-[var(--text)]">
              {(coverage?.top_detected_techniques || []).slice(0, 6).map((row) => (
                <li key={row.mitre_technique} className="flex items-center justify-between">
                  <span>{row.mitre_technique}</span>
                  <span className="stat-chip">{row.detections}</span>
                </li>
              ))}
              {(coverage?.top_detected_techniques || []).length === 0 && (
                <li className="text-[var(--muted)]">No recent detections mapped to ATT&CK.</li>
              )}
            </ul>
          </div>
        </div>
      </section>

      <section className="mb-8 grid gap-6 xl:grid-cols-[minmax(0,1fr)_minmax(420px,1fr)]">
        <div className="section-panel animate-in">
          <div className="mb-4 flex items-center justify-between gap-3">
            <h2 className="section-title">Rule inventory</h2>
            <span className="stat-chip-strong">{rules.length} rules</span>
          </div>
          {rules.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No detection rules yet.</p>
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
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => selectRule(rule)}
                      className="text-left font-medium text-[var(--text)] hover:text-[var(--green)]"
                    >
                      {rule.name}
                    </button>
                    <div className="flex items-center gap-2">
                      <span className="stat-chip">{rule.stage || 'active'}</span>
                      <span className="stat-chip">v{rule.version || 1}</span>
                      <span className="stat-chip uppercase">{rule.severity}</span>
                    </div>
                  </div>
                  <p className="mt-2 text-xs text-[var(--muted)]">
                    {rule.source || 'all sources'} | {rule.rule_key || '-'} |{' '}
                    {rule.mitre_technique || rule.mitre_tactic || 'no ATT&CK mapping'}
                  </p>
                  <p className="mt-1 text-xs text-[var(--muted)]">
                    {rule.last_tested_at
                      ? `Last run ${formatDateTime(rule.last_tested_at)} (${rule.last_test_matches ?? 0} matches)`
                      : 'Not tested yet'}
                  </p>
                  {canMutate && (
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => void runRuleTest(rule.rule_id)}
                        disabled={busy}
                        className="btn-secondary text-sm"
                      >
                        Test
                      </button>
                      <button
                        type="button"
                        onClick={() => void runRuleSimulation(rule.rule_id)}
                        disabled={busy}
                        className="btn-secondary text-sm"
                      >
                        Simulate
                      </button>
                      <button
                        type="button"
                        onClick={() => void cloneRule(rule.rule_id)}
                        disabled={busy}
                        className="btn-secondary text-sm"
                      >
                        Clone
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
              />
            </label>
            <label className="text-sm text-[var(--muted)]">
              Description
              <input
                type="text"
                value={ruleDescription}
                onChange={(event) => setRuleDescription(event.target.value)}
                className="input mt-1"
              />
            </label>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="text-sm text-[var(--muted)]">
                Rule key
                <input
                  type="text"
                  value={ruleKey}
                  onChange={(event) => setRuleKey(event.target.value)}
                  className="input mt-1"
                />
              </label>
              <label className="text-sm text-[var(--muted)]">
                Source
                <input
                  type="text"
                  value={ruleSource}
                  onChange={(event) => setRuleSource(event.target.value)}
                  className="input mt-1"
                />
              </label>
            </div>
            <div className="grid gap-4 md:grid-cols-4">
              <label className="text-sm text-[var(--muted)]">
                Version
                <input
                  type="number"
                  min={1}
                  value={ruleVersion}
                  onChange={(event) => setRuleVersion(Math.max(1, Number(event.target.value || 1)))}
                  className="input mt-1"
                />
              </label>
              <label className="text-sm text-[var(--muted)]">
                Stage
                <select
                  value={ruleStage}
                  onChange={(event) =>
                    setRuleStage(event.target.value as 'draft' | 'canary' | 'active')
                  }
                  className="input mt-1"
                >
                  <option value="draft">draft</option>
                  <option value="canary">canary</option>
                  <option value="active">active</option>
                </select>
              </label>
              <label className="text-sm text-[var(--muted)]">
                Format
                <select
                  value={ruleFormat}
                  onChange={(event) => setRuleFormat(event.target.value as 'json' | 'yaml' | 'sigma')}
                  className="input mt-1"
                >
                  <option value="json">json</option>
                  <option value="yaml">yaml</option>
                  <option value="sigma">sigma</option>
                </select>
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
            </div>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="text-sm text-[var(--muted)]">
                MITRE tactic
                <input
                  type="text"
                  value={mitreTactic}
                  onChange={(event) => setMitreTactic(event.target.value)}
                  className="input mt-1"
                  placeholder="TA0008"
                />
              </label>
              <label className="text-sm text-[var(--muted)]">
                MITRE technique
                <input
                  type="text"
                  value={mitreTechnique}
                  onChange={(event) => setMitreTechnique(event.target.value)}
                  className="input mt-1"
                  placeholder="T1021"
                />
              </label>
            </div>
            <label className="flex items-center gap-2 rounded-xl border border-[var(--border)] bg-[var(--surface-elevated)] px-3 py-2 text-sm text-[var(--text)]">
              <input
                type="checkbox"
                checked={ruleEnabled}
                onChange={(event) => setRuleEnabled(event.target.checked)}
              />
              Enabled
            </label>
            {ruleFormat === 'json' ? (
              <label className="text-sm text-[var(--muted)]">
                Rule definition (JSON)
                <textarea
                  rows={12}
                  value={ruleDefinitionJson}
                  onChange={(event) => setRuleDefinitionJson(event.target.value)}
                  className="input mt-1 font-mono text-xs"
                />
              </label>
            ) : (
              <label className="text-sm text-[var(--muted)]">
                Rule definition (YAML/Sigma)
                <textarea
                  rows={12}
                  value={ruleDefinitionYaml}
                  onChange={(event) => setRuleDefinitionYaml(event.target.value)}
                  className="input mt-1 font-mono text-xs"
                />
              </label>
            )}
            <div className="grid gap-4 md:grid-cols-[180px_1fr]">
              <label className="text-sm text-[var(--muted)]">
                Test/sim lookback (h)
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
                <div className="flex flex-wrap items-end gap-2">
                  <button type="button" onClick={() => void saveRule()} disabled={busy} className="btn-primary text-sm">
                    {busy ? 'Saving...' : selectedRuleId ? 'Update rule' : 'Create rule'}
                  </button>
                  {selectedRuleId && (
                    <>
                      <button
                        type="button"
                        onClick={() => void runRuleTest(selectedRuleId)}
                        disabled={busy}
                        className="btn-secondary text-sm"
                      >
                        Test
                      </button>
                      <button
                        type="button"
                        onClick={() => void runRuleSimulation(selectedRuleId)}
                        disabled={busy}
                        className="btn-secondary text-sm"
                      >
                        Simulate
                      </button>
                    </>
                  )}
                </div>
              )}
            </div>
          </div>
        </div>
      </section>

      <section className="section-panel animate-in">
        <h2 className="section-title">Recent runs</h2>
        {runs.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No detection runs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">Run</th>
                  <th className="px-4 py-3">Rule</th>
                  <th className="px-4 py-3">Mode</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Matches</th>
                  <th className="px-4 py-3">Snapshot</th>
                  <th className="px-4 py-3">Started</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.run_id} className="border-b border-[var(--border)]/40">
                    <td className="px-4 py-3">{run.run_id}</td>
                    <td className="px-4 py-3">{run.rule_name}</td>
                    <td className="px-4 py-3">{run.run_mode || '-'}</td>
                    <td className="px-4 py-3 uppercase">{run.status}</td>
                    <td className="px-4 py-3">{run.matches}</td>
                    <td className="px-4 py-3 font-mono text-xs">{shortHash(run.snapshot_hash)}</td>
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
