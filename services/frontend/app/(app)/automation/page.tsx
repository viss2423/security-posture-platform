'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  approveAutomationApproval,
  createAutomationPlaybook,
  executeAutomationRollback,
  getAutomationApprovals,
  getAutomationPlaybooks,
  getAutomationRollbacks,
  getAutomationRuns,
  rejectAutomationApproval,
  triggerAutomationRuns,
  updateAutomationPlaybook,
  type AutomationApproval,
  type AutomationPlaybook,
  type AutomationRollback,
  type AutomationRun,
  type AutomationRunAction,
} from '@/lib/api';
import { ApiDownHint } from '@/components/EmptyState';
import { useAuth } from '@/contexts/AuthContext';
import { friendlyApiMessage } from '@/lib/apiError';
import { formatDateTime } from '@/lib/format';

const DEFAULT_CONDITIONS_JSON = JSON.stringify([{ field: 'asset_key', op: 'exists' }], null, 2);
const DEFAULT_ACTIONS_JSON = JSON.stringify(
  [{ type: 'tag_asset', params: { asset_key: '{{asset_key}}', tag: 'under_investigation' } }],
  null,
  2
);
const DEFAULT_TRIGGER_PAYLOAD = JSON.stringify(
  { asset_key: 'cyberlab-demo-asset', severity: 'high' },
  null,
  2
);

function statusBadge(status: string): JSX.Element {
  const value = String(status || '').toLowerCase();
  const classes =
    value === 'done' || value === 'approved' || value === 'executed'
      ? 'bg-[var(--green)]/20 text-[var(--green)] border border-[var(--green)]/20'
      : value === 'failed' || value === 'rejected'
        ? 'bg-[var(--red)]/20 text-[var(--red)] border border-[var(--red)]/20'
        : value === 'pending_approval' || value === 'pending' || value === 'running'
          ? 'bg-[var(--amber)]/20 text-[var(--amber)] border border-[var(--amber)]/20'
          : 'bg-[var(--surface-elevated)] text-[var(--muted)] border border-[var(--border)]';
  return (
    <span className={`rounded-full px-2 py-0.5 text-xs font-medium uppercase tracking-[0.06em] ${classes}`}>
      {value || 'unknown'}
    </span>
  );
}

function actionSummary(actions?: AutomationRunAction[]): string {
  if (!actions || actions.length === 0) return '-';
  const parts = actions.map((item) => `${item.action_type}:${item.status}`);
  return parts.join(', ');
}

export default function AutomationPage() {
  const { canMutate } = useAuth();
  const [playbooks, setPlaybooks] = useState<AutomationPlaybook[]>([]);
  const [runs, setRuns] = useState<AutomationRun[]>([]);
  const [approvals, setApprovals] = useState<AutomationApproval[]>([]);
  const [rollbacks, setRollbacks] = useState<AutomationRollback[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [savingPlaybook, setSavingPlaybook] = useState(false);
  const [triggering, setTriggering] = useState(false);
  const [busyApprovalId, setBusyApprovalId] = useState<number | null>(null);
  const [busyRollbackId, setBusyRollbackId] = useState<number | null>(null);

  const [selectedPlaybookId, setSelectedPlaybookId] = useState<number | null>(null);
  const [playbookTitle, setPlaybookTitle] = useState('');
  const [playbookDescription, setPlaybookDescription] = useState('');
  const [playbookTrigger, setPlaybookTrigger] = useState('manual');
  const [playbookEnabled, setPlaybookEnabled] = useState(true);
  const [playbookApprovalRequired, setPlaybookApprovalRequired] = useState(false);
  const [playbookConditionsJson, setPlaybookConditionsJson] = useState(DEFAULT_CONDITIONS_JSON);
  const [playbookActionsJson, setPlaybookActionsJson] = useState(DEFAULT_ACTIONS_JSON);
  const [triggerPayloadJson, setTriggerPayloadJson] = useState(DEFAULT_TRIGGER_PAYLOAD);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [playbookResult, runResult, approvalResult, rollbackResult] = await Promise.all([
        getAutomationPlaybooks({ include_disabled: true }),
        getAutomationRuns({ limit: 100 }),
        getAutomationApprovals({ limit: 100 }),
        getAutomationRollbacks({ limit: 100 }),
      ]);
      setPlaybooks(playbookResult.items || []);
      setRuns(runResult.items || []);
      setApprovals(approvalResult.items || []);
      setRollbacks(rollbackResult.items || []);
      setError(null);
    } catch (loadError) {
      setError(loadError instanceof Error ? loadError.message : 'Failed to load automation data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
    const timer = window.setInterval(() => {
      void load();
    }, 30000);
    return () => window.clearInterval(timer);
  }, [load]);

  const pendingApprovals = useMemo(
    () => approvals.filter((item) => String(item.status).toLowerCase() === 'pending').length,
    [approvals]
  );
  const pendingRollbacks = useMemo(
    () => rollbacks.filter((item) => String(item.status).toLowerCase() === 'pending').length,
    [rollbacks]
  );
  const runFailures = useMemo(
    () => runs.filter((item) => String(item.status).toLowerCase() === 'failed').length,
    [runs]
  );

  const resetPlaybookForm = () => {
    setSelectedPlaybookId(null);
    setPlaybookTitle('');
    setPlaybookDescription('');
    setPlaybookTrigger('manual');
    setPlaybookEnabled(true);
    setPlaybookApprovalRequired(false);
    setPlaybookConditionsJson(DEFAULT_CONDITIONS_JSON);
    setPlaybookActionsJson(DEFAULT_ACTIONS_JSON);
  };

  const selectPlaybook = (playbook: AutomationPlaybook) => {
    setSelectedPlaybookId(playbook.playbook_id);
    setPlaybookTitle(playbook.title || '');
    setPlaybookDescription(playbook.description || '');
    setPlaybookTrigger(playbook.trigger || 'manual');
    setPlaybookEnabled(Boolean(playbook.enabled));
    setPlaybookApprovalRequired(Boolean(playbook.approval_required));
    setPlaybookConditionsJson(JSON.stringify(playbook.conditions_json || [], null, 2));
    setPlaybookActionsJson(JSON.stringify(playbook.actions_json || [], null, 2));
    setMessage(null);
    setError(null);
  };

  const savePlaybook = async () => {
    if (!canMutate) return;
    const title = playbookTitle.trim();
    if (!title) {
      setError('Playbook title is required');
      return;
    }
    let conditions: Array<Record<string, unknown>> = [];
    let actions: Array<Record<string, unknown>> = [];
    try {
      const parsedConditions = playbookConditionsJson.trim()
        ? JSON.parse(playbookConditionsJson)
        : [];
      const parsedActions = playbookActionsJson.trim() ? JSON.parse(playbookActionsJson) : [];
      if (!Array.isArray(parsedConditions)) throw new Error('Conditions must be a JSON array');
      if (!Array.isArray(parsedActions)) throw new Error('Actions must be a JSON array');
      conditions = parsedConditions;
      actions = parsedActions;
    } catch (parseError) {
      setError(parseError instanceof Error ? parseError.message : 'Invalid playbook JSON');
      return;
    }

    setSavingPlaybook(true);
    setMessage(null);
    setError(null);
    try {
      if (selectedPlaybookId) {
        await updateAutomationPlaybook(selectedPlaybookId, {
          description: playbookDescription || null,
          trigger: playbookTrigger,
          conditions,
          actions,
          approval_required: playbookApprovalRequired,
          enabled: playbookEnabled,
        });
        setMessage(`Playbook ${selectedPlaybookId} updated.`);
      } else {
        await createAutomationPlaybook({
          title,
          description: playbookDescription || null,
          trigger: playbookTrigger,
          conditions,
          actions,
          approval_required: playbookApprovalRequired,
          enabled: playbookEnabled,
        });
        setMessage(`Playbook "${title}" created.`);
      }
      await load();
      if (!selectedPlaybookId) {
        resetPlaybookForm();
      }
    } catch (saveError) {
      setError(saveError instanceof Error ? saveError.message : 'Failed to save playbook');
    } finally {
      setSavingPlaybook(false);
    }
  };

  const triggerPlaybook = async () => {
    if (!canMutate) return;
    let payload: Record<string, unknown> = {};
    try {
      payload = triggerPayloadJson.trim() ? JSON.parse(triggerPayloadJson) : {};
      if (typeof payload !== 'object' || Array.isArray(payload) || payload == null) {
        throw new Error('Trigger payload must be a JSON object');
      }
    } catch (parseError) {
      setError(parseError instanceof Error ? parseError.message : 'Invalid trigger payload JSON');
      return;
    }

    setTriggering(true);
    setMessage(null);
    setError(null);
    try {
      const out = await triggerAutomationRuns({
        trigger: playbookTrigger,
        payload,
        playbook_ids: selectedPlaybookId ? [selectedPlaybookId] : undefined,
      });
      setMessage(
        `Triggered ${out.runs_created} run(s) for trigger ${out.trigger}${
          selectedPlaybookId ? ` using playbook ${selectedPlaybookId}` : ''
        }.`
      );
      await load();
    } catch (triggerError) {
      setError(triggerError instanceof Error ? triggerError.message : 'Failed to trigger run');
    } finally {
      setTriggering(false);
    }
  };

  const approveRequest = async (approvalId: number) => {
    if (!canMutate) return;
    setBusyApprovalId(approvalId);
    setMessage(null);
    setError(null);
    try {
      await approveAutomationApproval(approvalId);
      setMessage(`Approval ${approvalId} approved.`);
      await load();
    } catch (approvalError) {
      setError(
        approvalError instanceof Error ? approvalError.message : 'Failed to approve automation action'
      );
    } finally {
      setBusyApprovalId(null);
    }
  };

  const rejectRequest = async (approvalId: number) => {
    if (!canMutate) return;
    setBusyApprovalId(approvalId);
    setMessage(null);
    setError(null);
    try {
      await rejectAutomationApproval(approvalId);
      setMessage(`Approval ${approvalId} rejected.`);
      await load();
    } catch (approvalError) {
      setError(
        approvalError instanceof Error ? approvalError.message : 'Failed to reject automation action'
      );
    } finally {
      setBusyApprovalId(null);
    }
  };

  const executeRollback = async (rollbackId: number) => {
    if (!canMutate) return;
    setBusyRollbackId(rollbackId);
    setMessage(null);
    setError(null);
    try {
      await executeAutomationRollback(rollbackId);
      setMessage(`Rollback ${rollbackId} executed.`);
      await load();
    } catch (rollbackError) {
      setError(rollbackError instanceof Error ? rollbackError.message : 'Failed to execute rollback');
    } finally {
      setBusyRollbackId(null);
    }
  };

  return (
    <main className="page-shell view-stack">
      <section className="page-hero animate-in">
        <div className="hero-grid">
          <div>
            <span className="stat-chip-strong">Automation</span>
            <h1 className="hero-title mt-3">Playbook Operations</h1>
            <p className="hero-copy">
              Define playbooks, trigger runs, approve guarded actions, and execute rollbacks from a
              single response workflow view.
            </p>
          </div>
          <div className="hero-stat-grid">
            <div className="hero-stat">
              <p className="hero-stat-label">Playbooks</p>
              <p className="hero-stat-value">{playbooks.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Recent runs</p>
              <p className="hero-stat-value">{runs.length}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Approvals pending</p>
              <p className="hero-stat-value">{pendingApprovals}</p>
            </div>
            <div className="hero-stat">
              <p className="hero-stat-label">Rollbacks pending</p>
              <p className="hero-stat-value">{pendingRollbacks}</p>
            </div>
          </div>
        </div>
      </section>

      {error && (
        <div className="alert-error animate-in" role="alert">
          {friendlyApiMessage(error)}
          <ApiDownHint />
        </div>
      )}
      {message && (
        <div className="rounded-xl border border-cyan-300/35 bg-cyan-300/12 px-4 py-3 text-sm text-[var(--text)]">
          {message}
        </div>
      )}

      <section className="grid gap-6 xl:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Playbook editor</h2>
              <p className="section-head-copy">
                Create or update additive playbooks with JSON conditions and actions.
              </p>
            </div>
            {selectedPlaybookId ? (
              <button type="button" onClick={resetPlaybookForm} className="btn-secondary text-sm">
                New playbook
              </button>
            ) : null}
          </div>
          <div className="grid gap-4">
            <label className="text-sm text-[var(--muted)]">
              Title
              <input
                type="text"
                value={playbookTitle}
                onChange={(event) => setPlaybookTitle(event.target.value)}
                className="input mt-1"
                placeholder="e.g. Tag suspicious asset"
              />
            </label>
            <label className="text-sm text-[var(--muted)]">
              Description
              <input
                type="text"
                value={playbookDescription}
                onChange={(event) => setPlaybookDescription(event.target.value)}
                className="input mt-1"
                placeholder="Optional"
              />
            </label>
            <div className="grid gap-4 md:grid-cols-2">
              <label className="text-sm text-[var(--muted)]">
                Trigger
                <select
                  value={playbookTrigger}
                  onChange={(event) => setPlaybookTrigger(event.target.value)}
                  className="input mt-1"
                >
                  <option value="manual">manual</option>
                  <option value="alert_created">alert_created</option>
                  <option value="incident_created">incident_created</option>
                  <option value="finding_created">finding_created</option>
                  <option value="scan_completed">scan_completed</option>
                  <option value="ioc_matched">ioc_matched</option>
                  <option value="anomaly_threshold_exceeded">anomaly_threshold_exceeded</option>
                </select>
              </label>
              <div className="grid gap-3 pt-6">
                <label className="inline-flex items-center gap-2 text-sm text-[var(--text)]">
                  <input
                    type="checkbox"
                    checked={playbookEnabled}
                    onChange={(event) => setPlaybookEnabled(event.target.checked)}
                  />
                  <span>Enabled</span>
                </label>
                <label className="inline-flex items-center gap-2 text-sm text-[var(--text)]">
                  <input
                    type="checkbox"
                    checked={playbookApprovalRequired}
                    onChange={(event) => setPlaybookApprovalRequired(event.target.checked)}
                  />
                  <span>Approval required (playbook-level)</span>
                </label>
              </div>
            </div>
            <label className="text-sm text-[var(--muted)]">
              Conditions JSON
              <textarea
                value={playbookConditionsJson}
                onChange={(event) => setPlaybookConditionsJson(event.target.value)}
                rows={8}
                className="input mt-1 font-mono text-xs"
              />
            </label>
            <label className="text-sm text-[var(--muted)]">
              Actions JSON
              <textarea
                value={playbookActionsJson}
                onChange={(event) => setPlaybookActionsJson(event.target.value)}
                rows={10}
                className="input mt-1 font-mono text-xs"
              />
            </label>
            {canMutate && (
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => void savePlaybook()}
                  disabled={savingPlaybook}
                  className="btn-primary text-sm"
                >
                  {savingPlaybook
                    ? 'Saving...'
                    : selectedPlaybookId
                      ? 'Update playbook'
                      : 'Create playbook'}
                </button>
              </div>
            )}
          </div>
        </div>

        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Playbook inventory</h2>
              <p className="section-head-copy">Select a playbook to edit or trigger.</p>
            </div>
            <span className="stat-chip">{playbooks.length} total</span>
          </div>
          {playbooks.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No playbooks available.</p>
          ) : (
            <ul className="space-y-3">
              {playbooks.map((item) => (
                <li
                  key={item.playbook_id}
                  className={`rounded-2xl border p-4 ${
                    selectedPlaybookId === item.playbook_id
                      ? 'border-cyan-300/45 bg-cyan-300/10'
                      : 'border-[var(--border)] bg-[var(--surface-elevated)]/40'
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <button
                      type="button"
                      onClick={() => selectPlaybook(item)}
                      className="text-left text-sm font-medium text-[var(--text)] hover:text-cyan-100"
                    >
                      {item.title}
                    </button>
                    {statusBadge(item.enabled ? 'enabled' : 'disabled')}
                  </div>
                  <p className="mt-1 text-xs text-[var(--muted)]">
                    Trigger {item.trigger} | Updated {formatDateTime(item.updated_at)}
                  </p>
                </li>
              ))}
            </ul>
          )}

          <div className="mt-5 rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
            <h3 className="mb-2 text-sm font-semibold text-[var(--text)]">Trigger run</h3>
            <p className="mb-3 text-xs text-[var(--muted)]">
              Runs selected playbook only when one is selected. Otherwise runs all playbooks for the
              trigger.
            </p>
            <label className="text-sm text-[var(--muted)]">
              Trigger payload JSON
              <textarea
                value={triggerPayloadJson}
                onChange={(event) => setTriggerPayloadJson(event.target.value)}
                rows={6}
                className="input mt-1 font-mono text-xs"
              />
            </label>
            {canMutate && (
              <button
                type="button"
                onClick={() => void triggerPlaybook()}
                disabled={triggering}
                className="btn-primary mt-3 text-sm"
              >
                {triggering ? 'Triggering...' : 'Trigger run'}
              </button>
            )}
          </div>
        </div>
      </section>

      <section className="section-panel animate-in">
        <div className="section-head">
          <div>
            <h2 className="section-title">Run history</h2>
            <p className="section-head-copy">
              End-to-end action status with approval and rollback visibility.
            </p>
          </div>
          <span className="stat-chip">
            Failed {runFailures} / {runs.length}
          </span>
        </div>
        {runs.length === 0 ? (
          <p className="text-sm text-[var(--muted)]">No automation runs yet.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[var(--border)] text-left text-xs uppercase tracking-[0.16em] text-[var(--muted)]">
                  <th className="px-4 py-3">Run</th>
                  <th className="px-4 py-3">Playbook</th>
                  <th className="px-4 py-3">Trigger</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Actions</th>
                  <th className="px-4 py-3">Started</th>
                </tr>
              </thead>
              <tbody>
                {runs.map((run) => (
                  <tr key={run.run_id} className="border-b border-[var(--border)]/40">
                    <td className="px-4 py-3 font-mono">{run.run_id}</td>
                    <td className="px-4 py-3">{run.playbook_title || run.playbook_id}</td>
                    <td className="px-4 py-3">{run.trigger_source}</td>
                    <td className="px-4 py-3">{statusBadge(run.status)}</td>
                    <td className="px-4 py-3 text-xs text-[var(--muted)]">
                      {actionSummary(run.actions)}
                    </td>
                    <td className="px-4 py-3">{formatDateTime(run.started_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="grid gap-6 xl:grid-cols-2">
        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Approval queue</h2>
              <p className="section-head-copy">Pending medium/high-risk actions requiring analyst or admin approval.</p>
            </div>
            <span className="stat-chip">{pendingApprovals} pending</span>
          </div>
          {approvals.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No approval requests.</p>
          ) : (
            <ul className="space-y-3">
              {approvals.map((item) => {
                const pending = String(item.status).toLowerCase() === 'pending';
                return (
                  <li key={item.approval_id} className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-medium text-[var(--text)]">
                        Approval #{item.approval_id} | Run #{item.run_id ?? '-'}
                      </p>
                      {statusBadge(item.status)}
                    </div>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      {item.action_type || '-'} | risk {item.risk_tier} | role {item.required_role}
                    </p>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      Requested by {item.requested_by || '-'} on {formatDateTime(item.created_at)}
                    </p>
                    {canMutate && pending && (
                      <div className="mt-3 flex flex-wrap gap-2">
                        <button
                          type="button"
                          onClick={() => void approveRequest(item.approval_id)}
                          disabled={busyApprovalId === item.approval_id}
                          className="btn-primary text-sm"
                        >
                          {busyApprovalId === item.approval_id ? 'Approving...' : 'Approve'}
                        </button>
                        <button
                          type="button"
                          onClick={() => void rejectRequest(item.approval_id)}
                          disabled={busyApprovalId === item.approval_id}
                          className="btn-secondary text-sm"
                        >
                          {busyApprovalId === item.approval_id ? 'Rejecting...' : 'Reject'}
                        </button>
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        <div className="section-panel animate-in">
          <div className="section-head">
            <div>
              <h2 className="section-title">Rollback queue</h2>
              <p className="section-head-copy">Reversible actions with execution status and operator traceability.</p>
            </div>
            <span className="stat-chip">{pendingRollbacks} pending</span>
          </div>
          {rollbacks.length === 0 ? (
            <p className="text-sm text-[var(--muted)]">No rollback records.</p>
          ) : (
            <ul className="space-y-3">
              {rollbacks.map((item) => {
                const pending = String(item.status).toLowerCase() === 'pending';
                return (
                  <li key={item.rollback_id} className="rounded-2xl border border-[var(--border)] bg-[var(--surface-elevated)]/35 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="text-sm font-medium text-[var(--text)]">
                        Rollback #{item.rollback_id} | Run #{item.run_id ?? '-'}
                      </p>
                      {statusBadge(item.status)}
                    </div>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      {item.rollback_type} | action {item.action_type || '-'}
                    </p>
                    <p className="mt-1 text-xs text-[var(--muted)]">
                      Requested by {item.requested_by || '-'} on {formatDateTime(item.created_at)}
                    </p>
                    {canMutate && pending && (
                      <button
                        type="button"
                        onClick={() => void executeRollback(item.rollback_id)}
                        disabled={busyRollbackId === item.rollback_id}
                        className="btn-secondary mt-3 text-sm"
                      >
                        {busyRollbackId === item.rollback_id ? 'Executing...' : 'Execute rollback'}
                      </button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}
        </div>
      </section>

      {loading && <p className="text-sm text-[var(--muted)]">Refreshing automation data...</p>}
    </main>
  );
}
