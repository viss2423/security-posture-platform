import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { URL } from 'node:url';

type MockApiServer = {
  close: () => Promise<void>;
};

type State = {
  nextAssetId: number;
  nextRuleId: number;
  nextAlertId: number;
  nextIncidentId: number;
  assets: Array<Record<string, unknown>>;
  telemetryEvents: Array<Record<string, unknown>>;
  detectionRules: Array<Record<string, unknown>>;
  alerts: {
    firing: Array<Record<string, unknown>>;
    acked: Array<Record<string, unknown>>;
    suppressed: Array<Record<string, unknown>>;
    resolved: Array<Record<string, unknown>>;
  };
  incidents: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  playbooks: Array<Record<string, unknown>>;
  runs: Array<Record<string, unknown>>;
  approvals: Array<Record<string, unknown>>;
  rollbacks: Array<Record<string, unknown>>;
  demoSeeded: boolean;
};

function isoNow(): string {
  return new Date().toISOString();
}

function createState(): State {
  return {
    nextAssetId: 1,
    nextRuleId: 1,
    nextAlertId: 1000,
    nextIncidentId: 2000,
    assets: [],
    telemetryEvents: [],
    detectionRules: [],
    alerts: { firing: [], acked: [], suppressed: [], resolved: [] },
    incidents: [],
    findings: [
      {
        finding_id: 701,
        finding_key: 'repo-demo:trivy:root-user',
        asset_id: 900,
        asset_key: 'repo-demo',
        asset_name: 'Repository demo',
        first_seen: isoNow(),
        last_seen: isoNow(),
        status: 'open',
        source: 'trivy_fs',
        category: 'misconfiguration',
        title: 'Image user should not be root',
        severity: 'high',
        confidence: 'high',
        evidence: 'Runtime image executes as root.',
        remediation: 'Set a non-root USER in the final stage.',
        vulnerability_id: null,
        package_ecosystem: null,
        package_name: null,
        package_version: null,
        fixed_version: null,
        scanner_metadata_json: { scanner: 'trivy' },
        accepted_risk_at: null,
        accepted_risk_expires_at: null,
        accepted_risk_reason: null,
        accepted_risk_by: null,
        risk_score: 87,
        risk_level: 'high',
        risk_factors_json: { score_source: 'heuristic', drivers: ['root_user', 'runtime_exposure'] },
        risk_label: 'incident_worthy',
        risk_label_updated_at: isoNow(),
      },
    ],
    playbooks: [
      {
        playbook_id: 1,
        title: 'Quarantine suspicious asset',
        description: 'Apply containment tags after analyst approval.',
        trigger: 'alert_created',
        conditions_json: [],
        actions_json: [{ action_type: 'tag_asset' }],
        rollback_steps_json: [{ action_type: 'remove_tag' }],
        approval_required: true,
        enabled: true,
        created_by: 'admin',
        created_at: isoNow(),
        updated_at: isoNow(),
      },
    ],
    runs: [
      {
        run_id: 11,
        playbook_id: 1,
        playbook_title: 'Quarantine suspicious asset',
        trigger_source: 'alert_created',
        trigger_payload_json: { asset_key: DEFAULT_ASSET_KEY },
        matched: true,
        status: 'pending_approval',
        requested_by: 'admin',
        started_at: isoNow(),
        finished_at: null,
        error: null,
        summary_json: {},
        actions: [
          {
            run_action_id: 41,
            run_id: 11,
            action_index: 0,
            action_type: 'tag_asset',
            risk_tier: 'high',
            status: 'pending_approval',
            params_json: { asset_key: DEFAULT_ASSET_KEY },
            result_json: {},
          },
        ],
      },
    ],
    approvals: [
      {
        approval_id: 501,
        run_action_id: 41,
        required_role: 'admin',
        risk_tier: 'high',
        status: 'pending',
        requested_by: 'admin',
        created_at: isoNow(),
        run_id: 11,
        action_type: 'tag_asset',
        params_json: { asset_key: DEFAULT_ASSET_KEY },
      },
    ],
    rollbacks: [
      {
        rollback_id: 601,
        run_action_id: 41,
        rollback_type: 'remove_tag',
        rollback_payload_json: { asset_key: DEFAULT_ASSET_KEY },
        status: 'pending',
        requested_by: 'admin',
        created_at: isoNow(),
        run_id: 11,
        action_type: 'tag_asset',
      },
    ],
    demoSeeded: false,
  };
}

const DEFAULT_ASSET_KEY = 'onboarding-edge-gateway';

async function readBody(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString('utf-8').trim();
  if (!raw) return {};
  try {
    return JSON.parse(raw) as Record<string, unknown>;
  } catch {
    const params = new URLSearchParams(raw);
    return Object.fromEntries(params.entries());
  }
}

function json(res: ServerResponse, status: number, body: unknown) {
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify(body));
}

function unauthorized(res: ServerResponse) {
  json(res, 401, { detail: 'Unauthorized' });
}

function requireAuth(req: IncomingMessage, res: ServerResponse): boolean {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    unauthorized(res);
    return false;
  }
  return true;
}

function findAlertForAsset(state: State, assetKey: string) {
  return [...state.alerts.firing, ...state.alerts.acked, ...state.alerts.suppressed, ...state.alerts.resolved].find(
    (item) => item.asset_key === assetKey
  );
}

function telemetrySummary(state: State) {
  return {
    totals: {
      events: state.telemetryEvents.length,
      ti_matches: 0,
      assets: new Set(state.telemetryEvents.map((event) => event.asset_key).filter(Boolean)).size,
      sources: new Set(state.telemetryEvents.map((event) => event.source).filter(Boolean)).size,
    },
    sources: [
      {
        source: 'cowrie',
        event_count: state.telemetryEvents.length,
        ti_matches: 0,
        asset_count: new Set(state.telemetryEvents.map((event) => event.asset_key).filter(Boolean)).size,
        last_event_at: state.telemetryEvents[0]?.event_time ?? null,
        alerts: { firing: state.alerts.firing.length, acked: 0, suppressed: 0, resolved: 0 },
      },
    ],
    recent_alerts: state.alerts.firing,
    latest_anomaly_scores: [],
  };
}

function postureSummary(state: State) {
  return {
    green: Math.max(state.assets.length - state.alerts.firing.length, 0),
    amber: 0,
    red: state.alerts.firing.length,
    posture_score_avg: state.assets.length > 0 ? 78 : null,
    down_assets: state.alerts.firing.map((item) => item.asset_key),
  };
}

function overview(state: State) {
  return {
    executive_strip: {
      posture_score_avg: state.assets.length > 0 ? 78 : null,
      total_assets: state.assets.length,
      alerts_firing: state.alerts.firing.length,
      score_trend_vs_yesterday: 'same',
      risk_change_24h: 0,
      green: Math.max(state.assets.length - state.alerts.firing.length, 0),
      amber: 0,
      red: state.alerts.firing.length,
      down_assets: state.alerts.firing.map((item) => item.asset_key),
    },
    top_drivers: {
      worst_assets: state.assets.slice(0, 3).map((asset) => ({
        asset_id: asset.asset_id,
        name: asset.name,
        posture_score: 78,
        status: state.alerts.firing.find((item) => item.asset_key === asset.asset_key) ? 'red' : 'green',
      })),
      by_reason: state.alerts.firing.length > 0 ? [{ reason: 'cowrie login failed', count: state.alerts.firing.length }] : [],
      recently_updated: state.assets.slice(0, 3).map((asset) => ({
        asset_id: asset.asset_id,
        name: asset.name,
        last_seen: isoNow(),
      })),
    },
  };
}

function demoStatus(state: State) {
  return {
    seed_version: 'v1',
    asset_key: 'cyberlab-demo-asset',
    repo_asset_key: 'cyberlab-demo-repo',
    ioc_source: 'cyberlab-demo',
    rule_name: 'cyberlab-demo-cowrie-login-failed-v1',
    seeded: state.demoSeeded,
    assets_present: state.demoSeeded ? 2 : 0,
    assets: state.demoSeeded
      ? [
          { asset_key: 'cyberlab-demo-asset', name: 'Cyberlab asset', environment: 'prod', criticality: 'high', verified: true },
          { asset_key: 'cyberlab-demo-repo', name: 'Cyberlab repo', environment: 'dev', criticality: 'medium', verified: true },
        ]
      : [],
    telemetry_events: state.demoSeeded ? 42 : 0,
    alerts: state.demoSeeded ? 3 : 0,
    incidents: state.demoSeeded ? 1 : 0,
    repository_findings: state.demoSeeded ? 2 : 0,
    attack_lab_runs: state.demoSeeded ? 1 : 0,
    detection_rule: state.demoSeeded
      ? { rule_id: 9, name: 'cyberlab-demo-cowrie-login-failed-v1', enabled: true, last_tested_at: isoNow(), last_test_matches: 3 }
      : null,
    latest_seed_at: state.demoSeeded ? isoNow() : null,
    latest_seed_details: state.demoSeeded ? { seeded: true } : null,
  };
}

export async function startMockApiServer(port: number): Promise<MockApiServer> {
  const state = createState();
  const server = createServer(async (req, res) => {
    const url = new URL(req.url || '/', `http://127.0.0.1:${port}`);
    const path = url.pathname;
    const method = req.method || 'GET';

    if (method === 'POST' && path === '/auth/login') {
      return json(res, 200, { access_token: 'token-admin', refresh_token: 'refresh-admin' });
    }
    if (path === '/auth/config') {
      return json(res, 200, { oidc_enabled: false });
    }
    if (!requireAuth(req, res)) {
      return;
    }
    if (path === '/auth/me') {
      return json(res, 200, { username: 'admin', role: 'admin' });
    }
    if (path === '/posture/summary') {
      return json(res, 200, postureSummary(state));
    }
    if (path === '/posture/overview') {
      return json(res, 200, overview(state));
    }
    if (path === '/posture/trend') {
      return json(res, 200, { range: url.searchParams.get('range') || '7d', points: [] });
    }
    if (path === '/ai/posture/anomalies') {
      return json(res, 200, { items: [] });
    }
    if (path === '/findings/repository-summary') {
      return json(res, 200, {
        asset_key: 'repo-demo',
        asset_name: 'Repository demo',
        asset_type: 'repository',
        environment: 'dev',
        criticality: 'medium',
        total_findings: state.findings.length,
        open_findings: state.findings.length,
        in_progress_findings: 0,
        accepted_risk_findings: 0,
        remediated_findings: 0,
        sources: [{ source: 'trivy_fs', total: state.findings.length, open: state.findings.length, in_progress: 0, accepted_risk: 0, remediated: 0, by_severity: { high: state.findings.length } }],
        top_packages: [],
        recent_findings: [],
        latest_jobs: [],
      });
    }
    if (path === '/threat-intel/summary') {
      return json(res, 200, {
        total_indicators: 0,
        high_confidence_indicators: 0,
        source_count: 0,
        total_asset_matches: 0,
        matched_asset_count: 0,
        campaign_count: 0,
        last_refreshed_at: isoNow(),
        sources: [],
        matched_assets: [],
        recent_indicators: [],
        top_sightings: [],
        campaigns: [],
        latest_jobs: [],
      });
    }
    if ((path === '/assets/' || path === '/assets') && method === 'GET') {
      return json(res, 200, state.assets);
    }
    if ((path === '/assets/' || path === '/assets') && method === 'POST') {
      const body = await readBody(req);
      const asset = {
        asset_id: state.nextAssetId++,
        asset_key: body.asset_key || DEFAULT_ASSET_KEY,
        type: body.type || 'external_web',
        name: body.name || 'Edge gateway',
        owner: body.owner || 'platform-security',
        environment: body.environment || 'prod',
        criticality: body.criticality || 'high',
        asset_type: body.asset_type || 'external_web',
        verified: false,
        address: body.address || 'https://gateway.example.test',
      };
      state.assets.push(asset);
      return json(res, 200, asset);
    }
    if (path === '/telemetry/summary') {
      return json(res, 200, telemetrySummary(state));
    }
    if (path === '/telemetry/events') {
      return json(res, 200, { items: state.telemetryEvents });
    }
    if (path === '/telemetry/ingest' && method === 'POST') {
      const body = await readBody(req);
      const assetKey = String(body.asset_key || DEFAULT_ASSET_KEY);
      const events = Array.isArray(body.events) ? body.events : [];
      for (const item of events) {
        state.telemetryEvents.unshift({
          event_id: state.telemetryEvents.length + 1,
          source: body.source || 'cowrie',
          event_type: (item as Record<string, unknown>).eventid || 'cowrie.login.failed',
          asset_key: assetKey,
          src_ip: (item as Record<string, unknown>).src_ip || '203.0.113.88',
          event_time: (item as Record<string, unknown>).timestamp || isoNow(),
          ti_match: false,
        });
      }
      if (body.create_alerts) {
        state.alerts.firing = [
          {
            asset_key: assetKey,
            alert_id: state.nextAlertId++,
            title: 'Cowrie failed login',
            description: 'Failed login attempt from onboarding flow',
            severity: 'high',
            event_count: events.length,
            first_seen_at: isoNow(),
            last_seen_at: isoNow(),
          },
          ...state.alerts.firing.filter((item) => item.asset_key !== assetKey),
        ];
      }
      return json(res, 200, {
        ok: true,
        source: body.source || 'cowrie',
        processed_events: events.length,
        alert_updates: body.create_alerts ? 1 : 0,
        ti_matches: 0,
        ti_sources: {},
      });
    }
    if (path === '/detections/rules' && method === 'GET') {
      return json(res, 200, { items: state.detectionRules });
    }
    if (path === '/detections/rules' && method === 'POST') {
      const body = await readBody(req);
      const rule = {
        rule_id: state.nextRuleId++,
        name: body.name || 'Rule',
        description: body.description || null,
        source: body.source || 'cowrie',
        rule_key: body.rule_key || `rule-${state.nextRuleId}`,
        version: 1,
        mitre_tactic: null,
        mitre_technique: null,
        parent_rule_id: null,
        stage: body.stage || 'active',
        rule_format: 'json',
        severity: body.severity || 'high',
        enabled: body.enabled !== false,
        definition_json: body.definition_json || {},
        created_by: 'admin',
      };
      state.detectionRules.push(rule);
      return json(res, 200, rule);
    }
    if (path.startsWith('/detections/rules/') && path.endsWith('/test') && method === 'POST') {
      const ruleId = Number(path.split('/')[3]);
      const rule = state.detectionRules.find((item) => item.rule_id === ruleId);
      if (rule && state.telemetryEvents.length > 0) {
        const assetKey = String(state.telemetryEvents[0].asset_key || DEFAULT_ASSET_KEY);
        if (!findAlertForAsset(state, assetKey)) {
          state.alerts.firing.unshift({
            asset_key: assetKey,
            alert_id: state.nextAlertId++,
            title: 'Detection matched cowrie login failure',
            description: 'Baseline detector matched the onboarding signal.',
            severity: 'high',
            event_count: 1,
            first_seen_at: isoNow(),
            last_seen_at: isoNow(),
          });
        }
      }
      return json(res, 200, {
        rule_id: ruleId,
        run_id: 1,
        matches: state.telemetryEvents.length > 0 ? 1 : 0,
        candidate_events: state.telemetryEvents.length,
        lookback_hours: 168,
      });
    }
    if (path === '/alerts') {
      return json(res, 200, state.alerts);
    }
    if (path === '/incidents' && method === 'GET') {
      return json(res, 200, { total: state.incidents.length, items: state.incidents });
    }
    if (path === '/incidents' && method === 'POST') {
      const body = await readBody(req);
      const incidentKey = String(body.incident_key || `incident-${state.nextIncidentId}`);
      const existing = state.incidents.find((item) => item.incident_key === incidentKey);
      if (existing) {
        return json(res, 201, existing);
      }
      const incident = {
        id: state.nextIncidentId++,
        incident_key: incidentKey,
        title: body.title || 'Onboarding incident',
        severity: body.severity || 'high',
        status: 'new',
        assigned_to: null,
        created_at: isoNow(),
        updated_at: isoNow(),
        resolved_at: null,
        closed_at: null,
        sla_due_at: null,
        alert_count: Array.isArray(body.alert_ids) ? body.alert_ids.length : 0,
      };
      state.incidents.unshift(incident);
      return json(res, 201, incident);
    }
    if (path === '/findings/' || path === '/findings') {
      return json(res, 200, state.findings);
    }
    if (path === '/risk/model/status') {
      return json(res, 200, {
        enabled: true,
        artifact_path: '/tmp/model.joblib',
        artifact_exists: true,
        artifact_loaded: true,
        current_scoring_mode: 'heuristic',
        scoring_signature: 'heuristic-v1',
        readiness: { status: 'ready', summary: { ok: true }, checks: [] },
        model_metadata: null,
        latest_snapshot: null,
      });
    }
    if (path === '/automation/playbooks') {
      return json(res, 200, { items: state.playbooks });
    }
    if (path === '/automation/runs') {
      return json(res, 200, { items: state.runs });
    }
    if (path === '/automation/approvals') {
      return json(res, 200, { items: state.approvals });
    }
    if (path.startsWith('/automation/approvals/') && path.endsWith('/approve')) {
      const approvalId = Number(path.split('/')[3]);
      const approval = state.approvals.find((item) => item.approval_id === approvalId);
      if (approval) {
        approval.status = 'approved';
      }
      const run = state.runs.find((item) => item.run_id === approval?.run_id);
      if (run) {
        run.status = 'done';
      }
      return json(res, 200, {
        approval,
        execution: {},
        run_status: 'done',
      });
    }
    if (path === '/automation/rollbacks') {
      return json(res, 200, { items: state.rollbacks });
    }
    if (path === '/platform/demo/status') {
      return json(res, 200, demoStatus(state));
    }
    if (path === '/platform/demo/seed' && method === 'POST') {
      state.demoSeeded = true;
      return json(res, 200, { requested_by: 'admin', result: { seeded: true } });
    }
    if (path === '/platform/demo/reset' && method === 'POST') {
      state.demoSeeded = true;
      return json(res, 200, { requested_by: 'admin', reset: true, cleanup: {}, seed: { seeded: true } });
    }

    return json(res, 404, { detail: `Unhandled mock route: ${method} ${path}` });
  });

  await new Promise<void>((resolve) => {
    server.listen(port, '127.0.0.1', () => resolve());
  });

  return {
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error) {
            reject(error);
            return;
          }
          resolve();
        });
      }),
  };
}
