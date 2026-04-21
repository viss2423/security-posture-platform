const http = require('http');
const https = require('https');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const defaultApiUrl = 'http://127.0.0.1:8000';
const apiUrl = process.env.API_URL || defaultApiUrl;
const defaultFrontendUrl = 'http://127.0.0.1:3000';
const frontendUrl = process.env.FRONTEND_URL || defaultFrontendUrl;
const frontendCommand = ['run', 'dev', '--prefix', 'services/frontend'];
const skipFrontend = String(process.env.DEV_SKIP_FRONTEND || '').toLowerCase() === 'true';
const defaultHealthTimeoutMs = 300000;
const defaultHealthPollIntervalMs = 2000;
const healthTimeoutMs = parsePositiveInt(process.env.DEV_API_HEALTH_TIMEOUT_MS, defaultHealthTimeoutMs);
const healthPollIntervalMs = parsePositiveInt(process.env.DEV_API_POLL_INTERVAL_MS, defaultHealthPollIntervalMs);

function log(message) {
  process.stdout.write(`[dev] ${message}\n`);
}

function logError(message) {
  process.stderr.write(`[dev] ${message}\n`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function parsePositiveInt(raw, fallback) {
  if (!raw) return fallback;
  const parsed = Number.parseInt(String(raw), 10);
  if (Number.isNaN(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function parseHealthUrl(rawApiUrl) {
  let baseUrl;
  try {
    baseUrl = new URL(rawApiUrl);
  } catch (error) {
    throw new Error(`Invalid API_URL: ${rawApiUrl}`);
  }
  return new URL('/health', `${baseUrl.toString().replace(/\/$/, '')}/`);
}

function isLoopbackHost(hostname) {
  return hostname === '127.0.0.1' || hostname === 'localhost' || hostname === '::1';
}

function requestStatus(url, timeoutMs) {
  return new Promise((resolve, reject) => {
    const transport = url.protocol === 'https:' ? https : http;
    const req = transport.request(
      url,
      {
        method: 'GET',
        timeout: timeoutMs,
      },
      (res) => {
        const statusCode = res.statusCode ?? 0;
        res.resume();
        resolve(statusCode);
      },
    );
    req.on('timeout', () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
    req.end();
  });
}

async function isApiHealthy(healthUrl) {
  try {
    const statusCode = await requestStatus(healthUrl, 3000);
    return statusCode >= 200 && statusCode < 300;
  } catch {
    return false;
  }
}

async function isFrontendReachable(rawFrontendUrl) {
  try {
    const url = new URL(rawFrontendUrl);
    const statusCode = await requestStatus(url, 3000);
    return statusCode >= 200 && statusCode < 500;
  } catch {
    return false;
  }
}

function runSync(command, args) {
  return spawnSync(command, args, {
    cwd: repoRoot,
    encoding: 'utf8',
    shell: process.platform === 'win32',
  });
}

function dockerDesktopAvailable() {
  const result = runSync('docker', ['version', '--format', '{{.Server.Version}}']);
  return result.status === 0 && result.stdout.trim().length > 0;
}

function runCommand(command, args, options = {}) {
  const inheritOutput = options.inheritOutput ?? true;
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env: process.env,
      shell: process.platform === 'win32',
      stdio: inheritOutput ? 'inherit' : ['ignore', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    if (!inheritOutput) {
      child.stdout?.on('data', (chunk) => {
        stdout += String(chunk);
      });
      child.stderr?.on('data', (chunk) => {
        stderr += String(chunk);
      });
    }

    child.on('exit', (code) =>
      resolve({
        code: code ?? 0,
        stdout,
        stderr,
      }),
    );
  });
}

async function waitForApi(healthUrl) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < healthTimeoutMs) {
    if (await isApiHealthy(healthUrl)) return true;
    await sleep(healthPollIntervalMs);
  }
  return false;
}

async function ensureApiAvailable(healthUrl) {
  if (await isApiHealthy(healthUrl)) {
    log(`API reachable at ${healthUrl.origin}.`);
    return true;
  }

  if (!isLoopbackHost(healthUrl.hostname)) {
    logError(`API not reachable at ${healthUrl.origin}. Start that backend or update API_URL before running the frontend.`);
    return false;
  }

  const forceBuild = String(process.env.DEV_API_BUILD || '').toLowerCase() === 'true';
  const verboseDocker = String(process.env.DEV_VERBOSE_DOCKER || '').toLowerCase() === 'true';
  const composeArgs = ['compose', 'up', '-d'];
  if (forceBuild) composeArgs.push('--build');
  composeArgs.push('api');

  log(`API not reachable at ${healthUrl.origin}; attempting to start Docker API service (${forceBuild ? 'with build' : 'without rebuild'}).`);

  if (!dockerDesktopAvailable()) {
    logError('Docker Desktop is not running. Start Docker Desktop, then run `docker compose up -d --build api` or set API_URL to a reachable backend.');
    return false;
  }

  const composeResult = await runCommand('docker', composeArgs, { inheritOutput: verboseDocker });
  if (composeResult.code !== 0) {
    logError('Failed to start the API container.');
    const detail = `${composeResult.stderr || ''}\n${composeResult.stdout || ''}`.trim();
    if (detail) logError(detail);
    logError('Check `docker compose logs api postgres opensearch redis`.');
    return false;
  }

  log(`Waiting for ${healthUrl.toString()} ...`);
  const healthy = await waitForApi(healthUrl);
  if (!healthy) {
    logError('API did not become healthy in time. Check `docker compose logs api postgres opensearch redis`.');
    await runCommand('docker', ['compose', 'logs', '--tail', '120', 'api', 'postgres', 'opensearch', 'redis']);
    return false;
  }

  log(`API reachable at ${healthUrl.origin}.`);
  return true;
}

function startFrontend() {
  log('Starting frontend dev server.');
  const child = spawn('npm', frontendCommand, {
    cwd: repoRoot,
    env: process.env,
    shell: process.platform === 'win32',
    stdio: 'inherit',
  });

  const forwardSignal = (signal) => {
    if (!child.killed) child.kill(signal);
  };

  process.on('SIGINT', forwardSignal);
  process.on('SIGTERM', forwardSignal);
  child.on('exit', (code) => process.exit(code ?? 0));
}

async function main() {
  let healthUrl;
  try {
    healthUrl = parseHealthUrl(apiUrl);
  } catch (error) {
    logError(error instanceof Error ? error.message : String(error));
    process.exit(1);
    return;
  }

  const ready = await ensureApiAvailable(healthUrl);
  if (!ready) {
    process.exit(1);
    return;
  }

  if (skipFrontend) {
    log('DEV_SKIP_FRONTEND=true; backend is ready, skipping frontend startup.');
    process.exit(0);
    return;
  }

  if (await isFrontendReachable(frontendUrl)) {
    log(`Frontend already reachable at ${frontendUrl}; skipping frontend dev server startup.`);
    process.exit(0);
    return;
  }

  startFrontend();
}

main().catch((error) => {
  logError(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
