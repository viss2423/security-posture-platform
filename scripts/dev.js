const http = require('http');
const https = require('https');
const path = require('path');
const { spawn, spawnSync } = require('child_process');

const repoRoot = path.resolve(__dirname, '..');
const defaultApiUrl = 'http://127.0.0.1:8000';
const apiUrl = process.env.API_URL || defaultApiUrl;
const frontendCommand = ['run', 'dev', '--prefix', 'services/frontend'];
const healthTimeoutMs = 120000;
const healthPollIntervalMs = 2000;

function log(message) {
  process.stdout.write(`[dev] ${message}\n`);
}

function logError(message) {
  process.stderr.write(`[dev] ${message}\n`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
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

function runCommand(command, args) {
  return new Promise((resolve) => {
    const child = spawn(command, args, {
      cwd: repoRoot,
      env: process.env,
      shell: process.platform === 'win32',
      stdio: 'inherit',
    });
    child.on('exit', (code) => resolve(code ?? 0));
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

  log(`API not reachable at ${healthUrl.origin}; attempting to start the Dockerized API.`);

  if (!dockerDesktopAvailable()) {
    logError('Docker Desktop is not running. Start Docker Desktop, then run `docker compose up -d --build api` or set API_URL to a reachable backend.');
    return false;
  }

  const composeExitCode = await runCommand('docker', ['compose', 'up', '-d', '--build', 'api']);
  if (composeExitCode !== 0) {
    logError('Failed to start the API container. Check `docker compose logs api postgres opensearch redis`.');
    return false;
  }

  log(`Waiting for ${healthUrl.toString()} ...`);
  const healthy = await waitForApi(healthUrl);
  if (!healthy) {
    logError('API did not become healthy in time. Check `docker compose logs api postgres opensearch redis`.');
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

  startFrontend();
}

main().catch((error) => {
  logError(error instanceof Error ? error.message : String(error));
  process.exit(1);
});
