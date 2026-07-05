const http = require('node:http');
const path = require('node:path');
const { spawn, spawnSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
const HOST = '127.0.0.1';
const PORT = 3100;
const LOGIN_URL = `http://${HOST}:${PORT}/login`;
const NEXT_BIN = path.join(ROOT, 'node_modules', 'next', 'dist', 'bin', 'next');
const PLAYWRIGHT_BIN = path.join(
  ROOT,
  'node_modules',
  '@playwright',
  'test',
  'cli.js'
);

let server;
let stopping = false;

function stopServer() {
  if (stopping || !server?.pid) return;
  stopping = true;

  if (process.platform === 'win32') {
    spawnSync('taskkill', ['/PID', String(server.pid), '/T', '/F'], {
      stdio: 'ignore',
      windowsHide: true,
    });
  } else {
    server.kill('SIGTERM');
  }
}

function probeServer() {
  return new Promise((resolve) => {
    const request = http.get(LOGIN_URL, (response) => {
      response.resume();
      resolve(response.statusCode === 200);
    });
    request.setTimeout(2_000, () => request.destroy());
    request.on('error', () => resolve(false));
  });
}

async function waitForServer(timeoutMs = 180_000) {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    if (server.exitCode !== null) {
      throw new Error(`Next.js exited before becoming ready (code ${server.exitCode}).`);
    }
    if (await probeServer()) return;
    await new Promise((resolve) => setTimeout(resolve, 500));
  }

  throw new Error(`Next.js did not become ready at ${LOGIN_URL}.`);
}

async function main() {
  server = spawn(process.execPath, [NEXT_BIN, 'dev', '-H', HOST, '-p', String(PORT)], {
    cwd: ROOT,
    env: {
      ...process.env,
      NODE_ENV: 'development',
      API_URL: 'http://127.0.0.1:4010',
    },
    stdio: ['ignore', 'inherit', 'inherit'],
    windowsHide: true,
  });

  await waitForServer();

  const testProcess = spawn(
    process.execPath,
    [PLAYWRIGHT_BIN, 'test', ...process.argv.slice(2)],
    {
      cwd: ROOT,
      env: process.env,
      stdio: 'inherit',
      windowsHide: true,
    }
  );

  const exitCode = await new Promise((resolve, reject) => {
    testProcess.once('error', reject);
    testProcess.once('exit', (code) => resolve(code ?? 1));
  });

  process.exitCode = exitCode;
}

process.once('SIGINT', () => {
  stopServer();
  process.exit(130);
});
process.once('SIGTERM', () => {
  stopServer();
  process.exit(143);
});

main()
  .catch((error) => {
    console.error(error);
    process.exitCode = 1;
  })
  .finally(stopServer);
