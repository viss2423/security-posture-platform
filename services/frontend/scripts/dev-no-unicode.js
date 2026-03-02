/**
 * Runs Next.js dev server and filters stdout to replace Unicode symbols
 * (e.g. checkmarks, circles) with ASCII so logs are plain-text friendly.
 */
const { spawn } = require('child_process');

const REPLACEMENTS = [
  [/[\u2713\u2714\u2705]/g, '[OK]'],   // checkmarks, white heavy check
  [/[\u2717\u2718\u274C]/g, '[X]'],    // crosses, cross mark
  [/[\u25CB\u25CF]/g, '[*]'],          // circle, black circle
  [/[\u2190\u2192\u2191\u2193]/g, '-'], // arrows
  [/[\u2022]/g, '*'],                 // bullet
  [/[\u2014\u2013]/g, '-'],            // em/en dash
];

function stripUnicode(line) {
  let out = line;
  for (const [re, replacement] of REPLACEMENTS) {
    out = out.replace(re, replacement);
  }
  return out;
}

const child = spawn('npx', ['next', 'dev'], {
  stdio: ['inherit', 'pipe', 'pipe'],
  shell: true,
  env: { ...process.env, NEXT_TELEMETRY_DISABLED: '1' },
});

child.stdout.on('data', (data) => {
  const lines = data.toString().split('\n');
  lines.forEach((line) => process.stdout.write(stripUnicode(line) + '\n'));
});

child.stderr.on('data', (data) => {
  const lines = data.toString().split('\n');
  lines.forEach((line) => process.stderr.write(stripUnicode(line) + '\n'));
});

child.on('close', (code) => process.exit(code ?? 0));
