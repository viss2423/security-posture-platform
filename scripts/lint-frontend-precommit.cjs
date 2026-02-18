/** Pre-commit: run ESLint on staged frontend files. Uses project's eslint (no npx cache). */
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..");
const frontendDir = path.join(repoRoot, "services", "frontend");
const eslintBin = path.join(frontendDir, "node_modules", "eslint", "bin", "eslint.js");
const prefix = "services/frontend/";

const files = process.argv.slice(2).filter((f) => f.startsWith(prefix));
const relFiles = files.map((f) => f.slice(prefix.length).replace(/\\/g, "/"));
if (relFiles.length === 0) process.exit(0);

const r = spawnSync("node", [eslintBin, "--max-warnings", "0", ...relFiles], {
  cwd: frontendDir,
  stdio: "inherit",
});
process.exit(r.status ?? 1);
