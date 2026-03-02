const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const repoRoot = path.resolve(__dirname, "..");
const frontendDir = path.join(repoRoot, "services", "frontend");
const nextDir = path.join(frontendDir, ".next");

const budgets = {
  maxRootMainJsKb: 450,
  maxLargestJsChunkKb: 250,
  maxLargestRouteHtmlKb: 50,
};

function walk(dir, predicate, results = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(fullPath, predicate, results);
      continue;
    }
    if (predicate(fullPath)) results.push(fullPath);
  }
  return results;
}

function toKb(bytes) {
  return Number((bytes / 1024).toFixed(1));
}

function readJson(filePath) {
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function countUseClientFiles(baseDir, filter = () => true) {
  const files = walk(
    baseDir,
    (filePath) =>
      [".ts", ".tsx", ".js", ".jsx"].includes(path.extname(filePath)) &&
      filter(filePath) &&
      !filePath.includes(`${path.sep}.next${path.sep}`) &&
      !filePath.includes(`${path.sep}node_modules${path.sep}`)
  );

  return files.filter((filePath) => {
    const source = fs.readFileSync(filePath, "utf8");
    return /^['"]use client['"];\s*/m.test(source);
  }).length;
}

function collectFiles(baseDir, ext, filter = () => true) {
  return walk(baseDir, (filePath) => path.extname(filePath) === ext && filter(filePath));
}

function sumRootMainJsBytes(buildManifest) {
  return (buildManifest.rootMainFiles || []).reduce((total, relativePath) => {
    const fullPath = path.join(nextDir, relativePath);
    if (!fs.existsSync(fullPath)) return total;
    return total + fs.statSync(fullPath).size;
  }, 0);
}

function findLargestFile(files) {
  return files.reduce((largest, filePath) => {
    const size = fs.statSync(filePath).size;
    if (!largest || size > largest.bytes) {
      return { path: filePath, bytes: size };
    }
    return largest;
  }, null);
}

function formatRepoPath(filePath) {
  return path.relative(repoRoot, filePath).replace(/\\/g, "/");
}

const shouldSkipBuild = process.argv.includes("--skip-build");

let buildSeconds = 0;
if (!shouldSkipBuild) {
  const start = Date.now();
  const nodeOptions = [process.env.NODE_OPTIONS, "--max-old-space-size=4096"]
    .filter(Boolean)
    .join(" ");
  const result = spawnSync("npm", ["run", "build"], {
    cwd: frontendDir,
    env: {
      ...process.env,
      NODE_OPTIONS: nodeOptions,
    },
    stdio: "inherit",
    shell: process.platform === "win32",
  });
  buildSeconds = Number(((Date.now() - start) / 1000).toFixed(1));
  if ((result.status ?? 1) !== 0) {
    process.exit(result.status ?? 1);
  }
}

const buildManifestPath = path.join(nextDir, "build-manifest.json");
if (!fs.existsSync(buildManifestPath)) {
  console.error("Missing Next build manifest. Run a frontend build first.");
  process.exit(1);
}

const buildManifest = readJson(buildManifestPath);
const rootMainJsBytes = sumRootMainJsBytes(buildManifest);
const jsChunks = collectFiles(
  path.join(nextDir, "static", "chunks"),
  ".js",
  (filePath) => !filePath.endsWith(".map")
);
const htmlRoutes = collectFiles(path.join(nextDir, "server", "app"), ".html");

const largestJsChunk = findLargestFile(jsChunks);
const largestRouteHtml = findLargestFile(htmlRoutes);
const appPageCount = collectFiles(path.join(frontendDir, "app"), ".tsx", (filePath) =>
  filePath.endsWith(`${path.sep}page.tsx`)
).length;
const clientAppPageCount = countUseClientFiles(
  path.join(frontendDir, "app"),
  (filePath) => filePath.endsWith(`${path.sep}page.tsx`)
);
const clientFileCount = countUseClientFiles(frontendDir);

const metrics = {
  buildSeconds,
  rootMainJsKb: toKb(rootMainJsBytes),
  largestJsChunkKb: largestJsChunk ? toKb(largestJsChunk.bytes) : 0,
  largestRouteHtmlKb: largestRouteHtml ? toKb(largestRouteHtml.bytes) : 0,
  clientFiles: clientFileCount,
  clientAppPages: clientAppPageCount,
  appPages: appPageCount,
};

const failures = [];

if (metrics.rootMainJsKb > budgets.maxRootMainJsKb) {
  failures.push(
    `root main JS ${metrics.rootMainJsKb}KB exceeded ${budgets.maxRootMainJsKb}KB`
  );
}
if (metrics.largestJsChunkKb > budgets.maxLargestJsChunkKb) {
  failures.push(
    `largest JS chunk ${metrics.largestJsChunkKb}KB exceeded ${budgets.maxLargestJsChunkKb}KB`
  );
}
if (metrics.largestRouteHtmlKb > budgets.maxLargestRouteHtmlKb) {
  failures.push(
    `largest route HTML ${metrics.largestRouteHtmlKb}KB exceeded ${budgets.maxLargestRouteHtmlKb}KB`
  );
}

console.log("\nFrontend performance budget");
console.log(
  `- Build time: ${shouldSkipBuild ? "skipped" : `${metrics.buildSeconds}s`}`
);
console.log(`- Root main JS: ${metrics.rootMainJsKb}KB`);
console.log(
  `- Largest JS chunk: ${metrics.largestJsChunkKb}KB (${largestJsChunk ? formatRepoPath(largestJsChunk.path) : "n/a"})`
);
console.log(
  `- Largest route HTML: ${metrics.largestRouteHtmlKb}KB (${largestRouteHtml ? formatRepoPath(largestRouteHtml.path) : "n/a"})`
);
console.log(`- Client files: ${metrics.clientFiles}`);
console.log(`- Client app pages: ${metrics.clientAppPages}/${metrics.appPages}`);

if (!shouldSkipBuild && metrics.buildSeconds > 75) {
  console.warn(
    `Warning: build time is ${metrics.buildSeconds}s. Treat this as a regression signal, but it is not a hard failure because local and CI hardware vary.`
  );
}

if (metrics.clientAppPages === metrics.appPages && metrics.appPages > 0) {
  console.warn(
    "Warning: every app route is still a client entrypoint. Converting high-traffic pages to server components is the biggest structural win."
  );
}

if (failures.length > 0) {
  for (const failure of failures) {
    console.error(`FAIL: ${failure}`);
  }
  process.exit(1);
}

console.log("Performance budget passed.");
