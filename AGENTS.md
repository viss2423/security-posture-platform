# security-posture-platform — shared agent context

> **Single source of truth for every AI agent** (Claude Code, Codex CLI, DeepSeek-via-Claude-Code-harness,
> Gemini CLI as occasional specialist). Each tool points here. Edit shared rules **in this file**,
> not in tool-specific ones.

## What this is
A **security posture platform** — a security product being built toward something sellable.
Treat anything touching secrets, auth, data flow, or external egress as high-stakes:
flag it, don't guess.

## Repo layout
- **Backend API:** `services/api/` (Python, FastAPI; settings in `services/api/app/settings.py`)
- **Frontend:** `services/frontend/` (Next.js App Router under `services/frontend/app/`; components in `services/frontend/components/`)
- **Infra/K8s:** `infra/`, Helm + manifests under `artifacts/`

## Working style (large repo — ~672 files, 6k+ symbols)
- Don't bulk-read. Open only what a task needs; scope edits to the named feature's file
  (e.g. the findings page = `services/frontend/app/(app)/findings/page.tsx`).
- Match surrounding code: naming, comment density, idioms. Keep routine UI changes minimal and in-style.
- If you have GitNexus (Claude, Codex), prefer graph queries over grepping / whole-file reads.

## Guardrails
- Don't commit or push unless asked.
- **NEVER add `Co-Authored-By` / Claude attribution to commits in this repo.**
- Before deleting or overwriting a file, inspect it first.
- Flag any change touching authentication, secret handling, or external data egress.

## Quality gates
- After every edit, verify the diff applied as intended — don't trust edit output alone.
- For scripts (PowerShell / bash / Python), trace every data path end-to-end: where each value
  comes from, where it goes, whether it wrongly crosses a container/host boundary.
- If you haven't executed a change, say so. Never claim a script works untested.
- If the shell is broken or output truncated, verify another way (lock files, installed binaries, timestamps).
- PowerShell: watch `-or` vs null-coalesce, container-vs-host path confusion in volume mounts,
  deprecated registries (Docker Hub → GHCR), and ZAP risk codes (only 0–3, no "Critical").

## Multi-model delegation — DETERMINISTIC, no discretion

Every category below has **exactly one owner**. There is no "or," no "whichever is free," no
picking based on preference. If a task matches a row, it goes to that row's owner. Full stop.

| # | Category (fixed trigger) | Owner | Claude tier (if Claude) |
|---|---|---|---|
| 0 | Ambiguous or cross-category task not yet split | **Claude (spec) → row owner (build)** | Sonnet, spec only |
| 1 | Backend core: new/changed endpoints, business logic in `services/api/app/` (`App`, `Routers` clusters) | **Codex CLI** | — |
| 2 | Frontend feature implementation: new/changed pages, components in `services/frontend/` | **Codex CLI** | — |
| 3 | `services/api/scripts/*` (backup, DR, verification scripts) | **DeepSeek harness** | — |
| 4 | Self-contained backend engines: `Scanner`, `Correlator`, `Notifier`, `Deriver`, `Policy` clusters | **DeepSeek harness** | — |
| 5 | Tests (any), boilerplate, docs | **DeepSeek harness** | — |
| 6 | Visual verification of any frontend change before merge (mandatory, every time) | **Claude Code** | Sonnet |
| 7 | Any change touching auth, secrets, data-boundary, or external egress (the AGENTS.md guardrail trigger) | **Claude Code** designs + hand-writes the sensitive core; DeepSeek harness writes mechanical scaffolding (schema fields, wiring, tests) from Claude's spec; Claude reviews the final diff | Opus |
| 8 | Cross-system architecture decisions with no existing pattern in the repo to follow; the single highest-severity security judgment calls (e.g. confirming a fix for an already-identified auth-bypass / data-exposure class bug) | **Claude/Fable decides** (short written decision: choice + why); build goes to whichever row the resulting code lands on — Fable does not author bulk implementation | Fable, decision only |
| 9 | Final `detect_changes()` gate before merge to `main` (every merge, no exception) | **Claude Code** | Haiku |
| 10 | CI/deploy pipeline changes (`.github/workflows/`, `docker-compose.yml`, deploy scripts) — single owner because this repo's history shows CI breaks when multiple hands touch it reactively | **Claude Code** | Sonnet (escalate to Opus only if the failure itself is the hard-debugging case, category 8's architecture clause does not apply here) |
| 11 | Any task requiring ingestion of content larger than a single agent's normal context (whole-repo dependency mapping, huge log files) | **Gemini CLI** | — |

Rules of engagement (no exceptions):
- One model owns a task at a time, on its own branch. Never two models on the same branch.
- Row 1–5 assignments are fixed by category, not by which agent is idle. If Codex is busy and a
  backend-core task (row 1) is ready, it waits for Codex — it does NOT go to DeepSeek.
- **Row 0 (ambiguous/cross-category tasks) never gets built by Claude by default.** Claude splits
  the task into a short spec — files touched, function signatures, acceptance criteria — and hands
  it to whichever row owner the split resolves to (usually DeepSeek harness), in the
  [[handoff-format-pref]] copy-paste format. Claude only keeps the implementation itself if the
  split lands the whole task on a Claude row (6–10).
  **Size floor:** if the task is small enough that writing the spec and reviewing the returned
  diff would cost more than just doing it directly (rough guide: a single-file, sub-~30-line
  change), skip the handoff — whichever agent is already in the session does it inline. Row 0
  exists to stop *real* delegation leakage, not to tax trivial edits with spec-and-review overhead.
- **Multi-phase tasks: delegation is re-evaluated at the start of every phase, and for every
  discrete action within a phase that could independently match a different row.** A phase
  inherits nothing from the row/owner/tier of the phase before it — "the last unit was Opus" is
  not a reason the next unit is Opus. State the row/owner/tier for each phase when it begins, the
  same one-line disclosure used per task, so drift is visible immediately instead of discovered
  later in a token-spend review.
- **Row 6 (UI verification) is verification only.** If Claude spots a bug while screenshotting, it
  writes up the bug (repro, file, expected vs actual) for Codex/DeepSeek rather than patching it
  inline. Silent inline fixes during a verification pass are the main way Claude ends up quietly
  doing frontend work — don't do it.
- **Row 7 (auth/secret/data-boundary/egress) is now split work, not all-Claude.** Claude decides the
  approach and writes the security-sensitive core (the part where a mistake is exploitable), then
  hands mechanical scaffolding around that core to DeepSeek harness with a precise spec, and reviews
  DeepSeek's diff before it merges. The guardrail ("flag it, don't guess") still applies to Claude's
  own core piece and to the review step — it does not mean Claude must type every line.
- The agent that writes a change (Codex or DeepSeek harness, both GitNexus-enabled) runs its own
  `impact()` before editing. Claude's row-9 `detect_changes()` is the final gate on top of that,
  always, regardless of who wrote the change.
- Only Claude Code on the real Anthropic account does visual verification (row 6). The DeepSeek
  harness is a different account/session and is never substituted for this step.
- Gemini CLI (row 11) is never given row 1–5 work, even if idle. It now HAS GitNexus (wired via
  `.gemini/settings.json`, verified connected) — so the restriction to row 11 is a deliberate policy
  choice, not a capability gap: adding it as a 5th/6th developer lane would duplicate the Codex/
  DeepSeek-harness roles and add coordination overhead for no gain, and its free-tier rate limits
  aren't suited to being hammered as a standing lane. Its only assigned job is row 11.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **security-posture-platform** (6509 symbols, 15416 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/security-posture-platform/context` | Codebase overview, check index freshness |
| `gitnexus://repo/security-posture-platform/clusters` | All functional areas |
| `gitnexus://repo/security-posture-platform/processes` | All execution flows |
| `gitnexus://repo/security-posture-platform/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
