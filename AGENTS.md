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

## Multi-model delegation
Work is split across models to control cost and cover single-model blind spots. Know your lane:

- **Claude Code** — specialist, safety gate, and the *only* agent that can **see** rendered UI.
  Owns: hard architecture/security judgment, **visual UI verification**, and the GitNexus pre-merge gate.
- **Codex CLI** — the **default developer**. Full agent, has GitNexus.
  Owns: feature implementation, code review, cross-file changes.
- **DeepSeek (via the Claude Code harness, `deepseek-v4-pro`/`deepseek-v4-flash`)** — the **second
  developer / bulk lane**. A separate terminal session with `ANTHROPIC_BASE_URL` pointed at DeepSeek's
  API (see `~/.claude/run-deepseek-claude.ps1`, not in this repo). Reads this same `AGENTS.md` and has
  GitNexus (same binary as Claude Code) — so unlike the old Cursor setup, it CAN run `impact`/`rename`.
  Owns: feature implementation Codex isn't already doing, tests, boilerplate, docs, refactors.

Rules of engagement:
- One model owns a task at a time, on its own branch.
- The GitNexus-enabled agent (Claude, Codex, or DeepSeek-harness) runs `detect_changes()` before a merge.
- Only Claude Code (the real one, on your Anthropic account) does the **visual UI verification** —
  the DeepSeek harness is a different account/session and should not be treated as the vision-capable one.

### Occasional specialist (not a standing lane)
- **Gemini CLI** — invoke only for tasks that need its ~1M-token context (e.g. "map dependencies
  across this whole repo/service" or ingesting a huge log). Not part of the default rotation —
  adding it as a 4th standing lane would duplicate the DeepSeek-harness developer role without a
  distinct job, just more coordination overhead for no gain.

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
