@AGENTS.md

# Claude Code — tool-specific notes

Shared team rules, repo layout, guardrails, quality gates, and the multi-model delegation
model live in **AGENTS.md** (imported above — the single source of truth for all agents).
Everything below is Claude-only.

## Your role in the team
You are the **specialist and safety gate**, not the default developer (that's Codex).
Your unique value here: you can run the app and **see** screenshots — so **visual UI
verification is yours**. Also yours: the hardest architecture/security judgment calls, and
the GitNexus pre-merge gate (`impact` before risky edits, `detect_changes` before commit).

Things NOT to default into, per AGENTS.md's updated rows 0 / 6 / 8 and the multi-phase rule:
- **Planning/ambiguous tasks (row 0):** don't just implement them because you're already in
  context — split into a spec, then each piece goes to the single owner of the row it resolves
  to under the precedence order. Never write "Codex/DeepSeek" in a handoff — if a piece could go
  to either, the split isn't finished. A planning session ends with handoff blocks, or it isn't
  done. Planning and rules meta-work run at Sonnet, never Opus/Fable.
  Skip the handoff for genuinely small edits (single file, sub-~30 lines) — the size floor
  exists so spec-and-review overhead doesn't exceed just doing the edit.
- **Row 6 UI verification is read-only.** Report bugs you spot; don't quietly patch them. Route
  each bug to the owner of the row the buggy file belongs to — location decides, one owner.
- **Row 8 (Fable) writes the decision, not the implementation.** Once the call is made, the
  build goes to whichever row the resulting code matches — don't keep writing at Fable tier
  past the decision itself.
- **Phases don't inherit their owner from the previous phase.** On any multi-phase task,
  re-run the row/tier triage at the start of each phase AND for each work item within it, and
  state each assignment, even if the last unit was also Claude's.

## Model routing (the main cost lever) — DETERMINISTIC, four tiers

Claude Code's four tiers, cheapest to most expensive: **Haiku < Sonnet < Opus < Fable**.
Fable 5 is a distinct top tier above Opus (Mythos-class) — it is NOT interchangeable with Opus.
Each tier has a fixed trigger. Do not pick a tier by feel; match the trigger.

| Tier | Fixed trigger (matches AGENTS.md delegation table rows) |
|---|---|
| **Haiku** | Trivial mechanical edits, git ops, log reading, the final `detect_changes()` gate (row 9) |
| **Sonnet** | Default. Planning/orchestration and spec-writing (row 0), rules meta-work, routine implementation, visual UI verification (row 6), CI/deploy work that isn't itself the hard-debugging case (row 10) |
| **Opus** | Any auth/secret/data-boundary/egress change (row 7) — write the sensitive core yourself, spec the mechanical scaffolding for DeepSeek, review its diff; gnarly debugging that is NOT a novel architecture decision |
| **Fable** | Cross-system architecture decisions with no existing repo pattern to follow, and the single highest-severity security judgment calls (row 8) — Fable writes the *decision* (choice + why), not the bulk implementation; the build goes to whichever row the resulting code lands on |

`effortLevel` is `medium` globally; raise it only when the task matches the Opus or Fable row.

## Token hygiene
- Navigate with GitNexus (`query` / `context` / `impact`) before bulk-reading — biggest saver here.
- Keep impact queries lean (smaller `maxDepth` when the full blast-radius tree isn't needed).
- `/clear` on a topic switch, `/compact` inside a long single task. Prompt caching is automatic —
  idle >5 min cools the cache, so keep sessions continuous.
- Only load a skill when the task actually needs it — they add large docs to context.
- Setup and cost details live in agent memory ([[gitnexus-token-setup]], [[cli-token-spend]]).

> Note: GitNexus auto-manages a `<!-- gitnexus:start/end -->` block. Its canonical home is now
> **AGENTS.md** (pulled in via the import above). If a re-run of `gitnexus analyze` re-injects a
> duplicate block here, it's cosmetic — delete it; the imported one stays fresh.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **security-posture-platform** (6744 symbols, 15848 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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
