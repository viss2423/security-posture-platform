<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **security-posture-platform** (6269 symbols, 14964 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

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

# Token-Efficient Workflow

Keep Claude token usage low while working on this large repo (≈672 files, 6k+ symbols). Apply in priority order:

1. **Navigate with GitNexus, don't bulk-read.** Default to `query` / `context` / `impact` (targeted graph snippets) before `Read`-ing whole files. Reach for full-file reads only when a symbol-level view is insufficient. On this repo that's the single biggest saver.
2. **Scope edits to a path.** When the user names a feature ("the findings page"), resolve it to the specific file (e.g. `services/frontend/app/(app)/findings/page.tsx`) and open that, instead of searching broadly.
3. **Model routing.** Routine UI work (CSS/Tailwind, copy, simple component edits) is fine on Sonnet (`/model sonnet`) — reserve Opus for hard debugging/architecture. `effortLevel` is `medium` globally; only raise it for genuinely hard problems.
4. **Session hygiene.** Suggest `/clear` when the user switches to an unrelated task, and `/compact` inside a long single task. Don't drag unrelated context across topics.
5. **Don't over-load skills/context.** Only invoke a skill (e.g. the Claude-API skill) when the task actually needs it — they add large docs to context. Prefer file paths over pasting large files/logs.
6. **Keep impact queries lean.** Use a smaller `maxDepth` when the full blast-radius tree isn't needed; the default deep tree is token-heavy.

Note: prompt caching is automatic in Claude Code — keep sessions continuous (idle >5 min cools the cache). Token-saving setup details live in agent memory ([[gitnexus-token-setup]], [[cli-token-spend]]).
