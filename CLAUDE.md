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

## Model routing (the main cost lever)
- **Haiku** — trivial mechanical edits, git ops, log reading, running `detect_changes`.
- **Sonnet** — default. Routine implementation, UI work + visual verification, code review.
- **Opus** — reserve for the hardest ~10%: gnarly debugging, cross-system architecture,
  security judgment. Don't burn Opus on routine work.

`effortLevel` is `medium` globally; raise it only for genuinely hard problems.

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
