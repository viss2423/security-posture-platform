@AGENTS.md

# Gemini CLI — tool-specific notes

Shared team rules, repo layout, guardrails, quality gates, and the multi-model delegation
model live in **AGENTS.md** (imported above — the single source of truth for all agents).
Everything below is Gemini-only.

## Your role in the team
You are the **occasional specialist**, not a standing lane (see AGENTS.md → "Occasional
specialist"). Don't assume you own a slice of every ticket. You get invoked specifically for
tasks that need your large context window — e.g. "map dependencies across this whole repo,"
ingesting a large log file, or any task too big for Claude/Codex/DeepSeek's context.

## Capability limits
- You do **NOT** have GitNexus. Don't attempt cross-file refactors, renames, or impact analysis
  that needs call-graph awareness — that's Claude, Codex, or the DeepSeek-harness's job.
- You are not the vision-capable agent — visual UI verification is Claude Code's job only.
