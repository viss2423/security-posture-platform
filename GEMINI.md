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
- You DO have GitNexus (`.gemini/settings.json` wires it in) — use `query`/`context`/`impact` if you
  need to understand code while doing row-11 work. But this does NOT make you a developer lane:
  cross-file refactors, renames, and feature implementation (rows 1–5) are never yours, by policy,
  regardless of whether you're technically capable of them.
- You are not the vision-capable agent — visual UI verification is Claude Code's job only.
