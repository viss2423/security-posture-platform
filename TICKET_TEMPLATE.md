# Ticket spec — <feature name>

Fill this in once, then paste the relevant slice into each tool's window.
This keeps the three lanes (Codex / Deepseek / Claude) consistent. See `AGENTS.md` for the delegation model.

## Goal
<one sentence: what the user should be able to do afterward>

## Files in scope
- `<path>` — <what changes here>

Keep edits to these files. Don't touch anything else without flagging it.

## Lane assignments
- [ ] **Codex** (default developer): <the implementation — endpoint / component / logic>.
      Run GitNexus `impact` first if this touches a shared symbol.
- [ ] **Deepseek / Cursor** (bulk lane): <tests / docs / boilerplate — single-file only, no cross-file refactor>.
- [ ] **Claude / Sonnet** (gate): impact check if risky · **screenshot the UI** · `detect_changes` before merge.

## Constraints
- Match surrounding style (naming, comments, idioms).
- Security: does this touch auth / secrets / data flow / external egress?  **[ yes / no ]**  — if yes, Claude reviews.
- Contract details: <API shape / prop types / expected behavior / edge cases>

## Branch
`feat/<slug>`  — one model owns it at a time.

## Done when
- <acceptance check 1>
- <acceptance check 2>
- Claude ran `detect_changes()` and the scope matches expectations.
