---
description: Turn a workflow that was completed successfully in this session into a reusable slash command in .claude/commands/. Uses only what the session actually shows; invents nothing.
argument-hint: "[command-name] [what the workflow did, if the session holds more than one]"
disable-model-invocation: true
---

# /capture-workflow — save a proven workflow as a command

Arguments: `$ARGUMENTS`
- First word (`$1`), optional: the new command's name, kebab-case
  (`^[a-z0-9]+(-[a-z0-9]+)*$`). If it is absent, propose one.
- The rest, optional: which workflow to capture, when this session holds more
  than one.

## Source: only what is accessible

Use only the history this session can actually see: this conversation, its
tool calls and their outputs. Read a transcript file only if the user names
its path.

- If the history does not contain a **completed and verified** workflow, stop
  and say so in one line. Do not reconstruct one from memory, from the
  repository or from what "usually" happens.
- A step, command, test or result enters the new command only if it appears
  in the history. If a step is implied but was not shown, mark it
  `NOT_VERIFIED: <why>` in your report and leave it out of the command.

## 1. Check for duplicates first (skills-first)

List `.claude/skills/*/SKILL.md` and `.claude/commands/*.md`.
- If an existing skill or command already covers the workflow, report which
  one and propose an edit to it instead of a new command. Stop there unless
  the user asks for the new command anyway.
- If `.claude/commands/<name>.md` exists, never overwrite it. Propose another
  name, or a diff to the existing file.

## 2. Extract from the history

Write these down for the user:
1. **Goal** — what the workflow achieved.
2. **Steps in order** — each with the tool or exact terminal command used.
3. **Verification** — how success was checked: tests, outputs, CI runs, with
   the evidence labels from `CLAUDE.md` (`RUNTIME_VERIFIED`,
   `SOURCE_VERIFIED`, …).
4. **Failures and corrections** — what went wrong, how it was found, and what
   fixed it. These become explicit checks or warnings in the command.
5. **Boundaries** — the approvals and limits the workflow respected. These
   include the owner-only actions in `CLAUDE.md`.

## 3. Separate procedure from data

- Keep what is reusable: the order of steps, the commands, the checks, the
  pitfalls.
- Remove what belongs to this one task: SHAs, PR numbers, file names that
  will differ next time, test counts, dates, temporary paths and secrets.
  Replace each variable input with `$1`, `$2`, … for positional values, or
  with `$ARGUMENTS` for free text. Document every argument in
  `argument-hint` and in the body.
- Never copy secrets, tokens, keys or private data into the command.

## 4. Write the command

Create `.claude/commands/<name>.md` in this shape:

```markdown
---
description: <one line: what it does and when to use it>
argument-hint: "<arguments>"
disable-model-invocation: true
---

# /<name> — <short title>

Arguments: `$ARGUMENTS` (<what each one means>)

## Steps
1. …
## Verification
- … (what must be observed before reporting success)
## Known pitfalls
- … (from the failures above)
## Boundaries
- Owner approval needed for: … (from CLAUDE.md and the workflow)
- Report in the three-line format from CLAUDE.md.
```

The command must not weaken any rule in `CLAUDE.md`. It must not authorize a
merge, a deploy, a cryptography or protocol change, or a hook activation the
workflow did not already need the Owner's approval for.

## 5. Report

Start with the three-line summary from `CLAUDE.md`. Below it:
- the file created, and `git diff --stat` plus the full content;
- every step that was left out as `NOT_VERIFIED`, and why;
- how to invoke it: `/<name> <example arguments>`.

Do not commit or push. Committing is a separate step the user asks for.
