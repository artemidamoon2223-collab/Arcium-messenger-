# Origin material — external principles, non-normative

Background only. **Nothing in this file is project policy.** The binding
engineering rules are in `SKILL.md` and `CLAUDE.md`. This file exists so the
original wording is not lost, and so a later reader can see what was adopted,
what was reworded into something testable, and what was deliberately dropped.

Source referenced by the original `CLAUDE.md`:
<https://github.com/forrestchang/andrej-karpathy-skills>

## Original bullets, as they stood in CLAUDE.md

- **Think Before Coding** — сначала найди реальные значения/API в коде и
  пакетах, потом пиши. Не выдумывай.
- **Simplicity First** — минимум кода решающего задачу. Никаких спекулятивных
  фич, лишних абстракций, обработки невозможных ошибок.
- **Surgical Changes** — не удаляй и не «улучшай» соседний код. Трогай только
  то, что просили.
- **Goal-Driven** — у каждой задачи есть шаг проверки (cargo test / cargo check
  / tsc).
- **Не падай молча** — если что-то не работает, объясни почему фактами.
- **Короткие блоки кода** — разработчик на планшете. Дроби длинный код.
- **Не притворяйся** — если шаг нельзя проверить (нет сети/toolchain), скажи
  прямо.

## What became binding, and where

| Original | Now lives as |
|----------|--------------|
| Think Before Coding | `SKILL.md` workflow step 1 — read the real signature, do not write against recollection |
| Simplicity First | `SKILL.md` workflow step 3 — no speculative features, no single-caller abstractions, no unreachable error branches |
| Surgical Changes | `SKILL.md` workflow step 2, and `repo-change-protocol` §3 |
| Goal-Driven | `SKILL.md` workflow step 4 + `references/delivery-checklist.md` |
| Не падай молча / Не притворяйся | `CLAUDE.md` → «Границы доказательств» |
| Короткие блоки кода | `SKILL.md` constraints |

## Deliberately not carried over

The framing as a named external methodology, the link as an authority, and the
scoring rubric style ("оцени каждый принцип ✅/⚠️/❌") were dropped from
always-loaded context. They are motivational rather than testable, and the
concrete requirements above stand on their own without the branding.

The four principles are still scored per change, by a local review in a
Claude Code session: `karpathy-review.md`.

## Parallel checks

The original `CLAUDE.md` asked for one subagent per independent part of a
task (source: <https://gist.github.com/hqman/e29cb6386c539d795767e8c3fd2c959b>).
What is kept: independent checks (for example `cargo test`, `tsc --noEmit`
and a grep for dangling references) are issued in parallel, as several tool
calls in one step, not one after another. Subagents are not the default: each
one costs a session of its own, so start one only when a task must read many
files or needs a review not anchored on your own conclusions (`CLAUDE.md`,
«Ревью и CI»).
