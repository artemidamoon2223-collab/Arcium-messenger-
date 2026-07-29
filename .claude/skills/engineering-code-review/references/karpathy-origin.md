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
| Не падай молча / Не притворяйся | `CLAUDE.md` → «Границы доказательств и формулировок» |
| Короткие блоки кода | `SKILL.md` constraints |

## Deliberately not carried over

The framing as a named external methodology, the link as an authority, and the
scoring rubric style ("оцени каждый принцип ✅/⚠️/❌") were dropped from
always-loaded context. They are motivational rather than testable, and the
concrete requirements above stand on their own without the branding.

Note that a CI job, `karpathy-review`, still scores pull requests against these
four principles — see `.github/workflows/karpathy-review.yml`. That workflow is
unchanged and remains a blocking gate; this file does not alter it.

## Subagent guidance — preserved, and in tension with session policy

The original `CLAUDE.md` carried this advice, sourced from
<https://gist.github.com/hqman/e29cb6386c539d795767e8c3fd2c959b>:

> Если задача распадается на независимые части — запускай их параллельно, по
> одной задаче на субагент. Не делай всё последовательно когда части не зависят
> друг от друга.
>
> Пример: нужно проверить `cargo test` + `tsc --noEmit` + grep на висячие
> ссылки — это три независимых вызова, запускай одновременно.

**Conflict, preserved rather than resolved:** some Claude Code sessions run
under a harness instruction not to spawn subagents unless the user explicitly
asks. Where that applies, it is the stricter constraint and it wins — but the
underlying point survives without subagents: independent checks should be
issued in parallel in a single step, not run one after another.
