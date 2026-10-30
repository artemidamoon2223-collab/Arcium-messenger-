---
name: qc-spec
description: "Write and lock executable acceptance criteria for an Arcium task BEFORE implementing it: classify the change's risk (crypto, identity, durable state, Android lifecycle, FFI, network, PSI, CI integrity, supply chain, agent control), turn each requirement into a command whose exit code and output decide it, and lock the spec so it cannot move mid-task. Use at the start of any Owner-authorized implementation that will later go through qc-loop. Authorizes nothing."
disable-model-invocation: true
argument-hint: "<spec-id> (3-64 chars, a-z 0-9 -)"
---

# qc-spec — acceptance criteria before implementation

This skill authorizes nothing. The Owner's instruction for the task is the
only authority; the spec quotes it, it does not replace it.

The engine is `.claude/qc/qc.py` (stdlib Python, deterministic). Specs and
evidence live in `<git-dir>/arcium-qc/`, outside the working tree, and are
never committed.

## Steps

1. Work in the disposable clone of `repo-change-protocol` §2, with HEAD on
   the task's base commit and a clean tree.
2. `python3 .claude/qc/qc.py spec-init $ARGUMENTS` — prints the spec path.
   It starts from the verification commands of `CLAUDE.md` («Команды
   проверки»); keep, narrow or extend them, never weaken them silently.
3. Predict the risk: which paths the task will touch. After implementing,
   `python3 .claude/qc/qc.py classify <base>` computes it from the real diff.
   - Owner-gated classes — `CRYPTO`, `PROTOCOL`, `PSI`, `CI_INTEGRITY`,
     `SUPPLY_CHAIN`, `AGENT_CONTROL` — may be changed only if the Owner's
     instruction says so. List exactly those in `owner_authorizes` and quote
     the instruction in `owner_instruction`. Anything else touched ends the
     loop in `ESCALATE_TO_OWNER`.
   - Never list a class the instruction does not name. The spec is read by
     the Owner; an unsupported authorization is a finding against you.
4. Write the criteria. Each one is decided by a command, not by a judgment:
   - `command`: an argv list. `spec-check` refuses a shell, `env` or `xargs`
     as the program, and `git` (except read-only subcommands), `gh`, `curl`,
     `wget`, `anchor`, `solana`, `arcium`. That checks the program name only:
     a criterion is code that runs on this machine, and `python3 -c …` or a
     script can do anything, including print a fake success line. The
     Owner and `qc-reviewer` judge the criteria; write them so a reader can
     see they test the requirement.
   - `must_match` / `must_not_match`: regexes over stdout+stderr. A test run
     must prove tests ran (`spec-check` refuses it otherwise): cargo
     `test result: ok\. [1-9][0-9]* passed; 0 failed`; Gradle with
     `--console=plain`, `^> Task :app:testDebugUnitTest$` (executed, not
     `NO-SOURCE` or `UP-TO-DATE`).
   - `requires` (tools on PATH), `requires_env_any`, `requires_path`,
     `network: true` (with an optional `network_probe` URL), `timeout`.
     A missing prerequisite yields `NOT_VERIFIED`, never a pass.
   - A requirement only a person or a device can judge (Pixel, UX) is
     `"manual": true`. It keeps the task at `NOT_VERIFIED` until the Owner
     checks it — that is the honest state, not a defect.
   - For a bug fix, include the regression test that fails on the base
     (`qc-investigate` records that it does).
   - If the task touches `arcium-psi/tests`, add the `npx tsc --noEmit` and
     `npx mocha` checks of `CLAUDE.md` («Команды проверки»).
5. `python3 .claude/qc/qc.py spec-check <id>` until it reports valid.
6. `python3 .claude/qc/qc.py lock <id>` — refuses unless HEAD equals `base`
   and the tree is clean, so the criteria provably predate the
   implementation. After lock, editing the spec or the QC tool turns every
   verdict into `BLOCKED`. A different task needs a new id.

Spec fields: `id`, `title`, `base` (40-hex SHA), `owner_instruction`,
`owner_authorizes`, `max_repair_rounds` (0–3), `criteria[]` with `id`,
`description`, `command` | `manual`, `cwd`, `env`, `timeout`, `expect_exit`,
`must_match`, `must_not_match`, `requires`, `requires_env_any`,
`requires_path`, `network`, `network_probe`.

Then continue with `qc-loop`.
