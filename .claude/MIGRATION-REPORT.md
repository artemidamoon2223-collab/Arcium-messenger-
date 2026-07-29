# CLAUDE.md → skills migration report

Base: `main` @ `93cddf5e394e688da031b20cc97ad1323004245b`.
Scope touched: `CLAUDE.md` and `.claude/**` only. No commit, push, or PR.

## Classification of the previous CLAUDE.md (171 lines)

| Section | Class | Outcome |
|---|---|---|
| Правила работы (Karpathy) — 4 principles | SKILL_CANDIDATE | Rewritten as concrete steps in `engineering-code-review`; original wording preserved in its `references/karpathy-origin.md` |
| «Не падай молча», «Не притворяйся» | ALWAYS_ON | Merged into CLAUDE.md → «Границы доказательств и формулировок» |
| «Короткие блоки кода» | ALWAYS_ON (small) | Moved to `engineering-code-review` constraints |
| «Security analysis» threat classes | ALWAYS_ON | Kept in CLAUDE.md verbatim in meaning, including the pseudoscience prohibition |
| «Не инвентаризируй состояние репозитория» | ALWAYS_ON | Kept in CLAUDE.md, now with the F-17 reference and the version-constraint carve-out |
| Язык общения | ALWAYS_ON | Kept, extended to commit messages and PR bodies |
| Агентский workflow → субагенты | UNCERTAIN | Preserved in `karpathy-origin.md` with its conflict flagged (see below) |
| Агентский workflow → чеклист | SKILL_CANDIDATE | `engineering-code-review/references/delivery-checklist.md`; two-line minimum kept in CLAUDE.md |
| Что за проект | ALWAYS_ON | Kept, compressed to prose |
| Крипто: два слоя / хэш / OffChainCircuitSource / RescueCipher STUB | ALWAYS_ON | Kept in CLAUDE.md, wording of prohibitions unchanged |
| Версии | ALWAYS_ON | Kept; CI-versions warning folded in |
| Окружение | ALWAYS_ON | Kept |
| Команды проверки | ALWAYS_ON (partly) | Confirmed commands kept; `cargo check` variants → UNCERTAIN, see below |
| Workflow → создать ветку и PR | DUPLICATE | Removed; `repo-change-protocol` already owns it |
| Workflow → обновить UniFFI биндинги | SKILL_CANDIDATE | `android-uniffi-bridge` |
| Workflow → добавить тест | REFERENCE_CANDIDATE | `engineering-code-review/references/delivery-checklist.md` → "Where a new test goes" |
| «TS-сторона уже следует этому (tests/src/utils.ts)» | HISTORICAL/pointer | Dropped from CLAUDE.md: a single derived pointer fact, not a rule. The canonical hash formula it annotated is kept in full |
| devcontainer → «Не покрывает Android SDK/NDK» | ALWAYS_ON (warning) | Preserved in `references/repo-map.md` top-level table |
| GitHub → репозиторий (coords, merge policy) | Mixed | Merge policy kept as a permanent constraint; repo coordinates dropped as inventory |
| GitHub → Secrets / ANTHROPIC_API_KEY | ALWAYS_ON | Kept, including the `continue-on-error` prohibition |
| GitHub → Версии CI | ALWAYS_ON | Folded into «Версии» |
| GitHub → devcontainer («Смёржен в PR #10») | HISTORICAL | Dropped from CLAUDE.md |
| Открытые задачи → PR #5 смёржен | HISTORICAL | Dropped from CLAUDE.md |
| Открытые задачи → M-3, RUSTSEC ×2, branch protection | ALWAYS_ON | Kept as permanent constraints |
| Открытые задачи → devnet deploy | ALWAYS_ON | Kept, pointing at `docs/HOME-DEPLOY.md` |
| Открытые задачи → stale branches | HISTORICAL/operational | Dropped; it is housekeeping, not a rule |
| Соглашение по веткам `claude/<task-slug>` | UNCERTAIN | See conflict below — preserved here, not asserted in CLAUDE.md |

## Conflicts — preserved, not resolved

**1. "Актуальная карта репозитория" vs F-17.** The task asked for a repository
map in `CLAUDE.md`. F-17's closure condition in `docs/SECURITY-FINDINGS.md`
states that `CLAUDE.md` must contain *no inventories of repository state — no
file/workflow counts, no directory trees, no listings of function signatures or
APIs*. F-17 is the stricter constraint and was not weakened: `CLAUDE.md` now
carries a four-path prose orientation only, and the detailed map lives in
`engineering-code-review/references/repo-map.md`, out of always-loaded context
and with re-derivation commands attached.

**2. Branch naming.** `CLAUDE.md` previously asserted `claude/<task-slug>` as
the convention. Observed practice across the last fifteen pull requests is
`docs/*`, `fix/*`, and `chore/*` — zero `claude/*`. Both readings are recorded
here; neither is asserted in the new `CLAUDE.md`, and the owner's decision is
outstanding.

**3. Subagent guidance.** The gist-sourced advice to fan work out across
subagents conflicts with a harness instruction, present in some sessions, not
to spawn subagents unless explicitly asked. Preserved verbatim in
`karpathy-origin.md` with the stricter constraint marked as winning.

**4. Persistent checkout is stale.** The working checkout at
`/home/user/Arcium-messenger-` sits on `claude/android-tls-conflict-review-r4go92`
@ `c46b850`, **56 commits behind `origin/main`**. Editing `CLAUDE.md` there
would have produced a diff against the pre-F-17 version and silently reverted
merged work. Per `repo-change-protocol` §2 the work was done in a fresh
disposable clone of current `main` instead.

## UNCERTAIN — retained, not deleted

- `cd arcium-psi && cargo check` and the claim "anchor build — нет, нужен CLI".
  Neither is confirmed by CI or the devcontainer; the CI evidence now shows
  `anchor build` *is* available and fails for an unrelated reason. Both were
  dropped from the confirmed-commands block rather than restated as fact, and
  are recorded here.
- Branch-naming convention (conflict 2 above).
- Whether the "ANTHROPIC_API_KEY периодически протухает" warning still reflects
  reality: both AI-review gates were green on every completed run over the two
  weeks before this migration. The warning was kept because it is a
  precaution, not a status claim.

## Files created or changed

- `CLAUDE.md` — rewritten, 171 → ~150 lines
- `.claude/skills/engineering-code-review/SKILL.md` — new
- `.claude/skills/engineering-code-review/references/delivery-checklist.md` — new
- `.claude/skills/engineering-code-review/references/repo-map.md` — new
- `.claude/skills/engineering-code-review/references/karpathy-origin.md` — new
- `.claude/skills/android-uniffi-bridge/SKILL.md` — new
- `.claude/skills/android-uniffi-bridge/references/bridge-topology.md` — new
- `.claude/MIGRATION-REPORT.md` — this file
- `.claude/skills/repo-change-protocol/SKILL.md` — **unchanged**

## Skills deliberately not created

- **markov-handoff** — no material for it exists in `CLAUDE.md` or anywhere in
  the repository; no such skill is present to update. Creating one would have
  meant inventing it.
- **mbr1-delivery-review** — "MBR1" does not appear anywhere in this
  repository. There is no protocol of that name here to review.

## Open collision with in-flight work

Pull request #70 (`docs/claude-md-three-gotchas`) is open and edits the *old*
`CLAUDE.md`, adding three gotchas: the `arcium-psi` separate-workspace rule,
the `lutOffset`/`lutOffsetSlot` devnet stub, and the JNA pin plus the
no-manual-`loadLibrary` rule. This rewrite is based on `main` and does not
include them. Two of the three are already covered by the new structure —
the workspace rule in `references/repo-map.md`, the JNA and `loadLibrary`
rules in `android-uniffi-bridge`, and the `lutOffset`/`lutOffsetSlot` stub in
`references/repo-map.md`. All three facts were re-verified against `main`'s own
sources rather than copied from the unmerged pull request, so this rewrite does
not depend on #70 landing. The two changes still edit the same file and will
conflict textually: whichever lands second needs the other reconciled by hand,
and that decision is the owner's.
