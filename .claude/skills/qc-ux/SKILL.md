---
name: qc-ux
description: "Optional fresh-context first-time-user test of the Arcium Android app. Uses a real runtime only — a connected device or emulator over adb, driven by the qc-android-ux subagent — and otherwise produces a phone-only manual script for the Owner and reports NOT_VERIFIED. Never a browser stand-in for Android. Non-destructive by default; uninstall, clear-data or identity reset need a separate Owner approval. Authorizes nothing."
disable-model-invocation: true
argument-hint: "[focus, e.g. onboarding | contact card | offline]"
---

# qc-ux — first-time-user test on a real Android runtime

This skill authorizes nothing. It never uninstalls the app, clears its data,
resets an identity or erases a phone; those need a separate Owner approval
naming the action. Emulator results are never reported as device results.

## 1. Find the runtime

```
command -v adb && adb devices -l
```

- An `emulator-*` entry → runtime `EMULATOR`. Another `device` entry →
  `DEVICE`. Anything else (no adb, no entry, `unauthorized`, `offline`) →
  `NONE`.
- A GitHub Actions emulator run (`android-instrumentation.yml`) is a runtime
  too, but dispatching it is an Owner decision.

## 2a. Runtime present → fresh-context exploration

Delegate to the `qc-android-ux` subagent with only: the runtime serial, the
focus (`$ARGUMENTS`), and the package `com.arcium.messenger`. It has not seen
this conversation, the source or the design, which is the point: it reports
what a first-time user meets. It may launch, tap, type, rotate, background
and force-stop the app; nothing that removes data. Its tool limits are
instructions to it, not enforcement: give it a runtime whose data you can
afford to expose to it.

## 2b. No runtime → phone-only manual script, state NOT_VERIFIED

Write a step list the Owner can do on the Pixel alone, non-destructive steps
first, each with the exact on-screen text to expect. Derive every expected
string from the UI source at the target SHA (`android/app/src/main/kotlin`),
not from memory. Mark any destructive step "needs separate Owner approval".
Report the UX state as `NOT_VERIFIED` (no runtime), and in a qc-spec, record
these as `"manual": true` criteria.

## 3. Report

Per step: what was done, what the screen showed (UI-tree text or screenshot
path), what a first-time user would find unclear or broken. Label each as
RUNTIME_VERIFIED (observed on the named runtime) or NOT_VERIFIED.
