#!/usr/bin/env python3
"""Print the localnet evidence that matters into the job log.

Usage: summarize_localnet_diagnostics.py DIAG_DIR

For each computation trace the localnet test wrote: its outcome, how long it
waited, the state changes it observed (status, mempool, executing pool) and
the transactions on its computation account. For each Arx node log: its size,
the lines that name a traced computation, and its error and warning lines.
Run after scrub_localnet_diagnostics.py, on what that left.
"""

import json
import re
import sys
from pathlib import Path

PROBLEM = re.compile(r"\b(error|warn|warning|panic|fail(ed|ure)?|timeout|timed out)\b", re.I)
MAX_LINES = 60


def traces(diag):
    out = []
    for path in sorted(diag.glob("computation-*.json")):
        t = json.loads(path.read_text())
        out.append(t)
        print(f"== computation {t['computationOffset']} ({t['computationAccount']})")
        print(f"   outcome: {t['outcome']}; waited {t['waitedMs']} ms; submitted in slot "
              f"{t['submitSlot']} at {t['startedAt']}, "
              f"{t['msSincePreviousFinalization']} ms after the previous finalization")
        last = None
        for o in t["observations"]:
            state = {k: o.get(k) for k in ("status", "inMempool", "inExecpool", "callbacksSubmitted", "error")}
            if state != last:
                print(f"   +{o['ms']} ms slot {o.get('slot')}: {json.dumps(state)}")
                last = state
        for tx in t["transactions"]:
            print(f"   tx slot {tx['slot']} err={json.dumps(tx['err'])} {tx['signature']}")
            for line in tx.get("logs", [])[-15:]:
                print(f"      {line}")
    return out


def node_logs(diag, computations):
    names = [c["computationOffset"] for c in computations] + [c["computationAccount"] for c in computations]
    for path in sorted(diag.rglob("*.log")):
        if "arx" not in path.name and "callback" not in path.name and "dealer" not in path.name:
            continue
        lines = path.read_text(errors="replace").splitlines()
        print(f"== {path.relative_to(diag)}: {len(lines)} lines")
        for name in names:
            hits = [l for l in lines if name in l]
            if hits:
                print(f"   -- lines naming {name}: {len(hits)}")
                for l in hits[:MAX_LINES]:
                    print(f"   {l[:400]}")
        problems = [l for l in lines if PROBLEM.search(l)]
        print(f"   -- error/warning lines: {len(problems)}")
        for l in problems[:MAX_LINES]:
            print(f"   {l[:400]}")
        print("   -- last lines:")
        for l in lines[-15:]:
            print(f"   {l[:400]}")


def main(argv):
    if len(argv) != 2:
        print(__doc__)
        return 2
    diag = Path(argv[1])
    node_logs(diag, traces(diag))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
