#!/usr/bin/env python3
"""stall_watchdog.py - tail a DSH session log, escalate on no-progress.

Adapted to DSH's real session.v4.jsonl schema (verified against
~/.dsh/sessions/--Users-julian-zk_rollup--/session-f16f404d*/session.v4.jsonl.zstd):

  * logs are zstd-compressed: <session dir>/session.v4.jsonl.zstd, appended
    as concatenated zstd frames; streamed with "zstd -dc".
  * the session dir name is the cwd with "/" -> "-" wrapped in "--...--".
  * event types that matter: "tool/call" (data.name, data.arguments = JSON
    string), "tool/ptc-dispatch" (data.name, data.arguments = object - this
    is where edit/write/bash actually appear in PTC sessions; the outer
    tool/call is just run_code), "assistant/message" (data.message.content[]
    blocks with type "reasoning"), "compaction/summary".
  * "time" is epoch milliseconds; some events (session header) have none.

Because bash runs inside run_code's code string, PROGRESS_BASH is matched
against the raw arguments text of run_code calls too - otherwise a session
that only ever calls run_code would look stalled while running cargo test.

Modes:
  --once   replay the whole log and report stall windows (threshold validation)
  --watch  tail the live log and escalate (default)

Escalation ladder: 1 nudge, 2 forced design write, 3+ relaunch fresh.
Escalations print and append to --escalate-file. If --escalate-cmd is set it
runs with STALL_LEVEL / STALL_MESSAGE / STALL_WINDOW_START in the environment
(this is the injection hook DSH does not expose over its 401-gated GUI port).

Python 3.9 compatible. Read-only with respect to the session log.
"""
import argparse
import glob
import json
import os
import subprocess
import sys
import time

EDIT_TOOLS = {"edit", "write", "apply_patch"}
PROGRESS_BASH = ("cargo test", "forge test", "cargo build", "git commit")
PROGRESS_SUBSTR = ("docs/design/", "STATE.md", "writeFileSync", "fs.writeFileSync")
RESTART_HINT = (
    "restart_fresh: relaunch a clean session seeded only with the design file, "
    "first action = write the failing test from its Acceptance section "
    "(e.g. dsh headless --profile headless --cwd <repo> -p 'Implement "
    "docs/design/<topic>.md. First action: write the failing test.')"
)
ESCALATION_MSGS = {
    1: "No edits or tests for a while. Write docs/design/<topic>.md now with what you know.",
    2: "Stop reading. Implement the smallest compiling change from the design, then run the test.",
}


def session_dir_for(cwd):
    return os.path.join(
        os.path.expanduser("~"), ".dsh", "sessions",
        "--" + os.path.abspath(cwd).strip("/").replace("/", "-") + "--",
    )


def newest_log(cwd):
    pat = os.path.join(session_dir_for(cwd), "*", "session.v4.jsonl.zstd")
    logs = [p for p in glob.glob(pat) if os.path.getsize(p) > 1024]
    if not logs:
        sys.exit("no non-trivial session log under " + os.path.dirname(pat))
    return max(logs, key=os.path.getmtime)


def open_log(path):
    """Return (proc, text_stream) for a plain or .zstd log."""
    if path.endswith(".zstd"):
        proc = subprocess.Popen(
            ["zstd", "-dc", path], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            text=True, bufsize=1 << 20,
        )
        return proc, proc.stdout
    proc = open(path, "r")
    return proc, proc


def is_progress(e):
    t = e.get("type")
    d = e.get("data") or {}
    if t == "tool/ptc-dispatch":
        name = d.get("name", "")
        if name in EDIT_TOOLS:
            return True
        args = d.get("arguments")
        if name == "bash" and isinstance(args, dict):
            cmd = args.get("command", "") or ""
            return any(p in cmd for p in PROGRESS_BASH) or "docs/design/" in cmd
        return False
    if t == "tool/call":
        name = d.get("name", "")
        if name in EDIT_TOOLS:
            return True
        raw = d.get("arguments")
        if not isinstance(raw, str):
            raw = json.dumps(raw or "")
        # run_code hides bash + fs writes inside its code string
        return any(p in raw for p in PROGRESS_BASH + PROGRESS_SUBSTR)
    return False


def reasoning_chars(e):
    d = e.get("data") or {}
    msg = d.get("message") or {}
    blocks = msg.get("content") or []
    return sum(
        len(b.get("text", "") or "") for b in blocks if b.get("type") == "reasoning"
    )


class Watchdog:
    def __init__(self, max_steps, max_min, max_reason, escalate_file, escalate_cmd):
        self.max_steps = max_steps
        self.max_min = max_min
        self.max_reason = max_reason
        self.escalate_file = escalate_file
        self.escalate_cmd = escalate_cmd
        self.steps = 0
        self.reason = 0
        self.level = 0
        self.last = None          # last progress time (ms)
        self.window_start = None  # start of current no-progress window
        self.fired = set()         # trigger categories already escalated this window
        self.restart_fired = False
        self.total_escalations = 0
        self.longest_ms = 0

    def note_progress(self, t):
        if self.window_start and self.last:
            self.longest_ms = max(self.longest_ms, self.window_start - self.last)
        self.steps = 0
        self.reason = 0
        self.level = 0
        self.restart_fired = False
        self.fired = set()
        self.last = t
        self.window_start = None

    def feed(self, e):
        t = e.get("time")
        if self.last is None:
            self.last = t
        if is_progress(e):
            self.note_progress(t)
            return
        if e.get("type") == "assistant/message":
            self.steps += 1
            self.reason += reasoning_chars(e)
            if self.window_start is None:
                self.window_start = t
        if self.window_start is None:
            return
        gap_ms = (t - self.last) if (t and self.last) else 0
        fired_now = []
        if self.steps >= self.max_steps and "steps" not in self.fired:
            fired_now.append("steps=%d" % self.steps)
            self.fired.add("steps")
        if gap_ms >= self.max_min * 60000 and "gap" not in self.fired:
            fired_now.append("gap=%.0fmin" % (gap_ms / 60000.0))
            self.fired.add("gap")
        if self.reason >= self.max_reason and "reason" not in self.fired:
            fired_now.append("reason=%dch" % self.reason)
            self.fired.add("reason")
        if fired_now:
            self.escalate(t, fired_now)

    def escalate(self, t, triggers):
        if self.level >= 3 and self.restart_fired:
            return  # one restart per window; wait for progress or restart
        if self.level >= 3:
            self.restart_fired = True
        self.level += 1
        self.total_escalations += 1
        # reset counters but keep level climbing until real progress
        self.steps = 0
        self.reason = 0
        self.window_start = t
        msg = ESCALATION_MSGS.get(self.level, RESTART_HINT)
        line = "[%s] STALL level=%d %s -> %s" % (
            time.strftime("%Y-%m-%d %H:%M:%S", time.localtime((t or 0) / 1000.0)),
            self.level, ",".join(triggers), msg,
        )
        print(line, flush=True)
        if self.escalate_file:
            with open(self.escalate_file, "a") as f:
                f.write(line + "\n")
        if self.escalate_cmd:
            env = dict(os.environ, STALL_LEVEL=str(self.level), STALL_MESSAGE=msg,
                       STALL_WINDOW_START=str(self.last or ""))
            subprocess.run(self.escalate_cmd, shell=True, env=env)

    def report(self):
        if self.window_start and self.last:
            self.longest_ms = max(self.longest_ms, self.window_start - self.last)
        print("summary: escalations=%d longest_no_progress=%.1fmin" % (
            self.total_escalations, self.longest_ms / 60000.0), flush=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--session", help="path to session.v4.jsonl[.zstd]; default: newest live log")
    ap.add_argument("--cwd", default=os.getcwd(), help="workspace to resolve the session dir from")
    ap.add_argument("--once", action="store_true", help="replay the whole log and report")
    ap.add_argument("--max-steps", type=int, default=25)
    ap.add_argument("--max-min", type=float, default=30.0)
    ap.add_argument("--max-reason-chars", type=int, default=32000)
    ap.add_argument("--escalate-file", default=None)
    ap.add_argument("--escalate-cmd", default=None,
                    help="shell command run on escalation; sees STALL_LEVEL/STALL_MESSAGE")
    args = ap.parse_args()

    path = args.session or newest_log(args.cwd)
    escalate_file = args.escalate_file or os.path.join(args.cwd, ".dsh-stall-escalations.log")
    wd = Watchdog(args.max_steps, args.max_min, args.max_reason_chars,
                  escalate_file, args.escalate_cmd)
    print("watching %s (max_steps=%d max_min=%.0f max_reason=%dch)" % (
        path, args.max_steps, args.max_min, args.max_reason_chars), flush=True)

    seen_seq = -1
    while True:
        proc, stream = open_log(path)
        try:
            for line in stream:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except ValueError:
                    continue
                seq = e.get("seq")
                if isinstance(seq, int):
                    if seq <= seen_seq:
                        continue
                    seen_seq = seq
                wd.feed(e)
        except (IOError, OSError):
            pass
        finally:
            if hasattr(proc, "wait"):
                try:
                    proc.wait(timeout=5)
                except Exception:
                    proc.kill()
            else:
                proc.close()
        if args.once:
            break
        time.sleep(2)  # log grew or writer rotated; reopen and resume by seq
    wd.report()


if __name__ == "__main__":
    main()
