# Repository agent instructions

## Design protocol
- Once you can state an approach, STOP reading and write docs/design/<topic>.md
  using the template below. Do this before any further greps or reads.
- A design is never "settled" in your head. It is settled when the file exists.
- An open question that compiling or running something can answer is answered
  by a spike (a scratch test), not by more reading.
- Next action after writing the design: create the failing test from its
  "Acceptance" section.
- After any context reset, read STATE.md and then docs/design/<topic>.md
  (the topic named in STATE.md) before anything else.

Keep the template small so writing it is cheap:

    # <topic> — status: draft | approved | implemented
    ## Decision        (3–5 lines: what we do and why; what we rejected)
    ## Changes         (file -> change, one line each)
    ## Invariants      (what must stay true; links to INVARIANTS.md IDs)
    ## Acceptance      (the tests that prove it; the first one to write)
    ## Open questions  (each with "spike:" or "ask user:")

## Session hygiene
- STATE.md at the repo root is the single resume pointer: current task card
  path, last gate/test result, next action. Update it whenever any of those
  change; keep it under 30 lines.
- Decisions live in docs/design/*.md (or the audit ledger
  .scratch/pq-shielded-rollup/verifier-redesign.md), never only in chat.
- A question a 20-line scratch test can answer is a spike, not a grep session.
