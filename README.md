# INF601 Mini Project 4: Vuln Hub pentest (Track A)

Track: A

Repository: `miniproject4SamuelHart`

This repository contains an authorized penetration test of a deliberately
vulnerable Flask application, together with the tooling used to run it and the
evidence it produced. Six planted vulnerabilities were identified and exploited,
and all six captured flags were accepted by the instructor's checker.

The target is insecure on purpose. Its own first lines say so, and each planted
bug hides a flag that only appears when the bug is genuinely exploited. The
target is treated as read-only here: it is the assignment, not something to fix.

## What is in this repository

| File | What it is |
|---|---|
| `app.py`, `templates/`, `static/` | The intentionally vulnerable target. Read-only for this project. |
| `check_flags.py` | The instructor's flag checker. Prints VALID / NOT VALID per flag, and always exits 0. |
| `verify.py` | A wrapper around the checker that turns its printed verdict into a real exit status. Exit 0 means all six flags are valid. |
| `recon.md` | The attack-surface map: every route, every input, and where each input goes. Every claim cites a line of `app.py` or a template. |
| `pocs.md` | The proofs of concept. One section per finding, with the literal request and the literal response, plus the controls run alongside. |
| `submission.txt` | The six captured flags, one per line. Tracked in git, because the rubric requires it committed. |
| `pocs/replay.py` | A harness that re-captures all six flags over HTTP from a running instance, one function per finding. |
| `report.md` | The pentest report: scope and authorization, methodology, the six findings ordered by severity with remediation, and what was not tested. |
| `LOOP_PROMPTS.md` | The three exploration loops that drove the work, each with the verifier it answers to. |
| `CLAUDE.md` | Project rules for working here: the target must not be modified, what is in scope, and the stopping rules for the loops. |

`submission.txt` is deliberately **not** gitignored, unlike the instructor's
starter setting, because the rubric requires it in the repository. The
runtime files that hold flags in plain text stay excluded: `vulnhub.db`, and the
generated `public/welcome.txt`, `private/employee_notes.txt` and
`backups/vulnhub.sql.bak`. Those files are produced by the application at
startup, so nothing generated is committed.

## Running the target

The virtual environment is per project and lives in `.venv` (Python 3.13).
Create it and install the pinned dependencies:

```fish
uv venv
source .venv/bin/activate.fish        # bash or zsh: source .venv/bin/activate
uv pip install -r requirements.txt
```

`requirements.txt` is a real `pip freeze` of this environment, not a `uv pip
freeze`, and it includes `requests` for the replay harness.

### The seed is required

`FLAG_SEED` must be your FHSU username. It determines the flags, so a run without
it produces flags that are **not valid** for your account. Without it the
application prints a warning and shows a red "DEFAULT seed" banner on every page.

### Start the application

```fish
FLAG_SEED=s_hart .venv/bin/python app.py
```

- The application binds `127.0.0.1` and must never be exposed to a network.
- The default port is **5000**. If it is taken, set `PORT=5001`.
- Restarting resets state: the database is rebuilt and the generated files are
  rewritten at startup.
- A public test account exists for the challenges that need a normal session:
  `alice / password123`.

`pocs/replay.py` reads the same `PORT` variable, so the two agree without any
edit if you move off 5000.

## Verifying the work

Two independent mechanisms, and both should be used.

**The flags, against the instructor's checker.** `verify.py` wraps
`check_flags.py` and turns its verdict into an exit status. Judge the result by
the exit code, not by the printed text, because `check_flags.py` always exits 0:

```fish
.venv/bin/python verify.py submission.txt --username s_hart
echo $status        # 0 means all six flags are valid
```

Non-zero means they are not, and the output names which challenges are still
missing. While the work was in progress this exited 1 and reported which flags
remained, which is expected until all six are captured.

**The exploits, against a replay harness.** `pocs/replay.py` derives every flag
itself by exploiting each bug over HTTP. It opens no file to obtain a flag; the
only file it reads is `submission.txt`, and only at the end, to compare its
captures against what was submitted. A mismatch exits non-zero.

```fish
.venv/bin/python pocs/replay.py
```

It prints each captured flag as it goes and finishes with `6/6 flags reproduced`.
Run it against a **freshly started** application: the stored-XSS step depends on
a simulated administrator that acts on each guestbook comment once per process
lifetime, so a freshly restarted app is the clean test. The harness identifies
its own capture with a per-run marker and prints a note rather than failing when
earlier captures are still present.

## Authorization and scope

This was an authorized test, and the boundary was treated as absolute.

- The target was assigned by the course instructor as the Mini Project 4
  cybersecurity exercise. It is intentionally vulnerable and exploiting it is the
  assigned work.
- The target ran **locally on the tester's own machine**, on the loopback
  interface.
- **Only this application was tested.** No other system, host, service or network
  was in scope, and none was touched.

Testing anything outside this scope is an academic honesty violation. Every
request recorded in `pocs.md`, `report.md` and `pocs/replay.py` was sent to
`http://127.0.0.1:5000`. One request that the reconnaissance raised, reading a
path outside the application's own directory, was deliberately not sent for this
reason, and is recorded as an open question rather than a finding.

## AI Usage

### 1. What AI was used for

The work was driven with Claude Code. It read the target source and mapped the
attack surface into `recon.md`, formed and tested one hypothesis per challenge,
wrote the proofs of concept, wrote `pocs/replay.py`, and drafted `report.md` and
this README. The exploration loops were written out as prompts in
`LOOP_PROMPTS.md`, each with the verifier it answers to.

The workflow was deliberately constrained, and the constraints were the point:

- **One challenge at a time**, in a fixed order, rather than letting the agent
  work the whole target at once.
- **A stated termination condition per loop.** The recon loop ended when the map
  covered all six challenge areas. The challenge loop ended when `verify.py`
  exited 0. The harness loop ended when `replay.py` printed `6/6 flags reproduced`
  against a freshly restarted application.
- **A 3-attempt stopping rule.** After three failed attempts at one challenge the
  agent had to stop, record the hypothesis, payload, response and suspected cause
  in `attempts.md`, and hand back rather than continuing unattended or moving on.
- **Flags verified independently.** Success was judged by `verify.py`'s exit
  code, never by the agent's own summary of what it had captured. The flags were
  also re-captured from scratch by `pocs/replay.py`, so the findings rest on a
  second mechanism rather than on the agent's prose.

Every flag in this repository was captured on the first attempt. No entry was
needed in `attempts.md`.

### 2. What was written or decided by hand

The decisions recorded in the repository were made for this project rather than
produced by the agent:

- The project rules in `CLAUDE.md`: that the target must not be modified, that
  only this application is in scope, and the stopping rules for the loops.
- The three loops in `LOOP_PROMPTS.md`, each paired with a verifier it cannot
  fake: the recon map, the checker's exit code, and the replay harness. The
  design choice throughout was that a claim should have something that can fail.
- Using `verify.py`'s exit code rather than `check_flags.py`'s printed text, and
  writing `verify.py` in the first place, for the reason given in part 3.
- Testing each exploit with a control alongside it, so that a success was not
  mistaken for the wrong cause. Every control in `pocs.md` exists for that reason.
- Classifying the backup-file disclosure as sensitive data exposure rather than
  path traversal, and withholding the one request that would have reached that
  file through the traversal route, so the two findings stay separate.
- Keeping the target unmodified throughout, and re-reading each request and
  response to confirm the literal text recorded is what was actually sent and
  received.

### 3. What was changed in the AI-generated output

Three concrete changes, all documented in the commit history. Each one is a place
where the generated work was wrong or incomplete and was corrected.

- **`verify.py` was written because the supplied checker cannot serve as a
  pass/fail signal.** `check_flags.py` prints VALID / NOT VALID per flag but
  always exits 0. Its exit status therefore carries no information, and a loop
  watching it would have read green on a total failure. `verify.py` was written
  to wrap it and turn the printed verdict into a real exit status, returning
  non-zero and naming the challenges still missing. This is what made the
  challenge loop's termination condition meaningful.
- **The starter's `.gitignore` line excluding `submission.txt` was removed.** The
  rubric requires that file committed, one captured flag per line, and it is
  graded. The starter's rule would have silently dropped a graded deliverable
  from the repository. The generated files that hold flags in plain text stay
  excluded, so nothing that should not be committed was committed by making this
  change.
- **A factual error in `recon.md` was corrected.** The document stated the count
  of `request.` reads as eight, which missed the second `request.method` test, the
  one guarding the guestbook handler. The count is nine, and both places that
  stated the old figure were fixed. The error was worth correcting rather than
  quietly dropping because it is a number a reader can check against the source,
  which is the property the rest of the document depends on.
