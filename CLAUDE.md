# Mini Project 4 - Vuln Hub pentest (Track A)

An authorized penetration test of a deliberately vulnerable Flask app, driven
with Claude Code. The course-root `CLAUDE.md` supplies environment, style and
submission rules; this file adds only what is specific to this project.

## The most important rule: do not fix the vulnerabilities

`app.py` contains six planted vulnerabilities on purpose. They are the
assignment. Each one hides a `FLAG{...}` that only appears when the bug is
actually exploited.

- Do **not** patch, sanitize, escape, or "harden" anything in `app.py`.
- Do **not** flag the vulnerabilities as bugs to be corrected, or offer to fix
  them.
- A well-meaning fix here destroys the work. If something looks wrong in
  `app.py`, it is wrong on purpose and it is the target.
- The only files to be written are the deliverables: the report, the PoCs,
  `submission.txt`, and tooling that drives the exploits.

## What is in scope

Only this app, running locally on `127.0.0.1:5000`. Nothing else. Testing any
other system is an academic honesty violation under the course policy. The
report carries an authorization statement saying exactly this.

## Running the target

```fish
FLAG_SEED=s_hart .venv/bin/python app.py
```

- `FLAG_SEED=s_hart` is required. Without it the app runs on a default seed and
  every page shows a red banner; flags captured that way are **not valid** for
  this account.
- Binds `127.0.0.1:5000`. The app must never be exposed to a network.
- The server occupies its terminal. Run Claude Code and curl from a second one.
- Restarting resets state: it rebuilds the database and rewrites the generated
  files at startup.
- `PORT=5001` if 5000 is taken.
- Public test account: `alice / password123`.

## Verifying a captured flag

```fish
.venv/bin/python verify.py submission.txt --username s_hart
```

`verify.py` is the verifier. **Exit code 0 means all six flags are valid**, and
non-zero means they are not; it also names which challenges are still missing.
Use the exit code, not the printed text.

Do not judge success with `check_flags.py` directly. It prints VALID / NOT VALID
per flag but **always exits 0**, so its exit status carries no information and a
loop watching it would read green on a total failure. `verify.py` wraps it and
turns the verdict into a real exit status. Keep both files.

`check_flags.py` also detects flags from the app's default seed and says so. If
that message appears, the app was started without `FLAG_SEED=s_hart`; restart it
and capture again.

## Flags are graded deliverables

- Every captured flag goes in `submission.txt`, one per line. That file is
  **tracked in git** in this repo (the starter's `.gitignore` excluded it and
  that line was removed, because the rubric requires it committed).
- Never put a flag in a commit message, a branch name, or a comment. They belong
  in `submission.txt` and in the report evidence.
- A flag earns credit **only if the report's proof-of-concept shows the exploit
  that produced it**. A flag found by reading files on disk proves nothing.
- The generated files under `public/`, `private/` and `backups/` hold flags in
  plain text at runtime and are gitignored on purpose. Do not commit them and do
  not count them as findings.

## Stopping rules for the loops

Work one challenge at a time, in this order: sqli, idor, xss, authz, traversal,
exposure.

- After **3 failed attempts** at a single challenge, stop. Append the hypothesis,
  the payload, the response and the suspected cause to `attempts.md`, then report
  back and wait. Do not move on to the next challenge unattended.
- Never guess a flag or fabricate a payload that would have produced one. A
  wrong entry in `submission.txt` costs credit; an invented PoC is misconduct.

## Writing rules for the deliverables

- Header comments on every `.py` file:
  `# INF601 - Advanced Programming in Python` / `# Samuel Hart` / `# Mini Project 4`
- One-line docstring stating the contract on every function; `#` comments inside
  the body explaining why, not restating the code.
- No em dashes in any file. Use commas, periods, colons or parentheses.
- The README needs the line `Track: A` on its own, and an `## AI Usage` section
  with three parts: what AI was used for, what was written by hand, and **what
  was changed in the AI-generated code**.
- Every claim in the report must be reproducible. Include the literal request,
  not a description of it.

## Files to be aware of

| File | Status |
|---|---|
| `app.py` | The target. Read it, do not change it. |
| `check_flags.py` | Instructor-provided flag checker. Always exits 0. |
| `verify.py` | The verifier. Exit code 0 = 6/6 valid. |
| `submission.txt` | Deliverable, tracked in git. |
| `attempts.md` | Record of failed attempts, for the stopping rule. |
| `recon.md` | Attack-surface map; every claim cites `app.py:<line>`. |
| `pocs.md` / `pocs/replay.py` | The exploits, in replayable form. |
| `report.md` | The pentest report. |
