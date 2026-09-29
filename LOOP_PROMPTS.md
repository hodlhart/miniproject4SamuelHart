# MP4 loop prompts

Three loops, run in order. Each one has a verifier the agent cannot fake, which
is what makes it a loop rather than a prompt. Paste them into Claude Code one at
a time, from `/home/hart/Documents/Advanced Programming with Python/Week 7/miniproject4SamuelHart`.

The app runs at <http://127.0.0.1:5000> on FLAG_SEED=s_hart. Start it with:

```fish
cd "/home/hart/Documents/Advanced Programming with Python/Week 7/miniproject4SamuelHart"
FLAG_SEED=s_hart .venv/bin/python app.py
```

---

## Loop 1: Recon (maps the attack surface)

No exploitation yet. The goal is an accurate map, and the verifier is that every
claim must cite a line of `app.py` you can check.

```
Read app.py and the templates. This is an intentionally vulnerable Flask app
with 6 planted bugs, and I am the authorized pentester for a class assignment.

Goal: write recon.md mapping the attack surface. For every route, record:
- the URL, HTTP methods, and whether it needs a session
- every place user input enters the app (form fields, query params, cookies)
- for each input, where it goes and whether it is validated, sanitized, or
  escaped before use

Rules for this task:
- Every claim must cite the file and line number, like "app.py:212". A claim
  without a citation is worthless to me.
- Do not guess. If you cannot tell from the source, say "unclear from source"
  and tell me what request would settle it.
- Do not exploit anything yet. Do not look for flags yet.

Loop until recon.md covers all 6 challenge areas: sqli, idor, xss, authz,
traversal, exposure. Then stop and show me the file.
```

**Verify it yourself before moving on:** open `app.py` at a few cited lines. If a
citation is wrong, the map is wrong, and everything after it inherits the error.

---

## Loop 2: The six challenges (the main loop)

One challenge at a time. This is where the loop runs hottest: probe, hypothesize,
exploit, verify, iterate.

```
Now work the challenges one at a time, starting with SQL injection. The app is
running at http://127.0.0.1:5000 with my seed.

For each challenge, loop like this:
1. Send a request that probes the hypothesis in recon.md.
2. Read the actual response.
3. If it did not work, form a new hypothesis from what the response told you.
4. When you capture a FLAG{...}, verify it immediately. Append it to
   submission.txt (one flag per line, no duplicates), then run:
   .venv/bin/python verify.py submission.txt --username s_hart
5. Exit code 0 IS the proof. verify.py exits 0 only when all 6 flags are valid
   and non-zero otherwise, and it names which challenges are still missing. It
   wraps check_flags.py, which prints NOT VALID but always exits 0, so never
   judge success by check_flags.py's exit code or by the printed text alone.
   If a flag is reported as coming from the DEFAULT seed, the app was not
   started with FLAG_SEED=s_hart, so tell me and I will restart it.

Stopping rule, and this matters: if you fail to capture a flag after 3 attempts,
STOP. Append what you tried to attempts.md (the hypothesis, the payload, the
response, and why you think it failed) and tell me. Do not move to the next
challenge. I decide when to continue.

Record every successful exploit in pocs.md as you go: the exact method, URL,
headers, and full payload. I need the literal request, not a description,
because the rubric awards a flag only if the PoC shows the exploit that produced
it.

Start with SQL injection only. Tell me the payload and why it works before you
move on, because I have to be able to explain this at a review.
```

**What to watch for:** does it read the response and adapt, or repeat the same
payload? Adaptation is the loop working. Repetition is where the stopping rule
should fire.

---

## Loop 3: The PoC harness (proves it reproduces)

The second verifier. A written PoC can be wrong; a script that re-captures every
flag cannot.

```
Every flag is captured. Now build pocs/replay.py that reproduces all of them
from scratch.

Requirements:
- Standard library plus requests is fine. Add requests to requirements.txt if
  you use it (run `uv pip install requests` then
  `.venv/bin/python -m pip freeze > requirements.txt`).
- For each of the 6 findings, one function, one exploit, one captured flag.
- It must print each captured flag and then a final summary line:
  "6/6 flags reproduced".
- It must not read the flags from any file on disk. It has to get them over
  HTTP by exploiting the bug, or it proves nothing.
- If it needs a session, log in as alice / password123 inside the script.
- Header comments at the top:
  # INF601 - Advanced Programming in Python
  # Samuel Hart
  # Mini Project 4

Loop until `python pocs/replay.py` prints 6/6 flags reproduced on a freshly
restarted app, and `verify.py` exits 0 on the flags it captured.

If a challenge cannot be reproduced by script, stop and tell me which one and
why, instead of writing something that fakes it.
```

Then restart the app and run it yourself:

```fish
.venv/bin/python pocs/replay.py
```

If it prints 6/6 on a fresh app, your PoC is real. That is also the artifact you
point at for the agentic-workflow evidence.

---

## After all three loops

1. `submission.txt` with the 6 flags, one per line (it is tracked in git now,
   unlike the starter's setting).
2. `report.md`: scope and authorization statement, methodology, then each finding
   with vulnerability class, severity, how you found and exploited it, evidence,
   and remediation.
3. `README.md` with the `## AI Usage` section and the exact line `Track: A`.
4. At least 5 commits (each loop is a natural commit boundary).
