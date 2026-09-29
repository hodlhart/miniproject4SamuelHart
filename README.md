# Vuln Hub — INF601 Practice Pentest Target

A small, intentionally vulnerable Flask web app. It is the **authorized target**
for **Mini Project 4 (Cybersecurity track)**. It contains **6 planted
vulnerabilities**; each one hides a unique `FLAG{...}` you can only read by
actually exploiting the bug.

> ⚠️ **This software is deliberately insecure.** Run it only on your own machine
> or an isolated lab network. **Never** put it on the public internet. Test
> **only this app** — nothing else is in scope.

---

## Run it

### Your seed

`FLAG_SEED` is **your FHSU username**, lowercase, without `@fhsu.edu`
(e.g. `jdoe`). It determines your flags. The app lowercases it and ignores any `@fhsu.edu`, so `JDoe` or `jdoe@fhsu.edu` work too. Set it in your shell first:

```bash
export FLAG_SEED=jdoe            # bash / zsh (macOS, Linux)
```

```powershell
$env:FLAG_SEED="jdoe"            # Windows PowerShell
```

If you forget: `docker compose` refuses to start and tells you to set `FLAG_SEED`. With `python app.py` or `docker run`, the app starts anyway but prints a warning, shows a red "DEFAULT seed" banner on every page, and uses a default seed whose flags are NOT valid for your username.

### Option A — Docker (recommended)

```bash
docker compose up --build
# or, plain docker:
docker build -t inf601-vulnhub .
docker run -p 127.0.0.1:5000:5000 -e FLAG_SEED=jdoe inf601-vulnhub
```

### Option B — Python venv

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py                    # uses the FLAG_SEED you set above
```

Then open <http://127.0.0.1:5000>. A public test account is
`alice / password123` (you need a normal session for some challenges).

> **macOS:** port 5000 is often taken by AirPlay Receiver. Use another port:
> `PORT=5001 python app.py`, or `docker run -p 127.0.0.1:5001:5000 -e FLAG_SEED=jdoe inf601-vulnhub`,
> then open <http://127.0.0.1:5001>.

> The flags also exist as plain files and database rows on your own machine, so
> finding them that way proves nothing. **Only flags whose exploit appears in
> your PoC earn credit.**

---

## The 6 challenges

Each is a different, common web vulnerability. Start at the home page — it has a
short hint for each.

1. **SQL injection** — bypass the login form.
2. **IDOR** — read a message that isn't yours.
3. **Stored XSS** — steal the admin's cookie via the guestbook.
4. **Broken authorization** — reach `/vault` (superadmins only).
5. **Path traversal** — make the `/download` endpoint serve a file it shouldn't.
6. **Sensitive data exposure** — find a file that was left exposed (start with `/robots.txt`).

You are encouraged to **drive the exploration with Claude Code** — that is the
point of the project. Capture each `FLAG{...}` you find.

---

## What to submit (per the MP4 rubric)

A GitHub repo named `miniproject4YourFullName` containing:

1. **`submission.txt`** — each captured flag on its own line.
2. A **Proof-of-Concept** for each finding (the exact request / payload /
   command / screenshot that captured the flag).
3. A **pentest report** (Markdown or PDF) with, for each finding: the
   vulnerability class, severity, how you found and exploited it, evidence, and
   **remediation** advice. Include a scope + **authorization statement** at the top.
4. A **README** with an **`## AI Usage`** section (what Claude Code did vs. what
   you did — you must be able to explain every step at the Week 16 review).

### Check your flags

```bash
python check_flags.py submission.txt --username jdoe
```

This prints `VALID` / `NOT VALID` for each line. It awards no points: each
flag counts only if your report's PoC shows the exploit that produced it.

---

## Scope & ethics

Testing systems you are not authorized to test is an academic-honesty and
conduct violation. **Only** this app, running on **your** machine, is in scope.
Put a short authorization/ethics statement at the top of your report.
