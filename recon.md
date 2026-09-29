# Recon: attack surface of the Vuln Hub target

Scope: `app.py` as it stands in this repository, running on `127.0.0.1:5000`.
Every claim below cites a file and line. Where the source does not settle a
question, the claim says `unclear from source` and names the request that would
settle it.

Nothing in this file is an exploit. It is a map of where input enters, where it
goes, and what happens to it on the way.

## 1. Route inventory

Flask's `@app.route` defaults to GET, and every route also answers HEAD and
OPTIONS; the two routes that declare POST accept OPTIONS as well. That is
framework behaviour, not something `app.py` states.

| URL | Methods | Session required | Handler | Renders |
|---|---|---|---|---|
| `/` | GET | no | `app.py:201` | `home.html` |
| `/login` | GET, POST | no | `app.py:206` | `login.html` |
| `/dashboard` | GET | yes (`app.py:231`) | `app.py:229` | `dashboard.html` |
| `/logout` | GET | no | `app.py:241` | none, 302 to `/` |
| `/messages` | GET | yes (`app.py:250`) | `app.py:248` | `messages.html` |
| `/messages/<int:msg_id>` | GET | yes (`app.py:261`) | `app.py:259` | `message_detail.html` |
| `/guestbook` | GET, POST | no | `app.py:273` | `guestbook.html` |
| `/grab` | GET | no | `app.py:297` | `grab.html`, or bare `ok` |
| `/vault` | GET | yes (`app.py:309`) | `app.py:307` | `vault.html` |
| `/download` | GET | no | `app.py:319` | none, raw body |
| `/robots.txt` | GET | no | `app.py:332` | none, raw body |
| `/backups/<path:name>` | GET | no | `app.py:338` | none, raw body |

"Session required" means the handler calls `current_user()` and redirects to
`/login` when it returns `None`. The three raw-body routes return
`flask.Response` with `mimetype="text/plain"` (`app.py:329`, `app.py:335`,
`app.py:347`), so nothing they return is parsed as HTML by a browser.

`/logout` is the one route with no check of any kind: it clears the cookie and
redirects regardless of who calls it (`app.py:241` to `app.py:245`).

## 2. The identity model

There is no Flask session and no `secret_key` on the app object (`app.py:77`
constructs `Flask(__name__)` with no arguments). All identity lives in one
cookie, `auth`:

- On successful login the cookie is set to
  `base64("<username>:<role>")` (`app.py:182` to `app.py:184`). The value is
  base64 only. There is no signature, no MAC, and no server-side record.
- `resp.set_cookie("auth", token)` (`app.py:184`) is called with no keyword
  arguments, so the cookie carries Flask's defaults: not `HttpOnly`, not
  `Secure`, and `SameSite` unset.
- On every request `current_user()` reads that cookie (`app.py:188`),
  base64-decodes it, splits once on `:` and returns
  `{"username": ..., "role": ...}` (`app.py:192`). Any exception at all returns
  `None` (`app.py:194` to `app.py:195`), which the handlers treat as "not logged
  in".
- The decoded `username` is what the dashboard, messages and guestbook treat as
  the caller's identity (`app.py:235`, `app.py:254`, `app.py:277`). The decoded
  `role` is what `/vault` treats as the caller's privilege level (`app.py:314`).

So both halves of the identity are attacker-controlled strings that the app
never verifies. `app.py:179` to `app.py:180` describes this in a comment as
"UNSIGNED" and names the forgery as challenge 4.

Note the asymmetry in how the two halves are used: `role` is only ever compared
(`app.py:314`), while `username` is fed into SQL as a bound parameter
(`app.py:235`, `app.py:254`), so a forged `username` is not an injection point.

## 3. Every input the app reads

`grep -n "request\." app.py` returns nine lines: `app.py:188`, `app.py:209`,
`app.py:210`, `app.py:211`, `app.py:276`, `app.py:278`, `app.py:299`,
`app.py:321` and `app.py:394`. Three are the form reads, one is the cookie
read, one is the raw query string, one is `request.args`, **two** are the
`request.method` test at the top of the login and guestbook handlers
(`app.py:209`, `app.py:276`), and one is the bot's outbound
`urllib.request` (`app.py:394`), which is not an input at all.

| # | Entry point | Source | Line | Sink | Validated / sanitized / escaped? |
|---|---|---|---|---|---|
| 1 | `username` (login form) | `request.form` | `app.py:210` | string-formatted into SQL | no. `%` interpolation at `app.py:213` to `app.py:216` |
| 2 | `password` (login form) | `request.form` | `app.py:211` | same SQL string | no. same interpolation |
| 3 | SQL error text | `sqlite3.Error` | `app.py:219` to `app.py:220` | `login.html` `{{ error }}` | escaped. Autoescape is on for `.html`, and `login.html:4` has no `|safe` |
| 4 | `comment` (guestbook form) | `request.form` | `app.py:278` | stored via bound parameter | not sanitized. Stored raw (`app.py:281`), and rendered unescaped |
| 5 | stored comment body | `comments.body` | `guestbook.html:17` | HTML page | **not escaped.** `| safe` at `guestbook.html:17` |
| 6 | `auth` cookie | `request.cookies` | `app.py:188` | identity and role | not verified. Decoded at `app.py:192` with no signature check |
| 7 | whole query string | `request.query_string` | `app.py:299` | `CAPTURES` list | not sanitized. URL-decoded (`app.py:302`) and stored in memory |
| 8 | `file` (download) | `request.args` | `app.py:321` | filesystem path | not validated. Joined onto a base dir at `app.py:323` |
| 9 | `msg_id` (message URL) | URL path converter | `app.py:259` | SQL, bound parameter | type-constrained to `int` by the converter; the SQL is parameterized, so no injection. Ownership is never checked |
| 10 | `name` (backup URL) | URL path converter | `app.py:338` | filesystem path | not validated. `<path:...>` deliberately permits slashes; joined at `app.py:341` |

Escaping notes that matter:

- `login.html:4` renders `{{ error }}` with no `|safe`, so the reflected SQL
  error is HTML-escaped. Reflected XSS through this path is therefore blocked by
  autoescape, and the useful behaviour of that path is the error text itself
  (it leaks SQL structure), not script execution.
- `guestbook.html:15` renders `{{ row.author }}` with no `|safe`, so the author
  field is escaped even though the body is not.
- `dashboard.html:4`, `dashboard.html:7`, `message_detail.html:5` to
  `message_detail.html:7`, `messages.html:6`, `vault.html:6` and `grab.html:8`
  all use plain `{{ }}` with no `|safe`, so they are autoescaped.
- `guestbook.html:17` is the only `|safe` in the whole template directory:
  `grep -rn "safe" templates/` returns that line and the comment above it at
  `guestbook.html:16`.

## 4. Input sources the app never reads

These are absence claims over `app.py:201` to `app.py:347`, which is the whole
route section:

- `request.headers` is never read, so no route takes input from a header.
- `request.get_json` and `request.json` are never read, so no route takes a JSON
  body.
- `request.files` is never read, so there is no upload path.
- `request.cookies` is read in exactly one place (`app.py:188`), so `auth` is
  the only cookie that carries input.
- No route reads `request.args` except `/download` (`app.py:321`).
- No route reads `request.form` except `/login` (`app.py:210`, `app.py:211`) and
  `/guestbook` (`app.py:278`).

## 5. The six challenge areas

Each subsection names the single route that carries the challenge, the input,
the sink line, and what the code does and does not do. The challenge list itself
is at `app.py:59`.

### sqli: POST `/login`

`username` and `password` are interpolated into the SQL string with `%`
formatting (`app.py:213` to `app.py:216`), then executed as-is (`app.py:218`).
There is no parameter binding, no escaping, and no input validation on either
field. The `sqlite3.Error` handler at `app.py:219` reflects the database's own
error message into the page, which is a second, quieter leak: it tells an
attacker when the injected SQL is syntactically wrong.

The reward is not returned by the login response. A successful bypass sets the
cookie from `row["username"]` and `row["role"]` (`app.py:223`), so whichever row
the injected `WHERE` clause returns becomes the caller's identity. The sqli flag
is the `secret_note` of the admin row (`app.py:136` to `app.py:137`) and is read
back on `/dashboard` (`app.py:234` to `app.py:238`). Reaching the flag therefore
needs the login bypass and then a `/dashboard` request with the cookie it
issued.

What the bypass has to satisfy: the handler only tests `if row` (`app.py:221`),
so any non-empty result set logs in, and the selected columns must include
`username` and `role` because `app.py:223` reads them by name.

### idor: GET `/messages/<int:msg_id>`

The query selects the message by id alone (`app.py:265` to `app.py:267`). The
`owner` column is fetched into the row but the function never compares it to the
caller: the only checks in the handler are "is there a user" (`app.py:261`) and
"did a row come back" (`app.py:268`). Nothing between `app.py:259` and
`app.py:270` references `user["username"]` after the login check.

Compare with `/messages` (`app.py:253` to `app.py:255`), which does filter by
owner. The list route hands the caller the ids they are allowed to see
(`messages.html:6`), and the detail route will serve any id, so the two
disagree.

The idor flag is in admin's message id 1 (`app.py:148` to `app.py:149`). Alice
owns ids 4 and 5 (`app.py:151` to `app.py:152`), so the intended path starts
from a normal session and walks the id.

The `<int:...>` converter at `app.py:259` constrains the value to digits before
the handler runs; a non-numeric path segment yields 404 without reaching the
code. Whether the converter in this Werkzeug version also accepts a leading `+`
or `-` is `unclear from source`; the requests `GET /messages/+1` and
`GET /messages/-1` would settle it. This matters only for enumeration breadth,
not for the challenge.

### xss: POST `/guestbook`, rendered on GET `/guestbook`

The comment body is read at `app.py:278`, bound as a parameter into the insert
at `app.py:280` to `app.py:282`, and stored with no sanitization. No login is
required: the author is taken from the session if there is one and set to the
literal `anonymous` otherwise (`app.py:277`), so an unauthenticated attacker can
plant a payload. There is no CSRF token anywhere in the app.

The payload executes because `guestbook.html:17` renders the body with
`| safe`, which switches off Jinja's autoescape for that expression. Every other
template expression in the app is autoescaped (see section 3).

What makes the flag reachable is the bot, not the page. `xss_bot()`
(`app.py:358` to `app.py:397`) polls the comments table every two seconds
(`app.py:397`), skips ids it has already handled (`app.py:371` to `app.py:374`),
and processes a comment only if, lowercased, it contains both `<script` and
`document.cookie` (`app.py:376`). It then extracts a target URL with a regex
that looks for `fetch(`, `.src=`, `location=` or `open(` followed by a quoted
string (`app.py:379` to `app.py:381`), and if that finds nothing it falls back
to any quoted string beginning with `/` (`app.py:384`). It requests the target
with the admin cookie appended (`app.py:390`), prefixing
`http://127.0.0.1:<PORT>` when the target is relative (`app.py:391` to
`app.py:392`).

The admin cookie it carries is `session=admin; flag=<xss flag>` (`app.py:360`).
The receiving end is `/grab` (`app.py:297` to `app.py:304`), which stores the
whole decoded query string in a process-global list (`app.py:294`, `app.py:302`)
and shows it at `grab.html:8`.

Two consequences for payload design, both visible in the source:

- Because the cookie is appended to the target with `+` and no separator
  (`app.py:390`), the target does not need to end in `?` or `&`. `/grab` reads
  the entire query string, so a payload pointing at `/grab?x=` and one pointing
  at `/grab?` both deposit the flag.
- `seen` starts as `{1}` and only grows (`app.py:359`, `app.py:373`), and the
  bot keeps no state across restarts, so a comment is processed once per
  process lifetime. `init_db()` wipes the database at import (`app.py:407`), so
  each restart re-seeds comment id 1 and forgets everything else.

### authz: GET `/vault`

The handler's entire authorization decision is
`if user.get("role") != "superadmin"` (`app.py:314`), and `user` comes from the
unsigned cookie. `app.py:74` to `app.py:75` note that the admin password is
random per process and generated precisely so that logging in as admin is not
the intended route, and `app.py:312` to `app.py:313` state that no normal login
ever issues the `superadmin` role. `set_auth` (`app.py:182`) is called only from
the login handler (`app.py:223`), and the role it writes is whatever the
database row holds, which for every seeded user is `admin` or `user`
(`app.py:136` to `app.py:139`).

So the only way `role` can equal `superadmin` is if the client supplies it. The
flag is rendered at `vault.html:6`.

### traversal: GET `/download`

`file` is read with a default of `welcome.txt` (`app.py:321`), then joined onto
`<APP_DIR>/public` with `os.path.join` (`app.py:323`) and opened directly
(`app.py:325`). There is no `basename`, no normalization, no `..` rejection, and
no allowlist of permitted names. Any `OSError` or `ValueError` is caught and
turned into a plain 404 (`app.py:327` to `app.py:328`), which confirms a
miss without revealing why.

The traversal flag is in `private/employee_notes.txt` (`app.py:164` to
`app.py:169`), whose own contents say the file is there to prove the filter
failed. A `..` segment in `file` reaches it, since `os.path.join` does not
collapse or reject `..`.

One property of `os.path.join` is worth flagging as a claim about Python rather
than about `app.py`: when the second argument is absolute, `join` discards the
earlier components entirely, so `file=/etc/passwd` would not be confined to
`public/` at all. This is `unclear from source` in the sense that no line in
`app.py` states it; the literal request `GET /download?file=/etc/passwd` would
confirm or refute it. It is outside the graded challenge, which asks for the
`private/` file, and testing it means reading a file outside the app directory,
so the report should say plainly whether that was tried.

### exposure: GET `/backups/<path:name>`

`/robots.txt` (`app.py:332` to `app.py:335`) is a static string that disallows
`/backups/`. That is a breadcrumb, not a control: the route it points at
(`app.py:338` to `app.py:347`) has no authentication check at all, no session
lookup, and no role test. It joins `name` onto `<APP_DIR>/backups` (`app.py:341`)
and serves the result as `text/plain` (`app.py:347`). The `<path:...>` converter
is what lets the name contain slashes.

The exposure flag is in `backups/vulnhub.sql.bak` (`app.py:170` to
`app.py:175`), planted there with a comment saying it should not be
world-readable.

Worth recording because the report will need to be precise about which challenge
is which: `/download` (`app.py:323`) and `/backups/<path:name>` (`app.py:341`)
reach the same directory tree from two different base directories. `/download`
with a `..` segment can also reach `backups/vulnhub.sql.bak`, and
`/backups/<path:name>` with a `..` segment can also reach `private/`. The two
flags are distinct and each has a route that reaches it without traversal at
all, but the PoCs must not be ambiguous about which bug produced which flag.

## 6. Where the flags live, and what each one requires

For the record, since the report has to tie each flag to the exploit that
produced it. Flags are derived from `FLAG_SEED` at `app.py:62` to `app.py:67`
and are never stored in source.

| Challenge | Flag stored at | Readable only after |
|---|---|---|
| sqli | `users.secret_note`, admin row, `app.py:136` | a login bypass, then `GET /dashboard` |
| idor | `messages.body`, id 1, `app.py:148` | any session, then `GET /messages/1` |
| xss | not in the DB. It is the value the bot puts in its own cookie, `app.py:360` | a stored payload that the bot runs, and a `/grab` read |
| authz | `FLAGS["authz"]`, returned at `app.py:316` | a forged `auth` cookie with role `superadmin` |
| traversal | `private/employee_notes.txt`, `app.py:164` | `GET /download` with a `..` segment |
| exposure | `backups/vulnhub.sql.bak`, `app.py:170` | `GET /backups/<name>` |

## 7. Process-level facts that affect reproducibility

- `init_db()` runs at import time, not under `if __name__ == "__main__"`
  (`app.py:407`). Starting the app by any means, including `flask run`,
  deletes and rebuilds `vulnhub.db` (`app.py:105` to `app.py:107`) and rewrites
  the three generated files (`app.py:162` to `app.py:175`).
- `start_bot()` also runs at import (`app.py:408`), as a daemon thread
  (`app.py:401` to `app.py:402`).
- `ADMIN_PASSWORD` is regenerated on every process start (`app.py:75`), so
  admin's stored password changes each restart. It is not a target.
- `CAPTURES` (`app.py:294`) is a plain module-level list with no locking and no
  clearing. It is process-wide, so it accumulates captures from every client and
  does not survive a restart.
- `app.run(..., threaded=True)` (`app.py:413`) is needed so the bot's
  self-request to `/grab` is served while another request is in flight
  (`app.py:412`).
- The app binds `127.0.0.1` unless `HOST` is set (`app.py:73`), and the port
  comes from `PORT` (`app.py:71`).

## 8. Open questions

Each of these is genuinely unresolved by reading the source. None of them blocks
the six challenges; each is listed with the request that would settle it.

1. Does `/download?file=/etc/passwd` escape the `public/` directory entirely,
   via the absolute-path behaviour of `os.path.join`? Settled by that request.
   Out of scope for the graded flags and involves a file outside the app.
2. Does this Werkzeug version's `<int:>` converter accept a leading `+` or `-`?
   Settled by `GET /messages/+1` and `GET /messages/-1`.
3. Does the bot's sink regex (`app.py:379` to `app.py:381`) match a payload that
   puts the URL in an attribute other than `src`, such as
   `<img onerror=...>`? The regex lists four specific sinks, so the answer bears
   on payload design rather than on whether XSS is possible. Settled by posting
   a payload and reading `/grab`.
4. Is the `auth` cookie marked `HttpOnly` in the response this Flask version
   builds? `app.py:184` passes no options, so the answer depends on the
   framework default, not on this file. Settled by reading `Set-Cookie` in the
   response to `POST /login`.

## 9. How this map was produced

Read `app.py` end to end, read all nine templates in `templates/`, and confirmed
coverage with three greps: `request\.` over `app.py` (nine hits, all accounted
for in section 3), `@app.route` over `app.py` (twelve hits, all in the section 1
table), and `safe` over `templates/` (one live hit, `guestbook.html:17`).

No requests were sent to the target and no flags were captured while writing
this file.
