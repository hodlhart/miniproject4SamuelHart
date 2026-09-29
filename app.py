# INF601 - Advanced Programming in Python
# Practice Pentest Target ("Vuln Hub") - INSTRUCTOR-PROVIDED CTF TARGET
#
# !!! INTENTIONALLY VULNERABLE SOFTWARE !!!
# This app deliberately contains security holes for the Mini Project 4
# cybersecurity track. DO NOT deploy it on the public internet. Run it only
# on a local machine / sandbox / isolated lab network.
#
# Each vulnerability hides a unique FLAG{...} token derived from FLAG_SEED.
# Students capture flags by exploiting the bugs; check_flags.py checks them.

import base64
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import threading
import time
import urllib.parse
import urllib.request

from flask import (
    Flask,
    Response,
    g,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

# --------------------------------------------------------------------------
# Flag derivation
# --------------------------------------------------------------------------
# Flags are NOT stored in source. They are derived from FLAG_SEED so that
# reading this file does not reveal the answers and each student's flags
# differ. Set FLAG_SEED to your FHSU username (e.g. jdoe). check_flags.py
# recomputes the same flags from the same seed.
def normalise_seed(s):
    """FHSU username -> seed: trim, lowercase, drop an @fhsu.edu or
    @mail.fhsu.edu suffix (nothing else). Must match normalise() in check_flags.py."""
    return re.sub(r"@(mail\.)?fhsu\.edu$", "", s.strip().lower())


FLAG_SEED = normalise_seed(os.environ.get("FLAG_SEED") or "")
# True when FLAG_SEED is unset or blank: every page then shows a warning banner.
USING_DEFAULT_SEED = not FLAG_SEED
if USING_DEFAULT_SEED:
    print("WARNING: FLAG_SEED not set: set it to your FHSU username "
          "(using the default seed for now).")
    FLAG_SEED = "inf601-default-seed-change-me"
elif "@" in FLAG_SEED:
    print("WARNING: FLAG_SEED %r is not an FHSU username; your flags will only "
          "count if it is (e.g. jdoe or jdoe@fhsu.edu)." % FLAG_SEED)

CHALLENGES = ["sqli", "idor", "xss", "authz", "traversal", "exposure"]


def make_flag(name: str) -> str:
    digest = hmac.new(FLAG_SEED.encode(), name.encode(), hashlib.sha256).hexdigest()[:12]
    return "FLAG{%s_%s}" % (name, digest)


FLAGS = {name: make_flag(name) for name in CHALLENGES}

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "vulnhub.db")
PORT = int(os.environ.get("PORT", "5000"))
# Bind to localhost only by default; the Docker image sets HOST=0.0.0.0.
HOST = os.environ.get("HOST", "127.0.0.1")
# Random per process start: the admin login is meant to be bypassed, not guessed.
ADMIN_PASSWORD = secrets.token_urlsafe(16)

app = Flask(__name__)


@app.context_processor
def inject_seed_warning():
    # Lets base.html show the default-seed banner on every page.
    return {"using_default_seed": USING_DEFAULT_SEED}


# --------------------------------------------------------------------------
# Database
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    """Build a fresh database and plant the flags."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    db.executescript(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            role TEXT,
            secret_note TEXT
        );
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY,
            owner TEXT,
            title TEXT,
            body TEXT
        );
        CREATE TABLE comments (
            id INTEGER PRIMARY KEY,
            author TEXT,
            body TEXT
        );
        """
    )
    # Users. admin's secret note is the SQLi reward (seen on the dashboard once
    # you bypass the login). alice's creds are public (handout) for the IDOR
    # and stored-XSS challenges that need a normal logged-in session.
    db.executemany(
        "INSERT INTO users (id, username, password, role, secret_note) VALUES (?,?,?,?,?)",
        [
            (1, "admin", ADMIN_PASSWORD, "admin",
             "Nice work bypassing the login. " + FLAGS["sqli"]),
            (2, "alice", "password123", "user", "Remember to water the plants."),
            (3, "bob", "qwerty2024", "user", "Lunch with the team Friday."),
        ],
    )
    # Messages. IDOR reward lives in admin's private message (id 1). alice owns
    # ids 4 and 5 so a logged-in student starts with their own and walks the ids.
    db.executemany(
        "INSERT INTO messages (id, owner, title, body) VALUES (?,?,?,?)",
        [
            (1, "admin", "Onboarding secret",
             "Internal only. Do not share. " + FLAGS["idor"]),
            (2, "bob", "Re: parking", "The north lot is closed next week."),
            (3, "admin", "Reminder", "Rotate the API keys this quarter."),
            (4, "alice", "Grocery list", "Milk, eggs, coffee."),
            (5, "alice", "Vacation", "Out of office next Monday."),
        ],
    )
    db.execute(
        "INSERT INTO comments (id, author, body) VALUES (1, 'admin', 'Welcome to the guestbook!')"
    )
    db.commit()
    db.close()

    # Plant the file-based flags (path traversal + sensitive-data exposure).
    with open(os.path.join(APP_DIR, "public", "welcome.txt"), "w") as fh:
        fh.write("Welcome to Vuln Hub. This file is meant to be downloadable.\n")
    with open(os.path.join(APP_DIR, "private", "employee_notes.txt"), "w") as fh:
        fh.write(
            "CONFIDENTIAL - employees only\n"
            "If you can read this through the download endpoint, the path "
            "filter failed.\n" + FLAGS["traversal"] + "\n"
        )
    with open(os.path.join(APP_DIR, "backups", "vulnhub.sql.bak"), "w") as fh:
        fh.write(
            "-- database backup (should NOT be world-readable)\n"
            "-- left in /backups/ by mistake\n"
            "INSERT INTO secrets VALUES ('" + FLAGS["exposure"] + "');\n"
        )


# --------------------------------------------------------------------------
# Home-rolled (broken) auth: an UNSIGNED base64 cookie of "username:role".
# Forging it is challenge 4 (authz). A real app would sign/encrypt this.
# --------------------------------------------------------------------------
def set_auth(resp, username, role):
    token = base64.b64encode(("%s:%s" % (username, role)).encode()).decode()
    resp.set_cookie("auth", token)


def current_user():
    token = request.cookies.get("auth")
    if not token:
        return None
    try:
        username, role = base64.b64decode(token).decode().split(":", 1)
        return {"username": username, "role": role}
    except Exception:
        return None


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def home():
    return render_template("home.html", user=current_user())


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        # VULN (sqli): user input concatenated straight into SQL.
        query = (
            "SELECT id, username, role FROM users "
            "WHERE username = '%s' AND password = '%s'" % (username, password)
        )
        try:
            row = get_db().execute(query).fetchone()
        except sqlite3.Error as exc:
            return render_template("login.html", error="SQL error: %s" % exc)
        if row:
            resp = make_response(redirect(url_for("dashboard")))
            set_auth(resp, row["username"], row["role"])
            return resp
        error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/dashboard")
def dashboard():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    row = get_db().execute(
        "SELECT secret_note FROM users WHERE username = ?", (user["username"],)
    ).fetchone()
    note = row["secret_note"] if row else "(no note on file)"
    return render_template("dashboard.html", user=user, note=note)


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("home")))
    resp.delete_cookie("auth")
    return resp


@app.route("/messages")
def messages():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    rows = get_db().execute(
        "SELECT id, title FROM messages WHERE owner = ?", (user["username"],)
    ).fetchall()
    return render_template("messages.html", user=user, rows=rows)


@app.route("/messages/<int:msg_id>")
def message_detail(msg_id):
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # VULN (idor): fetches the message by id with NO ownership check.
    row = get_db().execute(
        "SELECT id, owner, title, body FROM messages WHERE id = ?", (msg_id,)
    ).fetchone()
    if not row:
        return render_template("message_detail.html", user=user, row=None), 404
    return render_template("message_detail.html", user=user, row=row)


@app.route("/guestbook", methods=["GET", "POST"])
def guestbook():
    user = current_user()
    if request.method == "POST":
        author = user["username"] if user else "anonymous"
        body = request.form.get("comment", "")
        db = get_db()
        db.execute(
            "INSERT INTO comments (author, body) VALUES (?, ?)", (author, body)
        )
        db.commit()
        return redirect(url_for("guestbook"))
    rows = get_db().execute(
        "SELECT author, body FROM comments ORDER BY id"
    ).fetchall()
    # VULN (xss): comment bodies are rendered without escaping (see template).
    return render_template("guestbook.html", user=user, rows=rows)


# Exfiltration sink for the stored-XSS challenge. The simulated "admin bot"
# (below) runs the injected script with the admin's cookie and calls this.
CAPTURES = []


@app.route("/grab")
def grab():
    qs = request.query_string.decode()
    if qs:
        # Store the decoded form so the captured cookie/flag is readable.
        CAPTURES.append(urllib.parse.unquote(qs))
        return "ok"
    return render_template("grab.html", captures=CAPTURES)


@app.route("/vault")
def vault():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    # VULN (authz): trusts the role from the forgeable cookie. Only "superadmin"
    # gets in -- and no normal login ever issues that role.
    if user.get("role") != "superadmin":
        return render_template("vault.html", user=user, flag=None), 403
    return render_template("vault.html", user=user, flag=FLAGS["authz"])


@app.route("/download")
def download():
    name = request.args.get("file", "welcome.txt")
    # VULN (traversal): joins user input onto a base dir with no sanitization.
    path = os.path.join(APP_DIR, "public", name)
    try:
        with open(path, "r") as fh:
            data = fh.read()
    except (OSError, ValueError):
        return Response("File not found.", status=404, mimetype="text/plain")
    return Response(data, mimetype="text/plain")


@app.route("/robots.txt")
def robots():
    # Recon breadcrumb for the exposure challenge.
    return Response("User-agent: *\nDisallow: /backups/\n", mimetype="text/plain")


@app.route("/backups/<path:name>")
def backups(name):
    # VULN (exposure): a sensitive backup dir is served directly.
    path = os.path.join(APP_DIR, "backups", name)
    try:
        with open(path, "r") as fh:
            data = fh.read()
    except (OSError, ValueError):
        return Response("Not found.", status=404, mimetype="text/plain")
    return Response(data, mimetype="text/plain")


# --------------------------------------------------------------------------
# Simulated "admin bot" for the stored-XSS challenge.
# A real XSS bot is a headless browser with an admin session. We can't ship a
# browser, so this thread approximates one: it scans new comments, and if a
# comment contains a <script> that reads document.cookie and points at a URL,
# it "runs" that script by requesting the URL with the admin's cookie attached
# (which carries the xss flag). Students see the result at /grab.
# --------------------------------------------------------------------------
def xss_bot():
    seen = {1}  # comment id 1 is the seeded welcome message
    admin_cookie = "session=admin; flag=%s" % FLAGS["xss"]
    while True:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT id, body FROM comments").fetchall()
            conn.close()
        except sqlite3.Error:
            time.sleep(2)
            continue
        for row in rows:
            if row["id"] in seen:
                continue
            seen.add(row["id"])
            body = row["body"]
            low = body.lower()
            if "<script" not in low or "document.cookie" not in low:
                continue
            # Find the exfiltration URL inside a sink (fetch / .src= / location=).
            match = re.search(
                r"""(?:fetch\(|\.src\s*=|location(?:\.href)?\s*=|open\()\s*['"]([^'"]+)['"]""",
                body,
            )
            if not match:
                match = re.search(r"""['"](/[^'"]*)['"]""", body)
            if not match:
                continue
            target = match.group(1)
            # The injected script appends document.cookie; we supply it here.
            # A real browser percent-encodes the resulting URL, so we do too.
            full = target + urllib.parse.quote(admin_cookie)
            if full.startswith("/"):
                full = "http://127.0.0.1:%d%s" % (PORT, full)
            try:
                urllib.request.urlopen(full, timeout=2)
            except Exception:
                pass
        time.sleep(2)


def start_bot():
    thread = threading.Thread(target=xss_bot, daemon=True)
    thread.start()


# Build the DB and launch the bot at import time so it works under both
# `flask run`/`python app.py` and gunicorn.
init_db()
start_bot()


if __name__ == "__main__":
    # threaded=True so the bot's self-requests are served while a request waits.
    app.run(host=HOST, port=PORT, threaded=True)
