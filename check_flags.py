# INF601 - Advanced Programming in Python
# Self-check for the Vuln Hub pentest target (Mini Project 4, Track A).
#
# Checks each flag in your submission file against the flags Vuln Hub
# generates for your FLAG_SEED (your FHSU username). It only says VALID or
# NOT VALID; it never prints the expected flags and awards no points.
# A flag earns credit only if your report's PoC shows the exploit that
# produced it.
#
#   python check_flags.py submission.txt --username jdoe
#
# submission.txt: one captured flag per line (blank lines / # comments ignored).

import argparse
import hashlib
import hmac
import re
import sys

CHALLENGES = ["sqli", "idor", "xss", "authz", "traversal", "exposure"]

# Seeds used by earlier versions of Vuln Hub when FLAG_SEED was not set.
DEFAULT_SEEDS = ["inf601-default-seed-change-me", "change-me-before-class"]


FHSU_SUFFIX = re.compile(r"@(mail\.)?fhsu\.edu$")


def normalise(username):
    """FHSU username -> seed: trim, lowercase, drop an @fhsu.edu or
    @mail.fhsu.edu suffix (nothing else). Must match normalise_seed() in app.py."""
    return FHSU_SUFFIX.sub("", username.strip().lower())


def make_flag(seed, name):
    digest = hmac.new(seed.encode(), name.encode(), hashlib.sha256).hexdigest()[:12]
    return "FLAG{%s_%s}" % (name, digest)


def expected_flags(seed):
    """Return {flag: challenge} for the given FLAG_SEED."""
    return {make_flag(seed, name): name for name in CHALLENGES}


def load_submission(path):
    flags = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#"):
                flags.append(line)
    return flags


def main():
    parser = argparse.ArgumentParser(
        description="Check your Vuln Hub flags (VALID / NOT VALID only).")
    parser.add_argument("submission", help="file with one flag per line")
    parser.add_argument("--username", required=True,
                        help="your FHSU username (the FLAG_SEED you ran Vuln Hub with)")
    args = parser.parse_args()

    user = normalise(args.username)
    if not user or "@" in user:
        sys.exit("error: --username must be your FHSU username (e.g. jdoe or "
                 "jdoe@fhsu.edu), not %r" % args.username)
    mine = expected_flags(user)
    defaults = {}
    for seed in DEFAULT_SEEDS:
        defaults.update(expected_flags(seed))

    try:
        submitted = load_submission(args.submission)
    except OSError as exc:
        print("Could not read submission: %s" % exc, file=sys.stderr)
        sys.exit(1)

    solved = set()
    default_lines = set()
    for flag in submitted:
        if flag in mine:
            solved.add(mine[flag])
            print("%s  VALID (%s)" % (flag, mine[flag]))
        elif flag in defaults:
            default_lines.add(flag)
            print("%s  NOT VALID for %s: this flag came from the DEFAULT seed. "
                  "Your app is not using FLAG_SEED=%s; restart it with "
                  "FLAG_SEED=%s and capture again." % (flag, user, user, user))
        else:
            print("%s  NOT VALID" % flag)

    print("\n%d/%d flags valid for username %s" % (len(solved), len(CHALLENGES), user))
    print("Credit for each flag depends on your report's PoC showing the exploit.")
    if default_lines:
        print()
        print("=" * 70)
        print("WARNING: %d of your flags came from the DEFAULT seed, not from %s."
              % (len(default_lines), user))
        print("They are NOT counted above. Your Vuln Hub was started without")
        print("FLAG_SEED=%s (the page banner says 'running on the DEFAULT seed')." % user)
        print("Stop the app, restart it with FLAG_SEED=%s, and capture again." % user)
        print("If you already submitted work with these, say so in your report;")
        print("your instructor decides.")
        print("=" * 70)

if __name__ == "__main__":
    main()
