# INF601 - Advanced Programming in Python
# Samuel Hart
# Mini Project 4
#
# verify.py: a verifier wrapper around check_flags.py.
#
# check_flags.py prints VALID / NOT VALID for each submitted flag but always
# exits 0, so its exit code carries no information. An agent loop that watches
# exit codes would read green while every flag failed. This wrapper turns the
# printed verdict into a real exit status, which is what makes it usable as the
# loop's feedback signal.
#
#   python verify.py submission.txt --username s_hart
#
# Exit 0 only when all 6 flags are valid for the seed. Non-zero otherwise, and
# it prints which challenges are still missing.

import argparse
import re
import subprocess
import sys

CHALLENGES = ["sqli", "idor", "xss", "authz", "traversal", "exposure"]
SUMMARY = re.compile(r"^(\d+)/(\d+) flags valid for username")


def main():
    parser = argparse.ArgumentParser(
        description="Exit 0 only if every flag in the file is valid.")
    parser.add_argument("submission", help="file with one flag per line")
    parser.add_argument("--username", required=True, help="your FHSU username")
    args = parser.parse_args()

    proc = subprocess.run(
        [sys.executable, "check_flags.py", args.submission,
         "--username", args.username],
        capture_output=True, text=True,
    )
    output = proc.stdout + proc.stderr
    print(output, end="")

    match = None
    for line in output.splitlines():
        match = SUMMARY.match(line.strip())
        if match:
            break
    if not match:
        print("verify: could not read a summary line from check_flags.py",
              file=sys.stderr)
        return 2

    valid, total = int(match.group(1)), int(match.group(2))

    # Which challenges are still uncaptured, read from the VALID lines.
    found = {name for name in CHALLENGES
             if re.search(r"VALID \(%s\)" % name, output)}

    if valid == total:
        print("verify: all %d flags valid." % total)
        return 0

    missing = [name for name in CHALLENGES if name not in found]
    print("verify: %d/%d valid. Still missing: %s"
          % (valid, total, ", ".join(missing) or "none"), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
