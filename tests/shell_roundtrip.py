#!/usr/bin/env python3
"""Round-trip adversarial values through `ejson env` and real shells.

Usage: shell_roundtrip.py <ejson-binary> <workdir>

For every shell, evaluates `ejson env` output and checks that each variable
reads back byte-for-byte and that no injected command ran. Needs bash, dash,
zsh and fish on PATH; run by the "Shell round-trip" CI job.
"""
import json
import os
import subprocess
import sys

ejson, work = sys.argv[1], sys.argv[2]
os.makedirs(work, exist_ok=True)
marker = os.path.join(work, "PWNED")
BS = "\\"

values = {
    "V_TRAIL_BS": "x" + BS,
    "V_INJECT": "; touch " + marker + " #",
    "V_QUOTE": "it's",
    "V_BS_QUOTE": BS + "'",
    "V_QUOTE_BS": "'" + BS,
    "V_DOUBLE_BS": "a" + BS + BS + "b",
    "V_EXPANSIONS": "$(touch " + marker + ") `touch " + marker + "` $HOME",
    "V_NEWLINE": "multi\nline",
    "V_DQUOTES": '"double" quotes',
    "V_BS_N": BS + "n literal",
    "V_UNICODE": "é\U0001F600",
    "V_ONLY_BS": BS,
    "V_EMPTY": "",
    "V_FISH_ESCAPES": BS + "x41 " + BS + "u0041 " + BS + "$",
    "V_INJECT_FISH": "'; touch " + marker + "; echo '",
}

keydir = os.path.join(work, "keys")
os.makedirs(keydir, exist_ok=True)
pub = subprocess.run([ejson, "keygen", "-w", "-k", keydir],
                     check=True, capture_output=True, text=True).stdout.strip()
path = os.path.join(work, "env.ejson")
with open(path, "w") as f:
    json.dump({"_public_key": pub, "environment": values}, f)
subprocess.run([ejson, "encrypt", path], check=True, capture_output=True)


def ejson_env(shell_flag):
    return subprocess.run(
        [ejson, "env", "-k", keydir, "--shell", shell_flag, path],
        check=True, capture_output=True,
    ).stdout.decode()


# Print each variable NUL-separated so values with newlines read back exactly.
names = list(values)
posix_dump = "".join(f'printf "%s\\0" "${n}";' for n in names)
fish_dump = "".join(f'printf "%s\\0" "${n}";' for n in names)

cases = [
    ("bash", "posix", ["bash", "-c", 'eval "$1"; ' + posix_dump, "_"]),
    ("dash", "posix", ["dash", "-c", 'eval "$1"; ' + posix_dump, "_"]),
    ("zsh", "posix", ["zsh", "-c", 'eval "$1"; ' + posix_dump, "_"]),
    ("fish", "posix", ["fish", "-c", 'eval (printf "%s" $argv[1] | string collect); ' + fish_dump]),
    ("fish", "fish", ["fish", "-c", 'eval (printf "%s" $argv[1] | string collect); ' + fish_dump]),
]

failures = 0
for shell, flag, argv in cases:
    if os.path.exists(marker):
        os.remove(marker)
    argv = argv + [ejson_env(flag)]
    proc = subprocess.run(argv, capture_output=True)
    got = proc.stdout.decode(errors="replace").split("\0")[: len(names)]
    bad = [n for n, g in zip(names, got) if g != values[n]]
    if len(got) < len(names):
        bad.append(f"(only {len(got)} values printed)")
    pwned = os.path.exists(marker)
    ok = not bad and not pwned and proc.returncode == 0
    failures += not ok
    status = "OK  " if ok else "FAIL"
    print(f"{status} {shell:<5} eval of --shell {flag:<5} "
          f"mismatched={bad or 'none'} injected={'YES' if pwned else 'no'} rc={proc.returncode}")
    if not ok and proc.stderr:
        print("     stderr:", proc.stderr.decode(errors="replace").strip().splitlines()[:3])

sys.exit(1 if failures else 0)
