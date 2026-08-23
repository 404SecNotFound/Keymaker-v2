#!/usr/bin/env python3
"""
Regenerate reference/conformance-requirements.txt from reference/requirements.txt.

The conformance job installs its oracle from a hash-pinned file so the
implementation it cross-checks against is the audited code rather than whatever
PyPI served that morning. `requirements.txt` stays hash-free because it ships to
heirs in the recovery kit, where hash-checking mode turns an unfamiliar wheel
into a hard stop — see the header of the generated file.

Run this after changing a version in requirements.txt:

    python3 scripts/pin-conformance-deps.py            # regenerate (needs a network)
    python3 scripts/pin-conformance-deps.py --check    # CI gate: have the two drifted?

It resolves the full transitive closure against the interpreter CI uses, then
records every sha256 PyPI publishes for each pinned version, so the hash matches
whichever wheel the runner selects. Needs a network; writes nothing on failure.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRECT = ROOT / "reference" / "requirements.txt"
OUT = ROOT / "reference" / "conformance-requirements.txt"

# The runner the conformance job uses. Kept beside the workflow's own values on
# purpose: resolving against this container's interpreter instead would pin a
# closure CI never installs.
PY_VERSION = "3.12"
PLATFORM = "manylinux_2_17_x86_64"

PIN_RE = re.compile(r"^([A-Za-z0-9._-]+)==([^\s;#]+)")


def direct_pins() -> list[tuple[str, str]]:
    pins = []
    for line in DIRECT.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = PIN_RE.match(line)
        if not m:
            raise SystemExit(f"requirements.txt line is not a `name==version` pin: {line!r}")
        pins.append((m.group(1), m.group(2)))
    if not pins:
        raise SystemExit("requirements.txt lists no pinned dependencies")
    return pins


def closure(pins: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Every package pip would install, resolved for the CI runner."""
    with tempfile.TemporaryDirectory() as d:
        subprocess.run(
            [sys.executable, "-m", "pip", "download", "--dest", d,
             "--python-version", PY_VERSION, "--only-binary=:all:",
             "--platform", PLATFORM,
             *[f"{n}=={v}" for n, v in pins]],
            check=True, stdout=subprocess.DEVNULL,
        )
        found = {}
        for whl in sorted(Path(d).glob("*.whl")):
            name, version = whl.name.split("-")[:2]
            found[name.replace("_", "-").lower()] = version
    return sorted(found.items())


def hashes(name: str, version: str) -> list[str]:
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    with urllib.request.urlopen(url, timeout=60) as r:
        data = json.load(r)
    digests = sorted({f["digests"]["sha256"] for f in data["urls"]})
    if not digests:
        raise SystemExit(f"PyPI lists no files for {name}=={version}")
    return digests


def pinned_versions() -> dict[str, str]:
    """`name -> version` as currently recorded in the generated file."""
    if not OUT.exists():
        raise SystemExit(
            f"{OUT.relative_to(ROOT)} is missing. The conformance job installs its "
            "oracle from it; regenerate with `python3 scripts/pin-conformance-deps.py`."
        )
    out = {}
    for line in OUT.read_text(encoding="utf-8").splitlines():
        m = PIN_RE.match(line)
        if m:
            out[m.group(1).replace("_", "-").lower()] = m.group(2)
    return out


def check() -> int:
    """
    Fail if the hash-pinned file has drifted from requirements.txt.

    Only the direct dependencies are compared, because those are the two files'
    shared claim: requirements.txt is what RECOVERY.md tells an heir to install
    and what pip-audit scans, and the pinned file is what CI actually builds the
    oracle from. If they name different versions then the audited version and
    the tested version are different versions, and the conformance suite is
    confidently checking the wrong code — worse than not pinning at all, since
    the pin is what makes it look settled.

    Transitive versions are deliberately not checked here: requirements.txt does
    not name them, so there is nothing to compare against. They are pinned in
    the generated file and covered by --hash.
    """
    pinned = pinned_versions()
    problems = []
    for name, version in direct_pins():
        key = name.replace("_", "-").lower()
        if key not in pinned:
            problems.append(f"{name}=={version} is in requirements.txt but not in {OUT.name}")
        elif pinned[key] != version:
            problems.append(
                f"{name}: requirements.txt says {version}, {OUT.name} says {pinned[key]}"
            )
    if problems:
        print("conformance pins have drifted from requirements.txt:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print("\nRegenerate with `python3 scripts/pin-conformance-deps.py`.", file=sys.stderr)
        return 1
    print(f"conformance pins agree with requirements.txt "
          f"({', '.join(f'{n}=={v}' for n, v in direct_pins())})")
    return 0


def main() -> int:
    if "--check" in sys.argv[1:]:
        return check()
    pins = direct_pins()
    print(f"direct: {', '.join(f'{n}=={v}' for n, v in pins)}")
    resolved = closure(pins)
    print(f"closure: {', '.join(f'{n}=={v}' for n, v in resolved)}")

    # The header is every comment line before the first pin. Splitting on blank
    # lines was the first attempt and silently matched nothing, so the whole
    # previous file became the "header" and the packages were appended to it —
    # a regenerate that doubled the file instead of replacing it.
    header_lines = []
    for line in (OUT.read_text(encoding="utf-8").splitlines() if OUT.exists() else []):
        if PIN_RE.match(line):
            break
        header_lines.append(line)
    header = "\n".join(header_lines).rstrip("\n")
    if not header.startswith("#"):
        raise SystemExit(
            f"{OUT} is missing its explanatory header; refusing to overwrite it "
            "with a bare list of hashes."
        )

    blocks = [header]
    for name, version in resolved:
        body = " \\\n".join(f"    --hash=sha256:{d}" for d in hashes(name, version))
        blocks.append(f"{name}=={version} \\\n{body}")
    OUT.write_text("\n".join(blocks) + "\n", encoding="utf-8")
    print(f"wrote {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
