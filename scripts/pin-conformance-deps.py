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

It resolves the full transitive closure for each interpreter CI uses, then
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
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIRECT = ROOT / "reference" / "requirements.txt"
OUT = ROOT / "reference" / "conformance-requirements.txt"

# The interpreters the conformance workflow installs this file on: 3.12 for the
# conformance job, and 3.10 for `reference-python-floor`, the RECOVERY.md floor.
# Kept beside the workflow's own values on purpose: resolving against this
# container's interpreter instead would pin a closure CI never installs.
#
# Both, and merged, because the closures differ. On 3.10 cryptography also
# needs typing-extensions (it declares it for python_full_version < '3.11'), so
# a file resolved for 3.12 alone could only be installed on 3.10 with
# --no-deps, which is how the floor job had to run.
PY_VERSIONS = ("3.12", "3.10")

# Every manylinux tag an ubuntu-latest runner accepts that a pinned wheel is
# published under, newest first. This was manylinux_2_17 alone, which cannot
# resolve argon2-cffi-bindings 26.1.0 (published for manylinux_2_26/2_28 only):
# regenerating quietly fell back to 21.2.0, a version CI had never run.
PLATFORMS = (
    "manylinux_2_28_x86_64",
    "manylinux_2_26_x86_64",
    "manylinux_2_17_x86_64",
    "manylinux2014_x86_64",
)

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


def _canon(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _requires(whl: Path) -> list[str]:
    """A wheel's Requires-Dist lines, read from its own METADATA."""
    with zipfile.ZipFile(whl) as z:
        meta = next(n for n in z.namelist() if n.endswith(".dist-info/METADATA"))
        text = z.read(meta).decode("utf-8", "replace")
    return [line.split(":", 1)[1].strip() for line in text.splitlines()
            if line.startswith("Requires-Dist:")]


def closure_for(pins: list[tuple[str, str]], py_version: str) -> dict[str, str]:
    """
    Every package pip would install on one of the CI interpreters.

    pip's --python-version sets `python_version` for marker evaluation but not
    `python_full_version`, which is the one cryptography uses to require
    typing-extensions below 3.11. Resolved from this machine's interpreter, that
    dependency never appeared. So each wheel's own requirements are evaluated
    here against the target interpreter, and anything missing is downloaded in
    another round, until nothing is.
    """
    from pip._vendor.packaging.requirements import Requirement

    env = {
        "python_version": py_version,
        "python_full_version": f"{py_version}.0",
        "implementation_name": "cpython",
        "platform_python_implementation": "CPython",
        "sys_platform": "linux",
        "platform_system": "Linux",
        "platform_machine": "x86_64",
        "os_name": "posix",
        "extra": "",
    }
    wanted = [f"{n}=={v}" for n, v in pins]
    with tempfile.TemporaryDirectory() as d:
        while True:
            platform_args = [a for p in PLATFORMS for a in ("--platform", p)]
            subprocess.run(
                [sys.executable, "-m", "pip", "download", "--dest", d,
                 "--python-version", py_version, "--only-binary=:all:",
                 *platform_args, *wanted],
                check=True, stdout=subprocess.DEVNULL,
            )
            wheels = sorted(Path(d).glob("*.whl"))
            found = {_canon(w.name.split("-")[0]): w.name.split("-")[1] for w in wheels}
            missing = []
            for whl in wheels:
                for line in _requires(whl):
                    req = Requirement(line)
                    if req.marker is not None and not req.marker.evaluate(env):
                        continue
                    if _canon(req.name) not in found:
                        missing.append(f"{req.name}{req.specifier}")
            if not missing:
                return found
            wanted += sorted(set(missing))


def closure(pins: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """
    The union of every CI interpreter's closure.

    A package both need must resolve to the same version on both, or one file
    cannot serve both jobs; that is refused rather than papered over, since
    picking either version would install something one job never resolved.
    """
    merged: dict[str, str] = {}
    for py_version in PY_VERSIONS:
        for name, version in closure_for(pins, py_version).items():
            if merged.setdefault(name, version) != version:
                raise SystemExit(
                    f"{name} resolves to {merged[name]} on one CI interpreter and "
                    f"{version} on Python {py_version}; one pinned file cannot serve both."
                )
    return sorted(merged.items())


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
