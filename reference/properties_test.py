#!/usr/bin/env python3
"""
Property tests: keym2.py and the shipping TypeScript agree on inputs nobody
wrote by hand.

crosstest2.py checks the cases someone thought of. This generates the rest from
a seed and hands every case to both readers in one batch, through the same
`textverdicts` bridge command the conformance suite uses:

  1. armor with §7's ignorable characters inserted after the prefix reads as
     the bytes it encodes, and with one inserted inside the prefix it does not;
  2. armor cut short anywhere reads as a prefix of its bytes or not at all;
  3. a share re-spelt the ways §4.6 allows (case, I/L/O look-alikes, hyphens,
     ignorable characters) decodes to the record it was written from;
  4. a share with one character changed is refused;
  5. any k or more distinct shares of a set, in any order, with repeats in any
     spelling, combine to the secret, and fewer than k distinct never do;
  6. paper parts in any order, with ignorable characters inside them, reassemble
     the container, and a set missing one part, or holding one twice, is refused;
  7. Padmé's padded_len, at every magnitude a stream can have, gives the same
     length in both, never shorter than its input, and never decreasing.

Each verdict must match the other implementation's exactly, and where the right
answer is known it must also be that answer. Every case that can be enumerated
rather than drawn is enumerated (each ignorable character, each look-alike, each
part dropped in turn), so a negative control bites on every seed, not only on a
lucky one.

The seed is printed first. KEYMAKER_PROPERTY_SEED=<seed> replays a run exactly,
and KEYMAKER_PROPERTY_CASES sets how many cases each property draws.
"""

from __future__ import annotations

import json
import os
import random
import secrets
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import keym2  # noqa: E402

BRIDGE = HERE / "bridge.mjs"
CASES = int(os.environ.get("KEYMAKER_PROPERTY_CASES") or 200)

# §7's set, minus the line break. A line break inside a share or a part is a
# second line to every reader of a paste, which is a different input and not
# the property under test.
INLINE_IGNORABLE = keym2.IGNORABLE.replace("\n", "")

# §4.6: each canonical character and the spellings a reader folds onto it.
LOOKALIKES = {"1": "1IiLl", "0": "0Oo"}


def py_verdict(kind: str, text: str) -> dict:
    """The reference's verdict, in the shape the bridge writes."""
    try:
        if kind == "armor":
            return {"ok": True, "hex": keym2.dearmor(text).hex()}
        if kind == "share":
            x = keym2.decode_share_any(text)
            return {"ok": True,
                    "hex": f"{x.set_id.hex()}:{x.threshold}:{x.index}:{x.value.hex()}"}
        if kind == "parts":
            lines = [keym2._strip_ignorable(ln) for ln in text.split("\n")]
            lines = [ln for ln in lines if ln and not ln.startswith("#")]
            return {"ok": True, "hex": keym2.decode_parts_any(lines).hex()}
        if kind == "combine":
            lines = [ln for ln in text.split("\n") if ln.strip(keym2.IGNORABLE)]
            return {"ok": True, "hex": keym2.combine_shares(lines).hex()}
        if kind == "padlen":
            return {"ok": True, "hex": str(keym2.padded_len(int(text)))}
    except (keym2.KeymError, ValueError, UnicodeError):
        return {"ok": False}
    except Exception as e:  # noqa: BLE001
        # A crash is not a refusal. Recorded so it can never match the other
        # side's verdict and is reported against its case, rather than ending
        # the run with a traceback that names no property.
        return {"ok": False, "crash": repr(e)}
    raise AssertionError(kind)


def brief(v: dict) -> str:
    """A verdict short enough to read in a failure line."""
    h = v.get("hex")
    return str({**v, "hex": h[:24] + ("…" if len(h) > 24 else "")} if h else v)


def share_hex(s: keym2.Share) -> str:
    return f"{s.set_id.hex()}:{s.threshold}:{s.index}:{s.value.hex()}"


class Cases:
    """Every case of every property, each with the answer it must get."""

    def __init__(self) -> None:
        self.items: list[tuple[str, str, str, str, object]] = []

    def add(self, prop: str, label: str, kind: str, text: str, want: object) -> None:
        """`want` is a verdict dict, None for agreement only, or a callable on the verdict."""
        self.items.append((prop, label, kind, text, want))


def random_share(rng: random.Random) -> tuple[keym2.Share, str]:
    v2 = rng.random() < 0.5
    share = keym2.Share(
        set_id=rng.randbytes(16 if v2 else keym2.SHARE_SET_ID_LEN),
        threshold=rng.randint(2, 16), index=rng.randint(1, 255),
        value=rng.randbytes(32))
    return share, (keym2.encode_share_v2 if v2 else keym2.encode_share)(share)


def respell(rng: random.Random, text: str, ignorable: str) -> str:
    """A spelling of a share §4.6 says is the same share."""
    prefix_len = text.index(":") + 1
    prefix = "".join(c.lower() if rng.random() < 0.5 else c for c in text[:prefix_len])
    out: list[str] = []
    for c in text[prefix_len:]:
        if c == "-":
            out.append(rng.choice(["", "-", "--"]))
            continue
        if c in LOOKALIKES:
            c = rng.choice(LOOKALIKES[c])
        elif rng.random() < 0.5:
            c = c.lower()
        out.append(c)
        if rng.random() < 0.05:
            out.append(rng.choice(ignorable))
    return rng.choice(["", ignorable]) + prefix + "".join(out) + rng.choice(["", ignorable])


def build(rng: random.Random) -> Cases:
    cases = Cases()

    # 1 and 2. Armor. Random bytes, because a reader of armor does not parse
    # the container, and lengths that cover every residue of base64's padding.
    for i in range(max(CASES, len(keym2.IGNORABLE))):
        blob = rng.randbytes(rng.randint(1, 300))
        arm = keym2.armor(blob, columns=rng.choice([0, 64, 76]))
        pre = len(keym2.ARMOR_PREFIX)
        ch = keym2.IGNORABLE[i % len(keym2.IGNORABLE)]
        at = rng.randint(pre, len(arm))
        lead = ch if i % 3 == 0 else ""
        cases.add("armor: ignorable characters after the prefix are ignored",
                  f"U+{ord(ch):04X} at {at} of {len(arm)}", "armor",
                  lead + arm[:at] + ch + arm[at:], {"ok": True, "hex": blob.hex()})
        inside = rng.randint(1, pre - 1)
        cases.add("armor: an ignorable character inside the prefix is refused",
                  f"U+{ord(ch):04X} at {inside}", "armor",
                  arm[:inside] + ch + arm[inside:], {"ok": False})
        cut = rng.randint(0, len(arm) - 1)
        cases.add("armor: cut short, it reads a prefix of its bytes or nothing",
                  f"cut at {cut} of {len(arm)}", "armor", arm[:cut],
                  lambda v, blob=blob: not v["ok"] or blob.hex().startswith(v["hex"]))

    # 3 and 4. One share, spelt every way §4.6 allows, then damaged once.
    for i in range(CASES):
        share, text = random_share(rng)
        ch = INLINE_IGNORABLE[i % len(INLINE_IGNORABLE)]
        cases.add("share: every allowed spelling decodes to its record",
                  f"#{i}", "share", respell(rng, text, ch),
                  {"ok": True, "hex": share_hex(share)})
        body_at = [j for j, c in enumerate(text) if j > text.index(":") and c != "-"]
        j = rng.choice(body_at)
        canon = keym2.B32_ALPHABET
        old = LOOKALIKES.get(text[j], text[j]).upper()[0]
        new = rng.choice([c for c in canon if c != old])
        cases.add("share: one character changed is refused",
                  f"#{i} at {j}", "share", text[:j] + new + text[j + 1:], {"ok": False})

    # 5. Share sets: any k or more distinct, any order, repeats in any spelling.
    for i in range(CASES):
        k = rng.randint(2, 6)
        n = rng.randint(k, min(16, k + 5))
        secret = rng.randbytes(32)
        v2 = rng.random() < 0.5
        sid = rng.randbytes(16 if v2 else keym2.SHARE_SET_ID_LEN)
        enc = keym2.encode_share_v2 if v2 else keym2.encode_share
        texts = [enc(keym2.Share(set_id=sid, threshold=k, index=x, value=v))
                 for x, v in keym2.shamir_split(secret, k, n)]
        ch = INLINE_IGNORABLE[i % len(INLINE_IGNORABLE)]

        def with_repeats(chosen: list[str]) -> list[str]:
            picked = list(chosen)
            for _ in range(rng.randint(1 if i % 2 else 0, 3)):
                picked.append(respell(rng, rng.choice(chosen), ch))
            rng.shuffle(picked)
            return picked

        enough = rng.sample(texts, rng.randint(k, n))
        cases.add("combine: k or more distinct shares open, in any order, with repeats",
                  f"k={k} n={n} given {len(enough)}", "combine",
                  "\n".join(with_repeats(enough)), {"ok": True, "hex": secret.hex()})
        short = rng.sample(texts, rng.randint(1, k - 1))
        cases.add("combine: fewer than k distinct never open, however often repeated",
                  f"k={k} n={n} given {len(short)}", "combine",
                  "\n".join(with_repeats(short)), {"ok": False})

    # 6. Paper parts, both versions, in any order, each part then dropped once.
    for i in range(max(CASES // 4, 1)):
        blob = rng.randbytes(rng.randint(1, 2000))
        cap = rng.randint(max(1, len(blob) // 24), max(1, len(blob) // 2))
        enc = keym2.encode_parts_v2 if i % 2 else keym2.encode_parts
        parts = enc(blob, cap)
        ch = INLINE_IGNORABLE[i % len(INLINE_IGNORABLE)]
        shuffled = list(parts)
        rng.shuffle(shuffled)
        spaced = []
        for p in shuffled:
            at = rng.randint(0, len(p))
            spaced.append(p[:at] + ch + p[at:])
        cases.add("parts: any order, ignorable characters inside, reassemble the container",
                  f"{len(parts)} parts of {len(blob)} B", "parts", "\n".join(spaced),
                  {"ok": True, "hex": blob.hex()})
        # Unlike a share (§6), a part supplied twice is refused (§7.3): the app
        # drops a repeated scan before the reassembler sees it.
        cases.add("parts: a part supplied twice is refused",
                  f"{len(parts)} parts, one twice", "parts",
                  "\n".join(shuffled + [rng.choice(parts)]), {"ok": False})
        if len(parts) > 1:
            for drop in range(len(parts)):
                rest = [p for j, p in enumerate(shuffled) if j != drop]
                cases.add("parts: a set missing any one part is refused",
                          f"{len(parts)} parts, one dropped", "parts", "\n".join(rest),
                          {"ok": False})

    # 7. Padmé at every magnitude, and at each power of two and either side.
    lengths = {keym2.PAD_PREFIX_LEN, keym2.PAD_FLOOR, keym2.PAD_FLOOR + 1}
    for e in range(3, 48):
        lengths.update({(1 << e) - 1, 1 << e, (1 << e) + 1})
    for _ in range(CASES):
        lengths.add(keym2.PAD_PREFIX_LEN + rng.getrandbits(rng.randint(1, 47)))
    ordered = sorted(n for n in lengths if n >= keym2.PAD_PREFIX_LEN)
    for n in ordered:
        cases.add("padlen: the same length in both, never shorter than its input",
                  f"n={n}", "padlen", str(n),
                  lambda v, n=n: v["ok"] and int(v["hex"]) >= n)
    return cases


def run_bridge(tmp: Path, items: list[dict]) -> list[dict]:
    src, out = tmp / "property-cases.json", tmp / "property-verdicts.json"
    src.write_text(json.dumps(items))
    proc = subprocess.run(["node", str(BRIDGE), "textverdicts", "--in", str(src),
                           "--out", str(out)], capture_output=True, cwd=ROOT)
    if proc.returncode != 0:
        detail = proc.stderr.decode(errors="replace").strip().splitlines()
        raise RuntimeError(detail[-1] if detail else f"bridge exit {proc.returncode}")
    return json.loads(out.read_text())


def main() -> int:
    if shutil.which("node") is None:
        print("properties_test: node not found", file=sys.stderr)
        return 1
    seed = int(os.environ.get("KEYMAKER_PROPERTY_SEED") or secrets.randbits(32))
    print(f"Property tests, seed {seed}, {CASES} cases a property "
          f"(replay with KEYMAKER_PROPERTY_SEED={seed})")
    cases = build(random.Random(seed))

    tmp = Path(tempfile.mkdtemp(prefix="keym2-props-"))
    try:
        js = run_bridge(tmp, [{"kind": k, "text": t} for _, _, k, t, _ in cases.items])
    except RuntimeError as e:
        print(f"FAIL the TypeScript side did not answer: {e}")
        return 1
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if len(js) != len(cases.items):
        print(f"FAIL {len(cases.items)} cases, {len(js)} verdicts")
        return 1

    by_prop: dict[str, list[str]] = {}
    counts: dict[str, int] = {}
    padded: list[tuple[int, int]] = []
    for (prop, label, kind, text, want), jv in zip(cases.items, js):
        pv = py_verdict(kind, text)
        counts[prop] = counts.get(prop, 0) + 1
        problems = by_prop.setdefault(prop, [])
        if pv != jv:
            problems.append(f"{label}: py={brief(pv)} js={brief(jv)} text={ascii(text[:60])}")
        elif callable(want):
            if not want(pv):
                problems.append(f"{label}: both said {brief(pv)}")
        elif want is not None and pv != want:
            problems.append(f"{label}: both said {brief(pv)}, expected {brief(want)}")
        if kind == "padlen" and pv["ok"]:
            padded.append((int(text), int(pv["hex"])))

    # Padmé is monotone: a longer input never gets a shorter stream.
    prop = "padlen: never decreasing as the input grows"
    counts[prop] = len(padded)
    by_prop[prop] = [f"n={a[0]} pads to {a[1]} but n={b[0]} to {b[1]}"
                     for a, b in zip(padded, padded[1:]) if b[1] < a[1]]

    failed = 0
    for prop, problems in by_prop.items():
        if problems:
            failed += 1
            print(f"  FAIL {prop}: {len(problems)} of {counts[prop]} cases")
            for p in problems[:3]:
                print(f"         {p}")
        else:
            print(f"  ok   {prop} ({counts[prop]} cases)")

    if failed:
        print(f"\n{failed} of {len(by_prop)} properties FAILED. "
              f"Replay with KEYMAKER_PROPERTY_SEED={seed}")
        return 1
    print(f"\nAll {len(by_prop)} properties held over {len(cases.items)} cases (seed {seed}).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
