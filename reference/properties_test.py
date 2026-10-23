#!/usr/bin/env python3
"""
Property tests: keym2.py and the shipping TypeScript agree on inputs nobody
wrote by hand.

crosstest2.py checks the cases someone thought of. This generates the rest from
a seed and hands every case to both readers in one batch, through the same
`textverdicts` bridge command the conformance suite uses:

  1. armor with §7's ignorable characters inserted after the prefix reads as
     the bytes it encodes, with one inside the prefix it does not, and cut
     short anywhere it reads a prefix of its bytes or nothing;
  2. a share re-spelt the ways §4.6 allows (case, I/L/O look-alikes, hyphens,
     ignorable characters) decodes to the record it was written from, and one
     with an ignorable character inside its prefix, one character changed, a
     character from outside the alphabet swapped in or inserted, a non-ASCII
     letter that case-folds into it, or a spare padding bit set does not;
  3. any k or more distinct shares of a set, in any order, with repeats in any
     spelling and blank, comment and ignorable-only lines between them, combine
     to the secret; fewer than k distinct never do; a consistent extra share
     above the k lowest is never used; a different share at a supplied index,
     a copy differing only in k or set id, or a damaged copy is refused; and a
     copy differing only in its index is a different share;
  4. paper parts in any order, with ignorable characters inside their bodies
     and comment lines between them, reassemble the container, and a set
     missing one part, or holding one twice, is refused;
  5. Padmé's padded_len, at every magnitude a stream can have, gives the same
     length in both, never shorter than its input, and never decreasing.

Each verdict must match the other implementation's exactly, and where the right
answer is known it must also be that answer. A crash on either side is its own
verdict, so it can never pass as a refusal. Every case that can be enumerated
rather than drawn is enumerated (each ignorable character, each look-alike,
each spare padding bit, each part dropped in turn), so a negative control bites
on every seed, not only on a lucky one.

Multi-line cases are joined with each of §7's line ends (LF, CRLF, a lone CR) in
turn.

The seed is printed first. KEYMAKER_PROPERTY_SEED=<seed> replays a run exactly,
which the run checks by building its cases again in two child processes with
different hash seeds. KEYMAKER_PROPERTY_CASES sets how many cases each property
draws.
"""

from __future__ import annotations

import hashlib
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

# §7's set, minus the line ends. LF, CRLF and a lone CR inside a share or a
# part start a second line for every reader of a paste (and in a browser's text
# box), which is a different input and not the property under test. A single
# share, which is never split into lines, takes a lone CR as ignorable.
INLINE_IGNORABLE = keym2.IGNORABLE.replace("\n", "").replace("\r", "")
SHARE_IGNORABLE = keym2.IGNORABLE.replace("\n", "")

# §7, the three line ends. Every multi-line case is joined with one of them.
LINE_ENDS = ["\n", "\r\n", "\r"]

# §4.6: each canonical character and the spellings a reader folds onto it.
LOOKALIKES = {"1": "1IiLl", "0": "0Oo"}

# Outside the share alphabet, so a reader must refuse each: ASCII the alphabet
# leaves out, and non-ASCII letters that look like ones it holds.
NOT_IN_ALPHABET = "Uu!_=+./~\uff21\u0399\u0430"

# §7, folding is ASCII-only. Each of these upper-cases, in both languages, onto
# the character it is paired with, so one put in that character's place makes
# a valid share to a reader that folds with the language's own upper().
FOLD_TRAPS = {
    "\u0131": "1",   # dotless i: upper() gives I, which folds to 1
    "\u017f": "S",   # long s: upper() gives S
    "\u212a": "K",   # Kelvin sign: lower() gives k
}

# Lines a reader of a paste skips (§7, one item per line). U+0085 alone was a
# blank line to keym2.py and a failed share to the app's share box.
SKIPPED_LINES = ["", "# share 2 of 5", "\u0085", "  \u3000", "\ufeff# strips"]

# What keym2.py raises on purpose when it refuses each kind of text. Anything
# else is a crash, reported as one.
REFUSALS = {
    "armor": (keym2.KeymError, UnicodeError),
    "share": (keym2.KeymError,),
    "combine": (keym2.KeymError,),
    "parts": (keym2.KeymError, ValueError),   # §7.3 names what is wrong
    "padlen": (keym2.UsageError,),
}


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
            return {"ok": True, "hex": keym2.decode_parts_any(keym2.text_lines(text)).hex()}
        if kind == "combine":
            return {"ok": True, "hex": keym2.combine_shares(keym2.text_lines(text)).hex()}
        if kind == "padlen":
            return {"ok": True, "hex": str(keym2.padded_len(int(text)))}
    except Exception as e:  # noqa: BLE001
        if isinstance(e, REFUSALS[kind]):
            return {"ok": False}
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


def encoder(v2: bool):
    return keym2.encode_share_v2 if v2 else keym2.encode_share


def random_share(rng: random.Random) -> tuple[keym2.Share, str]:
    v2 = rng.random() < 0.5
    share = keym2.Share(
        set_id=rng.randbytes(16 if v2 else keym2.SHARE_SET_ID_LEN),
        threshold=rng.randint(2, 16), index=rng.randint(1, 255),
        value=rng.randbytes(32))
    return share, encoder(v2)(share)


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


def spare_bit_spellings(text: str) -> list[str]:
    """Every other final character carrying the same data bits (§4.6, one spelling)."""
    flat = text.replace("-", "")
    body = flat[flat.index(":") + 1:]
    nbytes = keym2.SHARE2_LEN if flat.upper().startswith(keym2.SHARE2_PREFIX) else keym2.SHARE_LEN
    pad = len(body) * 5 - nbytes * 8
    at = keym2.B32_ALPHABET.index(body[-1])
    return [flat[:-1] + keym2.B32_ALPHABET[at ^ x] for x in range(1, 1 << pad)]


def damaged_copies(share: keym2.Share, text: str) -> list[tuple[str, str]]:
    """A copy of one share that fails its own checks (§6, checked before a repeat is dropped)."""
    v2 = text.upper().startswith(keym2.SHARE2_PREFIX)
    record = bytearray(keym2._pack_share_v2(share) if v2 else share.pack())
    record[-1] ^= 1
    prefix = keym2.SHARE2_PREFIX if v2 else keym2.SHARE_PREFIX
    return [("a wrong checksum", prefix + keym2._b32_encode(bytes(record))),
            ("a spare padding bit", spare_bit_spellings(text)[0])]


def build(rng: random.Random) -> Cases:
    cases = Cases()
    n_inline = len(INLINE_IGNORABLE)
    n_share = len(SHARE_IGNORABLE)

    # 1. Armor. Random bytes, because a reader of armor does not parse the
    # container, and lengths that cover every residue of base64's padding.
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

    # 2. One share, spelt every way §4.6 allows, then spelt every way it does not.
    for i in range(max(CASES, n_share)):
        share, text = random_share(rng)
        ch = SHARE_IGNORABLE[i % n_share]
        record = {"ok": True, "hex": share_hex(share)}
        colon = text.index(":")
        cases.add("share: every allowed spelling decodes to its record",
                  f"#{i}", "share", respell(rng, text, ch), record)
        cases.add("share: an ignorable character just after the prefix is ignored",
                  f"#{i} U+{ord(ch):04X}", "share", text[:colon + 1] + ch + text[colon + 1:],
                  record)
        inside = rng.randint(1, colon)
        cases.add("share: an ignorable character inside the prefix is refused",
                  f"#{i} U+{ord(ch):04X} at {inside}", "share",
                  text[:inside] + ch + text[inside:], {"ok": False})
        body_at = [j for j, c in enumerate(text) if j > colon and c != "-"]
        j = rng.choice(body_at)
        old = LOOKALIKES.get(text[j], text[j]).upper()[0]
        new = rng.choice([c for c in keym2.B32_ALPHABET if c != old])
        cases.add("share: one character changed is refused",
                  f"#{i} at {j}", "share", text[:j] + new + text[j + 1:], {"ok": False})
        bad = NOT_IN_ALPHABET[i % len(NOT_IN_ALPHABET)]
        cases.add("share: a character from outside the alphabet is refused",
                  f"#{i} U+{ord(bad):04X} at {j}", "share", text[:j] + bad + text[j + 1:],
                  {"ok": False})
        # Inserted as well as swapped in: a reader that skipped the character,
        # as it skips a hyphen, is left one short by a swap and refuses for the
        # wrong reason, but reads an insertion as the share.
        cases.add("share: a character from outside the alphabet, inserted, is refused",
                  f"#{i} U+{ord(bad):04X} at {j}", "share", text[:j] + bad + text[j:],
                  {"ok": False})
        for trap, target in FOLD_TRAPS.items():
            at = [j for j in body_at if text[j] == target]
            if at:
                j = rng.choice(at)
                cases.add("share: a non-ASCII letter that case-folds into the alphabet is refused",
                          f"#{i} U+{ord(trap):04X} for {target}", "share",
                          text[:j] + trap + text[j + 1:], {"ok": False})
        for spelling in spare_bit_spellings(text):
            cases.add("share: a spare padding bit set is refused",
                      f"#{i} ending {spelling[-1]}", "share", spelling, {"ok": False})

    # 3. Share sets. Coefficients from the seeded generator, so a seed replays.
    for i in range(max(CASES, n_inline)):
        k = rng.randint(2, 6)
        n = rng.randint(k, min(16, k + 5))
        secret = rng.randbytes(32)
        v2 = rng.random() < 0.5
        sid = rng.randbytes(16 if v2 else keym2.SHARE_SET_ID_LEN)
        enc = encoder(v2)
        split = keym2.shamir_split(secret, k, n, coefficients=rng.randbytes((k - 1) * 32))
        texts = [enc(keym2.Share(set_id=sid, threshold=k, index=x, value=v)) for x, v in split]
        ch = INLINE_IGNORABLE[i % n_inline]
        opens = {"ok": True, "hex": secret.hex()}

        def pasted(chosen: list[str], extra: list[str] = ()) -> str:
            """Repeats in any spelling, any order, lines a reader skips, any line end."""
            picked = list(chosen) + list(extra)
            for _ in range(rng.randint(1 if i % 2 else 0, 3)):
                picked.append(respell(rng, rng.choice(chosen), ch))
            rng.shuffle(picked)
            for _ in range(rng.randint(0, 2)):
                picked.insert(rng.randint(0, len(picked)),
                              SKIPPED_LINES[(i + len(picked)) % len(SKIPPED_LINES)])
            return LINE_ENDS[i % len(LINE_ENDS)].join(picked)

        enough = rng.sample(texts, rng.randint(k, n))
        cases.add("combine: k or more distinct shares open, in any order, with repeats",
                  f"k={k} n={n} given {len(enough)}", "combine", pasted(enough), opens)
        short = rng.sample(texts, rng.randint(1, k - 1))
        cases.add("combine: fewer than k distinct never open, however often repeated",
                  f"k={k} n={n} given {len(short)}", "combine", pasted(short),
                  {"ok": False})

        # §6, the k lowest-indexed. A share of the right set and k but a random
        # value, at an index above the k lowest supplied, must never be used.
        lowest = sorted(split[j][0] for j in rng.sample(range(n), k))
        high = rng.randint(lowest[-1] + 1, 255) if lowest[-1] < 255 else None
        if high is not None:
            stray = enc(keym2.Share(set_id=sid, threshold=k, index=high,
                                    value=rng.randbytes(32)))
            cases.add("combine: a consistent extra share above the k lowest is never used",
                      f"k={k} lowest {lowest} stray at {high}", "combine",
                      pasted([texts[x - 1] for x in lowest], [stray]), opens)
        # Below the k lowest it is used, so only agreement is known.
        if lowest[0] > 1:
            stray = enc(keym2.Share(set_id=sid, threshold=k, index=rng.randint(1, lowest[0] - 1),
                                    value=rng.randbytes(32)))
            cases.add("combine: an inconsistent share among the k lowest, both agree",
                      f"k={k} lowest {lowest}", "combine",
                      "\n".join([stray] + [texts[x - 1] for x in lowest]), None)

        # §6, two different shares at one index, and a copy differing in one
        # field only (valid checksum), before and after the genuine share.
        target_text = enough[i % len(enough)]
        target = keym2.decode_share_any(target_text)
        other_k = rng.choice([x for x in range(2, 17) if x != k])
        # Differs in one byte, past the first four, so a comparison of the v1
        # width alone would miss it.
        flip = rng.randrange(len(sid) - 4, len(sid)) if len(sid) > 4 else rng.randrange(4)
        other_sid = sid[:flip] + bytes([sid[flip] ^ (1 << rng.randrange(8))]) + sid[flip + 1:]
        variants = [("value", enc(keym2.Share(set_id=sid, threshold=k, index=target.index,
                                              value=rng.randbytes(32)))),
                    ("k", enc(keym2.Share(set_id=sid, threshold=other_k, index=target.index,
                                          value=target.value))),
                    ("set id", enc(keym2.Share(set_id=other_sid, threshold=k,
                                               index=target.index, value=target.value)))]
        variants += damaged_copies(target, target_text)
        what, near_text = variants[i % len(variants)]
        first = i % 2 == 0
        lines = ([near_text] + enough) if first else (enough + [near_text])
        cases.add("combine: a different share at a supplied index is refused, in either order",
                  f"k={k} {what} differs, {'first' if first else 'last'}", "combine",
                  "\n".join(lines), {"ok": False})

        # Only its index changed: a different share at an index nobody supplied,
        # so it is interpolated with the rest, never dropped as a repeat.
        others = rng.sample(split, k - 1)
        used = {x for x, _ in others}
        fresh = rng.choice([x for x in range(1, 256) if x not in used])
        copied = rng.choice(others)
        moved = enc(keym2.Share(set_id=sid, threshold=k, index=fresh, value=copied[1]))
        points = sorted(others + [(fresh, copied[1])])
        cases.add("combine: a copy with only its index changed is a different share",
                  f"k={k} share {copied[0]} copied to {fresh}", "combine",
                  "\n".join([texts[x - 1] for x, _ in others] + [moved]),
                  {"ok": True, "hex": keym2.shamir_combine(points).hex()})

    # 4. Paper parts, both versions, in any order, each part then dropped once.
    for i in range(max(CASES // 4, n_inline)):
        blob = rng.randbytes(rng.randint(1, 2000))
        cap = rng.randint(max(1, len(blob) // 24), max(1, len(blob) // 2))
        enc = keym2.encode_parts_v2 if i % 2 else keym2.encode_parts
        parts = enc(blob, cap)
        ch = INLINE_IGNORABLE[i % n_inline]
        shuffled = list(parts)
        rng.shuffle(shuffled)
        spaced = []
        for j, p in enumerate(shuffled):
            if rng.random() < 0.5:
                spaced.append(f"# part {j + 1} of {len(parts)}")
            at = rng.randint(p.index(":") + 1, len(p))
            spaced.append(p[:at] + ch + p[at:])
        eol = LINE_ENDS[i % len(LINE_ENDS)]
        cases.add("parts: any order, ignorable characters in bodies, reassemble the container",
                  f"{len(parts)} parts of {len(blob)} B, U+{ord(ch):04X}", "parts",
                  eol.join(spaced), {"ok": True, "hex": blob.hex()})
        # Inside the KMPART prefix both readers currently ignore the character,
        # where armor and shares refuse it. §7 does not settle which is right,
        # so only agreement is held here.
        p0 = shuffled[0]
        inside = rng.randint(1, p0.index(":"))
        cases.add("parts: an ignorable character inside the prefix, both agree",
                  f"U+{ord(ch):04X} at {inside}", "parts",
                  "\n".join([p0[:inside] + ch + p0[inside:]] + shuffled[1:]), None)
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

    # 5. Padmé at every magnitude, and at each power of two and either side.
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


def digest(items: list) -> str:
    """What a replay must reproduce: every case's property, label, kind and text."""
    return hashlib.sha256(json.dumps([list(c[:4]) for c in items]).encode()).hexdigest()


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

    by_prop: dict[str, list[str]] = {}
    counts: dict[str, int] = {}

    # The promise the printed seed makes. Anything drawn from outside the
    # seeded generator (os.urandom, a set's iteration order) breaks it. Built
    # again in two child processes with different hash seeds, because a set's
    # order is fixed for the life of one process and a second build in this one
    # would match it.
    prop = "the seed replays the run exactly"
    counts[prop] = len(cases.items)
    mine = digest(cases.items)
    by_prop[prop] = []
    for hash_seed in ("1", "2"):
        child = subprocess.run(
            [sys.executable, str(Path(__file__).resolve()), "--digest"],
            env={**os.environ, "KEYMAKER_PROPERTY_SEED": str(seed),
                 "PYTHONHASHSEED": hash_seed},
            capture_output=True, text=True)
        theirs = child.stdout.strip()
        if theirs != mine:
            by_prop[prop].append(f"seed {seed} built again with PYTHONHASHSEED={hash_seed} "
                                 f"gave {theirs[:16] or child.stderr.strip()[-120:]}, "
                                 f"this run {mine[:16]}")

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
    if sys.argv[1:] == ["--digest"]:
        print(digest(build(random.Random(int(os.environ["KEYMAKER_PROPERTY_SEED"]))).items))
        sys.exit(0)
    sys.exit(main())
