# Test vectors

Expected bytes for the text and binary forms of the KEYM v2, v3 and v4 formats,
in plain JSON, for anyone writing a third reader. Nothing here needs Node,
Python or this repository's code to read. Every value is lowercase hex, a JSON
string, or a number, and every non-ASCII character in a string is written as a
`\u` escape, so a tool that normalises Unicode cannot silently change a vector.

Two implementations in this repository are held to these files on every pull
request. `reference/vectors.py` regenerates the pack from `reference/keym2.py`,
and each file must equal what it renders, byte for byte.
`scripts/vectors-test.mts` reproduces every vector with the shipping
TypeScript. A vector either suite cannot reproduce fails that suite by its id.

The pack is evidence, not the definition. Passing it is necessary for a reader
to conform, not sufficient, and where the pack and the design documents
disagree the documents win and the vector is an erratum.

Test-only credentials. Never use any of these values for real data. A pinned
salt, master key, container id or set of Shamir coefficients defeats what the
format's freshness rules (v2 §4.5) exist to guarantee.

## Files

| File | Family | What a reader checks |
|---|---|---|
| `primitives.json` | Published known answers for the four primitives the format builds on | Its own HKDF-SHA-256, AES-256-GCM, ChaCha20-Poly1305 and Argon2id against third-party values, before anything Keymaker-specific |
| `containers.json` | Whole containers from pinned inputs, with intermediates | `kdf_input`, `slot_key`, `core_header`, `k_table` and `slot_table_mac` one at a time, then the container byte for byte, then that it opens |
| `shares.json` | One Shamir split from pinned coefficients | Each share value, the v1 and v2 set ids, the set code, and both share texts |
| `parts.json` | Paper parts of one container | `KMPART1` and `KMPART2` strings at a fixed capacity |
| `text.json` | Armor, the IGNORABLE set and `padded_len` | The armored text in both widths, the exact set of ignorable code points, and v4 §4.2 lengths |
| `reject.json` | Inputs a reader MUST refuse, each tagged with the rule it breaks | That decrypting or decoding each one fails |
| `accept.json` | Inputs a reader MUST open although it may be tempted to refuse them | That each one opens to its plaintext |

Every file has the same top level.

```
{
  "family": "containers",
  "format": 1,
  "vectors": [ { "id": "...", ... }, ... ]
}
```

Each vector has an `id` unique across the whole pack and a `note` saying what it
pins. The other fields are named in the family's section below.

## How the pack grows

**Append-only, like the fixtures under `scripts/fixtures/keymaker/`.** A vector
is a promise that a reader conforming today still conforms tomorrow, so once a
vector is committed its bytes never change, its note and rule included.
`reference/vectors.py` fails if regenerating would change or drop a committed
vector, and `--write` only appends vectors whose ids are new. Both suites assert
the total count (`VECTOR_COUNT` in each), so a vector that silently stopped
being listed would fail them.

**The reference writes, the TypeScript reproduces.** The pack is generated from
`keym2.py`, which was written from the design documents alone, and the
TypeScript is checked against it, never the reverse. That keeps the one
implementation that tests the prose upstream of the one people use.

**A wrong vector is superseded, never edited.** A vector found to encode a
misreading of the spec gains an `erratum` field, a string that starts with the
id of the vector replacing it and goes on to name the spec text it got wrong.
The replacement is an ordinary new vector. **A reader skips every vector that
has an `erratum` field**, as both suites here do, and `vectors.py` stops
regenerating it but checks that the id it names exists.

## The families

### `primitives.json`

Values transcribed from their publications, never computed by this repository.
Each vector names its `source`.

- **HKDF-SHA-256.** RFC 5869 Appendix A, test cases 1 to 3. Fields `ikm`,
  `salt`, `info`, `length`, `prk` (HKDF-Extract's output, RFC 5869 §2.2) and
  `okm`. Both suites check `prk` as well as `okm`.
- **ChaCha20-Poly1305.** RFC 7539 and RFC 8439 §2.8.2 and Appendix A.5. Fields
  `key`, `nonce`, `aad`, `plaintext`, `ciphertext`, `tag`.
- **AES-256-GCM.** NIST CAVP `gcmEncryptExtIV256.rsp`, with a 96-bit IV and a
  128-bit tag, the only shape the format uses. Same fields.
- **Argon2id, version 0x13.** Fields `password`, `salt`, `time_cost`,
  `memory_kib`, `parallelism`, `length`, `output`. RFC 9106 §5.3's own vector
  also sets the optional `secret` and `ad` (associated data), which the format
  never uses. `keym2.py`'s library checks it through its low-level interface.
  The TypeScript's library takes no associated data, so that vector carries
  `"typescript": false` and the TypeScript suite skips it. The other Argon2id
  vectors come from OpenSSL's Argon2 test data and the reference `argon2`
  command-line tool, which use neither.

The transcriptions were taken from the `cryptography_vectors` package
(pyca/cryptography, version 50.0.2), which carries these publications' values
as data files. PBKDF2-HMAC-SHA-256 has no vector of its own here. It is covered
end to end by every PBKDF2 container in `containers.json`.

### `containers.json`

Fields `version`, `cipher`, `kdf` (`{"id": "pbkdf2", "iterations": n}` or
`{"id": "argon2id", "time_cost", "memory_kib", "parallelism"}`), `password` (a
JSON string, exactly as typed, which v2 §4.1 normalises to NFC before use),
`keyfile` (hex or null), `plaintext` (hex), `salt`, `master_key`,
`container_id` (hex, empty for v2), then the intermediates and the
`container`.

| Intermediate | Spec | What a mismatch means |
|---|---|---|
| `kdf_input` | v2 §4.1, §4.2 | The password's normalisation or the key-file digest |
| `slot_key` | v2 §4.3 | The KDF or its parameters |
| `core_header` | v2 §3, v3 §3 | The header layout |
| `k_table` | v3 §5.1 | The slot-table key's derivation (v3 and v4 only) |
| `slot_table_mac` | v3 §5.1 | The MAC's message (v3 and v4 only) |
| `container` | all | If every intermediate matches, the slot wrap or the payload |

`v3-s8-argon2id-aes` is v3 §8's vector and `v4-s8-argon2id-aes` is v4 §8's.
`reference/vectors.py` reads both design documents and fails if the hex printed
there differs from the pack, so the documents cannot drift from the bytes the
code is held to. `v3-nfc-password`'s password is typed decomposed (`e` then
U+0301), so its `kdf_input` holds the precomposed é only if the reader
normalises.

### `shares.json`

Fields `secret`, `k`, `n`, `coefficients`, `slot_salt`, `set_id_v1`,
`set_id_v2`, `set_code`, and `shares`, a list of
`{"index", "value", "kmshare1", "kmshare2"}`.

`coefficients` is the random part of v2 §4.6's polynomials, which a writer
draws fresh and the spec never serialises, so its byte order is the pack's own.
It is `k − 1` blocks of 32 bytes, coefficient by coefficient. Block `c − 1`
holds `a_{c,j}` for every byte position `j` from 0 to 31, so byte
`(c − 1) × 32 + j` is the coefficient of `x^c` in the polynomial for secret
byte `j`.

### `parts.json`

Fields `container` (hex), `capacity`, `kmpart1` and `kmpart2` (lists of
strings, in order).

### `text.json`

- `ignorable`, the §7 IGNORABLE set as a sorted list of code points. A reader's
  own table must equal it exactly.
- `armor`, a `container` (hex), `wrapped` and `compact`. `wrapped` is the
  layout v2 §7 describes, the base64url body broken every 64 characters with LF
  and the `keym2:` prefix in front of the first line, so that line is 70
  characters and there is no final newline. `compact` is one line.
- `padded_len`, a list of `[n, padded_len(n)]` pairs across v4 §4.2's branches.

### `reject.json`

Fields `rule` (the sections a reader enforces in refusing it), `kind`
(`container`, `armor`, `share`, `combine` or `parts`), `input` (hex for a
container, a string otherwise), and, for a container, `password` and
`authentic`. Each container row is a single change to `reject-base`, a
container in `containers.json` that opens with the same password, so a reader
that refuses every row by failing on everything is caught by the base opening.

**Authentic rows are the ones that test a rule.** They are sealed correctly
around one violation (every AAD, wrap, tag and the slot-table MAC computed over
the bytes as written), so nothing but the named rule refuses them, and a reader
that skips the rule opens the row. That includes nine well-formed slots, a
passphrase slot under HKDF, Argon2id and PBKDF2 parameters past their read
bounds, a lone chunk sealed with `final_flag` 0, and v4 streams that break
§4.4's length and padding checks.

A bad slot disqualifies that slot alone (v2 §4.4). Each slot-level row has one
slot, so the table is exhausted and the container refused (v2 §6), and
`accept.json` holds the same bad slot beside a good one, which must open. A
reader that refuses the whole container on a bad slot passes `reject.json` and
fails `accept.json`.

The other container rows are **structural**. An unknown cipher or a cut-off
file cannot be sealed, so those rows check that a reader refuses rather than
crashes. The wrong-password row is the base itself, with a different password.

A reader passes a container, armor, share or combine row by refusing it with
the one generic decryption failure v2 §6 requires, and the pack does not say
which check should fire, because §6 says a reader must not reveal that either.
Both suites here hold their reader to its exact generic message, so a refusal
that says more fails. A `parts` row is refused too, but v2 §7.3 has a reader
say what is wrong with the parts, since they carry no secret.

Share rows come in both versions, `KMSHARE1` and `KMSHARE2`. Two combine rows
mix sets, one with a set id that differs only in its last byte and one with
both versions in it.

### `accept.json`

Fields `rule`, `kind` (as in `reject.json`), `input` and `expect`. A reader
passes a row by reading `input` as `expect`. That is the plaintext for a
container, the container for armor and parts, the secret for a combine, and the
record (`set_id`, `k`, `index`, `value`) for a share. A container row also has
`password` and `slot_table`, which is `changed` where the reader must report
that the slot table does not authenticate and `authentic` otherwise.

- Every slot-level violation in `reject.json`, as slot 0 beside a good slot 1.
- An Argon2id slot whose `memory_kib` is below 8 × `parallelism`. v2 §6 admits
  it, no Argon2id library can derive it, and a reader must skip it rather than
  fail.
- A slot that does not open with the password, then one that does, and a full
  table of eight slots.
- A slot table that lost a slot after its MAC was computed. v3 §5.2 says open
  it and report the change, never refuse.
- Armor with every IGNORABLE character inside it.
- A share in a non-canonical spelling (lower case, spaces, look-alikes).
- Share sets out of order, with a repeat, with skipped lines between them, and
  with a consistent share above the k lowest listed first, which must not be
  used.
- Paper parts in reverse order, with comment lines, CRLF, and U+2028 inside
  each part.

## Not in the pack yet

- A container of more than one chunk (1 MiB of plaintext). Its hex would make a
  file several megabytes long. The conformance suite covers chunk boundaries.
- Shamir, passkey and passphrase-and-shares slots as whole containers, and the
  self-extracting page of v2 §7.2.

## Conforms with

| Implementation | Families | Checked by |
|---|---|---|
| `reference/keym2.py` | all | `reference/vectors.py` |
| Keymaker web app (`src/lib`) | all | `scripts/vectors-test.mts` |

A third implementation that passes the pack can be listed here.
