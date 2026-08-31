# The pinned corpus

Bytes a Quo kit must reproduce. Every vector states its input, the exact
output, and the section of the constitution that governs it. Nothing here is
randomised, timed or environment-dependent, so a second kit either produces
these bytes or disagrees with the law.

## How to read a file

Each file is one JSON object: `area`, `encoding` — always `hex` — and
`vectors`, a list. `material.json` carries no vectors; it holds the fixed
keys every other file refers to.

Every vector carries a `name` and a `law`, which is the heading of the
constitution's section that rules it.

- **`refuses: true`** — the input is invalid and the operation must refuse
  it. A refusal is asserted as strictly as an acceptance.
- **`unpinned: true`** — the constitution does not compel these exact bytes.
  The vector is here so two kits meet somewhere, but a disagreement is a
  question for the constitution rather than a defect in either kit.

## How a value is written

A vector under test names a `blueprint`: a class with exactly one field. The
type under test is that field's answer type, so reading a vector needs the
notation parser and no second grammar.

The `value` is the same value the `bytes` encode, written in JSON by one
rule per type.

| Type | JSON |
| --- | --- |
| `bool` | a boolean |
| `int` | a decimal string, so no precision is lost |
| `text` | a string |
| `bytes`, `b32`, `being` | lowercase hex |
| `invitation` | an object: `warden`, `commitment`, `padlock`, `heir`, `heirSecret`, `hints` |
| `card` | an object: `warden`, `commitment`, `padlock`, `hints` |
| `[T]` | an array |
| `T?` | `null` when absent, the value when present |
| a record | an object keyed by the names the blueprint declares |

## The areas

- **`notation.json`** — a blueprint's canonical text and its digest, and the
  texts that are refused.
- **`wire.json`** — the encoding of every closed type, both combinators,
  records, and the bytes a decoder must refuse.
- **`arithmetic.json`** — the four algorithms: the hash, the heir
  commitment, the two kinds of pair, signing, agreement, the derivation and
  the seal.
- **`envelope.json`** — the signed payload, the answer, and the whole sealed
  message.
- **`warden.json`** — the blueprint every warden holds, and the derived
  order of an estate.
