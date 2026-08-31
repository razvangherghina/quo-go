# Quo — the Go kit

The Go implementation of **Quo**, a small, open protocol that answers exactly
one question — _by whose authority?_ — and refuses every other.

```
go get quo.systems/kit
```

The import path is `quo.systems/kit` and it always will be. It names the
protocol rather than a host, an account or a company, because no vendor owns
Quo and the line every builder pastes into their file should say so.

Read the protocol, with worked examples, a conformance proof and a demo that
runs in your own tab, at **[quo.systems](https://quo.systems)**.

## What is here

This repository is the Go kit and nothing else, at the root, so the module path
and the repository root are the same thing.

- `notation` — the arithmetic's names, digests and parsing.
- `arithmetic` — the keys, the signatures and the derivations.
- `envelope` — the sealed letter, and the two faces of it.
- `wire` — the bytes on the socket.
- `carriage` — carrying a letter from one house to another.
- `warden` — the door: who is admitted, on whose standing, and for what.
- `cmd/subject` — a small executable that speaks the protocol for you.

Every package ships its bench beside it. A reader who cannot run the proof has
only been told about it:

```
go test ./...
```

## The constitution, and the other kit

The protocol's text and the JavaScript kit stand together at
[github.com/razvangherghina/quo](https://github.com/razvangherghina/quo). The
two kits were written from the same text by builders who had not seen each
other's source, and they exchange real sealed messages over a real socket and
derive identical digests. That is the proof the text is implementable from
itself.

This repository is emitted from that work rather than authored here. Issues and
discussion belong at the repository above.

## Status: pre-1.0 working draft

The law is written and complete enough to implement from, and it is still
moving. Nothing is sealed before 1.0.0: package names, signatures and wire
details may change, and a change will not always be gentle. Build on it, and
pin what you build on.

## Licence

Apache-2.0, held by a person rather than a company. See `LICENSE` and `NOTICE`.
The licence covers this source and the text of the constitution; it does not
reach the protocol they describe, which anyone may implement, in any language,
without permission and without any that can be revoked.
