package warden

import (
	"errors"
	"fmt"
	"maps"
	"slices"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

// Being is an object a warden holds. A language without reflection cannot look
// a field up by name, so a Go kit takes the dispatch the object's own author
// generates: the call goes in, the answer's bytes come out. Surplus in the
// blob is the being's refusal, never the warden's.
//
// A being that merely answers implements this and reads only the method and
// the args. It never learns it has an address, never judges, and never sees a
// key.
type Being interface {
	Invoke(call Call) ([]byte, error)
}

// Call is what a being is handed on invocation: the field named on it, its
// arguments as one opaque blob, and the leash this call may spend onward.
//
// The warden is deliberately not here. A being that acts takes a warden the
// ordinary way any dependency is taken, by its author, on purpose — nothing is
// ever injected into an object behind its back. What an author cannot hold in
// advance is the allowance, because it belongs to the message rather than to
// the being, so that is the one thing the call carries.
type Call struct {
	Method string
	Args   []byte
	Leash  Leash
}

// Leash is what one arriving call may hand to the next door. It is not a
// number the door worked out in advance: the hop count falls by one, and the
// time budget falls by this door's own dwell — the difference between when the
// message arrived and when it is handed onward. The second of those two
// readings cannot be taken until the handing onward happens, so a Leash holds
// the first reading and the clock, and works the rest out at the moment it is
// spent.
//
// Its zero value carries nothing and refuses to be spent, which is what a
// being invoked outside a judgment holds.
type Leash struct {
	received envelope.Allowance
	arrived  int64
	clock    func() int64
}

// Received is the allowance that arrived at this door, for a being that wants
// to look at it. Nothing may be sent onward under it.
func (l Leash) Received() envelope.Allowance { return l.received }

// Onward is what this call may hand to the next door, read now. A budget that
// has run out mid-work is refused here, exactly as it would have been refused
// at the door: the caller's allowance is the caller's, and no door beneath may
// widen it.
//
// A dwell is never negative. Two readings of one clock is what the law asks
// for, and a clock that has gone backwards between them is a broken clock, not
// a licence to hand on more time than arrived.
func (l Leash) Onward() (envelope.Allowance, error) {
	if l.clock == nil {
		return envelope.Allowance{}, errors.New("warden: this call carries no leash")
	}
	dwell := l.clock() - l.arrived
	if dwell < 0 {
		dwell = 0
	}
	a := envelope.Allowance{Time: l.received.Time - dwell, Hops: l.received.Hops - 1}
	if a.Time < 1 || a.Hops < 0 {
		return envelope.Allowance{}, errors.New("warden: the leash is spent")
	}
	return a, nil
}

// Keys are the thirty-two byte draws a being or a voice is minted from: its
// own signing seed, and its heir's. Nothing in this package reaches for a
// random source.
type Keys struct {
	Secret     [32]byte
	HeirSecret [32]byte
}

// Founding is what a host hands a warden at birth. The warden's own heir is
// the owner's, held outside the runner's reach, so only its commitment is
// given here.
//
// Nothing here mints the public being. The warden is a being, so the key that
// names the house and the key that names the being the house speaks as are one
// key, and NameSecret is both.
type Founding struct {
	NameSecret     [32]byte
	HeirCommitment [32]byte
	PadlockSecret  [32]byte
	Limit          int64
	Window         int64 // zero takes DefaultWindow

	// Clock reads the host's own clock in milliseconds, which is what the
	// allowance's time budget is counted in. It is required, because a door
	// that cannot measure its dwell cannot shrink the leash, and a door that
	// does not shrink the leash cannot stand in the middle of a chain.
	//
	// It is taken as an argument for the same reason every draw of randomness
	// is: an implementation that reaches for the wall clock cannot be pinned
	// to a test. It lives here rather than beside the draws because it is not
	// spent — a clock is a facility the host lends the warden for its life,
	// like its keys and its window, and a warden handed a different clock per
	// message could not honestly compare two readings of one.
	//
	// Only differences are ever taken, so where its zero is does not matter.
	Clock func() int64
}

// Draws are the randomness one judgment may need: the sealing key for the
// answer, fresh on every message, and the key a receive mints and the origin
// never saw.
type Draws struct {
	Ephemeral [32]byte
	Heir      [32]byte
}

type held struct {
	pk         [32]byte
	secret     [32]byte
	digest     [32]byte
	commitment [32]byte
	object     Being
	moved      *Word // the succession this door published, returned in place of work
}

// Warden is a door, the beings it keeps, and the two records it judges by.
type Warden struct {
	name           [32]byte
	nameSecret     [32]byte
	heirCommitment [32]byte
	padlock        [32]byte
	padlockSecrets [][32]byte // the current one first; keeping the old ones is the host's choice
	limit          int64

	clock func() int64

	beings     map[[32]byte]*held
	blueprints map[[32]byte]string
	record     *record
}

// self is the pk of the public being, which is the warden's own name. It is
// written this way rather than kept in a field because the two can never
// differ: a separate key would mean a card alone let you reach a door and ask
// it nothing.
func (w *Warden) self() [32]byte { return w.name }

// New stands a warden up. Nothing crosses a wire at birth, so there is nothing
// here for two strangers to agree on.
func New(f Founding) (*Warden, error) {
	if f.Clock == nil {
		return nil, errors.New("warden: a door with no clock cannot shrink a leash")
	}
	padlock, err := arithmetic.SealingKey(f.PadlockSecret)
	if err != nil {
		return nil, err
	}
	window := f.Window
	if window == 0 {
		window = DefaultWindow
	}
	w := &Warden{
		name:           arithmetic.SigningKey(f.NameSecret),
		nameSecret:     f.NameSecret,
		heirCommitment: f.HeirCommitment,
		padlock:        padlock,
		padlockSecrets: [][32]byte{f.PadlockSecret},
		limit:          f.Limit,
		clock:          f.Clock,
		beings:         map[[32]byte]*held{},
		blueprints:     map[[32]byte]string{},
		record:         newRecord(window),
	}
	// The public being is the one being every warden already has, of the class
	// Quo itself writes, and its pk is the warden's own name. Its heir is the
	// owner's, held outside the runner's reach, so the commitment is the one
	// the founding gave rather than one hashed from a secret held here.
	bp, err := notation.Parse(Blueprint)
	if err != nil {
		return nil, err
	}
	w.blueprints[Digest] = bp.Text()
	w.beings[w.name] = &held{
		pk:         w.name,
		secret:     f.NameSecret,
		digest:     Digest,
		commitment: f.HeirCommitment,
	}
	return w, nil
}

// Name is the warden's signing key: its identity, which never moves without
// succession.
func (w *Warden) Name() [32]byte { return w.name }

// Padlock is the lock every message to this ground is sealed with.
func (w *Warden) Padlock() [32]byte { return w.padlock }

// Self is the pk of the warden's own public being, which is the warden's own
// name. Whoever holds a card can address that door with nothing else, since a
// card carries the name.
func (w *Warden) Self() [32]byte { return w.self() }

// Limit is what this door will take, so a caller need not learn by silence. It
// is the only fact the law makes a warden publish about itself: the largest
// message it will accept, counted in bytes of the whole envelope as the
// carriage delivers it — the ephemeral key and the ciphertext together, which
// is the one size a caller can compute before sending.
func (w *Warden) Limit() int64 { return w.limit }

// Card is what a warden publishes so a stranger can begin: its name, its heir
// commitment, a padlock, and hints. It carries no standing whatsoever.
func (w *Warden) Card(hints []string) wire.Card {
	return wire.Card{
		Warden:     w.name,
		Commitment: w.heirCommitment,
		Padlock:    w.padlock,
		Hints:      slices.Clone(hints),
	}
}

// Hold takes an ordinary object and makes it a being: the warden mints its
// keys and records the pointer and the blueprint's digest. Nobody is told,
// because no one stands at it yet.
func (w *Warden) Hold(blueprint string, object Being, keys Keys) ([32]byte, error) {
	bp, err := notation.Parse(blueprint)
	if err != nil {
		return [32]byte{}, err
	}
	pk := arithmetic.SigningKey(keys.Secret)
	if _, taken := w.beings[pk]; taken {
		return pk, errors.New("warden: that key already names a being")
	}
	digest := bp.Digest()
	w.blueprints[digest] = bp.Text()
	w.beings[pk] = &held{
		pk:         pk,
		secret:     keys.Secret,
		digest:     digest,
		commitment: arithmetic.Commit(w.name, arithmetic.SigningKey(keys.HeirSecret)),
		object:     object,
	}
	return pk, nil
}

// Release drops the pointer, and the being's standings go with it — both
// records, because a relation follows the being that holds it. Nobody is told:
// absence is silence, and silence is already the answer for refused and broken
// alike.
//
// The outbound rows go with their keys. Once a being has migrated, its heir
// travelled in the cargo, and the origin keeping a copy would leave the old
// warden holding the one key that can take the standing over — in the same
// breath as every key it held is said to be dead.
func (w *Warden) Release(being [32]byte) {
	delete(w.beings, being)
	for voice, row := range w.record.in {
		delete(row.beings, being)
		if len(row.beings) == 0 {
			delete(w.record.in, voice)
		}
	}
	for far, rel := range w.record.out {
		if rel.holder == being {
			delete(w.record.out, far)
		}
	}
}

// Grant mints a voice, writes the inbound row, and hands back the invitation.
// Nobody is told — the invitation leaves as data.
//
// What leaves is the heir keypair, never the voice's own: whoever minted a
// voice has seen its keys, so the holder's first act is a rotate-and-ask to a
// key nobody else has ever seen.
func (w *Warden) Grant(being [32]byte, voice Keys, padlock [32]byte, hints []string) (wire.Invitation, error) {
	if _, ok := w.beings[being]; !ok {
		return wire.Invitation{}, errors.New("warden: no being of that name")
	}
	pk := arithmetic.SigningKey(voice.Secret)
	if _, taken := w.record.in[pk]; taken {
		return wire.Invitation{}, errors.New("warden: that voice already stands here")
	}
	heir := arithmetic.SigningKey(voice.HeirSecret)
	w.record.in[pk] = &inbound{
		voice:      pk,
		commitment: arithmetic.Commit(w.name, heir),
		beings:     map[[32]byte]bool{being: true},
		spent:      map[int64]bool{},
	}
	return wire.Invitation{
		Warden:     w.name,
		Commitment: w.heirCommitment,
		Padlock:    padlock,
		Heir:       heir,
		HeirSecret: voice.HeirSecret,
		Hints:      slices.Clone(hints),
	}, nil
}

// Widen adds a being to a voice's row. A standing is amended, not replaced:
// nobody is told, no secret is minted, and the holder simply finds more the
// next time it describes.
func (w *Warden) Widen(voice, being [32]byte) error {
	row, ok := w.record.in[voice]
	if !ok {
		return errors.New("warden: that voice stands nowhere here")
	}
	if _, held := w.beings[being]; !held {
		return errors.New("warden: no being of that name")
	}
	row.beings[being] = true
	return nil
}

// Narrow takes a being away. Taking the last one away is release, and there is
// no separate act for it.
func (w *Warden) Narrow(voice, being [32]byte) error {
	row, ok := w.record.in[voice]
	if !ok {
		return errors.New("warden: that voice stands nowhere here")
	}
	delete(row.beings, being)
	if len(row.beings) == 0 {
		delete(w.record.in, voice)
	}
	return nil
}

// Stand writes an outbound row: a relation this ground holds at another house,
// kept whole as the invitation gave it, and held by the being that may spend
// it — the record says which of its beings may spend which relation, and a row
// that named none could not travel when that being moves.
func (w *Warden) Stand(holder [32]byte, inv wire.Invitation, voiceSecret [32]byte) {
	w.record.out[inv.Warden] = &outbound{
		holder:      holder,
		warden:      inv.Warden,
		commitment:  inv.Commitment,
		padlock:     inv.Padlock,
		voice:       arithmetic.SigningKey(voiceSecret),
		voiceSecret: voiceSecret,
		hints:       slices.Clone(inv.Hints),
		spent:       map[int64]bool{},
		beings:      map[[32]byte][32]byte{},
	}
}

// Learn records the heir commitment of a being this ground stands at, as a
// describe handed it over. Without it a peer holds no material to believe that
// being's succession.
func (w *Warden) Learn(far, being, commitment [32]byte) error {
	rel, ok := w.record.out[far]
	if !ok {
		return errors.New("warden: no relation with that house")
	}
	rel.beings[being] = commitment
	return nil
}

// Relation reads back an outbound row: the far warden's name, its heir
// commitment, the padlock and the hints.
func (w *Warden) Relation(far [32]byte) (name, commitment, padlock [32]byte, hints []string, ok bool) {
	rel, ok := w.record.out[far]
	if !ok {
		return
	}
	return rel.warden, rel.commitment, rel.padlock, slices.Clone(rel.hints), true
}

// Publish records the succession this door published for a being, so the old
// door can point every arriving ask at where the being went.
func (w *Warden) Publish(being [32]byte, word Word) error {
	h, ok := w.beings[being]
	if !ok {
		return errors.New("warden: no being of that name")
	}
	h.moved = &word
	return nil
}

// Pack is a migration's cargo, read off what this warden holds for one being:
// its class, its cells, and both records of standings — the inbound one so its
// peers keep their standing at it, and the outbound one so it keeps its
// standing at theirs.
//
// The cells come from the host, because a being's memory is its own and the
// Being interface never hands it over.
//
// The rows are ordered by pk ascending. The law derives an order only for the
// estate, so this one is chosen rather than read — two kits packing one being
// agree on the bytes only because both sort.
func (w *Warden) Pack(being [32]byte, cells []byte) (Cargo, error) {
	h, ok := w.beings[being]
	if !ok {
		return Cargo{}, errors.New("warden: no being of that name")
	}
	c := Cargo{Being: h.pk, Digest: h.digest, Cells: cells}
	for _, row := range w.record.in {
		if !row.beings[being] {
			continue
		}
		// Only the being that moves travels in the row: what the voice reaches
		// here besides it is this door's affair and stays.
		c.Standings = append(c.Standings, Standing{
			Voice:      row.voice,
			Commitment: row.commitment,
			Beings:     [][32]byte{being},
			Mark:       row.mark,
			// The replay record travels whole. A mark alone would make the new
			// door either refuse everything at or below it — killing a caller
			// with asks in flight — or honour it all, reopening what was spent.
			Spent:   window(row.spent, row.mark),
			Padlock: row.padlock,
			Hints:   slices.Clone(row.hints),
		})
	}
	for _, rel := range w.record.out {
		if rel.holder != being {
			continue
		}
		// Both of the voice's keys travel. A row that has never rotated has no
		// committed heir yet — its current voice is the key the invitation
		// committed — so the heir fields carry nothing, which is the same
		// state the row was in here.
		var heir [32]byte
		if rel.heirSecret != ([32]byte{}) {
			heir = arithmetic.SigningKey(rel.heirSecret)
		}
		c.Relations = append(c.Relations, Relation{
			Warden:     rel.warden,
			Commitment: rel.commitment,
			Padlock:    rel.padlock,
			Voice:      rel.voice,
			Secret:     rel.voiceSecret,
			Heir:       heir,
			HeirSecret: rel.heirSecret,
			Seq:        rel.next,
			Hints:      slices.Clone(rel.hints),
		})
	}
	slices.SortFunc(c.Standings, func(a, b Standing) int { return compareKeys(a.Voice, b.Voice) })
	slices.SortFunc(c.Relations, func(a, b Relation) int { return compareKeys(a.Warden, b.Warden) })
	return c, nil
}

// Reach is one call this ground makes at a house it holds a relation with. A
// being never touches a key: it hands the warden a handle, and the warden
// signs, seals and carries.
type Reach struct {
	// Far is the house, by the name the outbound record is keyed on.
	Far [32]byte
	// Being is the pk addressed, or absent to speak to the ground's own
	// affairs. Method is the field named on it, or absent for a describe.
	Being  *[32]byte
	Method *envelope.Method
	// Allowance is the caller's own leash, set by a being that is starting a
	// walk rather than continuing one.
	Allowance envelope.Allowance
	// Leash is the call this ask is made in the course of, when it is one. A
	// being standing in the middle of a chain hands its own leash straight
	// back, and the allowance is read off it here, at the moment of sealing —
	// which is the moment the message is handed onward, and the second of the
	// two readings the dwell is the difference of. Present, it overrides
	// Allowance, so a being under a leash cannot widen one even by mistake.
	Leash *Leash
	// Padlock is what the far door seals its answer to. A voice has no lock of
	// its own, so this is one its warden holds: the same one it gives
	// everybody, or one it keeps for this relation alone. That choice is the
	// caller's, and it is the whole of what a caller can do about being linked
	// across doors — so the zero value takes this warden's own padlock, which
	// is the linkable option and is named as such.
	Padlock [32]byte
	// Hints are how to speak to this caller later.
	Hints []string
	// NextHeir is the secret of a key nobody has ever seen. Present, this
	// message spends the heir it currently holds and commits to that key, so
	// it is a rotate-and-ask; the kind is read off the voice at the far door
	// and is never declared here either.
	NextHeir *[32]byte
}

// Ask composes one utterance and hands back the sealed bytes and the number it
// spent. Nothing here delivers: what to do with the bytes is the carriage's,
// and whether they arrive is the weather.
func (w *Warden) Ask(ephemeral [32]byte, r Reach) ([]byte, int64, error) {
	rel, ok := w.record.out[r.Far]
	if !ok {
		return nil, 0, errors.New("warden: no relation with that house")
	}
	allowance := r.Allowance
	if r.Leash != nil {
		onward, err := r.Leash.Onward()
		if err != nil {
			return nil, 0, err
		}
		allowance = onward
	}
	if allowance.Time < 1 || allowance.Hops < 0 {
		return nil, 0, errors.New("warden: a call with no leash left")
	}
	padlock := r.Padlock
	if padlock == ([32]byte{}) {
		padlock = w.padlock
	}

	var commitment *[32]byte
	if r.NextHeir != nil {
		// A rotate-and-ask spends the heir this ground holds. On the first one
		// that is the key the invitation carried; on a later one it is the key
		// committed to last time, which the row kept.
		if rel.heirSecret != ([32]byte{}) {
			rel.voiceSecret = rel.heirSecret
			rel.voice = arithmetic.SigningKey(rel.heirSecret)
		}
		// A rotation starts the mark fresh at the door, because the old key
		// died with its count — so this ground's own count starts over too,
		// and the rotate-and-ask itself is number one.
		rel.next = 0
		// Every rotation carries a fresh commitment, or a standing could be
		// taken over exactly once and never again. It is hashed under the door
		// the heir would spend at.
		c := arithmetic.Commit(rel.warden, arithmetic.SigningKey(*r.NextHeir))
		commitment = &c
	}

	rel.next++
	say := envelope.Say{
		Voice:      rel.voice,
		Recipient:  rel.warden,
		Commitment: commitment,
		Seq:        rel.next,
		Padlock:    padlock,
		Hints:      slices.Clone(r.Hints),
		Allowance:  allowance,
		Being:      r.Being,
		Method:     r.Method,
	}
	message, err := envelope.SealSay(ephemeral, rel.padlock, rel.voiceSecret, say)
	if err != nil {
		return nil, 0, err
	}
	if r.NextHeir != nil {
		// The key that just signed is the current holder from here on; the one
		// committed to is the heir after it, and the row keeps its secret
		// because nothing else in Quo does.
		rel.heirSecret = *r.NextHeir
	}
	return message, say.Seq, nil
}

// Hear opens an answer a far door sent back, under the padlock secret the call
// asked it to seal to.
func (w *Warden) Hear(padlockSecret [32]byte, message []byte) (envelope.Answer, error) {
	return envelope.OpenAnswer(padlockSecret, message)
}

// PadlockSecret is the secret behind this warden's current padlock, which is
// what a caller using the default return padlock opens an answer with.
func (w *Warden) PadlockSecret() [32]byte { return w.padlockSecrets[0] }

// kind is what a message turns out to be, read off the voice and never
// declared. A caller cannot claim to be rotating.
type kind int

const (
	kindAsk kind = iota + 1
	kindRotation
	kindNews
	kindStranger
)

// Judge runs the eight steps over what arrived and hands back what to send.
//
// A nil answer is silence, and silence is the whole of every refusal. The
// error beside it is for the host: it names the step, and it never travels.
func (w *Warden) Judge(draws Draws, message []byte) ([]byte, error) {
	// The first of the two readings the dwell is the difference of. It is taken
	// before anything else, because what it marks is when the message arrived
	// and not when the door got round to it.
	arrived := w.clock()

	say, err := w.open(message)
	if err != nil {
		return nil, err
	}

	// Step three: the name or padlock the payload carries must be this door's.
	// Here and not later, because a payload addressed elsewhere must never
	// touch this house's records — a stranger who relays one could otherwise
	// spend a peer's numbers at a door that peer never spoke to.
	if say.Recipient != w.name && say.Recipient != w.padlock {
		return nil, errors.New("warden: this message names another door")
	}

	k, row, rel, err := w.place(say)
	if err != nil {
		return nil, err
	}

	if err := w.count(k, say, row, rel); err != nil {
		return nil, err
	}

	// Step six: the leash, judged on what arrived. A hop count of zero is a
	// legal leash for a call that goes no further — what it forbids is onward —
	// so only a count below zero, or a budget at or below zero, is silence. The
	// number is already consumed and nothing here gives it back: a message that
	// spends its number and is then refused for its leash, or at routing, has
	// still spent it.
	if say.Allowance.Hops < 0 || say.Allowance.Time < 1 {
		return nil, errors.New("warden: the leash is spent")
	}
	// What this call reaches onward carries less than it received. The hop
	// count is already spent by arriving here; the dwell is only known when the
	// handing onward happens, so the leash carries the arrival reading and the
	// clock rather than a number worked out now.
	leash := Leash{received: say.Allowance, arrived: arrived, clock: w.clock}

	if row != nil {
		// The way back is refreshed by every call that arrives, so a peer that
		// speaks is always reachable.
		padlock := say.Padlock
		row.padlock = &padlock
		row.hints = slices.Clone(say.Hints)
	}

	data, err := w.route(draws, leash, k, say, row, rel)
	if err != nil {
		return nil, err
	}

	return envelope.SealAnswer(draws.Ephemeral, say.Padlock, w.nameSecret, envelope.Answer{
		Warden: w.name,
		Seq:    say.Seq,
		Data:   data,
	})
}

// open is steps one and two: unseal with the warden's own secret, then verify
// the signature over the payload using the voice the payload carries. The
// payload has to be decoded to find that voice, so the reading is unseal,
// decode, verify.
func (w *Warden) open(message []byte) (envelope.Say, error) {
	var err error
	for _, secret := range w.padlockSecrets {
		var say envelope.Say
		if say, err = envelope.OpenSay(secret, message); err == nil {
			return say, nil
		}
	}
	if err == nil {
		err = errors.New("warden: no secret to open with")
	}
	return envelope.Say{}, err
}

// place is step four: the voice in the two records, in that order.
func (w *Warden) place(say envelope.Say) (kind, *inbound, *outbound, error) {
	if row, ok := w.record.in[say.Voice]; ok {
		if say.Commitment != nil {
			// The commitment rides only when the message spends an heir.
			return 0, nil, nil, errors.New("warden: an ask carrying a commitment")
		}
		return kindAsk, row, nil, nil
	}

	if row := w.record.heir(w.name, say.Voice); row != nil {
		if say.Commitment == nil {
			return 0, nil, nil, errors.New("warden: a rotation carrying no fresh commitment")
		}
		w.record.rotate(row, say.Voice, *say.Commitment)
		return kindRotation, row, nil, nil
	}

	if rel, fresh := w.hear(say.Voice); rel != nil {
		if say.Commitment != nil {
			// News carries its next commitment inside the word, not here.
			return 0, nil, nil, errors.New("warden: news carrying a commitment")
		}
		if fresh {
			// A succession starts the news mark fresh: the old key died with
			// its count. Only a padlock replacement, announced by a house that
			// persists, continues a mark.
			rel.mark = 0
			rel.spent = map[int64]bool{}
		}
		return kindNews, nil, rel, nil
	}

	if say.Commitment != nil {
		return 0, nil, nil, errors.New("warden: a stranger carrying a commitment")
	}
	return kindStranger, nil, nil, nil
}

// hear finds the voice in the outbound record: as a warden this door holds a
// relation with, or as an heir that house committed — its own, or one of its
// beings'. The second is a succession, and says so.
func (w *Warden) hear(voice [32]byte) (rel *outbound, succession bool) {
	for _, r := range w.record.out {
		if r.warden == voice {
			return r, false
		}
	}
	for _, r := range w.record.out {
		want := arithmetic.Commit(r.warden, voice)
		if want == r.commitment {
			return r, true
		}
		for _, c := range r.beings {
			if want == c {
				return r, true
			}
		}
	}
	return nil, false
}

// count is step five: the number spent against the window kept for that
// voice, by the window's own rules. A stranger spends nothing: it has no row, so no mark is
// kept for it and a door keeping one per stranger would be a door with
// unbounded memory.
func (w *Warden) count(k kind, say envelope.Say, row *inbound, rel *outbound) error {
	switch k {
	case kindAsk, kindRotation:
		return spend(&row.mark, row.spent, w.record.window, say.Seq)
	case kindNews:
		return spend(&rel.mark, rel.spent, w.record.window, say.Seq)
	}
	return nil
}

// route is step seven. What comes back is the answer's data, or nil when the
// field answers nothing.
func (w *Warden) route(draws Draws, leash Leash, k kind, say envelope.Say, row *inbound, rel *outbound) ([]byte, error) {
	if k == kindNews {
		// News reaches the warden's own being, named or not. A granting warden
		// sending news has never had a describe from its peer, so naming the
		// door alone is the only address it is sure of.
		if say.Being != nil && *say.Being != w.self() {
			return nil, errors.New("warden: news not addressed to the public being")
		}
		if say.Method == nil || say.Method.Name != FieldTell {
			return nil, errors.New("warden: news that is not a tell")
		}
		return w.tell(rel, say.Method.Args)
	}

	// A being named or not, a method named or not. Neither is the estate; a
	// being alone is that being's sketch; a method with no being reaches the
	// warden's own being, because addressing the door alone is how you speak to
	// the ground's own affairs.
	target := w.self()
	if say.Being != nil {
		target = *say.Being
	}
	if !w.reaches(row, target) {
		return nil, errors.New("warden: that voice does not reach that being")
	}
	h := w.beings[target]

	if say.Method == nil {
		if say.Being == nil {
			// Neither: the warden describes your view of the house.
			return w.answerOf(FieldDescribe, estateValue(w.estate(row)))
		}
		// Being, no method: the warden describes that one being.
		return w.answerOf(FieldSketch, map[string]any{
			"being": h.pk, "digest": h.digest, "commitment": h.commitment,
		})
	}

	if target == w.self() {
		return w.own(draws, k, row, *say.Method)
	}
	if h.moved != nil {
		// The old door only points: it never forwards and never acts on the
		// being's behalf again.
		return nil, errors.New("warden: that being has moved")
	}
	if h.object == nil {
		return nil, errors.New("warden: nothing answers for that being")
	}
	return h.object.Invoke(Call{Method: say.Method.Name, Args: say.Method.Args, Leash: leash})
}

// own answers the warden's own being. Every one of these fields is a field on
// the blueprint Quo writes, spent by an ordinary standing.
func (w *Warden) own(draws Draws, k kind, row *inbound, m envelope.Method) ([]byte, error) {
	switch m.Name {
	case FieldDescribe:
		if err := noArgs(m); err != nil {
			return nil, err
		}
		return w.answerOf(FieldDescribe, estateValue(w.estate(row)))

	case FieldLimit:
		if err := noArgs(m); err != nil {
			return nil, err
		}
		return w.answerOf(FieldLimit, w.limit)

	case FieldSketch:
		being, err := argKey(FieldSketch, m)
		if err != nil {
			return nil, err
		}
		if !w.reaches(row, being) {
			// Silence, not absence: a door that answered "absent" about a
			// being you do not reach would be a door confirming it exists.
			return nil, errors.New("warden: that voice does not reach that being")
		}
		h := w.beings[being]
		return w.answerOf(FieldSketch, map[string]any{
			"being": h.pk, "digest": h.digest, "commitment": h.commitment,
		})

	case FieldMoved:
		being, err := argKey(FieldMoved, m)
		if err != nil {
			return nil, err
		}
		if !w.reaches(row, being) {
			return nil, errors.New("warden: that voice does not reach that being")
		}
		if moved := w.beings[being].moved; moved != nil {
			return w.answerOf(FieldMoved, wordValue(*moved))
		}
		// An absent optional is a legal answer to a legal ask: nothing has
		// moved, so moved answers absence.
		return w.answerOf(FieldMoved, nil)

	case FieldBlueprint:
		digest, err := argKey(FieldBlueprint, m)
		if err != nil {
			return nil, err
		}
		if !w.declares(row, digest) {
			// A door that answered any digest put to it would be a door that
			// could be asked what it runs.
			return nil, errors.New("warden: that voice reaches no being of that class")
		}
		return w.answerOf(FieldBlueprint, w.blueprints[digest])

	case FieldReceive:
		if k == kindStranger {
			// A door any stranger could push a being into is a door with no
			// gate. The ordinary one serves.
			return nil, errors.New("warden: a stranger cannot push a being in")
		}
		return w.receive(draws, row, m)
	}
	return nil, fmt.Errorf("warden: the warden declares no field %q", m.Name)
}

// tell is news arriving. A peer believes it by a key it already holds, and
// there are only two: the heir it was promised, or the name it has held since
// the invitation.
func (w *Warden) tell(rel *outbound, args []byte) ([]byte, error) {
	v, err := wire.Decode(Own, argType(FieldTell), args)
	if err != nil {
		return nil, err
	}
	word, err := readWord(v)
	if err != nil {
		return nil, err
	}

	// The warden's own succession is said by Being absent. A word naming the far
	// warden's own pk there is refused: its name and its public being are one
	// key, so that word would be a second spelling of the name's own succession,
	// and a value with two spellings is two identities.
	if word.Being != nil && *word.Being == rel.warden {
		return nil, errors.New("warden: a word naming the far warden's own pk as a being")
	}

	switch {
	case word.Successor != nil:
		// A signing key is being succeeded: the successor signs and the peer
		// hashes. The commitment is under the name that committed it, which is
		// the house this relation is with.
		if word.Commitment == nil {
			return nil, errors.New("warden: a succession with no next commitment")
		}
		held, ok := rel.commitment, false
		if word.Being != nil {
			held, ok = rel.beings[*word.Being]
			if !ok {
				return nil, errors.New("warden: no commitment held for that being")
			}
		}
		if arithmetic.Commit(rel.warden, *word.Successor) != held {
			return nil, errors.New("warden: the successor hashes to nothing held here")
		}
		if word.Being != nil {
			delete(rel.beings, *word.Being)
			rel.beings[*word.Successor] = *word.Commitment
		} else {
			rel.commitment = *word.Commitment
		}

	case word.Padlock != nil:
		// A lock has no heir, so the news is signed by the name, which has not
		// moved and which the peer has held since the invitation.
		if word.Commitment != nil || word.Being != nil {
			return nil, errors.New("warden: a padlock replacement carrying more than a lock")
		}

	default:
		return nil, errors.New("warden: a word that says nothing")
	}

	// Believed news rewrites the outbound row entire, one for one off the
	// word's own fields, because the relation follows the being.
	if word.Name != nil {
		rel.warden = *word.Name
	}
	if word.Padlock != nil {
		rel.padlock = *word.Padlock
	}
	if len(word.Hints) > 0 {
		// An empty hints list means the road did not change, never an erasure.
		rel.hints = slices.Clone(word.Hints)
	}
	for far, r := range w.record.out {
		if r == rel && far != rel.warden {
			delete(w.record.out, far)
			w.record.out[rel.warden] = rel
		}
	}
	// tell answers nothing, and a field that answers nothing answers zero bytes.
	return nil, nil
}

// receive takes a being in: the destination generates the key the origin never
// saw, takes the cargo, and answers the commitment of that key under its own
// name — the one fact the origin must carry into the first news and cannot
// invent.
func (w *Warden) receive(draws Draws, row *inbound, m envelope.Method) ([]byte, error) {
	v, err := wire.Decode(Own, argType(FieldReceive), m.Args)
	if err != nil {
		return nil, err
	}
	cargo, err := readCargo(v)
	if err != nil {
		return nil, err
	}
	if _, taken := w.beings[cargo.Being]; taken {
		return nil, errors.New("warden: a being of that name already lives here")
	}
	if _, known := w.blueprints[cargo.Digest]; !known {
		return nil, errors.New("warden: no blueprint of that digest")
	}
	heir := arithmetic.SigningKey(draws.Heir)
	commitment := arithmetic.Commit(w.name, heir)
	w.beings[cargo.Being] = &held{
		pk:         cargo.Being,
		digest:     cargo.Digest,
		commitment: commitment,
	}
	// The inbound record and the replay window travel with the being, or every
	// peer's standing would have to be regranted and every spent number would
	// come round again.
	for _, s := range cargo.Standings {
		beings := map[[32]byte]bool{}
		for _, b := range s.Beings {
			beings[b] = true
		}
		spent := map[int64]bool{}
		for _, n := range s.Spent {
			spent[n] = true
		}
		w.record.in[s.Voice] = &inbound{
			voice:      s.Voice,
			commitment: s.Commitment,
			beings:     beings,
			mark:       s.Mark,
			spent:      spent,
			padlock:    s.Padlock,
			hints:      slices.Clone(s.Hints),
		}
	}
	// Its outbound record travels too. Nobody is owed news about this half —
	// the doors where the being holds a standing know only a voice and have
	// never heard of the being at all — but a being that cannot reach them has
	// still lost everything it could do.
	for _, r := range cargo.Relations {
		w.record.out[r.Warden] = &outbound{
			holder:      cargo.Being,
			warden:      r.Warden,
			commitment:  r.Commitment,
			padlock:     r.Padlock,
			voice:       r.Voice,
			voiceSecret: r.Secret,
			heirSecret:  r.HeirSecret,
			hints:       slices.Clone(r.Hints),
			next:        r.Seq,
			spent:       map[int64]bool{},
			beings:      map[[32]byte][32]byte{},
		}
	}
	_ = row
	return w.answerOf(FieldReceive, commitment)
}

// estate is every being that voice may reach. The public being is reachable by
// everyone, holders included, so it appears in every estate.
func (w *Warden) estate(row *inbound) Estate {
	reach := map[[32]byte]bool{w.self(): true}
	if row != nil {
		maps.Copy(reach, row.beings)
	}
	byDigest := map[[32]byte][]Held{}
	for pk := range reach {
		h, ok := w.beings[pk]
		if !ok {
			continue
		}
		byDigest[h.digest] = append(byDigest[h.digest], Held{Being: h.pk, Commitment: h.commitment})
	}
	e := Estate{Classes: make([]Class, 0, len(byDigest))}
	for digest, beings := range byDigest {
		e.Classes = append(e.Classes, Class{Digest: digest, Beings: beings})
	}
	return e.Order()
}

// reaches is the one binary record every describe and every call is scoped by,
// without exception.
func (w *Warden) reaches(row *inbound, being [32]byte) bool {
	if _, held := w.beings[being]; !held {
		return false
	}
	if being == w.self() {
		return true
	}
	return row != nil && row.beings[being]
}

// declares says whether that voice may be told a blueprint's text: it already
// reaches a being of that class, or the warden's own public being declares it.
func (w *Warden) declares(row *inbound, digest [32]byte) bool {
	if _, known := w.blueprints[digest]; !known {
		return false
	}
	for _, c := range w.estate(row).Classes {
		if c.Digest == digest {
			return true
		}
	}
	return false
}

// answerOf writes the answer's data as the field's declared answer type, by
// the notation's own rules — so both directions ride one encoder. A field that
// answers nothing answers zero bytes, and its data is absent.
func (w *Warden) answerOf(field string, v any) ([]byte, error) {
	t, ok := answerType(field)
	if !ok {
		return nil, nil
	}
	return wire.Encode(Own, t, v)
}

// ArgType and AnswerType are the declared types of a field of the Warden
// blueprint. A host that calls this door from outside needs them to write the
// arguments and read the answer, and the blueprint is Quo's own rather than
// this package's, so they are not private to it.
func ArgType(field string) notation.Type { return argType(field) }

// AnswerType is false for a field that answers nothing.
func AnswerType(field string) (notation.Type, bool) { return answerType(field) }

func answerType(field string) (notation.Type, bool) {
	for _, f := range Own.Fields {
		if f.Name == field {
			if f.Answer == nil {
				return notation.Type{}, false
			}
			return *f.Answer, true
		}
	}
	return notation.Type{}, false
}

// argType is the one argument a Warden field takes. Every field of this
// blueprint takes at most one, so the blob is that argument alone and needs no
// second decoder.
func argType(field string) notation.Type {
	for _, f := range Own.Fields {
		if f.Name == field && len(f.Args) == 1 {
			return f.Args[0].Type
		}
	}
	return notation.Type{}
}

func argKey(field string, m envelope.Method) ([32]byte, error) {
	v, err := wire.Decode(Own, argType(field), m.Args)
	if err != nil {
		return [32]byte{}, err
	}
	k, ok := v.([32]byte)
	if !ok {
		return [32]byte{}, errors.New("warden: that argument is not a key")
	}
	return k, nil
}

// noArgs holds a zero-argument field to an empty blob. A surplus byte is
// refused everywhere.
func noArgs(m envelope.Method) error {
	if len(m.Args) != 0 {
		return errors.New("warden: arguments to a field that takes none")
	}
	return nil
}
