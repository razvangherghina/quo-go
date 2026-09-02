package warden

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

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

	// Random is the host's randomness, handed to the warden at open rather
	// than to each judgment: an ephemeral sealing key is needed on every
	// answer and every ask, and a door that had to be given one per message
	// could not be reached by a road that only knows bytes.
	Random func() [32]byte

	// Delivery is what the warden hands an envelope and the row it belongs to.
	// It is the one thing beneath the warden that reads a hint. A warden with
	// none can still be arrived at; it simply cannot speak first.
	Delivery Delivery

	// Store is where what must survive a restart lives. Handed none, the
	// warden keeps its records in memory alone and a restart is a new house.
	Store Store

	// Allowance is what a walk is born with when a being here starts one of
	// its own. Zero takes DefaultAllowance.
	Allowance envelope.Allowance

	// Hints are the roads this door already knows it answers on. A road stood
	// up later publishes its own.
	Hints []string

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

// DefaultAllowance is what a walk started here is born with when the host says
// nothing: the warden's own number, which each warden sets for itself.
var DefaultAllowance = envelope.Allowance{Time: 5000, Hops: 8}

// Maker makes a being of one class from the cells that arrived with it. It is
// the host's program, so it is the host that writes it: the door mints the
// keys and keeps the records, and never invents an object.
//
// An error is the destination refusing the cargo, which reaches the origin as
// the silence every other refusal does.
type Maker func(cells []byte) (any, error)

// class is a blueprint this house can make a being of: what makes one, and the
// field names that blueprint declares, read once at registration rather than
// on every arrival.
type class struct {
	bp       *notation.Blueprint
	make     Maker
	declares map[string]bool
}

type held struct {
	pk         [32]byte
	secret     [32]byte
	digest     [32]byte
	commitment [32]byte
	// heir is the pk this being's commitment is of — the name it takes on the
	// first of a migration's two rotations, and so the name a cargo is packed
	// under. The secret stays the host's: a departure is handed the heir's key
	// and this door only ever checks it against the commitment.
	heir   [32]byte
	object any
	// bound is the blueprint bound to the object: which method answers each
	// declared field, and the types either side of it. The blueprint is the
	// scope, so a name it never declared is never reached for on the object at
	// all and the door refuses it before the object is touched.
	bound *bound
	// declares is the blueprint's field names.
	declares map[string]bool
	// quo is the closure this being was handed, held so a release can take it
	// back and so the being can be found by what it holds.
	quo *Quo
}

// armed is a commitment this door will take a standing over for, held at the
// door rather than as a row: an armed commitment is nobody's standing until it
// is proved, and a lock is never a standing.
type armed struct {
	commitment [32]byte
	name       [32]byte // the door name the commitment was hashed under
	beings     [][32]byte
}

// Arming is what an arm names besides the commitment: the beings a successful
// claim reaches, and the door name the commitment was hashed under when that
// is not the name this door wears now — the same fact a standing keeps.
type Arming struct {
	Beings [][32]byte
	Name   *[32]byte
}

// Silence is what the answering house is told when the door says nothing.
// Nothing outward changes: the wire still gets the one silence, and this is
// the house talking to itself, so a blueprint's own layer can log, degrade, or
// answer its caller a typed refusal.
//
// Reason names the step the judgment refused at. Being and Method are the
// address the message carried, when it carried one.
type Silence struct {
	Reason error
	Being  *[32]byte
	Method string
}

// CallerKind is which kind of caller the judgment found. It is read off the
// voice and never declared: a caller cannot claim to be rotating.
type CallerKind string

const (
	// CallerHolder is a voice already in the inbound record.
	CallerHolder CallerKind = "holder"
	// CallerRotation is a voice that arrived on a fresh key — an heir taking a
	// standing over, or a claim proving an armed commitment.
	CallerRotation CallerKind = "rotation"
	// CallerStranger is a voice that stands nowhere, whose describe is served
	// like any other.
	CallerStranger CallerKind = "stranger"
	// CallerLocal is no voice at all: a call from a being under this same
	// warden, where there are no strangers and nothing was judged.
	CallerLocal CallerKind = "local"
)

// Caller is the verified voice, offered inward for the call about to be
// served. It is a fact, never a judgment: permission stays in the inbound
// record, and nothing here changes a byte of what crosses the wire. Marks,
// windows, padlocks, hints and the steps themselves stay at the door.
type Caller struct {
	Voice [32]byte
	Kind  CallerKind
}

// Warden is a door, the beings it keeps, and the two records it judges by.
type Warden struct {
	name           [32]byte
	nameSecret     [32]byte
	heirCommitment [32]byte
	padlock        [32]byte
	padlockSecrets [][32]byte // the current one first; keeping the old ones is the host's choice
	limit          int64

	// Handed in by the host at open, never reached for: the clock, the
	// randomness, delivery, and the store the records live in.
	clock     func() int64
	random    func() [32]byte
	delivery  Delivery
	store     Store
	allowance envelope.Allowance

	// hints are the roads this door answers on. A warden does not know where
	// it stands until something stands it up, so a road is told to it rather
	// than fixed at birth, and every mint after that carries what is true then.
	hints []string

	// labels are the private names beside the rows: a being minted beside
	// another, or a relation accepted under that label. Nothing resolves a
	// label but this map, and no label travels.
	labels map[string]*label

	// mu is the one lock. A warden is reached from several goroutines at once
	// — a road's reader, a host's own walk, a being answering — and it is
	// released around every call into a being and every hand to delivery,
	// because both may reach back in.
	mu sync.Mutex

	beings     map[[32]byte]*held
	blueprints map[[32]byte]string
	// classes are the blueprints this house can make a being of, by digest.
	// Holding a class's text is not holding the class: a being that arrives at
	// a house with only the text is addressable and mute, which is a migration
	// the origin was told succeeded.
	classes map[[32]byte]class
	record  *record

	// moved is the word this door published for each name that has gone,
	// answered by `moved` alone. It is keyed by the name the word is about and
	// not kept on the being, because both halves of a migration write here and
	// only one of them has a being to hang it on: the origin points for a name
	// it held, and the destination points for the name the arriving being wore
	// before, which is a being at no door any more.
	moved map[[32]byte]Word
	// arrived is what the last receive took in — the word it published, the
	// name it minted, and the voices that came with the standings — which is
	// everything the migration's second news is sent from.
	arrived *Arrival

	// armed holds the commitments this door will take a standing over for,
	// which are not standings and so are not rows.
	arms []armed
	// observer is what the answering house is told when the door falls silent,
	// and consumer is what it is told about the caller of a call it serves.
	// Both are held on the warden rather than handed per message: what to do
	// about a fault, and who may learn who is calling, are the house's facts
	// and not the road's.
	observer func(Silence)
	consumer func(Caller)
}

// label is one private name: a being beside this one, or a relation accepted
// under it. A relation carries a handle per being the standing names, because a
// standing names beings and one name over the relation is the name a being
// gives the whole of what it accepted.
type label struct {
	local *[32]byte
	row   *outbound
	at    []reached
}

// reached is one being under an accepted relation: what it is, what class it
// is of, and the handle built from that class's text.
type reached struct {
	being  [32]byte
	digest [32]byte
	handle Handle
}

// heard is one answer settling the ask that awaited it.
type heard struct{ answer envelope.Answer }

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
	allowance := f.Allowance
	if allowance.Time == 0 && allowance.Hops == 0 {
		allowance = DefaultAllowance
	}
	random := f.Random
	if random == nil {
		// A warden with no randomness can judge nothing: every answer is sealed
		// under an ephemeral key, and reaching for one here is what taking it
		// as an argument exists to refuse.
		return nil, errors.New("warden: a door with no randomness can seal nothing")
	}
	w := &Warden{
		name:           arithmetic.SigningKey(f.NameSecret),
		nameSecret:     f.NameSecret,
		heirCommitment: f.HeirCommitment,
		padlock:        padlock,
		padlockSecrets: [][32]byte{f.PadlockSecret},
		limit:          f.Limit,
		clock:          f.Clock,
		random:         random,
		delivery:       f.Delivery,
		store:          f.Store,
		allowance:      allowance,
		hints:          slices.Clone(f.Hints),
		labels:         map[string]*label{},
		beings:         map[[32]byte]*held{},
		blueprints:     map[[32]byte]string{},
		classes:        map[[32]byte]class{},
		moved:          map[[32]byte]Word{},
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
		declares:   fieldNames(bp),
	}
	// What must survive a restart is read back from the store the host handed
	// in, before anything is held: the rows find their beings by name as the
	// host holds them again on the same keys.
	if w.store != nil {
		if err := w.restore(); err != nil {
			return nil, err
		}
	}
	return w, nil
}

// Publish tells the warden a road it answers on. A warden does not know where
// it stands until something stands it up: a door on an ephemeral port has no
// address until it is listening, and a domain is the host's fact. Roads
// accumulate, because a warden offers as many as it has and none is
// authoritative; telling it the same road twice adds nothing.
func (w *Warden) Publish(hints ...string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, hint := range hints {
		if !slices.Contains(w.hints, hint) {
			w.hints = append(w.hints, hint)
		}
	}
	w.persist()
	return slices.Clone(w.hints)
}

// Retract drops a road that has stopped carrying. It is not news on its own:
// the peers that need to hear it are told by whatever moved the door, and this
// only stops the dead road being minted into anything new.
func (w *Warden) Retract(hints ...string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.hints = slices.DeleteFunc(w.hints, func(hint string) bool { return slices.Contains(hints, hint) })
	w.persist()
	return slices.Clone(w.hints)
}

// Hints are the roads this door currently answers on.
func (w *Warden) Hints() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.hints)
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

// Succeed moves the warden's own name. The heir the founding committed to
// spends, and from here on the house signs by that key and is addressed by it;
// the key it commits to next is the owner's again, so only its commitment is
// given. The public being's pk is the warden's name, so it moves with it.
//
// Every standing stays where it was. Each inbound row keeps the name its
// commitment was minted under, so a standing granted before the succession
// still rotates — its heir hashes to a commitment at the old name — while
// every commitment minted from here on is under the new one.
func (w *Warden) Succeed(nameSecret, heirCommitment [32]byte) error {
	name := arithmetic.SigningKey(nameSecret)
	if arithmetic.Commit(w.name, name) != w.heirCommitment {
		return errors.New("warden: that key is not the heir this door committed to")
	}
	public := w.beings[w.name]
	delete(w.beings, w.name)
	public.pk = name
	public.secret = nameSecret
	public.commitment = heirCommitment
	w.beings[name] = public
	w.name = name
	w.nameSecret = nameSecret
	w.heirCommitment = heirCommitment
	return nil
}

// Holding is what a hold needs besides the object: the blueprint that is its
// bound surface, the keys it is minted from — drawn from the warden's own
// randomness when none are given — and a private label to reach it by later.
type Holding struct {
	Blueprint string
	Keys      Keys
	Label     string
}

// Hold takes an ordinary object and makes it a being: the warden mints its
// keys, binds the blueprint to the object's methods, and records the pointer
// and the digest. Nobody is told, because no one stands at it yet.
//
// The object is a plain Go value and stays one. What it gains is the closure —
// when it embeds Attach — and a codec: its declared methods are called with
// decoded arguments and answer plain values, which the warden encodes by the
// field's declared answer type. The being never sees a byte.
func (w *Warden) Hold(object any, h Holding) ([32]byte, Handle, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hold(object, h)
}

func (w *Warden) hold(object any, h Holding) ([32]byte, Handle, error) {
	bp, err := notation.Parse(h.Blueprint)
	if err != nil {
		return [32]byte{}, nil, err
	}
	keys := h.Keys
	if keys.Secret == ([32]byte{}) {
		keys.Secret = w.random()
	}
	if keys.HeirSecret == ([32]byte{}) {
		keys.HeirSecret = w.random()
	}
	pk := arithmetic.SigningKey(keys.Secret)
	if _, taken := w.beings[pk]; taken {
		return pk, nil, errors.New("warden: that key already names a being")
	}
	// The binding is checked here rather than at the door: a class whose
	// blueprint declares a field its object cannot answer is refused before the
	// being is addressable.
	b, err := bind(bp, object)
	if err != nil {
		return [32]byte{}, nil, err
	}
	digest := bp.Digest()
	w.blueprints[digest] = bp.Text()
	one := &held{
		pk:         pk,
		secret:     keys.Secret,
		digest:     digest,
		commitment: arithmetic.Commit(w.name, arithmetic.SigningKey(keys.HeirSecret)),
		heir:       arithmetic.SigningKey(keys.HeirSecret),
		object:     object,
		bound:      b,
		declares:   fieldNames(bp),
	}
	one.quo = &Quo{w: w, being: pk}
	w.beings[pk] = one
	if a, ok := object.(attaching); ok {
		a.attach(one.quo)
	}
	if h.Label != "" {
		at := pk
		w.labels[h.Label] = &label{local: &at}
	}
	w.persist()
	return pk, &localHandle{w: w, being: pk}, nil
}

// Relation is a handle by its private label: a being minted beside another, or
// a relation accepted under that label. Nothing resolves a label but this map,
// and no label travels.
//
// A standing may name several beings, and this answers the first of them in the
// estate's own derived order. Relations answers all of them.
func (w *Warden) Relation(name string) Handle {
	held := w.Relations(name)
	if len(held) == 0 {
		return nil
	}
	return held[0]
}

// Relations is every handle under one private label.
func (w *Warden) Relations(name string) []Handle {
	w.mu.Lock()
	defer w.mu.Unlock()
	kept, ok := w.labels[name]
	if !ok {
		return nil
	}
	if kept.local != nil {
		if _, held := w.beings[*kept.local]; !held {
			return nil
		}
		return []Handle{&localHandle{w: w, being: *kept.local}}
	}
	out := make([]Handle, 0, len(kept.at))
	for _, one := range kept.at {
		out = append(out, one.handle)
	}
	return out
}

// Amend adds beings to a voice's standing or takes them away. A standing is
// amended, not replaced, and taking the last being away is release.
func (w *Warden) Amend(voice [32]byte, add, remove [][32]byte) error {
	for _, being := range add {
		if err := w.Widen(voice, being); err != nil {
			return err
		}
	}
	for _, being := range remove {
		if err := w.Narrow(voice, being); err != nil {
			return err
		}
	}
	return nil
}

// Welcome says this house can make a being of one class, and how. It is what a
// destination does before a migration: Article IX gates `receive` on the
// destination already holding the arriving class, and this is what holding one
// means — the text to check the digest against, and the program to run behind
// the name the door is about to mint.
//
// It is per class and not per arrival. The keys a receive mints are handed in
// the judgment's own Draws, where every draw of randomness in this kit is
// handed, so nothing has to be armed a message in advance; what the door
// cannot take from a draw is the host's program, and that belongs to the class
// rather than to the one being that happens to arrive next.
//
// A class registered twice takes the later maker: a host re-registering is
// saying what a being of that class is now.
func (w *Warden) Welcome(blueprint string, make Maker) ([32]byte, error) {
	if make == nil {
		return [32]byte{}, errors.New("warden: a class with no maker is not a class")
	}
	bp, err := notation.Parse(blueprint)
	if err != nil {
		return [32]byte{}, err
	}
	digest := bp.Digest()
	w.blueprints[digest] = bp.Text()
	w.classes[digest] = class{bp: bp, make: make, declares: fieldNames(bp)}
	return digest, nil
}

// fieldNames is the blueprint read as a scope: the names it declares, and
// nothing else exists for the being that compiles from it.
func fieldNames(bp *notation.Blueprint) map[string]bool {
	names := make(map[string]bool, len(bp.Fields))
	for _, f := range bp.Fields {
		names[f.Name] = true
	}
	return names
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
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.beings, being)
	for voice, row := range w.record.in {
		delete(row.beings, being)
		if len(row.beings) == 0 {
			delete(w.record.in, voice)
		}
	}
	for name, kept := range w.labels {
		if kept.local != nil && *kept.local == being {
			delete(w.labels, name)
		}
	}
	w.forget(being, nil)
	w.persist()
}

// Grant mints a voice, writes the inbound row, and hands back the invitation.
// Nobody is told — the invitation leaves as data.
//
// What leaves is the heir keypair, never the voice's own: whoever minted a
// voice has seen its keys, so the holder's first act is a rotate-and-ask to a
// key nobody else has ever seen.
// The voice's keys are drawn from the warden's own randomness, and the lock
// and the roads are the ones this door currently holds. A grant names the
// being it opens, and nothing else about this house.
func (w *Warden) Grant(being [32]byte) (wire.Invitation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.grant(being, Keys{Secret: w.random(), HeirSecret: w.random()}, w.padlock, w.hints)
}

// GrantAs is Grant with the voice's keys, the return lock and the roads named
// by the caller. Which lock a peer seals to is the caller's own choice and the
// whole of what it can do about being linked across doors.
func (w *Warden) GrantAs(being [32]byte, voice Keys, padlock [32]byte, hints []string) (wire.Invitation, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.grant(being, voice, padlock, hints)
}

func (w *Warden) grant(being [32]byte, voice Keys, padlock [32]byte, hints []string) (wire.Invitation, error) {
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
		name:       w.name,
		beings:     map[[32]byte]bool{being: true},
		spent:      map[int64]bool{},
	}
	w.persist()
	return wire.Invitation{
		Warden:     w.name,
		Commitment: w.heirCommitment,
		Padlock:    padlock,
		Heir:       heir,
		HeirSecret: voice.HeirSecret,
		Hints:      slices.Clone(hints),
	}, nil
}

// Arm holds a commitment this door did not derive: a claim nobody has made
// yet, toward the beings a successful claim reaches. Grant mints the voice and
// the heir itself, which a ground whose keys were never made on the machine
// cannot use — here the claimant's own keys become the holder, and the door
// learns them only when the claim is proved.
//
// Nothing is written into the inbound record: an armed commitment is held at
// the door, because no standing means the public face and a lock is never a
// standing. It is spent by the first claim that proves it, judged after the
// inbound record so an arm can never take a standing away from its holder; a
// wrong proof is ordinary silence and leaves the arm where it was. Re-arming
// is the caller's own act.
func (w *Warden) Arm(commitment [32]byte, a Arming) {
	name := w.name
	if a.Name != nil {
		name = *a.Name
	}
	w.arms = append(w.arms, armed{commitment: commitment, name: name, beings: slices.Clone(a.Beings)})
}

// Forget drops the relations a being holds outward. `at` narrows it to the
// relations that being holds at one far warden, named by that warden's own
// key — which is how a relation re-remembered at a house supersedes the one it
// replaces, without a consumer reaching into the record. Nil drops them all,
// which is what a being leaving takes with it. It answers how many rows it
// dropped.
func (w *Warden) Forget(being [32]byte, at *[32]byte) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.forget(being, at)
}

func (w *Warden) forget(being [32]byte, at *[32]byte) int {
	dropped := 0
	w.record.out = slices.DeleteFunc(w.record.out, func(rel *outbound) bool {
		if rel.holder != being || (at != nil && rel.warden != *at) {
			return false
		}
		dropped++
		return true
	})
	return dropped
}

// Standings is a being's own layer reading who holds a standing at it — never
// who is calling on a given message, and never another being's rows. What
// listing who holds what needs is the voice pk alone: marks, spent windows,
// padlocks and hints are the door's bookkeeping, not social data. A being
// nobody stands at, or none this door holds, answers empty.
//
// The order is by voice ascending, chosen rather than derived, so a host reads
// the same list twice.
func (w *Warden) Standings(being [32]byte) [][32]byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	holders := [][32]byte{}
	for _, row := range w.record.in {
		if row.beings[being] {
			holders = append(holders, row.voice)
		}
	}
	slices.SortFunc(holders, compareKeys)
	return holders
}

// Observe registers the inward view of silence. The stranger across the wire
// meets the same nothing it always did. A nil observer is no observer.
func (w *Warden) Observe(observer func(Silence)) *Warden {
	w.observer = observer
	return w
}

// Offer registers who is told the verified caller, per served call. Having
// verified the voice, the warden hands it to the house's own layer for the
// call it is about to serve; the layer registers once and reads the offer as
// its being runs, which is why the offer is made immediately before the call
// is routed.
func (w *Warden) Offer(consumer func(Caller)) *Warden {
	w.consumer = consumer
	return w
}

// hush is the one place every silence in the judgment exits through, so the
// two directions cannot drift: outward it is always nothing, inward it is a
// reason. An observer that falls over is the observer's problem and never the
// caller's.
func (w *Warden) hush(say *envelope.Say, reason error) {
	if w.observer == nil {
		return
	}
	s := Silence{Reason: reason}
	if say != nil {
		if say.Being != nil {
			being := *say.Being
			s.Being = &being
		}
		if say.Method != nil {
			s.Method = say.Method.Name
		}
	}
	contained(func() { w.observer(s) })
}

// offer hands the caller inward. A consumer that falls over is the consumer's
// problem: the answer is the same either way.
func (w *Warden) offer(voice [32]byte, k kind) {
	if w.consumer == nil {
		return
	}
	c := Caller{Voice: voice, Kind: CallerStranger}
	switch k {
	case kindAsk:
		c.Kind = CallerHolder
	case kindRotation:
		c.Kind = CallerRotation
	}
	contained(func() { w.consumer(c) })
}

// contained runs a hook the house registered. The door does not answer
// differently because a watcher fell over.
func contained(hook func()) {
	defer func() { _ = recover() }()
	hook()
}

// Widen adds a being to a voice's row. A standing is amended, not replaced:
// nobody is told, no secret is minted, and the holder simply finds more the
// next time it describes.
func (w *Warden) Widen(voice, being [32]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer w.persist()
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
	w.mu.Lock()
	defer w.mu.Unlock()
	defer w.persist()
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
//
// Kept whole means all five things Article VII names, the heir keypair
// included: a rotation is signed by the heir and by nothing else, so a row
// that dropped it would stand at a house it could never rotate at, and a
// cargo packed off it would carry an heir nobody holds.
func (w *Warden) Stand(holder [32]byte, inv wire.Invitation, voiceSecret [32]byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stand(holder, inv, voiceSecret)
}

func (w *Warden) stand(holder [32]byte, inv wire.Invitation, voiceSecret [32]byte) *outbound {
	rel := &outbound{
		holder:      holder,
		warden:      inv.Warden,
		commitment:  inv.Commitment,
		padlock:     inv.Padlock,
		voice:       arithmetic.SigningKey(voiceSecret),
		voiceSecret: voiceSecret,
		heirSecret:  inv.HeirSecret,
		hints:       slices.Clone(inv.Hints),
		spent:       map[int64]bool{},
		beings:      map[[32]byte][32]byte{},
		awaiting:    map[await]chan *heard{},
	}
	w.record.out = append(w.record.out, rel)
	w.persist()
	return rel
}

// Learn records the heir commitment of a being this ground stands at, as a
// describe handed it over. Without it a peer holds no material to believe that
// being's succession.
func (w *Warden) Learn(far, being, commitment [32]byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer w.persist()
	rel := w.record.at(far, nil)
	if rel == nil {
		return errors.New("warden: no relation with that house")
	}
	rel.beings[being] = commitment
	return nil
}

// RelationAt reads back an outbound row: the far warden's name, its heir
// commitment, the padlock and the hints.
func (w *Warden) RelationAt(far [32]byte) (name, commitment, padlock [32]byte, hints []string, ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	rel := w.record.at(far, nil)
	if rel == nil {
		return
	}
	return rel.warden, rel.commitment, rel.padlock, slices.Clone(rel.hints), true
}

// Point records the succession this door published for a name, so the door
// can point every arriving ask at where the being went.
//
// The name need not be a being here, and a door that required one could not
// point for the half of a migration that matters most: a destination points for
// the name the arriving being wore before, and that name is a being at no door
// any more. Both halves of a migration publish the identical word, so a peer
// that asks either house learns the same thing.
func (w *Warden) Point(being [32]byte, word Word) {
	w.moved[being] = word
}

// Peer is one row that stands at a being, read as the way back to whoever
// holds it: the voice, the padlock that voice named, and the roads it gave.
// Both are refreshed by every call that arrives, so this is the freshest way
// back the door has.
type Peer struct {
	Voice   [32]byte
	Padlock *[32]byte
	Hints   []string
}

// Peers are the rows that stand at one being: who must be told when that being
// moves, and how to reach them. Ordered by the voice's bytes ascending,
// because ranging a Go map is randomised and a list of who is owed news is not
// a thing that should differ between two runs.
func (w *Warden) Peers(being [32]byte) []Peer {
	out := []Peer{}
	for _, row := range w.record.in {
		if !row.beings[being] {
			continue
		}
		out = append(out, Peer{Voice: row.voice, Padlock: row.padlock, Hints: slices.Clone(row.hints)})
	}
	slices.SortFunc(out, func(a, b Peer) int { return compareKeys(a.Voice, b.Voice) })
	return out
}

// Departing is what the origin's half of a migration needs, once the cargo has
// landed: the being's committed heir, which signs the first news and is the
// successor the peer hashes; the commitment `receive` answered, which is the
// one fact the origin cannot invent; and where the being answers now.
type Departing struct {
	HeirSecret [32]byte
	Commitment [32]byte
	Name       [32]byte
	Padlock    [32]byte
	Hints      []string
}

// Departed is what the origin holds after departing: the word to send, the key
// that signs it, and the peers owed it.
type Departed struct {
	Word Word
	// Voice is the being's committed heir. It is handed back because the first
	// news is signed by it and the origin no longer holds the being: after the
	// double rotation every key the old warden held for it is dead.
	Voice       [32]byte
	VoiceSecret [32]byte
	Peers       []Peer
}

// Depart is the origin's half, after the cargo has landed. It publishes the
// succession of the being's committed heir — carrying as its next commitment
// the one `receive` answered, and naming the new door — and stops acting on the
// being's behalf for good.
//
// The old door never forwards a call and never acts on the being's behalf
// again. The standings stay so a peer still reaches the door and is pointed;
// the relations went with the cargo, so the old door holds no voice of the
// being's any more and can spend nothing on it.
func (w *Warden) Depart(being [32]byte, d Departing) (Departed, error) {
	h, ok := w.beings[being]
	if !ok {
		return Departed{}, errors.New("warden: no being of that name")
	}
	successor := arithmetic.SigningKey(d.HeirSecret)
	// The peer believes the succession by hashing the successor against the
	// commitment it holds, so a key this door never committed to would compose
	// news nobody can believe.
	if arithmetic.Commit(w.name, successor) != h.commitment {
		return Departed{}, errors.New("warden: that key is not the heir this being committed to")
	}
	word := Word{
		Being:      &being,
		Successor:  &successor,
		Commitment: &d.Commitment,
		// Where it answers has changed, so the word says so, and the peer
		// rewrites its row entire from it.
		Name:    &d.Name,
		Padlock: &d.Padlock,
		Hints:   slices.Clone(d.Hints),
	}
	told := w.Peers(being)
	// The relations went with the cargo, so the old door holds no voice of the
	// being's any more.
	w.Forget(being, nil)
	// The pointer stays and answers `moved` alone: every other ask meets
	// silence, and a peer that never asks `moved` learns by the news below.
	w.Point(being, word)
	return Departed{Word: word, Voice: successor, VoiceSecret: d.HeirSecret, Peers: told}, nil
}

// Arrival is the destination's half of a migration, once a cargo has landed:
// the word this door published, the name it minted, and the peers that arrived
// with the standings.
//
// Migration is that message sent twice (Article XIV). The origin's Departed is
// the first — the being's committed heir, carrying as its next commitment the
// one `receive` answered. This is the second, and the only key that can send it
// is the one this door generated and the origin never saw.
type Arrival struct {
	Word Word
	// Being is the name the arriving being wears here, and BeingSecret its
	// key. The second news is signed by it: the peer holds the hash of it from
	// the first news, so this is the one key the peer can believe it from.
	Being       [32]byte
	BeingSecret [32]byte
	// Peers are the rows that arrived with the cargo, read as the way back to
	// each — freshest at the moment they are read, because a call that arrives
	// in the meantime refreshes the padlock and the roads.
	Peers []Peer

	voices [][32]byte
}

// Landed hands back what the second news is composed from, and names the roads
// this door answers on into the word it published — so the word a peer hears
// and the word a peer gets by asking `moved` are the identical bytes.
//
// The roads are handed in rather than held, as they are for a card, a grant,
// an ask and every other act this kit composes. A door that lands a being and
// never says where it answers publishes a word with no roads, which a peer
// reads as "the road did not change" and which would leave it calling the
// house the being left.
func (w *Warden) Landed(hints []string) (Arrival, bool) {
	if w.arrived == nil {
		return Arrival{}, false
	}
	a := *w.arrived
	a.Word.Hints = slices.Clone(hints)
	w.arrived.Word = a.Word
	w.Point(*a.Word.Being, a.Word)

	// The rows that came with the cargo, and only those: a standing granted
	// here since the being landed was never told the being moved, because it
	// never knew the being anywhere else.
	held := map[[32]byte]bool{}
	for _, voice := range a.voices {
		held[voice] = true
	}
	for _, one := range w.Peers(a.Being) {
		if held[one.Voice] {
			a.Peers = append(a.Peers, one)
		}
	}
	return a, true
}

// Tell is one piece of news this door composes for one peer: the word, the key
// that signs it, and the number it spends against that peer's own mark.
type Tell struct {
	Peer Peer
	// Voice is whichever key the peer can believe this word from. Article XIV
	// gives two roads and only two: the name, which has not moved, or a key the
	// peer holds the hash of.
	Voice       [32]byte
	VoiceSecret [32]byte
	Word        Word
	// Seq is the number this news spends. News counts against the mark the peer
	// keeps for this house, which is its own counter and never the one this
	// door's callers spend, so the sender names it.
	Seq       int64
	Allowance envelope.Allowance
	// Hints are how to speak to this door later, the same roads an ask carries.
	Hints []string
}

// News composes one piece of news and hands back the sealed bytes. It is an
// ordinary envelope — ephemeral key outside, one signed payload sealed inside,
// the recipient named, a number that only rises — judged at the peer's door by
// the same steps as any ask. What makes it news is only where its voice is
// found: not in the inbound record, which says who may enter, but in the
// outbound one, which is the peer's own memory of the houses it holds
// relations with.
//
// News names no being: the voice is placed in the outbound record, and that is
// the whole of what makes it news.
func (w *Warden) News(t Tell) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ephemeral := w.random()
	// An inbound row keeps the padlock the peer named and never that peer's
	// warden name — a door never learns the house behind a voice — so the
	// recipient is the padlock. A padlock is per door, so it binds the message
	// to one door exactly as a name would.
	//
	// A peer that has never spoken left no way back. It is reached by the only
	// means left: it eventually asks, and this door tells it it has moved.
	if t.Peer.Padlock == nil {
		return nil, errors.New("warden: that peer left no way back")
	}
	if t.Allowance.Time < 1 || t.Allowance.Hops < 0 {
		return nil, errors.New("warden: a call with no leash left")
	}
	args, err := EncodeWord(t.Word)
	if err != nil {
		return nil, err
	}
	return envelope.SealSay(ephemeral, *t.Peer.Padlock, t.VoiceSecret, envelope.Say{
		Voice:     t.Voice,
		Recipient: *t.Peer.Padlock,
		Seq:       t.Seq,
		Padlock:   w.padlock,
		Hints:     slices.Clone(t.Hints),
		Allowance: t.Allowance,
		Method:    &envelope.Method{Name: FieldTell, Args: args},
	})
}

// Pack is a migration's cargo, read off what this warden holds for one being:
// its class, its cells, and both records of standings — the inbound one so its
// peers keep their standing at it, and the outbound one so it keeps its
// standing at theirs.
//
// The cells come from the host, because a being's memory is its own and the
// Being interface never hands it over.
//
// Every list is ordered by the rule Article IX gives, and the order is derived
// rather than chosen: standings by the voice's bytes, relations by the far
// warden's, beings under a standing by their pk bytes, and spent numerically —
// all ascending. A cargo crosses the wire, so two wardens packing one being
// must produce one byte string, and ranging a Go map is deliberately
// randomised: unsorted, this would differ from itself between two runs of one
// process.
func (w *Warden) Pack(being [32]byte, cells []byte) (Cargo, error) {
	h, ok := w.beings[being]
	if !ok {
		return Cargo{}, errors.New("warden: no being of that name")
	}
	// Packed under the name the first rotation gives the being, which is the
	// committed heir. Migration is one message sent twice: the first moves the
	// being's identity to that heir, and the second — the destination's — moves
	// it on to the key the destination minted. A cargo packed under the name
	// the being wore before would leave the destination composing a succession
	// of a name every peer has already succeeded past, and a peer refuses a
	// succession of a name it holds no commitment for.
	c := Cargo{Being: h.heir, Digest: h.digest, Cells: cells}
	for _, row := range w.record.in {
		if !row.beings[being] {
			continue
		}
		// Only the being that moves travels in the row: what the voice reaches
		// here besides it is this door's affair and stays.
		c.Standings = append(c.Standings, Standing{
			Voice:      row.voice,
			Commitment: row.commitment,
			// The name the heir commitment was minted under travels with the
			// row, or a migrated standing could never verify an older
			// commitment again.
			Name: row.name,
			// Under the same name the cargo is packed under, for the same
			// reason: this row travels to a door where the being's old name
			// stands in nothing.
			Beings: [][32]byte{h.heir},
			Mark:   row.mark,
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
			// The mark kept for that far warden's news, which is its own
			// counter and never the one this door sends by.
			News:  rel.mark,
			Hints: slices.Clone(rel.hints),
		})
	}
	slices.SortFunc(c.Standings, func(a, b Standing) int { return compareKeys(a.Voice, b.Voice) })
	slices.SortFunc(c.Relations, func(a, b Relation) int { return compareKeys(a.Warden, b.Warden) })
	for _, one := range c.Standings {
		slices.SortFunc(one.Beings, compareKeys)
	}
	return c, nil
}

// Reach is one call this ground makes at a house it holds a relation with. A
// being never touches a key: it hands the warden a handle, and the warden
// signs, seals and carries.
type Reach struct {
	// Far is the house this relation stands at.
	Far [32]byte
	// Holder narrows it to the relation one of this ground's beings spends,
	// for the ordinary case where two of them stand at the same house. Absent,
	// the first relation with that house is taken.
	Holder *[32]byte
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
	// Seq is the number this ask spends, when the caller wants to choose it.
	// Article VIII leaves that choice to the caller: a fresh mark is empty, so
	// every number at or above one stands above it, and no door may require a
	// first message to carry exactly one. Absent, the row counts on from what
	// it last spent, which is the ordinary case. A number at or below what the
	// row has already spent is refused here rather than at the far door, where
	// it would be silence.
	Seq *int64
}

// Ask composes one utterance and hands back the sealed bytes and the number it
// spent. Nothing here delivers: what to do with the bytes is delivery's, and
// whether they arrive is the weather.
func (w *Warden) Ask(r Reach) ([]byte, int64, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	message, seq, _, err := w.ask(r)
	return message, seq, err
}

// ask is Ask with the return lock handed back too, because the caller needs
// all three to await the answer and to forgo it.
func (w *Warden) ask(r Reach) ([]byte, int64, [32]byte, error) {
	return w.compose(w.record.at(r.Far, r.Holder), r)
}

func (w *Warden) compose(rel *outbound, r Reach) ([]byte, int64, [32]byte, error) {
	ephemeral := w.random()
	var none [32]byte
	if rel == nil {
		return nil, 0, none, errors.New("warden: no relation with that house")
	}
	allowance := r.Allowance
	if r.Leash != nil {
		onward, err := r.Leash.Onward()
		if err != nil {
			return nil, 0, none, err
		}
		allowance = onward
	}
	if allowance.Time < 1 || allowance.Hops < 0 {
		return nil, 0, none, errors.New("warden: a call with no leash left")
	}
	padlock := r.Padlock
	if padlock == ([32]byte{}) {
		padlock = w.padlock
	}

	// The row is read, never written, until there is something to send. A hop
	// this kit refuses itself puts no message on the wire, so it spends no
	// number and no key against a door that never heard of it.
	voice, voiceSecret, next := rel.voice, rel.voiceSecret, rel.next

	var commitment *[32]byte
	if r.NextHeir != nil {
		// A rotate-and-ask is signed by the heir and by nothing else: the heir
		// is the only key the far door will take the standing over for, and
		// signing with the voice would present a standing's current holder as
		// its own heir. On the first rotation the two are one key, because an
		// invitation hands the same key out as both.
		if rel.heirSecret == ([32]byte{}) {
			return nil, 0, padlock, errors.New("warden: a relation with no heir cannot rotate")
		}
		voiceSecret = rel.heirSecret
		voice = arithmetic.SigningKey(rel.heirSecret)
		// A rotation starts the mark fresh at the door, because the old key
		// died with its count — so this ground's own count starts over too,
		// and the rotate-and-ask itself is number one.
		next = 0
		// Every rotation carries a fresh commitment, or a standing could be
		// taken over exactly once and never again. It is hashed under the door
		// the heir would spend at.
		c := arithmetic.Commit(rel.warden, arithmetic.SigningKey(*r.NextHeir))
		commitment = &c
	}

	seq := next + 1
	if r.Seq != nil {
		if *r.Seq <= next {
			return nil, 0, padlock, errors.New("warden: a number this relation has already spent")
		}
		seq = *r.Seq
	}

	// An answer is paired to its ask by the padlock, the warden and the seq,
	// and by nothing else. Two asks out at once carrying the same three would
	// be answered indistinguishably, so this kit refuses to send the second —
	// which is the shape a rotation makes, because it starts the count over.
	pending := await{seq: seq, padlock: padlock}
	if _, waiting := rel.awaiting[pending]; waiting {
		return nil, 0, padlock, errors.New("warden: an ask on that number is already awaiting an answer")
	}

	say := envelope.Say{
		Voice:      voice,
		Recipient:  rel.warden,
		Commitment: commitment,
		Seq:        seq,
		Padlock:    padlock,
		Hints:      slices.Clone(r.Hints),
		Allowance:  allowance,
		Being:      r.Being,
		Method:     r.Method,
	}
	message, err := envelope.SealSay(ephemeral, rel.padlock, voiceSecret, say)
	if err != nil {
		return nil, 0, padlock, err
	}
	if rel.awaiting == nil {
		rel.awaiting = map[await]chan *heard{}
	}
	// One value ever passes, and the buffer is what lets the door settle an
	// answer whether or not anybody is still listening for it.
	rel.awaiting[pending] = make(chan *heard, 1)
	// There is an envelope: the number is spent and the row moves with it.
	rel.voice, rel.voiceSecret, rel.next = voice, voiceSecret, say.Seq
	if r.NextHeir != nil {
		// The key that just signed is the current holder from here on; the one
		// committed to is the heir after it, and the row keeps its secret
		// because nothing else in Quo does.
		rel.heirSecret = *r.NextHeir
	}
	w.persist()
	return message, say.Seq, padlock, nil
}

// await marks an ask as awaiting again, for a caller resending the identical
// envelope after silence. The number stays what it was, and the far door
// honours those bytes at most once whatever this end does.
func (w *Warden) await(rel *outbound, seq int64, padlock [32]byte) chan *heard {
	pending := await{seq: seq, padlock: padlock}
	if waiting, ok := rel.awaiting[pending]; ok {
		return waiting
	}
	waiting := make(chan *heard, 1)
	rel.awaiting[pending] = waiting
	return waiting
}

// Accepting is what spending an invitation whole needs besides the invitation:
// the being of this ground that will hold the relation, the private label to
// reach it by, and the return lock and roads this caller wants answers on.
//
// A relation nobody here owns belongs to the warden itself and travels
// nowhere, which is what a zero Holder means.
type Accepting struct {
	Holder    [32]byte
	Label     string
	Padlock   [32]byte
	Hints     []string
	Allowance envelope.Allowance
}

// Accept spends an invitation whole and hands back a handle. An invitation is
// spent, not held: whoever minted the voice has seen its keys and its heirs, so
// until the holder stands on a key it generated itself, the granter can still
// speak as the holder at its own door.
//
// That takes two rotate-and-asks, and forgetting the second is the mistake this
// does inside so that it cannot be forgotten. The first is signed by the
// invitation's heir — the only key the granting door takes the standing over
// for — and commits to a fresh voice nobody else has seen. The second is signed
// by that voice, commits to a fresh heir, and describes the estate. After it,
// every key the granter ever held for this standing is dead.
//
// Then every being the standing opens is found in that estate, each class's
// blueprint is fetched by digest, and a handle is built per being from the
// text. What comes back is what a being calls.
func (w *Warden) Accept(ctx context.Context, inv wire.Invitation, a Accepting) ([]Handle, error) {
	w.mu.Lock()
	if w.delivery == nil {
		w.mu.Unlock()
		return nil, errors.New("warden: accepting an invitation needs a road")
	}
	allowance := a.Allowance
	if allowance.Time == 0 && allowance.Hops == 0 {
		allowance = w.allowance
	}
	hints := a.Hints
	if hints == nil {
		hints = slices.Clone(w.hints)
	}
	voiceSecret, heirSecret := w.random(), w.random()
	rel := w.stand(a.Holder, inv, inv.HeirSecret)
	w.mu.Unlock()

	abandon := func() {
		w.mu.Lock()
		w.record.out = slices.DeleteFunc(w.record.out, func(one *outbound) bool { return one == rel })
		w.mu.Unlock()
	}

	step := func(being *[32]byte, method *envelope.Method, next *[32]byte) *envelope.Answer {
		return w.exchange(ctx, rel, Reach{
			Far:       inv.Warden,
			Being:     being,
			Method:    method,
			Allowance: allowance,
			Padlock:   a.Padlock,
			Hints:     hints,
			NextHeir:  next,
		})
	}

	// Both rotations open the count at one, because each starts the far door's
	// mark fresh. The first is spent and settled before the second is composed,
	// so the two never await under the same padlock, warden and number at once.
	if first := step(nil, nil, &voiceSecret); first == nil {
		abandon()
		return nil, errors.New("warden: the far door did not answer the first rotation")
	}
	second := step(nil, nil, &heirSecret)
	if second == nil {
		abandon()
		return nil, errors.New("warden: the far door did not answer the second rotation")
	}

	estate, err := DecodeEstate(second.Data)
	if err != nil {
		abandon()
		return nil, err
	}
	at, err := w.harvest(ctx, rel, estate, allowance)
	if err != nil {
		abandon()
		return nil, err
	}
	if len(at) == 0 {
		abandon()
		return nil, errors.New("warden: that standing opens nothing")
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	if a.Label != "" {
		w.labels[a.Label] = &label{row: rel, at: at}
	}
	w.persist()
	return handlesOf(at), nil
}

// Reread asks a far door to describe again and rebuilds the handles under a
// label. A standing widened after it was accepted is re-read rather than
// remembered: nobody was told it grew, so the holder finds what was added by
// asking the door that granted it.
func (w *Warden) Reread(ctx context.Context, name string) ([]Handle, error) {
	w.mu.Lock()
	kept, ok := w.labels[name]
	if !ok || kept.row == nil {
		w.mu.Unlock()
		return nil, errors.New("warden: no relation under that label")
	}
	rel := kept.row
	allowance, err := w.allowanceIn(ctx)
	w.mu.Unlock()
	if err != nil {
		return nil, err
	}

	described, ok := w.atFar(ctx, rel, FieldDescribe, nil, allowance)
	if !ok {
		return nil, errors.New("warden: the far door did not describe")
	}
	estate, err := readEstate(described)
	if err != nil {
		return nil, err
	}
	at, err := w.harvest(ctx, rel, estate, allowance)
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()
	// A handle at the far door's own public being is nobody's standing and is
	// in no estate, so a re-read keeps the one a knock put there rather than
	// describing it away.
	var door []reached
	for _, one := range kept.at {
		if one.being == rel.warden {
			door = append(door, one)
		}
	}
	kept.at = append(door, at...)
	w.persist()
	return handlesOf(at), nil
}

// harvest turns an estate a far door described into a handle per being it
// names. The far door's own public being is not one of them: a standing names
// beings of that house, and the door itself is what a knock answers with.
//
// A describe hands back a commitment per being; a peer that means to believe
// that being's succession keeps it, because otherwise the news arrives with
// nothing to hash against.
func (w *Warden) harvest(ctx context.Context, rel *outbound, estate Estate, allowance envelope.Allowance) ([]reached, error) {
	var at []reached
	for _, c := range estate.Order().Classes {
		var beings []Held
		for _, one := range c.Beings {
			if one.Being != rel.warden {
				beings = append(beings, one)
			}
		}
		if len(beings) == 0 {
			continue
		}

		w.mu.Lock()
		text, known := w.blueprints[c.Digest]
		w.mu.Unlock()
		if !known {
			named, ok := w.atFar(ctx, rel, FieldBlueprint, c.Digest, allowance)
			if !ok {
				return nil, errors.New("warden: the far door would not name that class")
			}
			if text, ok = named.(string); !ok {
				return nil, errors.New("warden: the far door named no text for that class")
			}
		}

		w.mu.Lock()
		w.blueprints[c.Digest] = text
		for _, one := range beings {
			rel.beings[one.Being] = one.Commitment
		}
		w.mu.Unlock()

		for _, one := range beings {
			handle, err := w.remote(rel, one.Being, text)
			if err != nil {
				return nil, err
			}
			at = append(at, reached{being: one.Being, digest: c.Digest, handle: handle})
		}
	}
	return at, nil
}

func handlesOf(at []reached) []Handle {
	out := make([]Handle, 0, len(at))
	for _, one := range at {
		out = append(out, one.handle)
	}
	return out
}

// Knocking is what a knock needs besides the card: the being of this ground
// that will hold the relation, and the private label to reach it by.
type Knocking struct {
	Holder [32]byte
	Label  string
}

// Knock turns a card into a handle at the far door's public being, held as a
// stranger. The voice is drawn here and nobody granted it, so it stands nowhere
// at that door and every ask down it is judged as a stranger's — which is what
// makes the estate it describes the one that door shows a stranger.
//
// The row keeps no heir: a stranger holds no standing, so there is nothing for
// a rotation to take over. What the card gives it is the far door's own heir
// commitment, which is how a stranger believes that house's succession.
func (w *Warden) Knock(card wire.Card, k Knocking) (Handle, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if card.Warden == ([32]byte{}) {
		return nil, errors.New("warden: a card naming no door")
	}
	secret := w.random()
	rel := &outbound{
		holder:      k.Holder,
		warden:      card.Warden,
		commitment:  card.Commitment,
		padlock:     card.Padlock,
		voice:       arithmetic.SigningKey(secret),
		voiceSecret: secret,
		hints:       slices.Clone(card.Hints),
		spent:       map[int64]bool{},
		beings:      map[[32]byte][32]byte{},
		awaiting:    map[await]chan *heard{},
	}
	// The public being is of the one class nobody authors, so its text is
	// already held and a knock asks the door nothing to reach it.
	handle, err := w.remote(rel, card.Warden, Blueprint)
	if err != nil {
		return nil, err
	}
	w.record.out = append(w.record.out, rel)
	if k.Label != "" {
		w.labels[k.Label] = &label{row: rel, at: []reached{{being: card.Warden, digest: Digest, handle: handle}}}
	}
	w.persist()
	return handle, nil
}

// atFar is one ask at the far door's own being: the four introspections a
// handle offers, and the blueprint fetch an accept makes on its own account.
// Nothing here is a second mechanism — it is the ordinary envelope, addressed
// to the door rather than to a being.
func (w *Warden) atFar(ctx context.Context, rel *outbound, field string, arg any, allowance envelope.Allowance) (any, bool) {
	m := envelope.Method{Name: field, Args: []byte{}}
	if arg != nil {
		blob, err := wire.Encode(Own, ArgType(field), arg)
		if err != nil {
			return nil, false
		}
		m.Args = blob
	}
	answer := w.exchange(ctx, rel, Reach{Far: rel.warden, Method: &m, Allowance: allowance})
	if answer == nil || answer.Data == nil {
		return nil, false
	}
	t, ok := answerType(field)
	if !ok {
		return nil, false
	}
	v, err := wire.Decode(Own, t, answer.Data)
	if err != nil {
		return nil, false
	}
	// An optional answered absent is a value nobody can use, and the caller is
	// told the same nothing a refusal tells it.
	return v, v != nil
}

// introspect is atFar under the leash in scope, which is what a being's own
// call is made under.
func (w *Warden) introspect(ctx context.Context, rel *outbound, field string, arg any) (any, bool) {
	w.mu.Lock()
	allowance, err := w.allowanceIn(ctx)
	w.mu.Unlock()
	if err != nil {
		return nil, false
	}
	return w.atFar(ctx, rel, field, arg, allowance)
}

// exchange is one composed message put on its road and the answer waited for.
// The lock is not held across delivery, because a judgment on this ground may
// itself be what answers.
func (w *Warden) exchange(ctx context.Context, rel *outbound, r Reach) *envelope.Answer {
	w.mu.Lock()
	message, seq, padlock, err := w.compose(rel, r)
	if err != nil {
		w.mu.Unlock()
		return nil
	}
	waiting := w.await(rel, seq, padlock)
	view := Row{Padlock: rel.padlock, Hints: slices.Clone(rel.hints)}
	delivery, deadline := w.delivery, r.Allowance.Time
	w.mu.Unlock()

	back, later := delivery.Send(view, message)
	switch {
	case back != nil:
		w.Arrive(back, nil)
	case !later:
		w.forgoAt(rel, seq, padlock)
	}
	return waitFor(ctx, waiting, deadline)
}

// forgoAt is Forgo on a row the caller already holds.
func (w *Warden) forgoAt(rel *outbound, seq int64, padlock [32]byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	pending := await{seq: seq, padlock: padlock}
	waiting, ok := rel.awaiting[pending]
	if !ok {
		return false
	}
	delete(rel.awaiting, pending)
	// The caller waiting on it is told nothing came, which is the same nothing
	// a refused ask gets. The number stays spent.
	waiting <- nil
	return true
}

// Hear opens an answer a far door sent back, under the padlock secret the call
// asked it to seal to.
//
// Article XII judges an answer by a shorter road, and names four checks. The
// unseal and the leading byte are the envelope's; the signature is verified
// against the `warden` the answer's own record carries, which is the
// envelope's too. The last two are the caller's own bookkeeping and live here:
// that warden must be a door this ground actually asked, and an ask must be
// awaiting under that padlock, that warden and that seq. An answer nothing
// awaits is the same silence as every other failure.
// The padlock secret is the warden's own, because the warden is the only thing
// that holds one: a road that opened a seal to sort a frame would have climbed
// a layer it does not belong to.
func (w *Warden) Hear(message []byte) (envelope.Answer, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.hear2(message)
}

func (w *Warden) hear2(message []byte) (envelope.Answer, error) {
	var last error
	for _, secret := range w.padlockSecrets {
		a, err := envelope.OpenAnswer(secret, message)
		if err != nil {
			last = err
			continue
		}
		padlock, err := arithmetic.SealingKey(secret)
		if err != nil {
			return envelope.Answer{}, err
		}
		// One far warden may be held by more than one row — the record says
		// which of this ground's beings may spend which relation — so the
		// awaiting entry is what picks the row, not the name alone.
		pending := await{seq: a.Seq, padlock: padlock}
		stood := false
		for _, rel := range w.record.out {
			if rel.warden != a.Warden {
				continue
			}
			stood = true
			waiting, ok := rel.awaiting[pending]
			if !ok {
				continue
			}
			delete(rel.awaiting, pending)
			// Hearing one spends the record, so the same bytes never answer
			// twice, and the caller waiting on this ask is settled with what
			// arrived.
			waiting <- &heard{answer: a}
			return a, nil
		}
		if !stood {
			return envelope.Answer{}, errors.New("warden: an answer from a house this ground holds no relation with")
		}
		return envelope.Answer{}, errors.New("warden: an answer nothing awaits")
	}
	if last == nil {
		last = errors.New("warden: no secret to open with")
	}
	return envelope.Answer{}, last
}

// Forgo drops an awaiting ask whose answer will never come — a road that
// failed to carry, or a caller that has stopped waiting. Nothing on the wire
// changes: the number stays spent, because a message the far door judged spent
// it there whatever this end does with its own record.
func (w *Warden) Forgo(far [32]byte, seq int64, padlock [32]byte) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if padlock == ([32]byte{}) {
		padlock = w.padlock
	}
	pending := await{seq: seq, padlock: padlock}
	for _, rel := range w.record.out {
		if rel.warden != far {
			continue
		}
		waiting, ok := rel.awaiting[pending]
		if !ok {
			continue
		}
		delete(rel.awaiting, pending)
		// The caller waiting on it is told nothing came, which is the same
		// nothing a refused ask gets.
		waiting <- nil
		return true
	}
	return false
}

// Pending is one ask this ground has out with no answer heard yet. It is taken
// before the bytes are put on a road, because the answer may be back before the
// caller has stopped sending — a road that answers in its own response, or a
// judgment on this same ground.
type Pending struct{ waiting chan *heard }

// Expect hands back the ask awaiting under that padlock, that warden and that
// number, so a host that composed with Ask and carries the bytes itself settles
// exactly as a handle does. A zero padlock is this warden's own, which is what
// an ask that named none asked the far door to seal to.
//
// An ask nothing awaits answers a Pending that is never settled, which waits out
// its deadline and reports nothing — the same nothing every other failure gets.
func (w *Warden) Expect(far [32]byte, seq int64, padlock [32]byte) *Pending {
	w.mu.Lock()
	defer w.mu.Unlock()
	if padlock == ([32]byte{}) {
		padlock = w.padlock
	}
	pending := await{seq: seq, padlock: padlock}
	for _, rel := range w.record.out {
		if rel.warden != far {
			continue
		}
		if held, ok := rel.awaiting[pending]; ok {
			return &Pending{waiting: held}
		}
	}
	return &Pending{}
}

// Wait blocks until the answer arrives through the warden's one entry point, the
// ask is forgone, or the deadline passes. The deadline is in the milliseconds an
// allowance is counted in.
func (p *Pending) Wait(ctx context.Context, deadline int64) (envelope.Answer, bool) {
	answer := waitFor(ctx, p.waiting, deadline)
	if answer == nil {
		return envelope.Answer{}, false
	}
	return *answer, true
}

// Lock takes a second return lock into this warden's keeping and hands back
// its public key, so a caller may name it as the padlock an answer is sealed
// to. Which lock a peer seals to is the caller's own choice and the whole of
// what a caller can do about being linked across doors; the secret stays here,
// because a road that held one would be a road holding a secret.
func (w *Warden) Lock(secret [32]byte) ([32]byte, error) {
	padlock, err := arithmetic.SealingKey(secret)
	if err != nil {
		return [32]byte{}, err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !slices.Contains(w.padlockSecrets, secret) {
		w.padlockSecrets = append(w.padlockSecrets, secret)
	}
	return padlock, nil
}

// kind is what a message turns out to be, read off the voice and never
// declared. A caller cannot claim to be rotating.
type kind int

const (
	kindAsk kind = iota + 1
	kindRotation
	kindNews
	kindStranger
)

// Arrive is the one entry point for arriving bytes, whatever road carried
// them. It unseals once; the record byte inside the seal says which of the two
// records arrived, and only the warden reads it. An answer settles the ask
// awaiting it and the road gets nothing back; a say is judged and the road gets
// bytes or silence. A road never opens a seal to route.
//
// via is the road the bytes arrived on, opaque to the warden and handed back to
// delivery beside the caller's padlock once the way back is refreshed — so a
// peer that publishes nothing can be reached down the line it holds, and the
// road never had to open a seal to be remembered.
func (w *Warden) Arrive(message []byte, via any) []byte {
	w.mu.Lock()
	inside, err := w.unseal(message)
	if err != nil {
		w.mu.Unlock()
		w.hush(nil, err)
		return nil
	}
	if len(inside) > 0 && inside[0] == envelope.AnswerTag {
		_, err := w.hear2(message)
		w.mu.Unlock()
		if err != nil {
			w.hush(nil, err)
		}
		return nil
	}
	// The judgment runs with the lock held and drops it around the being, which
	// may reach back in — a call made while answering a call is the ordinary
	// middle of a chain.
	answer, err := w.judgeLocked(message, via)
	w.mu.Unlock()
	return answer
}

// unseal opens the envelope far enough to read the record byte and no further.
// It is the one place a seal is opened for sorting, and it is inside the
// warden, which is the layer that holds the secret.
func (w *Warden) unseal(message []byte) ([]byte, error) {
	var last error
	for _, secret := range w.padlockSecrets {
		plain, err := envelope.Unseal(secret, message)
		if err != nil {
			last = err
			continue
		}
		return plain, nil
	}
	if last == nil {
		last = errors.New("warden: no secret to open with")
	}
	return nil, last
}

// judgeLocked runs the eight steps over what arrived and hands back what to
// send. A nil answer is silence, and silence is the whole of every refusal.
// The error beside it never travels: it is the reason the door reports inward,
// through hush.
func (w *Warden) judgeLocked(message []byte, via any) (answer []byte, err error) {
	// Every silence leaves through here and nowhere else, so the inward fault
	// and the outward silence cannot drift apart. A being that panics is the
	// same silence as every other refusal: the door is the global recover, and
	// it never panics at its host.
	var say *envelope.Say
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("warden: something beneath the door panicked: %v", r)
		}
		if err != nil {
			answer = nil
			w.hush(say, err)
		}
	}()
	answer, err = w.judge(message, via, &say)
	return answer, err
}

// judge is the eight steps themselves. It hands the payload back through `at`
// the moment it has one, so a fault beneath the door is still observed with
// the address the message carried.
func (w *Warden) judge(message []byte, via any, at **envelope.Say) ([]byte, error) {
	// The first of the two readings the dwell is the difference of. It is taken
	// before anything else, because what it marks is when the message arrived
	// and not when the door got round to it.
	arrived := w.clock()

	// The published limit binds on every road and not only on the one with a
	// socket in it. It is what a caller can compute before sending, so it is
	// judged before anything is unsealed — and a door whose limit was enforced
	// by its line alone would accept over distance zero exactly what it told
	// every caller it would refuse.
	if w.limit > 0 && int64(len(message)) > w.limit {
		return nil, errors.New("warden: an envelope beyond the limit this door publishes")
	}

	say, err := w.open(message)
	if err != nil {
		return nil, err
	}
	*at = &say

	// The key this door's answer is sealed under, drawn once the message has
	// opened and before anything else this judgment may draw. Every draw is
	// taken from the randomness the host handed in at open, and the order they
	// are taken in is fixed so a host that hands a pinned sequence gets the
	// same bytes twice.
	ephemeral := w.random()

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

	// The way back is refreshed here, between the seq and the leash: the
	// padlock and hints the payload carried replace what the row held. Not
	// earlier, because a replayed message would otherwise rewrite a live way
	// back with a retired one, and the seq is what tells a replay from a call.
	// Not later, because a message refused for its leash still arrived and
	// still spent its number — a door that refreshed only what it went on to
	// route would slowly lose the way back to any peer whose calls it keeps
	// refusing, and news is what that peer would stop receiving.
	if row != nil {
		padlock := say.Padlock
		row.padlock = &padlock
		// An empty hints list means the road did not change, never an erasure:
		// a dialing end publishes nothing by nature, and erasing on that would
		// destroy its way back on its first ask.
		if len(say.Hints) > 0 {
			row.hints = slices.Clone(say.Hints)
		}
	}
	// The number is spent and the way back refreshed: what a restart must not
	// lose has just changed.
	w.persist()
	// Delivery learns the road this padlock's asks arrive on, as an address
	// beside an opaque token it never read. That is the warden's one call
	// downward, and anything more handed that way is the leak.
	if via != nil && w.delivery != nil {
		w.delivery.Arrived(say.Padlock, via)
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

	// The caller is verified and the call is about to be served: the one moment
	// the house may be told who is asking. News never reaches here, because a
	// peer announcing a succession is calling nobody's layer.
	if k != kindNews {
		w.offer(say.Voice, k)
	}

	data, err := w.route(leash, k, say, row, rel)
	if err != nil {
		return nil, err
	}

	return envelope.SealAnswer(ephemeral, say.Padlock, w.nameSecret, envelope.Answer{
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

	row, ambiguous := w.record.heir(say.Voice)
	if ambiguous {
		return 0, nil, nil, errors.New("warden: a hash matching more than one standing")
	}
	if row != nil {
		if say.Commitment == nil {
			return 0, nil, nil, errors.New("warden: a rotation carrying no fresh commitment")
		}
		w.record.rotate(row, say.Voice, *say.Commitment, w.name)
		return kindRotation, row, nil, nil
	}

	// Still nowhere, and carrying a commitment: the claim on an armed one. It is
	// the rotation path above with the minting taken out — the claimant's own
	// keys become the holder, and the standing is written at the beings the arm
	// named. Judged after the inbound record, so an arm can never take a
	// standing that already stands away from its holder.
	if say.Commitment != nil {
		for at, held := range w.arms {
			if arithmetic.Commit(held.name, say.Voice) != held.commitment {
				continue
			}
			w.arms = slices.Delete(w.arms, at, at+1)
			beings := map[[32]byte]bool{}
			for _, b := range held.beings {
				beings[b] = true
			}
			row := &inbound{
				voice:      say.Voice,
				commitment: *say.Commitment,
				name:       w.name,
				beings:     beings,
				spent:      map[int64]bool{},
				hints:      slices.Clone(say.Hints),
			}
			w.record.in[say.Voice] = row
			return kindRotation, row, nil, nil
		}
	}

	if rel, fresh := w.hear(say.Voice); rel != nil {
		// A commitment the message carries is ignored here rather than refused.
		// Article XI names two refusals on this field — a plain ask carrying
		// one, a rotation carrying none — and they are the only two: each has a
		// mechanical reason in step 4, and neither reason exists for news,
		// which places a voice by the outbound record and never reads the
		// field. News carries its next commitment inside the word. A door that
		// refused a stray one would meet a house that has succeeded with
		// silence, and a house that has succeeded and is not believed is a
		// house nobody can reach.
		if fresh {
			// A succession starts the news mark fresh: the old key died with
			// its count. Only a padlock replacement, announced by a house that
			// persists, continues a mark.
			rel.mark = 0
			rel.spent = map[int64]bool{}
		}
		return kindNews, nil, rel, nil
	}

	// Nowhere: the stranger's case, which is a standing at nothing. A
	// commitment the message carries changes none of this — the kind is read
	// off the voice and never declared, so the field is ignored here rather
	// than refused. A door that refused it would meet the holder whose door
	// has forgotten it, restored from an old backup or its standing released,
	// with silence — where the stranger's case tells that caller the house is
	// alive and answers what any stranger may see.
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
func (w *Warden) route(leash Leash, k kind, say envelope.Say, row *inbound, rel *outbound) ([]byte, error) {
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
		return w.tell(rel, say.Voice, say.Method.Args)
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
		return w.own(k, row, *say.Method)
	}
	if _, gone := w.moved[target]; gone {
		// The old door only points: it answers `moved` with the succession and
		// every other ask meets silence. An answer's data is the field's
		// declared answer type by the notation's rules, and a succession is not
		// that type, so the word cannot be put where the caller asked for
		// something else. A peer that never asks `moved` learns by news. It
		// never forwards and never acts on the being's behalf again.
		return nil, errors.New("warden: that being has moved")
	}
	if h.object == nil || h.bound == nil {
		return nil, errors.New("warden: nothing answers for that being")
	}
	// The blueprint is the scope: a name it never declared is not reached for
	// on the object at all, so the door refuses before the object is touched.
	if !h.declares[say.Method.Name] {
		return nil, fmt.Errorf("warden: that being's blueprint declares no field %q", say.Method.Name)
	}
	// The being is reached with the caller and the leash in scope, arguments
	// decoded and the answer encoded. What must be bytes or nothing at the wire
	// is made so here, never by the being.
	//
	// The lock is dropped around it: a being in the middle of a chain does its
	// own work before it answers, and reaching another house means reaching
	// back into this warden.
	ctx := within(context.Background(), InScope{
		Caller: Caller{Voice: say.Voice, Kind: k.caller()},
		Leash:  leash,
	})
	bound, name, args := h.bound, say.Method.Name, say.Method.Args
	return w.outside(func() ([]byte, error) { return bound.invoke(ctx, name, args) })
}

// outside runs work with the lock let go and takes it back however the work
// ends. A being that panics is the same silence as every other refusal, and a
// door that came back from one without its own lock would be a door that
// panics at its host next.
func (w *Warden) outside(work func() ([]byte, error)) (data []byte, err error) {
	w.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("warden: something beneath the door panicked: %v", r)
		}
		w.mu.Lock()
	}()
	return work()
}

// caller is which kind of caller a placement found, as the house is told it.
func (k kind) caller() CallerKind {
	switch k {
	case kindAsk:
		return CallerHolder
	case kindRotation:
		return CallerRotation
	}
	return CallerStranger
}

// own answers the warden's own being. Every one of these fields is a field on
// the blueprint Quo writes, spent by an ordinary standing.
func (w *Warden) own(k kind, row *inbound, m envelope.Method) ([]byte, error) {
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
		// A being this door has moved on is reached by the succession it
		// published and by nothing else: an arriving row names the being by
		// the name the destination minted and by that name alone, so the name
		// it wore before stands in no standing here. If a published pointer
		// were not reach enough, the old door could not point about the one
		// being Article XIII sends every peer behind the news to ask it about.
		word, published := w.moved[being]
		// To a holder who reached it before, never to a stranger — and holding
		// a standing at some other being here is not having reached this one.
		// At the old door the standings still name the being that left, which
		// the reach test below catches; at a destination they name it by the
		// key this house minted, so reaching the successor the published word
		// names is what reached-it-before means there. A door that pointed for
		// anyone with a row would tell whoever holds anything here that this
		// being exists and where it went.
		pointing := published && word.Successor != nil && w.reaches(row, *word.Successor)
		if !w.reaches(row, being) && !pointing {
			return nil, errors.New("warden: that voice does not reach that being")
		}
		if published {
			return w.answerOf(FieldMoved, wordValue(word))
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
		return w.receive(row, m)
	}
	return nil, fmt.Errorf("warden: the warden declares no field %q", m.Name)
}

// tell is news arriving. A peer believes it by a key it already holds, and
// there are only two: the heir it was promised, or the name it has held since
// the invitation.
func (w *Warden) tell(rel *outbound, voice [32]byte, args []byte) ([]byte, error) {
	// Which of Article XIV's two roads of belief this news came down. A peer
	// believes news by a key it already holds and there are only two, so the
	// road is a fact about the signer and never about the word: the name,
	// which has not moved, or the heir the peer holds the hash of. The
	// placement found the voice on one of them; which one decides what this
	// word is allowed to say.
	byName := voice == rel.warden

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
		// The successor signs and the peer hashes. A word naming a successor
		// the signer is not proves nothing about that key: it would let a
		// committed heir hand this relation to a third party it chose.
		if *word.Successor != voice {
			return nil, errors.New("warden: a succession the successor did not sign")
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
		// moved and which the peer has held since the invitation. Article XIV
		// gives this act exactly one signer, and anything else is silence: a
		// door that believed it from the committed heir would let that heir
		// replace this house's lock at every peer before succeeding anything,
		// and every message those peers sent next would be sealed to a lock
		// the heir chose.
		if !byName {
			return nil, errors.New("warden: a padlock replacement the name did not sign")
		}
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
	// The row is a pointer in a list, so a house that succeeded its name is
	// found by the name it now wears with nothing to re-key.
	// tell answers nothing, and a field that answers nothing answers zero bytes.
	return nil, nil
}

// receive takes a being in: the destination generates the keys the origin never
// saw, takes the cargo, and answers a commitment under its own name — the one
// fact the origin must carry into the first news and cannot invent.
//
// **A destination mints two keys — the one the being is named by here and that
// one's heir — and the commitment is of the first** (Article IX). The being's
// new name is where the migration's second news moves the being's identity, and
// it is what a peer hashes that succession against; a commitment to the heir
// instead names a key that will not sign anything until the succession after
// this one, so the peer disbelieves the news and is left standing at a house
// that has stopped answering.
func (w *Warden) receive(row *inbound, m envelope.Method) ([]byte, error) {
	// The two keys the destination mints and the origin never saw, drawn from
	// the randomness the host handed in at open.
	draws := struct{ Being, Heir [32]byte }{Being: w.random(), Heir: w.random()}
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
	// **A destination that does not already hold that class refuses the cargo
	// in silence, and there is nobody it may ask** (Article IX). Holding the
	// class is holding the program: a house with only the text could take the
	// being in, answer the commitment, and leave it standing there unable to
	// answer a field its own blueprint declares.
	c, known := w.classes[cargo.Digest]
	if !known {
		return nil, errors.New("warden: no class of that digest lives here")
	}
	// The being's new name at this house, and that name's own heir.
	pk := arithmetic.SigningKey(draws.Being)
	heir := arithmetic.SigningKey(draws.Heir)
	if pk == cargo.Being {
		return nil, errors.New("warden: a receive minting the name the being already wore")
	}
	// The cells are the being's own memory and travelled with it, so they are
	// what it is made from. Nothing else in this door reads them.
	object, err := c.make(cargo.Cells)
	if err != nil {
		return nil, err
	}
	b, err := bind(c.bp, object)
	if err != nil {
		return nil, err
	}
	one := &held{
		pk:         pk,
		secret:     draws.Being,
		digest:     cargo.Digest,
		commitment: arithmetic.Commit(w.name, heir),
		// The heir the door minted, so a being that arrived can migrate again:
		// a cargo is packed under the name the being takes on the first of a
		// migration's two rotations, and a being with no heir has none.
		heir:     heir,
		object:   object,
		bound:    b,
		declares: c.declares,
	}
	one.quo = &Quo{w: w, being: pk}
	w.beings[pk] = one
	if a, ok := object.(attaching); ok {
		a.attach(one.quo)
	}
	// The inbound record and the replay window travel with the being, or every
	// peer's standing would have to be regranted and every spent number would
	// come round again.
	for _, s := range cargo.Standings {
		// **An arriving row reaches the being by the name this door minted and
		// by that name alone** (Article XIII), never also by the name the being
		// wore before: a name a door must remember for whoever might still be
		// behind is a name it can never stop remembering, and the peer that is
		// behind is not stranded, because the old door still answers `moved`.
		beings := map[[32]byte]bool{pk: true}
		spent := map[int64]bool{}
		for _, n := range s.Spent {
			spent[n] = true
		}
		w.record.in[s.Voice] = &inbound{
			voice:      s.Voice,
			commitment: s.Commitment,
			// The name each commitment was minted at travels with the row, so
			// a standing that arrives still rotates at the name it was granted
			// under rather than at this door's.
			name:    s.Name,
			beings:  beings,
			mark:    s.Mark,
			spent:   spent,
			padlock: s.Padlock,
			hints:   slices.Clone(s.Hints),
		}
	}
	// Its outbound record travels too. Nobody is owed news about this half —
	// the doors where the being holds a standing know only a voice and have
	// never heard of the being at all — but a being that cannot reach them has
	// still lost everything it could do.
	for _, r := range cargo.Relations {
		w.record.out = append(w.record.out, &outbound{
			// Held by the name the being wears here, so it travels again when
			// the being does.
			holder:      pk,
			warden:      r.Warden,
			commitment:  r.Commitment,
			padlock:     r.Padlock,
			voice:       r.Voice,
			voiceSecret: r.Secret,
			heirSecret:  r.HeirSecret,
			hints:       slices.Clone(r.Hints),
			next:        r.Seq,
			// The news mark travels too, so a peer's numbers stay spent across
			// the move rather than coming round again at the new door.
			mark:     r.News,
			spent:    map[int64]bool{},
			beings:   map[[32]byte][32]byte{},
			awaiting: map[await]chan *heard{},
		})
	}
	_ = row

	// The second rotation: to a key this door generated and the origin never
	// saw. The word is the old door's shape exactly, so a peer that hears it
	// and a peer that asks the old door learn the identical thing.
	//
	// It is published here for the name the being wore before, because that is
	// the name every peer behind the news still holds. A destination that
	// recorded nothing would leave those peers with one road to the being's new
	// home — asking the door it left — and no house should be the only way to
	// find a house.
	word := Word{
		Being:      &cargo.Being,
		Successor:  &pk,
		Commitment: &w.beings[pk].commitment,
		Name:       &w.name,
		Padlock:    &w.padlock,
		// The roads are the host's, as they are for every other act this kit
		// composes — a card, a grant, an ask, a piece of news. Landed is where
		// they are named, and it names them into this same word.
	}
	w.Point(cargo.Being, word)
	voices := make([][32]byte, 0, len(cargo.Standings))
	for _, s := range cargo.Standings {
		voices = append(voices, s.Voice)
	}
	slices.SortFunc(voices, compareKeys)
	w.arrived = &Arrival{Word: word, Being: pk, BeingSecret: draws.Being, voices: voices}

	// The commitment of the being's new name, hashed under this door's own.
	return w.answerOf(FieldReceive, arithmetic.Commit(w.name, pk))
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
