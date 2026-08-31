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
// answer, fresh on every message, and the two keys a receive mints and the
// origin never saw.
//
// A destination mints two (Article IX): Being is the key the arriving being is
// named by at this house, and Heir is that name's heir. They are two because
// the answer commits to the first — the being's new name, which is where the
// migration's second news moves the being's identity — while the second is
// what lets that name be succeeded afterwards like any other.
type Draws struct {
	Ephemeral [32]byte
	Being     [32]byte
	Heir      [32]byte
}

type held struct {
	pk         [32]byte
	secret     [32]byte
	digest     [32]byte
	commitment [32]byte
	object     Being
	moved      *Word // the succession this door published, answered by `moved` alone
	// declares is the blueprint's field names. The blueprint is the scope: a
	// name it never declared is never reached for on the object at all, so the
	// door refuses it before the object is touched.
	declares map[string]bool
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
// Reason is the same error Judge hands the host, which names the step. Being
// and Method are the address the message carried, when it carried one.
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

	clock func() int64

	beings     map[[32]byte]*held
	blueprints map[[32]byte]string
	record     *record

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
		declares:   fieldNames(bp),
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
		declares:   fieldNames(bp),
	}
	return pk, nil
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
	delete(w.beings, being)
	for voice, row := range w.record.in {
		delete(row.beings, being)
		if len(row.beings) == 0 {
			delete(w.record.in, voice)
		}
	}
	w.Forget(being, nil)
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
		name:       w.name,
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

// Armed is how many commitments this door is currently holding a claim open
// for, so a host can see an arm was spent without reaching into the record.
func (w *Warden) Armed() int { return len(w.arms) }

// Forget drops the relations a being holds outward. `at` narrows it to the
// relations that being holds at one far warden, named by that warden's own
// key — which is how a relation re-remembered at a house supersedes the one it
// replaces, without a consumer reaching into the record. Nil drops them all,
// which is what a being leaving takes with it. It answers how many rows it
// dropped.
func (w *Warden) Forget(being [32]byte, at *[32]byte) int {
	dropped := 0
	for far, rel := range w.record.out {
		if rel.holder != being || (at != nil && rel.warden != *at) {
			continue
		}
		delete(w.record.out, far)
		dropped++
	}
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
//
// Kept whole means all five things Article VII names, the heir keypair
// included: a rotation is signed by the heir and by nothing else, so a row
// that dropped it would stand at a house it could never rotate at, and a
// cargo packed off it would carry an heir nobody holds.
func (w *Warden) Stand(holder [32]byte, inv wire.Invitation, voiceSecret [32]byte) {
	w.record.out[inv.Warden] = &outbound{
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
		awaiting:    map[await]bool{},
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
			// The name the heir commitment was minted under travels with the
			// row, or a migrated standing could never verify an older
			// commitment again.
			Name:   row.name,
			Beings: [][32]byte{being},
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
			return nil, 0, errors.New("warden: a relation with no heir cannot rotate")
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
			return nil, 0, errors.New("warden: a number this relation has already spent")
		}
		seq = *r.Seq
	}

	// An answer is paired to its ask by the padlock, the warden and the seq,
	// and by nothing else. Two asks out at once carrying the same three would
	// be answered indistinguishably, so this kit refuses to send the second —
	// which is the shape a rotation makes, because it starts the count over.
	pending := await{seq: seq, padlock: padlock}
	if rel.awaiting[pending] {
		return nil, 0, errors.New("warden: an ask on that number is already awaiting an answer")
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
		return nil, 0, err
	}
	if rel.awaiting == nil {
		rel.awaiting = map[await]bool{}
	}
	rel.awaiting[pending] = true
	// There is an envelope: the number is spent and the row moves with it.
	rel.voice, rel.voiceSecret, rel.next = voice, voiceSecret, say.Seq
	if r.NextHeir != nil {
		// The key that just signed is the current holder from here on; the one
		// committed to is the heir after it, and the row keeps its secret
		// because nothing else in Quo does.
		rel.heirSecret = *r.NextHeir
	}
	return message, say.Seq, nil
}

// Accepting is what spending an invitation whole needs: the being of this
// ground that will hold the relation, the two keys nobody has ever seen, the
// ask to carry, and the road to carry it on.
//
// Ephemeral holds the two sealing keys the two messages need, drawn by the
// host like every other draw. Send is the road: one envelope out, the sealed
// answer back, and an error only where the road itself failed to carry.
type Accepting struct {
	Holder      [32]byte
	VoiceSecret [32]byte
	HeirSecret  [32]byte

	Being     *[32]byte
	Method    *envelope.Method
	Allowance envelope.Allowance
	Padlock   [32]byte
	Hints     []string

	Ephemeral [2][32]byte
	Send      func(message []byte) ([]byte, error)
}

// Accepted is what the caller keeps: the house it now stands at, the voice it
// stands on, the heir it committed to and that commitment, the two messages it
// sent, and the sealed answer to the ask it carried.
type Accepted struct {
	Far        [32]byte
	Voice      [32]byte
	Heir       [32]byte
	Commitment [32]byte
	Opening    []byte
	Envelope   []byte
	Answer     []byte
	Seq        int64
}

// Accept spends an invitation whole. An invitation is spent, not held: whoever
// minted the voice has seen its keys and its heirs, so until the holder stands
// on a key it generated itself, the granter can still speak as the holder at
// its own door.
//
// That takes two rotate-and-asks, and forgetting the second is the mistake this
// helper exists to make unmakeable. The first is signed by the invitation's
// heir — the only key the granting door takes the standing over for — and
// commits to a fresh voice nobody else has seen. The second is signed by that
// voice, commits to a fresh heir, and carries the caller's own ask. After it,
// every key the granter ever held for this standing is dead.
//
// Nothing here is wire. It is the raw path composed, and the raw path stays
// open: Stand and Ask do exactly this for a caller that wants the steps.
func (w *Warden) Accept(inv wire.Invitation, a Accepting) (Accepted, error) {
	if a.Send == nil {
		return Accepted{}, errors.New("warden: accepting an invitation needs a road")
	}
	w.Stand(a.Holder, inv, inv.HeirSecret)

	voice := a.VoiceSecret
	first, _, err := w.Ask(a.Ephemeral[0], Reach{
		Far:       inv.Warden,
		Allowance: a.Allowance,
		Padlock:   a.Padlock,
		Hints:     a.Hints,
		NextHeir:  &voice,
	})
	if err != nil {
		return Accepted{}, err
	}
	opening, err := a.Send(first)
	if err != nil {
		return Accepted{}, err
	}
	// Both rotations open the count at one, because each starts the far door's
	// mark fresh — so the two asks carry the same padlock, warden and seq, and
	// their answers cannot be told apart. The opening is handed back sealed
	// for the caller to judge, which is what stops awaiting it here; without
	// this the second ask would be the one its own kit refuses to send.
	w.Forgo(inv.Warden, 1, a.Padlock)

	heir := a.HeirSecret
	second, seq, err := w.Ask(a.Ephemeral[1], Reach{
		Far:       inv.Warden,
		Being:     a.Being,
		Method:    a.Method,
		Allowance: a.Allowance,
		Padlock:   a.Padlock,
		Hints:     a.Hints,
		NextHeir:  &heir,
	})
	if err != nil {
		return Accepted{}, err
	}
	answer, err := a.Send(second)
	if err != nil {
		return Accepted{}, err
	}
	return Accepted{
		Far:        inv.Warden,
		Voice:      arithmetic.SigningKey(a.VoiceSecret),
		Heir:       arithmetic.SigningKey(a.HeirSecret),
		Commitment: arithmetic.Commit(inv.Warden, arithmetic.SigningKey(a.HeirSecret)),
		Opening:    opening,
		Envelope:   second,
		Answer:     answer,
		Seq:        seq,
	}, nil
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
func (w *Warden) Hear(padlockSecret [32]byte, message []byte) (envelope.Answer, error) {
	a, err := envelope.OpenAnswer(padlockSecret, message)
	if err != nil {
		return envelope.Answer{}, err
	}
	padlock, err := arithmetic.SealingKey(padlockSecret)
	if err != nil {
		return envelope.Answer{}, err
	}
	rel, ok := w.record.out[a.Warden]
	if !ok {
		return envelope.Answer{}, errors.New("warden: an answer from a house this ground holds no relation with")
	}
	pending := await{seq: a.Seq, padlock: padlock}
	if !rel.awaiting[pending] {
		return envelope.Answer{}, errors.New("warden: an answer nothing awaits")
	}
	delete(rel.awaiting, pending)
	return a, nil
}

// Forgo drops an awaiting ask whose answer will never come — a road that
// failed to carry, or a caller that has stopped waiting. Nothing on the wire
// changes: the number stays spent, because a message the far door judged spent
// it there whatever this end does with its own record.
func (w *Warden) Forgo(far [32]byte, seq int64, padlock [32]byte) bool {
	rel, ok := w.record.out[far]
	if !ok {
		return false
	}
	if padlock == ([32]byte{}) {
		padlock = w.padlock
	}
	pending := await{seq: seq, padlock: padlock}
	if !rel.awaiting[pending] {
		return false
	}
	delete(rel.awaiting, pending)
	return true
}

// Awaiting is how many asks this ground has out down one relation with no
// answer heard yet.
func (w *Warden) Awaiting(far [32]byte) int {
	rel, ok := w.record.out[far]
	if !ok {
		return 0
	}
	return len(rel.awaiting)
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
func (w *Warden) Judge(draws Draws, message []byte) (answer []byte, err error) {
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
	answer, err = w.judge(draws, message, &say)
	return answer, err
}

// judge is the eight steps themselves. It hands the payload back through `at`
// the moment it has one, so a fault beneath the door is still observed with
// the address the message carried.
func (w *Warden) judge(draws Draws, message []byte, at **envelope.Say) ([]byte, error) {
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

	if row := w.record.heir(say.Voice); row != nil {
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
		return w.own(draws, k, row, *say.Method)
	}
	if h.moved != nil {
		// The old door only points: it answers `moved` with the succession and
		// every other ask meets silence. An answer's data is the field's
		// declared answer type by the notation's rules, and a succession is not
		// that type, so the word cannot be put where the caller asked for
		// something else. A peer that never asks `moved` learns by news. It
		// never forwards and never acts on the being's behalf again.
		return nil, errors.New("warden: that being has moved")
	}
	if h.object == nil {
		return nil, errors.New("warden: nothing answers for that being")
	}
	// The blueprint is the scope: a name it never declared is not reached for
	// on the object at all, so the door refuses before the object is touched.
	if !h.declares[say.Method.Name] {
		return nil, fmt.Errorf("warden: that being's blueprint declares no field %q", say.Method.Name)
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
		// A being this door has moved on is reached by the succession it
		// published and by nothing else: an arriving row names the being by
		// the name the destination minted and by that name alone, so the name
		// it wore before stands in no standing here. If a published pointer
		// were not reach enough, the old door could not point about the one
		// being Article XIII sends every peer behind the news to ask it about.
		h, held := w.beings[being]
		pointing := held && h.moved != nil && row != nil
		if !w.reaches(row, being) && !pointing {
			return nil, errors.New("warden: that voice does not reach that being")
		}
		if held && h.moved != nil {
			return w.answerOf(FieldMoved, wordValue(*h.moved))
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
	for far, r := range w.record.out {
		if r == rel && far != rel.warden {
			delete(w.record.out, far)
			w.record.out[rel.warden] = rel
		}
	}
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
	// The being's new name at this house, and that name's own heir.
	pk := arithmetic.SigningKey(draws.Being)
	heir := arithmetic.SigningKey(draws.Heir)
	if pk == cargo.Being {
		return nil, errors.New("warden: a receive minting the name the being already wore")
	}
	w.beings[pk] = &held{
		pk:         pk,
		secret:     draws.Being,
		digest:     cargo.Digest,
		commitment: arithmetic.Commit(w.name, heir),
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
		w.record.out[r.Warden] = &outbound{
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
			awaiting: map[await]bool{},
		}
	}
	_ = row
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
