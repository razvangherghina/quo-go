package warden

import (
	"context"
	"errors"
	"slices"
	"time"

	"quo.systems/kit/envelope"
	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

// The being's whole API to Quo: the struct a warden hands each object it
// holds, the call in scope on the context, and the handle a being calls a far
// being through. Nothing here sees a key or a road. A handle is a Quo handle
// and looks like one — every declared field callable, able to block on the
// network, answering a value or silence — and a being always knows which of
// its references are Quo.

// InScope is what a being is handed for the call it is answering: the verified
// caller and the leash that arrived. It reaches a method through the context,
// because Go has no ambient scope and one warden serves several calls at once.
type InScope struct {
	Caller Caller
	Leash  Leash
}

type scopeKey struct{}

// Of reads the call in scope. A being invoked outside a judgment — by a
// neighbour under the same warden, or by its own host — gets a zero InScope,
// whose leash refuses to be spent.
func Of(ctx context.Context) InScope {
	if ctx == nil {
		return InScope{}
	}
	s, _ := ctx.Value(scopeKey{}).(InScope)
	return s
}

func within(ctx context.Context, s InScope) context.Context {
	return context.WithValue(ctx, scopeKey{}, s)
}

// Quo is the closure the warden hands a being: facts and acts, never a
// judgment. Permission lives in the warden's record alone, and narrowing is
// done with beings.
type Quo struct {
	w     *Warden
	being [32]byte
}

// Being is the pk this being is named by.
func (q *Quo) Being() [32]byte { return q.being }

// Standings is who holds a place at me, as voices only. Marks, windows,
// padlocks and hints stay at the door.
func (q *Quo) Standings() [][32]byte { return q.w.Standings(q.being) }

// Relation is a handle at a being elsewhere, or beside me, under a private
// label of my own. A standing may name several beings, and this answers the
// first of them in the estate's own derived order; Relations answers them all.
func (q *Quo) Relation(label string) Handle { return q.w.Relation(label) }

// Relations is every handle under one private label, in the order the estate
// derives. A label taken by a being minted beside me names exactly one.
func (q *Quo) Relations(label string) []Handle { return q.w.Relations(label) }

// Grant opens a being of this ground to a voice the warden mints, and hands
// back the invitation. Granting nothing grants this being itself.
func (q *Quo) Grant(being *[32]byte) (wire.Invitation, error) {
	at := q.being
	if being != nil {
		at = *being
	}
	return q.w.Grant(at)
}

// Amend adds beings to a voice's standing or takes them away. Taking the last
// one away is release, and there is no separate act for it.
func (q *Quo) Amend(voice [32]byte, add, remove [][32]byte) error {
	return q.w.Amend(voice, add, remove)
}

// Release drops a being this ground holds, and every standing at it goes too.
func (q *Quo) Release(being [32]byte) { q.w.Release(being) }

// Expose offers a being to every voice, the stranger included; Conceal takes
// it back. `Expose(nil)` opens the being itself, as `Grant(nil)` does.
func (q *Quo) Expose(being *[32]byte) bool {
	if being == nil {
		return q.w.Expose(q.being)
	}
	return q.w.Expose(*being)
}

func (q *Quo) Conceal(being *[32]byte) bool {
	if being == nil {
		return q.w.Conceal(q.being)
	}
	return q.w.Conceal(*being)
}

// Accept turns an invitation received as data into handles, with the double
// rotation done and impossible to forget. A standing names beings, so accepting
// one answers a handle per being it names, and the caller tells them apart by
// what each handle reaches.
func (q *Quo) Accept(ctx context.Context, inv wire.Invitation, label string) ([]Handle, error) {
	return q.w.Accept(ctx, inv, Accepting{Holder: q.being, Label: label})
}

// Knock turns a card received as data into a handle at the far door's public
// being, held as a stranger. The estate that door shows a stranger is what this
// handle's describe answers with, and nothing else.
func (q *Quo) Knock(card wire.Card, label string) (Handle, error) {
	return q.w.Knock(card, Knocking{Holder: q.being, Label: label})
}

// Reread asks the far door to describe again and rebuilds the handles under a
// label. A standing widened after it was accepted is re-read rather than
// remembered, so what was added is reached by asking rather than by being told.
func (q *Quo) Reread(ctx context.Context, label string) ([]Handle, error) {
	return q.w.Reread(ctx, label)
}

// Hold mints a smaller being beside me and hands back its handle. The minting
// being owns what it minted.
func (q *Quo) Hold(object any, h Holding) ([32]byte, Handle, error) {
	return q.w.Hold(object, h)
}

// Handle is what a being holds to reach someone elsewhere. Every declared
// field is callable, the call may block on the network, and what comes back is
// a value or silence — never an exception the caller can tell apart from a
// refusal.
type Handle interface {
	// Being is the pk this handle reaches.
	Being() [32]byte
	// Fields are the names this handle's blueprint declares.
	Fields() []string
	// Call names a declared field and its arguments as ordinary Go values. The
	// second answer is whether anything came back: false is silence, which
	// means refused, broken or absent with no way to tell which.
	Call(ctx context.Context, field string, args ...any) (any, bool)
	// Seal composes the call without sending it, so a caller that met silence
	// after a write can resend the identical envelope rather than a fresh one.
	Seal(ctx context.Context, field string, args ...any) (*Sealed, error)
	// Send puts a sealed call on its road and waits for the answer.
	Send(ctx context.Context, sealed *Sealed) (any, bool)

	// Describe is the estate the far door shows this voice. A being that could
	// invoke a field but not learn what fields exist would be back to composing
	// envelopes by hand, so the four below are on every handle beside the
	// blueprint's own fields, and each answers a value or silence like any
	// other ask.
	Describe(ctx context.Context) (Estate, bool)
	// Sketch is this being's own: its pk, its class and its heir commitment.
	Sketch(ctx context.Context) (Sketch, bool)
	// Blueprint is the text of a class this voice reaches a being of.
	Blueprint(ctx context.Context, digest [32]byte) (string, bool)
	// Limit is the largest message that door will take.
	Limit(ctx context.Context) (int64, bool)
}

// Sealed is one composed call, held apart from its sending. Every message
// spends a number once, so resending these identical bytes is honoured at most
// once by the far door.
type Sealed struct {
	field    string
	seq      int64
	padlock  [32]byte
	envelope []byte
	deadline int64
	// args is a same-warden call held the same way: there is no envelope
	// because there are no strangers here, and one shape is kept anyway.
	args []any
	kept bool
}

// Seq is the number this call spends.
func (s *Sealed) Seq() int64 { return s.seq }

// Envelope is the sealed bytes, or nothing for a same-warden call.
func (s *Sealed) Envelope() []byte { return slices.Clone(s.envelope) }

// remote is a handle at a being under another warden.
type remoteHandle struct {
	w     *Warden
	row   *outbound
	being [32]byte
	bp    *notation.Blueprint
}

func (w *Warden) remote(row *outbound, being [32]byte, text string) (Handle, error) {
	bp, err := notation.Parse(text)
	if err != nil {
		return nil, err
	}
	return &remoteHandle{w: w, row: row, being: being, bp: bp}, nil
}

func (h *remoteHandle) Being() [32]byte { return h.being }

func (h *remoteHandle) Fields() []string {
	names := make([]string, 0, len(h.bp.Fields))
	for _, f := range h.bp.Fields {
		names = append(names, f.Name)
	}
	return names
}

func (h *remoteHandle) declared(name string) (notation.Field, bool) {
	for _, f := range h.bp.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return notation.Field{}, false
}

func (h *remoteHandle) Seal(ctx context.Context, name string, args ...any) (*Sealed, error) {
	f, ok := h.declared(name)
	if !ok {
		return nil, errors.New("warden: that blueprint declares no such field")
	}
	blob, err := encodeArgs(h.bp, f.Args, args)
	if err != nil {
		return nil, err
	}
	h.w.mu.Lock()
	allowance, err := h.w.allowanceIn(ctx)
	if err != nil {
		h.w.mu.Unlock()
		return nil, err
	}
	message, seq, padlock, err := h.w.compose(h.row, Reach{
		Far:       h.row.warden,
		Being:     &h.being,
		Method:    &envelope.Method{Name: name, Args: blob},
		Allowance: allowance,
	})
	h.w.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return &Sealed{field: name, seq: seq, padlock: padlock, envelope: message, deadline: allowance.Time}, nil
}

func (h *remoteHandle) Send(ctx context.Context, sealed *Sealed) (any, bool) {
	if sealed == nil {
		return nil, false
	}
	f, ok := h.declared(sealed.field)
	if !ok {
		return nil, false
	}
	// A handle keeps its shape whatever the road did — a value or nothing —
	// because a being's code pushing at a peer that went away is not in error.
	// What weather changes is inward: the ground's observer was told the road's
	// fault, and the handle does not go asking whether the being moved, that
	// question needing the very road that just failed.
	answer, weathered := h.w.carry(ctx, h.row, sealed)
	if answer == nil {
		if !weathered {
			h.rehouse(ctx)
		}
		return nil, false
	}
	if f.Answer == nil {
		return nil, true
	}
	if answer.Data == nil {
		return nil, false
	}
	v, err := wire.Decode(h.bp, *f.Answer, answer.Data)
	if err != nil {
		return nil, false
	}
	return v, true
}

func (h *remoteHandle) Call(ctx context.Context, name string, args ...any) (any, bool) {
	sealed, err := h.Seal(ctx, name, args...)
	if err != nil {
		return nil, false
	}
	return h.Send(ctx, sealed)
}

// rehouse is the peer that missed the news finding out for itself. Every ask at
// a departed being is silence, so silence is the whole of the sign a handle
// gets; it asks the old door the one question that door still answers, and
// hands the word back to its own warden by the road news takes. Nothing new is
// on the wire: `moved` is a field the Warden blueprint has always declared, and
// the word is the same bytes the news carried.
//
// The call that met the move is not retried at the new house. It is answered
// silence, as the law says every ask at a departed being is, and the caller
// decides whether to make it again: a call that reached the old door once may
// have been judged there before the being left, and a handle that quietly sent
// it on would spend the caller's write a second time without being asked.
func (h *remoteHandle) rehouse(ctx context.Context) {
	// One migration publishes two words — the old door's and the new house's,
	// which points for the name the being wore before — so a handle that
	// believed one and stopped would still be a house short. It follows the
	// pointer while it points, and no further than pointers: a door that
	// pointed forever would hold the caller for its whole leash.
	for range pointers {
		v, ok := h.w.introspect(ctx, h.row, FieldMoved, h.being)
		if !ok {
			return
		}
		word, err := readWord(v)
		if err != nil {
			return
		}
		h.w.mu.Lock()
		err = h.w.believe(h.row, word, nil)
		if err == nil {
			// The being's identity moved with it, so the handle follows the
			// row: the next call down this same handle names the being by the
			// key the new house minted, which is the only name that stands in
			// a standing there.
			if word.Successor != nil {
				h.being = *word.Successor
			}
			h.w.persist()
		}
		h.w.mu.Unlock()
		if err != nil {
			return
		}
	}
}

// pointers is how many houses deep a handle follows a `moved` word in one call.
// A being that migrated twice while a peer slept left four words behind it, so
// the bound is not two.
const pointers = 8

// The four introspections are ordinary asks at the far door's own being, which
// is what the Warden blueprint declares them as. Nothing here is a second
// mechanism: a describe is the same envelope a call is, addressed to the door
// rather than to the being.

func (h *remoteHandle) Describe(ctx context.Context) (Estate, bool) {
	v, ok := h.w.introspect(ctx, h.row, FieldDescribe, nil)
	if !ok {
		return Estate{}, false
	}
	e, err := readEstate(v)
	if err != nil {
		return Estate{}, false
	}
	return e, true
}

func (h *remoteHandle) Sketch(ctx context.Context) (Sketch, bool) {
	v, ok := h.w.introspect(ctx, h.row, FieldSketch, h.being)
	if !ok {
		return Sketch{}, false
	}
	s, err := readSketch(v)
	if err != nil {
		return Sketch{}, false
	}
	return s, true
}

func (h *remoteHandle) Blueprint(ctx context.Context, digest [32]byte) (string, bool) {
	v, ok := h.w.introspect(ctx, h.row, FieldBlueprint, digest)
	if !ok {
		return "", false
	}
	text, ok := v.(string)
	return text, ok
}

func (h *remoteHandle) Limit(ctx context.Context) (int64, bool) {
	v, ok := h.w.introspect(ctx, h.row, FieldLimit, nil)
	if !ok {
		return 0, false
	}
	limit, ok := v.(int64)
	return limit, ok
}

// carry is the two halves of one remote call after the sealing: the envelope
// handed to delivery, and whatever comes back through the warden's one door.
// The lock is not held across either, because a judgment on this ground may
// itself be what answers.
func (w *Warden) carry(ctx context.Context, row *outbound, sealed *Sealed) (*envelope.Answer, bool) {
	w.mu.Lock()
	if w.delivery == nil {
		w.mu.Unlock()
		return nil, false
	}
	// An ask resent after silence is awaiting again under the number it always
	// spent; a fresh one is already awaiting from the sealing.
	waiting := w.await(row, sealed.seq, sealed.padlock)
	view := Row{Padlock: row.padlock, Hints: slices.Clone(row.hints)}
	delivery := w.delivery
	w.mu.Unlock()

	back, later, fault := delivery.Send(view, sealed.envelope)
	switch {
	case fault != nil:
		// Weather. Nothing left this ground, so the number is spent here
		// alone, and the house is told which road it was.
		w.roadFault(row, sealed.seq, sealed.padlock, fault)
		return nil, true
	case back != nil:
		// A road that answered in its own response: the bytes go in the one
		// entry point like anything else, and settle the ask there.
		w.Arrive(back, nil)
	case !later:
		// The number stays spent, because a message the far door judged spent
		// it there whatever this end does with its own record.
		w.forgoAt(row, sealed.seq, sealed.padlock)
	}
	return waitFor(ctx, waiting, sealed.deadline), false
}

// waitFor is the caller's own deadline: the allowance it sent, in the
// milliseconds the allowance is counted in.
func waitFor(ctx context.Context, waiting chan *heard, deadline int64) *envelope.Answer {
	if waiting == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	timer := time.NewTimer(time.Duration(deadline) * time.Millisecond)
	defer timer.Stop()
	select {
	case got := <-waiting:
		if got == nil {
			return nil
		}
		return &got.answer
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return nil
	}
}

// localHandle is a handle at a being under this same warden. One shape:
// leashed, a value or silence — and no seal, because there are no strangers
// here and no voices. The value still rides through the codec, so a being
// cannot answer a neighbour what it could not answer a stranger.
type localHandle struct {
	w     *Warden
	being [32]byte
}

func (h *localHandle) Being() [32]byte { return h.being }

func (h *localHandle) Fields() []string {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	held, ok := h.w.beings[h.being]
	if !ok || held.bound == nil {
		return nil
	}
	names := make([]string, 0, len(held.bound.bp.Fields))
	for _, f := range held.bound.bp.Fields {
		names = append(names, f.Name)
	}
	return names
}

func (h *localHandle) Seal(ctx context.Context, name string, args ...any) (*Sealed, error) {
	if _, err := h.w.allowanceIn(ctx); err != nil {
		return nil, err
	}
	return &Sealed{field: name, args: args, kept: true}, nil
}

func (h *localHandle) Send(ctx context.Context, sealed *Sealed) (any, bool) {
	if sealed == nil || !sealed.kept {
		return nil, false
	}
	return h.Call(ctx, sealed.field, sealed.args...)
}

func (h *localHandle) Call(ctx context.Context, name string, args ...any) (any, bool) {
	h.w.mu.Lock()
	held, ok := h.w.beings[h.being]
	if !ok || held.bound == nil {
		h.w.mu.Unlock()
		return nil, false
	}
	allowance, err := h.w.allowanceIn(ctx)
	if err != nil {
		h.w.mu.Unlock()
		return nil, false
	}
	bound, arrived, clock := held.bound, h.w.clock(), h.w.clock
	h.w.mu.Unlock()

	f, ok := bound.fields[name]
	if !ok {
		return nil, false
	}
	blob, err := encodeArgs(bound.bp, f.declared.Args, args)
	if err != nil {
		return nil, false
	}
	// Under one warden there are no strangers, so the caller is nobody and only
	// the leash travels. It is the one thing a same-warden call still pays.
	inner := within(ctx, InScope{
		Caller: Caller{Kind: CallerLocal},
		Leash:  Leash{received: allowance, arrived: arrived, clock: clock},
	})
	data, err := bound.invoke(inner, name, blob)
	if err != nil {
		return nil, false
	}
	if f.declared.Answer == nil {
		return nil, true
	}
	v, err := wire.Decode(bound.bp, *f.declared.Answer, data)
	if err != nil {
		return nil, false
	}
	return v, true
}

// The same four answers beside a handle at a neighbour. There is no door to
// ask, so they are read off this warden's own tables — scoped to the one being
// this handle reaches, which is what a standing naming that being alone shows
// at any other door. The leash is still paid, because it is the one thing a
// same-warden call pays.

func (h *localHandle) reach() *inbound {
	return &inbound{beings: map[[32]byte]bool{h.being: true}}
}

func (h *localHandle) held(ctx context.Context) (*held, bool) {
	if _, err := h.w.allowanceIn(ctx); err != nil {
		return nil, false
	}
	one, ok := h.w.beings[h.being]
	return one, ok
}

func (h *localHandle) Describe(ctx context.Context) (Estate, bool) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if _, ok := h.held(ctx); !ok {
		return Estate{}, false
	}
	return h.w.estate(h.reach()), true
}

func (h *localHandle) Sketch(ctx context.Context) (Sketch, bool) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	one, ok := h.held(ctx)
	if !ok {
		return Sketch{}, false
	}
	return Sketch{Being: one.pk, Digest: one.digest, Commitment: one.commitment}, true
}

func (h *localHandle) Blueprint(ctx context.Context, digest [32]byte) (string, bool) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if _, ok := h.held(ctx); !ok {
		return "", false
	}
	if !h.w.declares(h.reach(), digest) {
		return "", false
	}
	return h.w.blueprints[digest], true
}

func (h *localHandle) Limit(ctx context.Context) (int64, bool) {
	h.w.mu.Lock()
	defer h.w.mu.Unlock()
	if _, ok := h.held(ctx); !ok {
		return 0, false
	}
	return h.w.limit, true
}

// allowanceIn is what a walk may be made under from here: the leash in scope,
// shrunk, or the warden's own default when a being starts a walk of its own.
func (w *Warden) allowanceIn(ctx context.Context) (envelope.Allowance, error) {
	if leash := Of(ctx).Leash; leash.clock != nil {
		return leash.Onward()
	}
	return w.allowance, nil
}
