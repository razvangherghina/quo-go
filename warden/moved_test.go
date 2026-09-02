package warden_test

import (
	"testing"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
)

// The peer that missed the news. Article XIII leaves the old door pointing so
// that peer is not stranded, and the word it answers is the word the news
// carried. What is asserted here is the other end of that: a handle that meets
// the word believes it by the steps news is believed by, so the peer is
// rehoused without a new invitation and without anybody telling it anything.

// dogFrom is what a house that welcomes Dogs makes one with. A name is not in
// the cells, so a being that arrives is named by the house that took it in.
func dogFrom(cells []byte) (any, error) {
	d := &Dog{dogName: "Rex"}
	if len(cells) == 0 {
		return d, nil
	}
	if err := d.Take(cells); err != nil {
		return nil, err
	}
	return d, nil
}

// migration is one being moved from one house to another with two peers
// standing at it, and both news held back. Everything a case here needs is on
// it, so each case says only what it is about.
type migration struct {
	t                  *testing.T
	origin, dest, peer *warden.Warden
	// missed holds a handle at the being and was never told anything.
	missed warden.Handle
	// told is the second peer, which hears both pieces of news.
	told       *warden.Warden
	toldHandle warden.Handle
	rex        [32]byte
	// arrived is the name the destination minted for the being.
	arrived  [32]byte
	first    warden.Departed
	second   warden.Arrival
	firstTo  []warden.Peer
	secondTo []warden.Peer
}

func migrated(t *testing.T) *migration {
	t.Helper()
	d := warden.NewMemory()
	at := func(label, hint string) *warden.Warden {
		w := housed(t, label, d)
		d.Attach(hint, w)
		w.Publish(hint)
		return w
	}
	m := &migration{
		t:      t,
		origin: at("moved/origin", "mem://origin"),
		dest:   at("moved/dest", "mem://dest"),
		peer:   at("moved/peer", "mem://peer"),
		told:   at("moved/told", "mem://told"),
	}

	// The destination can make a being of the class, which is what lets one
	// migrate there at all.
	if _, err := m.dest.Welcome(dogText, dogFrom); err != nil {
		t.Fatal(err)
	}
	rex := &Dog{dogName: "Rex"}
	being, _, err := m.origin.Hold(rex, warden.Holding{
		Blueprint: dogText,
		Keys:      warden.Keys{Secret: secret("moved/rex"), HeirSecret: secret("moved/rexHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	m.rex = being

	// Two peers, each standing at the being with a handle of its own. The
	// accept is what leaves each holding the being's heir commitment, which is
	// the material a succession is believed with.
	stand := func(w *warden.Warden, label string) warden.Handle {
		t.Helper()
		inv, err := m.origin.GrantAs(being,
			warden.Keys{Secret: secret("moved/" + label), HeirSecret: secret("moved/" + label + "Heir")},
			m.origin.Padlock(), []string{"mem://origin"})
		if err != nil {
			t.Fatal(err)
		}
		h, err := sole(w.Accept(ctx(), inv, warden.Accepting{Label: "rex"}))
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	m.missed = stand(m.peer, "voiceA")
	m.toldHandle = stand(m.told, "voiceB")

	// Both reach the being where it stands now.
	for _, h := range []warden.Handle{m.missed, m.toldHandle} {
		if v, ok := h.Call(ctx(), "logWalk", int64(7)); !ok || v != true {
			t.Fatalf("the being did not answer before it moved: %v %v", v, ok)
		}
	}

	// The destination's half. The origin needs a standing there to push the
	// cargo through the ordinary gate, and nothing about a receive waives one.
	gate, _, err := m.dest.Hold(&Profile{}, warden.Holding{
		Blueprint: profileText,
		Keys:      warden.Keys{Secret: secret("moved/gate"), HeirSecret: secret("moved/gateHeir")},
	})
	if err != nil {
		t.Fatal(err)
	}
	inv, err := m.dest.GrantAs(gate,
		warden.Keys{Secret: secret("moved/pusher"), HeirSecret: secret("moved/pusherHeir")},
		m.dest.Padlock(), []string{"mem://dest"})
	if err != nil {
		t.Fatal(err)
	}
	m.origin.Stand(m.origin.Self(), inv, inv.HeirSecret)

	cargo, err := m.origin.Pack(being, rex.Cells())
	if err != nil {
		t.Fatal(err)
	}
	packed, err := warden.EncodeCargo(cargo)
	if err != nil {
		t.Fatal(err)
	}
	destSelf := m.dest.Self()
	// The standing is taken over on the way in, as any first message down a
	// fresh invitation is.
	next := secret("moved/pusherNext")
	message, _, err := m.origin.Ask(warden.Reach{
		Far:       m.dest.Name(),
		Being:     &destSelf,
		Method:    &envelope.Method{Name: warden.FieldReceive, Args: packed},
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &next,
	})
	if err != nil {
		t.Fatal(err)
	}
	reply := m.dest.Arrive(message, nil)
	if reply == nil {
		t.Fatal("the destination refused the cargo")
	}
	answered, err := m.origin.Hear(reply)
	if err != nil {
		t.Fatal(err)
	}
	var commitment [32]byte
	if len(answered.Data) != 32 {
		t.Fatalf("receive answered %d bytes where a commitment was due", len(answered.Data))
	}
	copy(commitment[:], answered.Data)

	landed, ok := m.dest.Landed([]string{"mem://dest"})
	if !ok {
		t.Fatal("the destination has nothing to say about the being it took in")
	}
	m.second, m.arrived, m.secondTo = landed, landed.Being, landed.Peers

	departed, err := m.origin.Depart(being, warden.Departing{
		HeirSecret: secret("moved/rexHeir"),
		Commitment: commitment,
		Name:       m.dest.Name(),
		Padlock:    m.dest.Padlock(),
		Hints:      []string{"mem://dest"},
	})
	if err != nil {
		t.Fatal(err)
	}
	m.first, m.firstTo = departed, departed.Peers
	return m
}

// news puts one piece of news at one peer, which is what the peer that missed
// it never gets.
func (m *migration) news(w *warden.Warden) {
	m.t.Helper()
	find := func(peers []warden.Peer) warden.Peer {
		m.t.Helper()
		for _, one := range peers {
			padlock := w.Padlock()
			if one.Padlock != nil && *one.Padlock == padlock {
				return one
			}
		}
		m.t.Fatal("that peer is not among the ones the migration names")
		return warden.Peer{}
	}
	first, err := m.origin.News(warden.Tell{
		Peer: find(m.firstTo), Voice: m.first.Voice, VoiceSecret: m.first.VoiceSecret,
		Word: m.first.Word, Seq: 1, Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	})
	if err != nil {
		m.t.Fatal(err)
	}
	if w.Arrive(first, nil) == nil {
		m.t.Fatal("the peer met the first news with silence")
	}
	second, err := m.dest.News(warden.Tell{
		Peer: find(m.secondTo), Voice: m.second.Being, VoiceSecret: m.second.BeingSecret,
		Word: m.second.Word, Seq: 1, Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		Hints: []string{"mem://dest"},
	})
	if err != nil {
		m.t.Fatal(err)
	}
	if w.Arrive(second, nil) == nil {
		m.t.Fatal("the peer met the second news with silence")
	}
}

// stands is where a peer's relation points, as the peer itself reads it.
func stands(t *testing.T, w *warden.Warden, far [32]byte) (padlock [32]byte, held bool) {
	t.Helper()
	_, _, padlock, _, ok := w.RelationAt(far)
	return padlock, ok
}

// TestAPeerThatMissedTheNewsIsRehousedByTheWordItMeets is the whole of the
// promise. The peer is told nothing; it calls, meets the silence every ask at a
// departed being meets, and comes out of that call standing at the new house
// with no new invitation anywhere.
func TestAPeerThatMissedTheNewsIsRehousedByTheWordItMeets(t *testing.T) {
	m := migrated(t)

	// Before the call the peer still stands at the house the being left.
	if _, ok := stands(t, m.peer, m.origin.Name()); !ok {
		t.Fatal("the peer does not stand at the origin")
	}
	if _, ok := stands(t, m.peer, m.dest.Name()); ok {
		t.Fatal("the peer stands at the destination before it has heard anything")
	}

	// The call that met the move is silence, as every ask at a departed being
	// is. It is not retried at the new house.
	if _, ok := m.missed.Call(ctx(), "logWalk", int64(11)); ok {
		t.Fatal("the call that met the move was answered")
	}

	// And the row followed the being: the peer now stands at the destination,
	// sealing to its padlock.
	padlock, ok := stands(t, m.peer, m.dest.Name())
	if !ok {
		t.Fatal("the row did not follow the being")
	}
	if padlock != m.dest.Padlock() {
		t.Fatal("the row stands at the destination under the wrong lock")
	}
	if _, ok := stands(t, m.peer, m.origin.Name()); ok {
		t.Fatal("the row still stands at the house the being left")
	}

	// The next call down the same handle reaches the new house, and the being
	// there is the one that travelled: its cells came with it.
	if v, ok := m.missed.Call(ctx(), "logWalk", int64(11)); !ok || v != true {
		t.Fatalf("the next call did not reach the new house: %v %v", v, ok)
	}
	if v, ok := m.missed.Call(ctx(), "name"); !ok || v.(string) != "Rex" {
		t.Fatalf("the being at the new house answered %v %v", v, ok)
	}
}

// TestAWordTheRowCannotBelieveRehousesNothing is the refusal, asserted as
// strictly as the acceptance. A pointer is believed by hashing the successor
// against the commitment the row holds, and a word naming a key that hashes to
// nothing held here moves nothing — the peer is left where it was, which is
// standing at a door that answers it silence.
func TestAWordTheRowCannotBelieveRehousesNothing(t *testing.T) {
	m := migrated(t)

	// The old door points with a word about the right being, naming a
	// successor nobody ever committed to.
	impostor := arithmetic.SigningKey(secret("moved/impostor"))
	commitment := arithmetic.Commit(m.dest.Name(), arithmetic.SigningKey(secret("moved/impostorHeir")))
	name, padlock := m.dest.Name(), m.dest.Padlock()
	m.origin.Point(m.rex, warden.Word{
		Being: &m.rex, Successor: &impostor, Commitment: &commitment,
		Name: &name, Padlock: &padlock, Hints: []string{"mem://dest"},
	})

	if _, ok := m.missed.Call(ctx(), "logWalk", int64(11)); ok {
		t.Fatal("the call that met the move was answered")
	}
	if _, ok := stands(t, m.peer, m.dest.Name()); ok {
		t.Fatal("a word the row cannot believe rehoused it")
	}
	if _, ok := stands(t, m.peer, m.origin.Name()); !ok {
		t.Fatal("a refused word moved the relation off the house it stood at")
	}
	// And the handle still names the being it always named, so nothing about
	// it moved either.
	if m.missed.Being() != m.rex {
		t.Fatal("a refused word moved the handle")
	}
}

// TestAWordAlreadyBelievedRehousesNothingAgain is the replay. A succession
// spends the commitment the row holds for that being: believed once, there is
// nothing left for the same word to hash against, so a door that pointed with
// it a second time moves nothing.
func TestAWordAlreadyBelievedRehousesNothingAgain(t *testing.T) {
	m := migrated(t)
	if _, ok := m.missed.Call(ctx(), "logWalk", int64(11)); ok {
		t.Fatal("the call that met the move was answered")
	}
	if v, ok := m.missed.Call(ctx(), "logWalk", int64(11)); !ok || v != true {
		t.Fatalf("the peer was not rehoused: %v %v", v, ok)
	}
	padlock, ok := stands(t, m.peer, m.dest.Name())
	if !ok {
		t.Fatal("the peer does not stand at the destination")
	}
	at := m.missed.Being()

	// The new house points for the name the being wears there, with the word
	// the peer has already believed.
	m.dest.Point(at, m.first.Word)
	if _, ok := m.missed.Call(ctx(), "logWalk", int64(12)); ok {
		t.Fatal("a being the door points about answered")
	}
	if now, ok := stands(t, m.peer, m.dest.Name()); !ok || now != padlock {
		t.Fatal("a word already believed moved the relation a second time")
	}
	if m.missed.Being() != at {
		t.Fatal("a word already believed moved the handle a second time")
	}
}

// TestAPeerThatHeardTheNewsIsNotMovedTwice holds the two roads apart. News and
// the pointer say the same thing, so a peer that took the first has nothing
// left to take from the second: it reaches the being directly, meets no word,
// and its row is what the news left it.
func TestAPeerThatHeardTheNewsIsNotMovedTwice(t *testing.T) {
	m := migrated(t)
	m.news(m.told)

	padlock, ok := stands(t, m.told, m.dest.Name())
	if !ok {
		t.Fatal("the news did not move the row")
	}
	// The standing is at the being by the name the destination minted, so the
	// peer reads its handles off the door it now stands at.
	handles, err := m.told.Reread(ctx(), "rex")
	if err != nil {
		t.Fatal(err)
	}
	h, err := sole(handles, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h.Being() != m.arrived {
		t.Fatal("the peer that heard the news does not reach the being by the name the new house minted")
	}
	if v, ok := h.Call(ctx(), "logWalk", int64(13)); !ok || v != true {
		t.Fatalf("the peer that heard the news met silence: %v %v", v, ok)
	}
	if now, ok := stands(t, m.told, m.dest.Name()); !ok || now != padlock {
		t.Fatal("the row moved again for a peer that had already heard it")
	}
	if _, ok := stands(t, m.told, m.origin.Name()); ok {
		t.Fatal("the peer that heard the news still stands at the house the being left")
	}
}
