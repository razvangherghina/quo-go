// The Go kit answering the conformance subject contract. It is the second kit
// to answer it, and the first one written by somebody who had only the contract
// and not the JS subject beside them — which is the whole point of it existing.
//
// A subject decides nothing. It stands a warden from handed keys, hands the
// door bytes, and reports the records as Article IX's cargo. Every expectation
// lives in the scenario file.
package main

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/envelope"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

// The two Article II freedoms, handed in as finite queues drawn in order.
// Running one dry is a fault the scenario must hear about: a kit that drew more
// than it was given has said something, and a silent refill would hide it.
type queue[T any] struct {
	name   string
	values []T
	at     int
}

func (q *queue[T]) draw() (T, error) {
	var zero T
	if q.at >= len(q.values) {
		return zero, fmt.Errorf("the %s queue ran out after %d", q.name, len(q.values))
	}
	one := q.values[q.at]
	q.at++
	return one, nil
}

var (
	house  *warden.Warden
	clock  *queue[int64]
	random *queue[[32]byte]
	cells  = map[[32]byte][]byte{}
	// The two keys this door mints for a being it is about to take in: the name
	// it will wear here, and that name's own heir. Article IX, since S-16, says
	// a destination mints both and commits to the first.
	expectedBeing [32]byte
	expectedHeir  [32]byte
	// Every ask this warden composed while judging the message in hand.
	onward [][]byte
	// The roads this door answers on. This kit takes them per call rather than
	// keeping them, so the subject keeps what `stand` was given and hands them
	// back wherever the kit asks for them.
	roads []string
)

// A being that answers nothing. Every exchange in the first scenario is refused
// before step 7, so nothing here is ever invoked — and a subject that supplied
// a clever being would be supplying behaviour the scenario did not ask for.
type quiet struct{}

func (quiet) Invoke(warden.Call) ([]byte, error) { return nil, errors.New("nothing to say") }

// The one thing a being in this contract does. A warden never makes an onward
// ask of its own — it hands the leash to the being it routed to — so a being
// that calls out is the only way Article VIII's onward rules can be reached at
// all. It decides nothing: the scenario named the far warden, the being, the
// method and the ephemeral key, and what this returns is never asserted.
type caller struct {
	when      string
	far       [32]byte
	being     *[32]byte
	method    *envelope.Method
	ephemeral [32]byte
	seq       int64
}

func (c caller) Invoke(call warden.Call) ([]byte, error) {
	if call.Method != c.when {
		return nil, errors.New("nothing to say")
	}
	// The leash the kit handed in, spent as it was handed. Recomputing it here
	// would be the subject doing the arithmetic the case is about.
	leash := call.Leash
	seq := c.seq
	message, _, err := house.Ask(c.ephemeral, warden.Reach{
		Far:    c.far,
		Leash:  &leash,
		Being:  c.being,
		Method: c.method,
		Seq:    &seq,
	})
	// A leash with nothing left to spend composes nothing, and the being
	// answers anyway: Article VIII has the onward ask withheld while "the work
	// already routed stands". A being that failed here would be turning its own
	// kit's refusal into the door's silence.
	if err == nil && message != nil {
		onward = append(onward, message)
	}
	return []byte{}, nil
}

func un(s string) ([32]byte, error) {
	var out [32]byte
	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, err
	}
	if len(raw) != 32 {
		return out, fmt.Errorf("expected 32 bytes, got %d", len(raw))
	}
	copy(out[:], raw)
	return out, nil
}

func hx(b [32]byte) string { return hex.EncodeToString(b[:]) }

// A grant may name no padlock: Article VII has the row keep "the padlock it
// named and the hints it gave" — the voice's — and at grant time the voice has
// said nothing. This kit's Grant takes a value rather than a pointer, so an
// absent padlock is the zero array, which reaches only the invitation this
// scenario never spends.
func orZero(s string) ([32]byte, error) {
	if s == "" {
		return [32]byte{}, nil
	}
	return un(s)
}

type order struct {
	Do     string `json:"do"`
	Warden struct {
		NameSeed       string   `json:"nameSeed"`
		PadlockSeed    string   `json:"padlockSeed"`
		HeirSeed       string   `json:"heirSeed"`
		HeirCommitment string   `json:"heirCommitment"`
		Limit          string   `json:"limit"`
		Hints          []string `json:"hints"`
	} `json:"warden"`
	Beings []struct {
		Seed      string `json:"seed"`
		HeirSeed  string `json:"heirSeed"`
		Blueprint string `json:"blueprint"`
		Cells     string `json:"cells"`
		Onward    *struct {
			When   string `json:"when"`
			At     string `json:"at"`
			Being  string `json:"being"`
			Method *struct {
				Name string `json:"name"`
				Args string `json:"args"`
			} `json:"method"`
			Ephemeral string `json:"ephemeral"`
			Seq       string `json:"seq"`
		} `json:"onward"`
	} `json:"beings"`
	Grants []struct {
		Being     string   `json:"being"`
		VoiceSeed string   `json:"voiceSeed"`
		HeirSeed  string   `json:"heirSeed"`
		Padlock   string   `json:"padlock"`
		Hints     []string `json:"hints"`
	} `json:"grants"`
	Relations []struct {
		Being      string   `json:"being"`
		Warden     string   `json:"warden"`
		Commitment string   `json:"commitment"`
		Padlock    string   `json:"padlock"`
		VoiceSeed  string   `json:"voiceSeed"`
		HeirSeed   string   `json:"heirSeed"`
		Hints      []string `json:"hints"`
	} `json:"relations"`
	Moved []struct {
		Being string `json:"being"`
		Word  struct {
			Being      string   `json:"being"`
			Successor  string   `json:"successor"`
			Commitment string   `json:"commitment"`
			Name       string   `json:"name"`
			Padlock    string   `json:"padlock"`
			Hints      []string `json:"hints"`
		} `json:"word"`
	} `json:"moved"`
	Expecting *struct {
		Seed      string `json:"seed"`
		HeirSeed  string `json:"heirSeed"`
		Blueprint string `json:"blueprint"`
		Cells     string `json:"cells"`
	} `json:"expecting"`
	Clock  []string `json:"clock"`
	Random []string `json:"random"`
	Bytes  string   `json:"bytes"`
	Being  string   `json:"being"`
	At     string   `json:"at"`
	Answer string   `json:"answer"`
	Voice  string   `json:"voice"`
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
	// The commitment `receive` answered, which the origin carries into the
	// first news and cannot invent.
	Commitment string `json:"commitment"`
	// The roads this door answers on, for a kit that takes them per call.
	Hints []string `json:"hints"`
	// Where a departing being answers now: the new door's name, its padlock and
	// its roads, which are three fields of the `word` the kit composes.
	Gone *struct {
		Name    string   `json:"name"`
		Padlock string   `json:"padlock"`
		Hints   []string `json:"hints"`
	} `json:"gone"`
	// One piece of news per peer: the key it seals with and the number it
	// spends against that peer's own mark.
	News []struct {
		Ephemeral string `json:"ephemeral"`
		Seq       string `json:"seq"`
		Allowance struct {
			Time string `json:"time"`
			Hops string `json:"hops"`
		} `json:"allowance"`
	} `json:"news"`
	// The house moving its own name. This kit is the one that never sees the
	// next heir's key, so it takes the commitment and ignores the seed beside
	// it; both name one heir.
	NameSeed       string `json:"nameSeed"`
	HeirSeed       string `json:"heirSeed"`
	HeirCommitment string `json:"heirCommitment"`
	Ask            struct {
		At         string `json:"at"`
		Being      string `json:"being"`
		Commitment string `json:"commitment"`
		Seq        string `json:"seq"`
		Allowance  struct {
			Time string `json:"time"`
			Hops string `json:"hops"`
		} `json:"allowance"`
		Method *struct {
			Name string `json:"name"`
			Args string `json:"args"`
		} `json:"method"`
	} `json:"ask"`
}

func stand(o order) (any, error) {
	nameSeed, err := un(o.Warden.NameSeed)
	if err != nil {
		return nil, err
	}
	padlockSeed, err := un(o.Warden.PadlockSeed)
	if err != nil {
		return nil, err
	}
	// This kit takes the warden's own heir as a commitment rather than a seed,
	// because the owner's heir is held outside the runner's reach (Article
	// XIII). The contract supplies both and says why; a subject takes whichever
	// its kit's founding wants.
	heirCommitment, err := un(o.Warden.HeirCommitment)
	if err != nil {
		return nil, err
	}
	limit, err := strconv.ParseInt(o.Warden.Limit, 10, 64)
	if err != nil {
		return nil, err
	}
	clock = &queue[int64]{name: "clock"}
	for _, one := range o.Clock {
		reading, err := strconv.ParseInt(one, 10, 64)
		if err != nil {
			return nil, err
		}
		clock.values = append(clock.values, reading)
	}
	random = &queue[[32]byte]{name: "random"}
	for _, one := range o.Random {
		draw, err := un(one)
		if err != nil {
			return nil, err
		}
		random.values = append(random.values, draw)
	}
	house, err = warden.New(warden.Founding{
		NameSecret:     nameSeed,
		HeirCommitment: heirCommitment,
		PadlockSecret:  padlockSeed,
		Limit:          limit,
		Clock: func() int64 {
			reading, err := clock.draw()
			if err != nil {
				// A clock that has run dry cannot be reported from inside a
				// func() int64, so it stops the process rather than quietly
				// repeating a reading and making a scenario pass on a lie.
				fmt.Fprintln(os.Stderr, "subject:", err)
				os.Exit(1)
			}
			return reading
		},
	})
	if err != nil {
		return nil, err
	}
	roads = o.Warden.Hints
	if roads == nil {
		roads = []string{}
	}
	cells = map[[32]byte][]byte{}
	beings := []string{}
	for _, one := range o.Beings {
		seed, err := un(one.Seed)
		if err != nil {
			return nil, err
		}
		heirSeed, err := un(one.HeirSeed)
		if err != nil {
			return nil, err
		}
		var object warden.Being = quiet{}
		if one.Onward != nil {
			far, err := un(one.Onward.At)
			if err != nil {
				return nil, err
			}
			ephemeral, err := un(one.Onward.Ephemeral)
			if err != nil {
				return nil, err
			}
			seq, err := strconv.ParseInt(one.Onward.Seq, 10, 64)
			if err != nil {
				return nil, err
			}
			acts := caller{when: one.Onward.When, far: far, ephemeral: ephemeral, seq: seq}
			if one.Onward.Being != "" {
				at, err := un(one.Onward.Being)
				if err != nil {
					return nil, err
				}
				acts.being = &at
			}
			if one.Onward.Method != nil {
				args, err := hex.DecodeString(one.Onward.Method.Args)
				if err != nil {
					return nil, err
				}
				acts.method = &envelope.Method{Name: one.Onward.Method.Name, Args: args}
			}
			object = acts
		}
		pk, err := house.Hold(one.Blueprint, object, warden.Keys{Secret: seed, HeirSecret: heirSeed})
		if err != nil {
			return nil, err
		}
		raw, err := hex.DecodeString(one.Cells)
		if err != nil {
			return nil, err
		}
		cells[pk] = raw
		beings = append(beings, hx(pk))
	}
	grants := []map[string]string{}
	for _, one := range o.Grants {
		being, err := un(one.Being)
		if err != nil {
			return nil, err
		}
		voiceSeed, err := un(one.VoiceSeed)
		if err != nil {
			return nil, err
		}
		heirSeed, err := un(one.HeirSeed)
		if err != nil {
			return nil, err
		}
		padlock, err := orZero(one.Padlock)
		if err != nil {
			return nil, err
		}
		inv, err := house.Grant(being, warden.Keys{Secret: voiceSeed, HeirSecret: heirSeed}, padlock, one.Hints)
		if err != nil {
			return nil, err
		}
		grants = append(grants, map[string]string{
			"warden":     hx(inv.Warden),
			"commitment": hx(inv.Commitment),
			"padlock":    hx(inv.Padlock),
			"heir":       hx(inv.Heir),
		})
	}
	expectedBeing, expectedHeir = [32]byte{}, [32]byte{}
	if o.Expecting != nil {
		seed, err := un(o.Expecting.Seed)
		if err != nil {
			return nil, err
		}
		heirSeed, err := un(o.Expecting.HeirSeed)
		if err != nil {
			return nil, err
		}
		expectedBeing, expectedHeir = seed, heirSeed
		// A door that cannot make a being of the arriving class refuses the
		// cargo, so the class is welcomed before the receive can land. The
		// keys stay in the draws, where every draw this kit takes is handed.
		if _, err := house.Welcome(o.Expecting.Blueprint, func([]byte) (warden.Being, error) {
			return quiet{}, nil
		}); err != nil {
			return nil, err
		}
	}
	// The beings that have gone, and the succession this door published for
	// each. An absent field of the `word` stays absent.
	for _, one := range o.Moved {
		being, err := un(one.Being)
		if err != nil {
			return nil, err
		}
		word := warden.Word{Hints: one.Word.Hints}
		for _, field := range []struct {
			raw  string
			into **[32]byte
		}{
			{one.Word.Being, &word.Being},
			{one.Word.Successor, &word.Successor},
			{one.Word.Commitment, &word.Commitment},
			{one.Word.Name, &word.Name},
			{one.Word.Padlock, &word.Padlock},
		} {
			if field.raw == "" {
				continue
			}
			key, err := un(field.raw)
			if err != nil {
				return nil, err
			}
			*field.into = &key
		}
		house.Publish(being, word)
	}
	// The outbound rows: invitations this ground holds at other houses, each
	// held by the being that may spend it.
	for _, one := range o.Relations {
		holder, err := un(one.Being)
		if err != nil {
			return nil, err
		}
		far, err := un(one.Warden)
		if err != nil {
			return nil, err
		}
		commitment, err := un(one.Commitment)
		if err != nil {
			return nil, err
		}
		padlock, err := un(one.Padlock)
		if err != nil {
			return nil, err
		}
		voiceSeed, err := un(one.VoiceSeed)
		if err != nil {
			return nil, err
		}
		heirSeed, err := un(one.HeirSeed)
		if err != nil {
			return nil, err
		}
		house.Stand(holder, wire.Invitation{
			Warden:     far,
			Commitment: commitment,
			Padlock:    padlock,
			Heir:       arithmetic.SigningKey(heirSeed),
			HeirSecret: heirSeed,
			Hints:      one.Hints,
		}, voiceSeed)
	}
	return map[string]any{
		"warden": map[string]string{"name": hx(house.Name()), "padlock": hx(house.Padlock())},
		"beings": beings,
		"grants": grants,
	}, nil
}

// The caller's half: one ask composed down an outbound row. Nil bytes are a
// refusal to send, which Article III makes an ordinary outcome, never an error.
func send(o order) (any, error) {
	far, err := un(o.Ask.At)
	if err != nil {
		return nil, err
	}
	seq, err := strconv.ParseInt(o.Ask.Seq, 10, 64)
	if err != nil {
		return nil, err
	}
	budget, err := strconv.ParseInt(o.Ask.Allowance.Time, 10, 64)
	if err != nil {
		return nil, err
	}
	hops, err := strconv.ParseInt(o.Ask.Allowance.Hops, 10, 64)
	if err != nil {
		return nil, err
	}
	ephemeral, err := random.draw()
	if err != nil {
		return nil, err
	}
	// The number the scenario named is handed to the kit. Article VIII gives
	// the choice to the caller — "which number a caller opens with, above one,
	// is the caller's own" — and the caller here is the scenario.
	reach := warden.Reach{
		Far:       far,
		Allowance: envelope.Allowance{Time: budget, Hops: hops},
		Seq:       &seq,
	}
	if o.Ask.Being != "" {
		being, err := un(o.Ask.Being)
		if err != nil {
			return nil, err
		}
		reach.Being = &being
	}
	if o.Ask.Method != nil {
		args, err := hex.DecodeString(o.Ask.Method.Args)
		if err != nil {
			return nil, err
		}
		reach.Method = &envelope.Method{Name: o.Ask.Method.Name, Args: args}
	}
	message, _, err := house.Ask(ephemeral, reach)
	if err != nil || message == nil {
		return map[string]any{"bytes": nil}, nil
	}
	return map[string]any{"bytes": hex.EncodeToString(message)}, nil
}

// And the caller's other half: one answer judged at this end. A nil answer is
// the whole of what any failed check looks like.
func read(o order) (any, error) {
	message, err := hex.DecodeString(o.Answer)
	if err != nil {
		return nil, err
	}
	asked, err := un(o.At)
	if err != nil {
		return nil, err
	}
	answer, err := house.Hear(house.PadlockSecret(), message)
	if err != nil {
		return map[string]any{"answer": nil}, nil
	}
	// Article XI names two checks and this kit's Hear runs the first. The
	// second — that the warden the record carries is the warden the ask was
	// sent to — is the caller's own, so the subject cannot make it and must not
	// fake it: it reports what the kit handed back.
	_ = asked
	var data any
	if answer.Data != nil {
		data = hex.EncodeToString(answer.Data)
	}
	return map[string]any{
		"answer": map[string]any{
			"warden": hx(answer.Warden),
			"seq":    strconv.FormatInt(answer.Seq, 10),
			"data":   data,
		},
	}, nil
}

func door(o order) (any, error) {
	message, err := hex.DecodeString(o.Bytes)
	if err != nil {
		return nil, err
	}
	ephemeral, err := random.draw()
	if err != nil {
		return nil, err
	}
	// The heir is not drawn from the queue: this kit takes it per judgment and
	// only a `receive` spends it, so drawing one per message would make how far
	// the queue ran depend on which route a call took — and no scenario asserts
	// a draw count precisely because kits differ there. It comes from
	// `expecting` instead, which is where the contract puts the keys a door
	// mints for a being it is taking in.
	onward = nil
	answer, _ := house.Judge(
		warden.Draws{Ephemeral: ephemeral, Being: expectedBeing, Heir: expectedHeir},
		message,
	)
	composed := []string{}
	for _, one := range onward {
		composed = append(composed, hex.EncodeToString(one))
	}
	if answer == nil {
		return map[string]any{"answer": nil, "onward": composed}, nil
	}
	return map[string]any{"answer": hex.EncodeToString(answer), "onward": composed}, nil
}

// The house changing its own mind about a standing. Nothing crosses and
// nothing is spent. This kit spells it as two calls where the JS one spells it
// as a single amend — the contract fixes the effect, not the spelling, and
// Narrow releases the row when the last being goes because Article VII has no
// separate act for release.
func amend(o order) (any, error) {
	voice, err := un(o.Voice)
	if err != nil {
		return nil, err
	}
	for _, one := range o.Add {
		being, err := un(one)
		if err != nil {
			return nil, err
		}
		if err := house.Widen(voice, being); err != nil {
			return nil, err
		}
	}
	for _, one := range o.Remove {
		being, err := un(one)
		if err != nil {
			return nil, err
		}
		if err := house.Narrow(voice, being); err != nil {
			return nil, err
		}
	}
	return map[string]any{}, nil
}

// The house moving its own name. Nothing crosses and nothing is spent; every
// standing stays where it is, keeping the name its own commitment was minted
// under, and the door is addressed by the successor from here on.
func succeed(o order) (any, error) {
	nameSecret, err := un(o.NameSeed)
	if err != nil {
		return nil, err
	}
	commitment, err := un(o.HeirCommitment)
	if err != nil {
		return nil, err
	}
	if err := house.Succeed(nameSecret, commitment); err != nil {
		return nil, err
	}
	return map[string]any{}, nil
}

// One piece of news per peer, each sealed with the key it was handed and
// spending the number it was given. A peer that left no way back composes
// nothing, which the kit decides and this only passes on.
func told(word warden.Word, voice, secret [32]byte, peers []warden.Peer, o order) (any, error) {
	out := []string{}
	for at, peer := range peers {
		if at >= len(o.News) {
			break
		}
		one := o.News[at]
		ephemeral, err := un(one.Ephemeral)
		if err != nil {
			return nil, err
		}
		seq, err := strconv.ParseInt(one.Seq, 10, 64)
		if err != nil {
			return nil, err
		}
		time, err := strconv.ParseInt(one.Allowance.Time, 10, 64)
		if err != nil {
			return nil, err
		}
		hops, err := strconv.ParseInt(one.Allowance.Hops, 10, 64)
		if err != nil {
			return nil, err
		}
		sealed, err := house.News(ephemeral, warden.Tell{
			Peer:        peer,
			Voice:       voice,
			VoiceSecret: secret,
			Word:        word,
			Seq:         seq,
			Allowance:   envelope.Allowance{Time: time, Hops: hops},
			Hints:       roads,
		})
		if err != nil {
			continue
		}
		out = append(out, hex.EncodeToString(sealed))
	}
	return map[string]any{"news": out}, nil
}

// The origin's half of a migration's news. The word is the kit's: this only
// says which being left, which key it committed to, and where it went.
func depart(o order) (any, error) {
	being, err := un(o.Being)
	if err != nil {
		return nil, err
	}
	heir, err := un(o.HeirSeed)
	if err != nil {
		return nil, err
	}
	commitment, err := un(o.Commitment)
	if err != nil {
		return nil, err
	}
	if o.Gone == nil {
		return nil, errors.New("a departure that does not say where the being went")
	}
	name, err := un(o.Gone.Name)
	if err != nil {
		return nil, err
	}
	padlock, err := un(o.Gone.Padlock)
	if err != nil {
		return nil, err
	}
	hints := o.Gone.Hints
	if hints == nil {
		hints = []string{}
	}
	gone, err := house.Depart(being, warden.Departing{
		HeirSecret: heir,
		Commitment: commitment,
		Name:       name,
		Padlock:    padlock,
		Hints:      hints,
	})
	if err != nil {
		return nil, err
	}
	return told(gone.Word, gone.Voice, gone.VoiceSecret, gone.Peers, o)
}

// The destination's half, after a cargo has arrived. Everything it needs
// already arrived; this kit takes the roads it answers on per call, so those
// are handed back to it.
func landed(o order) (any, error) {
	hints := o.Hints
	if hints == nil {
		hints = []string{}
	}
	here, ok := house.Landed(hints)
	if !ok {
		return nil, errors.New("nothing has arrived at this door")
	}
	return told(here.Word, here.Being, here.BeingSecret, here.Peers, o)
}

func state(o order) (any, error) {
	being, err := un(o.Being)
	if err != nil {
		return nil, err
	}
	cargo, err := house.Pack(being, cells[being])
	if err != nil {
		// A being this door does not hold has no record, which is a `null`
		// cargo and not an error: a destination waiting for a migration is
		// asked about a being that has not arrived yet, and "no record" is the
		// true answer rather than a fault in the run.
		return map[string]any{"cargo": nil, "cannot": []string{}}, nil
	}
	standings := []map[string]any{}
	for _, row := range cargo.Standings {
		// The readout names the being by the name this door holds it under,
		// which is the name the run asked about. A cargo is packed under the
		// name the first of a migration's two rotations gives the being, so
		// what travels is not what a door reading its own record calls it.
		beings := make([]string, 0, len(row.Beings))
		for range row.Beings {
			beings = append(beings, hx(being))
		}
		sort.Strings(beings)
		spent := []string{}
		for _, one := range row.Spent {
			spent = append(spent, strconv.FormatInt(one, 10))
		}
		var padlock any
		if row.Padlock != nil {
			padlock = hx(*row.Padlock)
		}
		hints := row.Hints
		if hints == nil {
			hints = []string{}
		}
		standings = append(standings, map[string]any{
			"voice":      hx(row.Voice),
			"commitment": hx(row.Commitment),
			// Article IX's `standing.name` — the door name this heir
			// commitment was hashed under.
			"name":    hx(row.Name),
			"beings":  beings,
			"mark":    strconv.FormatInt(row.Mark, 10),
			"spent":   spent,
			"padlock": padlock,
			"hints":   hints,
		})
	}
	sort.Slice(standings, func(i, j int) bool {
		return standings[i]["voice"].(string) < standings[j]["voice"].(string)
	})
	relations := []map[string]any{}
	for _, rel := range cargo.Relations {
		hints := rel.Hints
		if hints == nil {
			hints = []string{}
		}
		relations = append(relations, map[string]any{
			"warden":     hx(rel.Warden),
			"commitment": hx(rel.Commitment),
			"padlock":    hx(rel.Padlock),
			"voice":      hx(rel.Voice),
			"heir":       hx(rel.Heir),
			"seq":        strconv.FormatInt(rel.Seq, 10),
			// Article IX's `relation.news`, the mark kept for that far
			// warden's news, split from `seq`.
			"news":  strconv.FormatInt(rel.News, 10),
			"hints": hints,
		})
	}
	return map[string]any{
		"cargo": map[string]any{
			"being":     hx(being),
			"digest":    hx(cargo.Digest),
			"cells":     hex.EncodeToString(cargo.Cells),
			"standings": standings,
			"relations": relations,
		},
		// The facts this kit cannot report at all, declared rather than left to
		// be read off a null. This kit now carries every Article IX field its
		// cargo declares, so the list is empty and a null anywhere is a real
		// value.
		"cannot": []string{},
	}, nil
}

func obey(o order) any {
	verbs := map[string]func(order) (any, error){
		"stand":   stand,
		"door":    door,
		"state":   state,
		"send":    send,
		"read":    read,
		"amend":   amend,
		"succeed": succeed,
		"depart":  depart,
		"landed":  landed,
	}
	verb, ok := verbs[o.Do]
	if !ok {
		return map[string]string{"error": "no such verb: " + o.Do}
	}
	out, err := verb(o)
	if err != nil {
		return map[string]string{"error": err.Error()}
	}
	return out
}

func main() {
	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 1<<20), 1<<24)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var o order
		if err := json.Unmarshal(line, &o); err != nil {
			fmt.Fprintln(os.Stderr, "subject:", err)
			os.Exit(1)
		}
		encoded, err := json.Marshal(obey(o))
		if err != nil {
			fmt.Fprintln(os.Stderr, "subject:", err)
			os.Exit(1)
		}
		out.Write(encoded)
		out.WriteByte('\n')
		out.Flush()
	}
}
