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

	"quo.systems/kit/warden"
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
)

// A being that answers nothing. Every exchange in the first scenario is refused
// before step 7, so nothing here is ever invoked — and a subject that supplied
// a clever being would be supplying behaviour the scenario did not ask for.
type quiet struct{}

func (quiet) Invoke(warden.Call) ([]byte, error) { return nil, errors.New("nothing to say") }

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
	} `json:"beings"`
	Grants []struct {
		Being     string   `json:"being"`
		VoiceSeed string   `json:"voiceSeed"`
		HeirSeed  string   `json:"heirSeed"`
		Padlock   string   `json:"padlock"`
		Hints     []string `json:"hints"`
	} `json:"grants"`
	Clock  []string `json:"clock"`
	Random []string `json:"random"`
	Bytes  string   `json:"bytes"`
	Being  string   `json:"being"`
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
		pk, err := house.Hold(one.Blueprint, quiet{}, warden.Keys{Secret: seed, HeirSecret: heirSeed})
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
	return map[string]any{
		"warden": map[string]string{"name": hx(house.Name()), "padlock": hx(house.Padlock())},
		"beings": beings,
		"grants": grants,
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
	answer, _ := house.Judge(warden.Draws{Ephemeral: ephemeral}, message)
	if answer == nil {
		return map[string]any{"answer": nil}, nil
	}
	return map[string]any{"answer": hex.EncodeToString(answer)}, nil
}

func state(o order) (any, error) {
	being, err := un(o.Being)
	if err != nil {
		return nil, err
	}
	cargo, err := house.Pack(being, cells[being])
	if err != nil {
		return nil, err
	}
	standings := []map[string]any{}
	for _, row := range cargo.Standings {
		beings := []string{}
		for _, one := range row.Beings {
			beings = append(beings, hx(one))
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
			// Article IX's `standing.name` — the name the heir commitment was
			// minted under. This kit keeps it in memory but its cargo does not
			// carry it and nothing exports it, so the honest answer is null.
			// Null is a gap the runner reports, never a value it accepts.
			"name":    nil,
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
			// Article IX's `relation.news`, split from `seq`. This kit has no
			// such field yet, so null rather than a zero that would read as
			// agreement.
			"news":  nil,
			"hints": hints,
		})
	}
	return map[string]any{
		"cargo": map[string]any{
			"being":     hx(cargo.Being),
			"digest":    hx(cargo.Digest),
			"cells":     hex.EncodeToString(cargo.Cells),
			"standings": standings,
			"relations": relations,
		},
		// The facts this kit cannot report at all, declared rather than left to
		// be read off a null. Both are Article IX fields its cargo does not
		// carry: the name a commitment was minted under, and the news mark kept
		// apart from the seq. A null anywhere else is a real value.
		"cannot": []string{"standings.*.name", "relations.*.news"},
	}, nil
}

func obey(o order) any {
	verbs := map[string]func(order) (any, error){
		"stand": stand,
		"door":  door,
		"state": state,
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
