// Command subject is a Quo ground another language can knock on, and knock
// with. It exists so a kit written from the law in one language can be shown
// to speak to a kit written from the law in another, with neither side ever
// reading the other's source.
//
// Two modes.
//
// Serve hangs a door on the common carriage, holds one granted being, mints an
// invitation, and prints one line of plain facts on startup — everything a
// stranger needs to speak to it and nothing about how it is built. It does not
// publish the being: the invitation does not even name it, so a stranger
// rotates, describes, and finds what it now reaches.
//
// Speak takes another door's facts the same way and sends it a real message,
// reporting what came back.
//
// Either mode will run over the framed TCP carriage instead of HTTP when it is
// given -line, and nothing above it changes: the same warden, the same
// invitation, the same messages, a different road. Speaking over a line, this
// command can also hold a being of its own and grant the far ground a standing
// at it, so that the ground it dialled can ask down the connection it never
// opened — which is the whole reason a line is worth holding.
//
// The facts line is JSON because a hint is an opaque string the protocol never
// parses, and a space-separated line cannot carry one that holds a space. It
// is the only line this command writes that is meant to be read by a machine
// looking for it: every line it prints is one JSON object carrying the member
// "quo".
package main

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/carriage"
	"quo.systems/kit/envelope"
	"quo.systems/kit/line"
	"quo.systems/kit/warden"
	"quo.systems/kit/wire"
)

// Counter is the class the door holds. A stranger is told none of this: it
// learns the digest from a describe and the text by asking the warden for the
// blueprint that hashes to it, which is the path the law already gives.
//
// Both fields ride as one `int` — eight bytes, signed two's complement, most
// significant first — so a kit in any language can call them without a codec.
const Counter = `Counter
  bump(by int) int
  count() int
`

func main() {
	if len(os.Args) < 2 {
		fail(errors.New("usage: subject serve|speak"))
	}
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(os.Args[2:])
	case "speak":
		err = speak(os.Args[2:])
	default:
		err = fmt.Errorf("no mode named %q", os.Args[1])
	}
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "subject:", err)
	os.Exit(1)
}

// facts is what a stranger is owed and no more: the five things a holder
// holds. The law never says in what form a door publishes them, so this
// shape is this subject's own and the far side is given it verbatim.
type facts struct {
	Quo        int      `json:"quo"`
	Role       string   `json:"role"`
	Warden     string   `json:"warden"`
	Commitment string   `json:"commitment"`
	Padlock    string   `json:"padlock"`
	Heir       string   `json:"heir"`
	HeirSecret string   `json:"heirSecret"`
	Hints      []string `json:"hints"`
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:0", "where the door hangs")
	limit := fs.Int64("limit", 1<<20, "what this door will take, the one fact the law makes a warden publish")
	framed := fs.Bool("line", false, "hang the door on the framed TCP carriage instead of HTTP")
	if err := fs.Parse(args); err != nil {
		return err
	}

	w, err := stand(*limit)
	if err != nil {
		return err
	}
	g := &ground{w: w}
	being, err := w.Hold(Counter, &counter{}, warden.Keys{Secret: draw(), HeirSecret: draw()})
	if err != nil {
		return err
	}

	if *framed {
		// The listening half is the one that knows where it ended up, so it is
		// the one with a road to grant. Nothing above this changes: the same
		// warden judges the same messages.
		ears, err := line.Listen(line.Door{Judge: g.judge, Limit: w.Limit()}, *listen, nil)
		if err != nil {
			return err
		}
		if err := stranger(w, being, ears.Hint); err != nil {
			return err
		}
		// The listener runs itself, so there is no serve loop to hold this
		// process up; the driver kills it when it has seen enough.
		select {}
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	// The hint is the whole address, posted to exactly as given. Plain HTTP
	// here: the law names HTTPS as the common carriage and does not say
	// whether the scheme is part of the carriage or part of the road, and a
	// subject driven on loopback has nothing to gain from a certificate.
	hint := "http://" + ln.Addr().String() + "/"

	if err := stranger(w, being, hint); err != nil {
		return err
	}
	return http.Serve(ln, carriage.Handler(w.Limit(), g.judge))
}

// stranger mints the invitation and prints the facts line: everything a
// stranger needs to speak to this ground, over whichever road it was given.
func stranger(w *warden.Warden, being [32]byte, hint string) error {
	inv, err := w.Grant(being, warden.Keys{Secret: draw(), HeirSecret: draw()}, w.Padlock(), []string{hint})
	if err != nil {
		return err
	}
	return emit(facts{
		Quo:        1,
		Role:       "door",
		Warden:     hexOf(inv.Warden),
		Commitment: hexOf(inv.Commitment),
		Padlock:    hexOf(inv.Padlock),
		Heir:       hexOf(inv.Heir),
		HeirSecret: hexOf(inv.HeirSecret),
		Hints:      inv.Hints,
	})
}

// ground is this command's warden with the one lock that keeps it to itself. A
// warden is not concurrent, and both roads reach it from several goroutines at
// once: an HTTP door serves each request on its own, and a line judges arriving
// frames on its reader while the main goroutine composes asks of its own.
type ground struct {
	w  *warden.Warden
	mu sync.Mutex
}

// judge is the whole of what a door does with an arriving message. Every draw
// of randomness is taken as an argument rather than reached for, so the host
// draws them here, once per judgment.
func (g *ground) judge(message []byte) []byte {
	g.mu.Lock()
	reply, err := g.w.Judge(warden.Draws{Ephemeral: draw(), Heir: draw()}, message)
	g.mu.Unlock()
	if err != nil {
		// Silence is the whole of every refusal, and the reason never travels.
		// It goes to this host's own stderr and nowhere else.
		fmt.Fprintln(os.Stderr, "subject: refused:", err)
		return nil
	}
	return reply
}

func (g *ground) ask(r warden.Reach) ([]byte, int64, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.w.Ask(draw(), r)
}

func (g *ground) hear(message []byte) (envelope.Answer, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.w.Hear(g.w.PadlockSecret(), message)
}

func (g *ground) roads(far [32]byte) ([]string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	_, _, _, hints, ok := g.w.Relation(far)
	return hints, ok
}

func speak(args []string) error {
	fs := flag.NewFlagSet("speak", flag.ContinueOnError)
	beingHex := fs.String("being", "", `the pk of the being to address; "door" is the far warden's own public being, whose pk is its name; "auto" is the one being the describe found that is not the door's own; empty names no being at all, which with a method named is silence`)
	method := fs.String("method", "", "the field named on it, or empty for a describe")
	argsHex := fs.String("args", "", "that field's arguments, already encoded, as hex")
	texts := fs.Bool("blueprint", false, "ask the far warden for the text of every class the describe named")
	framed := fs.Bool("line", false, "reach the far ground down a framed TCP line instead of the common carriage")
	holding := fs.Bool("hold", false, "hold a being of this ground's own, grant the far ground a standing at it, and stay until the line is let go")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: subject speak [flags] <facts-json>")
	}
	var f facts
	if err := json.Unmarshal([]byte(fs.Arg(0)), &f); err != nil {
		return err
	}
	inv, err := f.invitation()
	if err != nil {
		return err
	}

	// A caller is always a being, and always one its own warden holds — so
	// this mode is a whole ground too, not a bare key.
	w, err := stand(1 << 20)
	if err != nil {
		return err
	}
	w.Stand(w.Self(), inv, inv.HeirSecret)
	g := &ground{w: w}

	// Which road this ground speaks over is the whole of what -line changes.
	send := byDoor
	var road *line.Line
	if *framed {
		hint, ok := lineIn(f.Hints)
		if !ok {
			return errors.New("those facts carry no tcp:// road")
		}
		dialled, err := line.Dial(line.Door{Judge: g.judge, Hear: g.hear, Limit: w.Limit()}, hint)
		if err != nil {
			return err
		}
		defer dialled.Close()
		road = dialled
		send = downLine(dialled)
	}

	// Whoever minted a voice has seen its keys, so the holder's first act is a
	// rotate-and-ask to a key nobody else has ever seen. It asks nothing, and
	// what comes back is what this voice now stands at.
	next := draw()
	estate, err := exchange(g, inv.Warden, "describe", warden.Reach{
		Far:       inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &next,
	}, send)
	if err != nil {
		return err
	}
	if estate == nil {
		return nil // the door answered silence, and it has already been reported
	}
	classes, err := readEstate(estate.data)
	if err != nil {
		return err
	}
	if err := emit(estate.with(map[string]any{"classes": classes})); err != nil {
		return err
	}

	if *texts {
		for _, c := range classes {
			digest, err := keyOf(c.Digest)
			if err != nil {
				return err
			}
			blob, err := wire.Encode(warden.Own, warden.ArgType(warden.FieldBlueprint), digest)
			if err != nil {
				return err
			}
			// blueprint is a field on the far door's public being, whose pk is
			// that warden's own name — reached by naming it, like every other
			// field on every other being.
			door := inv.Warden
			step, err := exchange(g, inv.Warden, "blueprint", ask(inv.Warden, &door, &envelope.Method{
				Name: warden.FieldBlueprint, Args: blob,
			}), send)
			if err != nil {
				return err
			}
			if step == nil {
				continue
			}
			text, err := readOptionalText(step.data)
			if err != nil {
				return err
			}
			if err := emit(step.with(map[string]any{"digest": c.Digest, "text": text})); err != nil {
				return err
			}
		}
	}

	if *method != "" {
		if err := invoke(g, inv, *beingHex, *method, *argsHex, classes, send); err != nil {
			return err
		}
	}
	if !*holding {
		return nil
	}
	if road == nil {
		return errors.New("a standing granted back can only ride a line")
	}
	return held(g, inv.Warden, road)
}

// invoke is the one ask this command was asked to make: a field on a being it
// names, or on none.
func invoke(g *ground, inv wire.Invitation, beingHex, method, argsHex string, classes []class, send sender) error {
	var being *[32]byte
	switch beingHex {
	case "":
	case "door":
		door := inv.Warden
		being = &door
	case "auto":
		// The invitation does not name the being, so a holder finds it by
		// describing. The one class every estate carries is the Warden's own,
		// whose digest is the same on every ground in the world; what is left
		// is what this voice was granted.
		b, err := granted(classes)
		if err != nil {
			return err
		}
		being = &b
	default:
		b, err := keyOf(beingHex)
		if err != nil {
			return err
		}
		being = &b
	}
	blob, err := hex.DecodeString(argsHex)
	if err != nil {
		return err
	}
	step, err := exchange(g, inv.Warden, "ask", ask(inv.Warden, being, &envelope.Method{
		Name: method, Args: blob,
	}), send)
	if err != nil || step == nil {
		return err
	}
	return emit(step.with(map[string]any{"data": hex.EncodeToString(step.data)}))
}

// held is the other half of a line, and the half a door cannot have: this
// ground holds a being of its own and grants the ground it dialled a standing
// at it. The invitation carries no road, because this ground has none — it is
// reachable only down the line it opened, which is exactly the tab's case. Then
// it stays for as long as the far ground keeps the line, and says what its own
// object was left holding once the line is let go.
func held(g *ground, far [32]byte, road *line.Line) error {
	g.mu.Lock()
	own := &counter{}
	being, err := g.w.Hold(Counter, own, warden.Keys{Secret: draw(), HeirSecret: draw()})
	if err == nil {
		var inv wire.Invitation
		inv, err = g.w.Grant(being, warden.Keys{Secret: draw(), HeirSecret: draw()}, g.w.Padlock(), []string{})
		if err == nil {
			err = emit(map[string]any{
				"quo": 1, "step": "standing", "far": hexOf(far),
				"warden":     hexOf(inv.Warden),
				"commitment": hexOf(inv.Commitment),
				"padlock":    hexOf(inv.Padlock),
				"heir":       hexOf(inv.Heir),
				"heirSecret": hexOf(inv.HeirSecret),
			})
		}
	}
	g.mu.Unlock()
	if err != nil {
		return err
	}

	// The far end closes the line when it has finished asking, and a line is
	// dumb — it has no event to wait on, only the fact of whether it is still
	// carrying. Leaving before it is let go would be leaving mid-answer.
	for at := time.Now(); road.Open(); {
		if time.Since(at) > 10*time.Second {
			return errors.New("the line this ground opened was never let go")
		}
		time.Sleep(10 * time.Millisecond)
	}
	g.mu.Lock()
	total := own.total
	g.mu.Unlock()
	return emit(map[string]any{"quo": 1, "step": "held", "being": hexOf(being), "total": total})
}

func ask(far [32]byte, being *[32]byte, m *envelope.Method) warden.Reach {
	return warden.Reach{
		Far:       far,
		Being:     being,
		Method:    m,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
	}
}

// step is one exchange: the number it spent, the door that signed the answer,
// and the answer's data.
type step struct {
	name string
	seq  int64
	from [32]byte
	data []byte
}

func (s *step) with(extra map[string]any) map[string]any {
	out := map[string]any{
		"quo": 1, "step": s.name, "seq": s.seq, "warden": hexOf(s.from),
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// sender is a road: it takes one composed message to the far ground and hands
// back what came back, or nil for silence. The far warden and the number the
// ask spent go with it because a line pairs an arriving answer by them — both
// facts this caller's own, neither ever travelling outside a seal.
type sender func(hints []string, message []byte, far [32]byte, seq int64) ([]byte, error)

// byDoor is the common carriage: one message, one reply, and silence arrives
// as an empty body because HTTP forces a response.
func byDoor(hints []string, message []byte, _ [32]byte, _ int64) ([]byte, error) {
	return carriage.Caller{}.Send(hints, message)
}

// downLine is the framed carriage, where the hints are already spent: the road
// is the connection this ground is holding. Silence has no wire form here, so
// nothing comes back at all and the deadline is this caller's own affair.
func downLine(held *line.Line) sender {
	return func(_ []string, message []byte, far [32]byte, seq int64) ([]byte, error) {
		select {
		case reply := <-held.Carry(message, &line.Expect{Warden: far, Seq: seq}):
			return reply, nil
		case <-time.After(10 * time.Second):
			return nil, nil
		}
	}
}

// lineIn picks the first road that is a line. A hint is opaque to the protocol
// and this is the one place this command looks inside one.
func lineIn(hints []string) (string, bool) {
	for _, hint := range hints {
		if strings.HasPrefix(hint, "tcp://") {
			return hint, true
		}
	}
	return "", false
}

// exchange composes one utterance, puts it down the roads the far door
// offered, and opens what came back. A nil step is silence, which is a door
// speaking and not an error.
func exchange(g *ground, far [32]byte, name string, r warden.Reach, send sender) (*step, error) {
	message, seq, err := g.ask(r)
	if err != nil {
		return nil, err
	}
	hints, ok := g.roads(far)
	if !ok {
		return nil, errors.New("no relation with that house")
	}
	reply, err := send(hints, message, far, seq)
	if err != nil {
		return nil, err
	}
	if reply == nil {
		return nil, emit(map[string]any{"quo": 1, "step": name, "seq": seq, "silence": true})
	}
	answer, err := g.hear(reply)
	if err != nil {
		return nil, err
	}
	if answer.Seq != seq {
		return nil, fmt.Errorf("the answer names ask %d, not %d", answer.Seq, seq)
	}
	return &step{name: name, seq: seq, from: answer.Warden, data: answer.Data}, nil
}

// class is one line of a describe, flattened for the far side: a digest and
// the pks under it, in the order the warden derived.
type class struct {
	Digest string   `json:"digest"`
	Beings []string `json:"beings"`
}

// granted picks the one being an estate holds that is not the door's own
// public being. It refuses anything else rather than choosing: which of two
// granted beings was meant is the caller's to say.
func granted(classes []class) ([32]byte, error) {
	own := hexOf(warden.Digest)
	var found []string
	for _, c := range classes {
		if c.Digest == own {
			continue
		}
		found = append(found, c.Beings...)
	}
	if len(found) != 1 {
		return [32]byte{}, fmt.Errorf("the estate holds %d beings besides the door's own", len(found))
	}
	return keyOf(found[0])
}

func readEstate(data []byte) ([]class, error) {
	e, err := warden.DecodeEstate(data)
	if err != nil {
		return nil, err
	}
	out := make([]class, 0, len(e.Classes))
	for _, c := range e.Classes {
		beings := make([]string, 0, len(c.Beings))
		for _, h := range c.Beings {
			beings = append(beings, hexOf(h.Being))
		}
		out = append(out, class{Digest: hexOf(c.Digest), Beings: beings})
	}
	return out, nil
}

// readOptionalText reads a `text?` answer: one byte saying present or absent,
// and the value only when present.
func readOptionalText(data []byte) (any, error) {
	t, ok := warden.AnswerType(warden.FieldBlueprint)
	if !ok {
		return nil, errors.New("that field answers nothing")
	}
	return wire.Decode(warden.Own, t, data)
}

func (f facts) invitation() (wire.Invitation, error) {
	var inv wire.Invitation
	for _, pair := range []struct {
		into *[32]byte
		from string
	}{
		{&inv.Warden, f.Warden}, {&inv.Commitment, f.Commitment}, {&inv.Padlock, f.Padlock},
		{&inv.Heir, f.Heir}, {&inv.HeirSecret, f.HeirSecret},
	} {
		k, err := keyOf(pair.from)
		if err != nil {
			return wire.Invitation{}, err
		}
		*pair.into = k
	}
	if len(f.Hints) == 0 {
		return wire.Invitation{}, errors.New("those facts carry no road")
	}
	inv.Hints = f.Hints
	return inv, nil
}

// stand puts up a whole ground. Every key is a fresh draw: nothing here is
// pinned, because nothing here is a vector.
func stand(limit int64) (*warden.Warden, error) {
	name := draw()
	return warden.New(warden.Founding{
		NameSecret:     name,
		HeirCommitment: arithmetic.Commit(arithmetic.SigningKey(name), arithmetic.SigningKey(draw())),
		PadlockSecret:  draw(),
		Limit:          limit,
		// A clock is taken as an argument for the same reason a draw of
		// randomness is. This host lends the warden the wall clock in
		// milliseconds; only differences are ever taken of it.
		Clock: func() int64 { return time.Now().UnixMilli() },
	})
}

// counter is an ordinary object. It never learns it has an address, judges
// nothing, and sees no key.
type counter struct{ total int64 }

func (c *counter) Invoke(call warden.Call) ([]byte, error) {
	args := call.Args
	switch call.Method {
	case "bump":
		if len(args) != 8 {
			// Bytes left after the declared arguments are the being's to
			// refuse, never the warden's.
			return nil, errors.New("bump takes one int")
		}
		c.total += int64(binary.BigEndian.Uint64(args))
	case "count":
		if len(args) != 0 {
			return nil, errors.New("count takes nothing")
		}
	default:
		return nil, errors.New("the blueprint declares no such field")
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, uint64(c.total))
	return out, nil
}

func draw() [32]byte {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		fail(err)
	}
	return b
}

func hexOf(k [32]byte) string { return hex.EncodeToString(k[:]) }

func keyOf(s string) ([32]byte, error) {
	b, err := hex.DecodeString(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("a key is 32 bytes, got %d", len(b))
	}
	return [32]byte(b), nil
}

// emit writes one line of JSON to stdout and flushes it, so a driver reading
// this process line by line sees it before the process blocks.
func emit(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(os.Stdout, string(b))
	return err
}
