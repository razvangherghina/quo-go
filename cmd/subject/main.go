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
// Serving over a line, -push is the other half of that: this ground asks down
// a connection it accepted. A standing granted back never travels on the wire,
// so it is handed to this command one JSON object per line on stdin, and each
// is spent on a line this door accepted.
//
// Serving with -relay <facts>, this ground stands as the middle of a chain: it
// holds a Brief of its own whose one field is answered by reaching a third
// house, under the leash it was handed rather than under one of its own. That
// is Article III's "each hop acts as itself", and it needs a being that does
// its work by asking somebody else.
//
// The facts line is JSON because a hint is an opaque string the protocol never
// parses, and a space-separated line cannot carry one that holds a space. It
// is the only line this command writes that is meant to be read by a machine
// looking for it: every line it prints is one JSON object carrying the member
// "quo".
//
// This command stands below the seam an application stands on, in two ways it
// says here rather than hiding.
//
// It composes its own asks through the warden, with Ask, Expect and Forgo,
// instead of calling fields on a handle. It has to: the whole point of it is to
// name a being and a field it was handed on the command line, at a door whose
// blueprints it does not hold, and a handle encodes through the blueprint and
// so can never say them. The seam never grows a raw-ask surface to let it — an
// application would then have a public way around the blueprint, permanently,
// for the benefit of a harness.
//
// It also stands its own roads and its own delivery rather than opening a
// host, which is the third part of the kit and does exactly that work. Here the
// road is the thing under test: this command holds the line it dialled and
// waits for the far ground to let it go, and holds the lines it accepted to
// spend a standing down one. A host keeps its lines to itself, because a being
// above it must never learn which road it is on; a subject exists to prove that
// road, so it is one layer lower.
package main

import (
	"bufio"
	"context"
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

// Brief is what a relaying ground puts in front of whoever it answers to, and
// the whole of it: one field, answering a number it does not itself hold.
// There is no way to write to the far house through it.
const Brief = `Brief
  filed() int
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
	pushing := fs.Bool("push", false, "ask down a line this ground accepted, spending a standing handed to it on stdin")
	beingHex := fs.String("being", "", `which being to push at; "auto" is the one the describe found that is not the far door's own`)
	method := fs.String("method", "", "the field to push at it, or empty for a describe alone")
	argsHex := fs.String("args", "", "that field's arguments, already encoded, as hex; on a relay, the entry it files in the far house's book")
	relaying := fs.String("relay", "", "stand as the middle of a chain: hold a Brief whose one field is answered by reaching the house these facts name")
	if err := fs.Parse(args); err != nil {
		return err
	}

	w, err := stand(*limit)
	if err != nil {
		return err
	}
	// Silence is the whole of every refusal, and the reason never travels: the
	// house is told inward, on this host's own stderr and nowhere else.
	w.Observe(func(s warden.Silence) { fmt.Fprintln(os.Stderr, "subject: refused:", s.Reason) })
	g := &ground{w: w}
	// A relay has already spoken to a third house before it is ready to be
	// spoken to, and what it found waits behind the facts: the facts line is
	// the first line this command writes, whatever else it did to get there.
	var being [32]byte
	var found map[string]any
	if *relaying != "" {
		being, found, err = relay(g, *relaying, *argsHex)
	} else {
		being, _, err = w.Hold(&counter{}, warden.Holding{Blueprint: Counter})
	}
	if err != nil {
		return err
	}

	if *framed {
		// A ground that pushes keeps every line it accepts, because the standing
		// it will spend down one arrives later and by another road entirely.
		accepted := make(chan *line.Line, 8)
		var arriving func(*line.Line)
		if *pushing {
			arriving = func(l *line.Line) {
				select {
				case accepted <- l:
				default:
				}
			}
		}
		// The listening half is the one that knows where it ended up, so it is
		// the one with a road to grant. Nothing above this changes: the same
		// warden judges the same messages.
		ears, err := line.Listen(line.Door{Arrive: g.arrive, Limit: w.Limit()}, *listen, arriving)
		if err != nil {
			return err
		}
		if err := stranger(w, being, ears.Hint); err != nil {
			return err
		}
		if err := emitFound(found); err != nil {
			return err
		}
		if *pushing {
			go pushes(g, accepted, *beingHex, *method, *argsHex)
		}
		// The listener runs itself, so there is no serve loop to hold this
		// process up; the driver kills it when it has seen enough.
		select {}
	}
	if *pushing {
		return errors.New("a push can only ride a line")
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
	if err := emitFound(found); err != nil {
		return err
	}
	return http.Serve(ln, carriage.Handler(w.Limit(), func(message []byte) []byte {
		// The common carriage holds no line, so there is no road token to hand
		// down: an answer rides the response it came in on.
		return g.arrive(message, nil)
	}))
}

// What a relay found at the third house, printed once the facts are out.
func emitFound(found map[string]any) error {
	if found == nil {
		return nil
	}
	return emit(found)
}

// stranger mints the invitation and prints the facts line: everything a
// stranger needs to speak to this ground, over whichever road it was given.
func stranger(w *warden.Warden, being [32]byte, hint string) error {
	w.Publish(hint)
	inv, err := w.Grant(being)
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

// ground is this command's warden. The warden holds its own lock, so there is
// none here: both roads reach it from several goroutines at once, and an
// arriving frame goes in its one entry point exactly as an HTTP body does.
type ground struct {
	w *warden.Warden
}

// arrive is the whole of what a road does with bytes: hands them to the
// warden's one entry point and sends back whatever comes.
func (g *ground) arrive(message []byte, via any) []byte {
	return g.w.Arrive(message, via)
}

func (g *ground) ask(r warden.Reach) ([]byte, int64, error) {
	return g.w.Ask(r)
}

func (g *ground) roads(far [32]byte) ([]string, bool) {
	_, _, _, hints, ok := g.w.RelationAt(far)
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
		dialled, err := line.Dial(line.Door{Arrive: g.arrive, Limit: w.Limit()}, hint)
		if err != nil {
			return err
		}
		defer dialled.Close()
		road = dialled
		send = downLine(dialled)
	}

	classes, err := opening(g, inv.Warden, send)
	if err != nil || classes == nil {
		return err // silence has already been reported where it happened
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

// opening is the first act at any door, over any road: whoever minted a voice
// has seen its keys, so a holder rotates to a key nobody else has ever seen and
// reads back the estate it now stands at. A nil answer with no error is
// silence, already reported where it happened.
func opening(g *ground, far [32]byte, send sender) ([]class, error) {
	next := draw()
	estate, err := exchange(g, far, "describe", warden.Reach{
		Far:       far,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &next,
	}, send)
	if err != nil || estate == nil {
		return nil, err
	}
	classes, err := readEstate(estate.data)
	if err != nil {
		return nil, err
	}
	return classes, emit(estate.with(map[string]any{"classes": classes}))
}

// pushes is the other half of -hold, and the half only a listening ground can
// play: an ask down a connection this ground never opened, spending a standing
// the dialling ground granted it. The standing never travels on the wire — it
// is the dialler's own to hand over however it likes — so it arrives here one
// JSON object per line on stdin, and each is spent on a line this door
// accepted.
func pushes(g *ground, accepted <-chan *line.Line, beingHex, method, argsHex string) {
	reader := bufio.NewScanner(os.Stdin)
	reader.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for reader.Scan() {
		if len(strings.TrimSpace(reader.Text())) == 0 {
			continue
		}
		var f facts
		if err := json.Unmarshal(reader.Bytes(), &f); err != nil {
			fail(err)
		}
		inv, err := f.standing()
		if err != nil {
			fail(err)
		}
		if err := push(g, inv, <-accepted, beingHex, method, argsHex); err != nil {
			fail(err)
		}
	}
}

func push(g *ground, inv wire.Invitation, held *line.Line, beingHex, method, argsHex string) error {
	g.w.Stand(g.w.Self(), inv, inv.HeirSecret)
	send := downLine(held)
	classes, err := opening(g, inv.Warden, send)
	if err != nil || classes == nil {
		return err
	}
	if err := emit(map[string]any{"quo": 1, "step": "pushed", "far": hexOf(inv.Warden)}); err != nil {
		return err
	}
	if method == "" {
		return nil
	}
	return invoke(g, inv, beingHex, method, argsHex, classes, send)
}

// relay makes this ground the middle of a chain. It holds a Brief whose one
// field it cannot answer alone, and before it is ready to be spoken to it has
// already spoken to the house whose facts it was handed: rotating, describing,
// and filing whatever entry it was told to file. What it found is handed back
// to be printed once the facts are out.
func relay(g *ground, written, entry string) ([32]byte, map[string]any, error) {
	var f facts
	if err := json.Unmarshal([]byte(written), &f); err != nil {
		return [32]byte{}, nil, err
	}
	inv, err := f.invitation()
	if err != nil {
		return [32]byte{}, nil, err
	}
	b := &brief{g: g, far: inv.Warden, hints: inv.Hints, voice: inv.Heir}
	being, _, err := g.w.Hold(b, warden.Holding{Blueprint: Brief})
	if err != nil {
		return [32]byte{}, nil, err
	}
	// The relation belongs to the being that spends it, not to the house: it
	// is Brief that reaches the far house, and nothing else here may.
	g.w.Stand(being, inv, inv.HeirSecret)

	// The opening, said in this ground's own voice and reported to nobody: a
	// relay's own errand at the third house is not a step the driver reads.
	next := draw()
	estate, err := b.send(warden.Reach{
		Far:       inv.Warden,
		Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		NextHeir:  &next,
	})
	if err != nil {
		return [32]byte{}, nil, err
	}
	if estate == nil {
		return [32]byte{}, nil, errors.New("the far house answered the relay nothing")
	}
	classes, err := readEstate(estate.Data)
	if err != nil {
		return [32]byte{}, nil, err
	}
	book, err := granted(classes)
	if err != nil {
		return [32]byte{}, nil, err
	}
	b.book = book

	// What this ground put in the far house's book, if it was told to put
	// anything. Only this ground could have written it and only that house
	// holds it, so a number read back through Brief came from there and
	// nowhere else.
	var filed int64
	if entry != "" {
		blob, err := hex.DecodeString(entry)
		if err != nil {
			return [32]byte{}, nil, err
		}
		wrote, err := b.send(warden.Reach{
			Far:       inv.Warden,
			Being:     &book,
			Method:    &envelope.Method{Name: "bump", Args: blob},
			Allowance: envelope.Allowance{Time: 5000, Hops: 8},
		})
		if err != nil {
			return [32]byte{}, nil, err
		}
		if wrote == nil {
			return [32]byte{}, nil, errors.New("the far house would not take the relay's entry")
		}
		filed, err = readInt(wrote.Data)
		if err != nil {
			return [32]byte{}, nil, err
		}
	}
	return being, map[string]any{
		"quo": 1, "step": "relay",
		"far":   hexOf(inv.Warden),
		"being": hexOf(book),
		"brief": hexOf(being),
		"filed": filed,
	}, nil
}

// brief is a being that does its work by asking somebody else. It reaches the
// far house under the leash that arrived rather than under one of its own, and
// hands back what that house said. It never learns who asked it.
type brief struct {
	g     *ground
	far   [32]byte
	book  [32]byte
	hints []string
	// The voice this ground speaks to the far house with: the heir the far
	// house minted, which the opening rotation spent. It is not the voice this
	// ground published to whoever calls it, and that is the whole point.
	voice [32]byte
}

func (b *brief) Filed(ctx context.Context) (int64, error) {
	leash := warden.Of(ctx).Leash
	received := leash.Received()
	onward, err := leash.Onward()
	if err != nil {
		return 0, err
	}
	answer, err := b.send(warden.Reach{
		Far:    b.far,
		Being:  &b.book,
		Method: &envelope.Method{Name: "count", Args: []byte{}},
		Leash:  &leash,
	})
	if err != nil {
		return 0, err
	}
	if err := emit(map[string]any{
		"quo": 1, "step": "relayed",
		"far":      hexOf(b.far),
		"voice":    hexOf(b.voice),
		"received": map[string]any{"time": received.Time, "hops": received.Hops},
		"onward":   map[string]any{"time": onward.Time, "hops": onward.Hops},
		"silence":  answer == nil,
	}); err != nil {
		return 0, err
	}
	if answer == nil {
		// Silence from the far house is silence from this one: a warden never
		// narrates what happened behind it.
		return 0, errors.New("the far house said nothing")
	}
	// Both fields ride as one `int`, so what the far house answered is already
	// what this field answers with.
	return readInt(answer.Data)
}

// send is one errand at the far house, reported to nobody: the relay's own
// conversation is not a step a driver reads. It is an ordinary spend down the
// common carriage — a being in the middle of a chain reaches the next house
// exactly as anybody does.
func (b *brief) send(r warden.Reach) (*envelope.Answer, error) {
	message, seq, err := b.g.w.Ask(r)
	if err != nil {
		return nil, err
	}
	pending := b.g.w.Expect(r.Far, seq, r.Padlock)
	reply, err := carriage.Caller{}.Send(b.hints, message)
	if err != nil {
		return nil, err
	}
	if reply != nil {
		b.g.arrive(reply, nil)
	} else {
		b.g.w.Forgo(r.Far, seq, r.Padlock)
	}
	answer, heard := pending.Wait(context.Background(), 10_000)
	if !heard {
		return nil, nil
	}
	if answer.Seq != seq {
		return nil, fmt.Errorf("the answer names ask %d, not %d", answer.Seq, seq)
	}
	return &answer, nil
}

func readInt(data []byte) (int64, error) {
	if len(data) != 8 {
		return 0, errors.New("an answer that is not one int")
	}
	return int64(binary.BigEndian.Uint64(data)), nil
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
	own := &counter{}
	being, _, err := g.w.Hold(own, warden.Holding{Blueprint: Counter})
	if err == nil {
		var inv wire.Invitation
		// This ground publishes no road, so the standing it hands back carries
		// none: it is reachable only down the line it opened.
		inv, err = g.w.GrantAs(being, warden.Keys{Secret: draw(), HeirSecret: draw()}, g.w.Padlock(), []string{})
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
	total := own.Count()
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

// sender is a road: it takes one composed message to the far ground. Bytes
// back are a road that answered in its own response; no bytes and `later` is a
// road that answers through the door as a frame of its own; neither is
// weather. Nothing here opens a seal, and nothing here pairs an answer with an
// ask — that is the warden's, because only the warden holds the secret.
type sender func(hints []string, message []byte) (back []byte, later bool, err error)

// byDoor is the common carriage: one message, one reply, and silence arrives
// as an empty body because HTTP forces a response.
func byDoor(hints []string, message []byte) ([]byte, bool, error) {
	back, err := carriage.Caller{}.Send(hints, message)
	return back, false, err
}

// downLine is the framed carriage, where the hints are already spent: the road
// is the connection this ground is holding. Silence has no wire form here, so
// nothing comes back at all and the answer, when there is one, arrives as a
// frame of its own through the warden's one entry point.
func downLine(held *line.Line) sender {
	return func(_ []string, message []byte) ([]byte, bool, error) {
		return nil, held.Carry(message), nil
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
	answer, seq, err := g.spend(far, r, send)
	if err != nil {
		return nil, err
	}
	if answer == nil {
		return nil, emit(map[string]any{"quo": 1, "step": name, "seq": seq, "silence": true})
	}
	return &step{name: name, seq: seq, from: answer.Warden, data: answer.Data}, nil
}

// spend composes one ask, puts it on its road, and waits for the answer the
// warden pairs with it. A nil answer is silence, which is a door speaking and
// not an error.
func (g *ground) spend(far [32]byte, r warden.Reach, send sender) (*envelope.Answer, int64, error) {
	message, seq, err := g.ask(r)
	if err != nil {
		return nil, 0, err
	}
	hints, ok := g.roads(far)
	if !ok {
		return nil, seq, errors.New("no relation with that house")
	}
	// The ask is held before the bytes go out, because the answer may be back
	// before the sending returns — a road that answers in its own response, or
	// a frame judged on this ground's own reader.
	pending := g.w.Expect(far, seq, r.Padlock)
	back, later, err := send(hints, message)
	if err != nil {
		return nil, seq, err
	}
	switch {
	case back != nil:
		g.arrive(back, nil)
	case !later:
		g.w.Forgo(far, seq, r.Padlock)
	}
	answer, heard := pending.Wait(context.Background(), 10_000)
	if !heard {
		return nil, seq, nil
	}
	if answer.Seq != seq {
		return nil, seq, fmt.Errorf("the answer names ask %d, not %d", answer.Seq, seq)
	}
	return &answer, seq, nil
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

// standing reads the five keys and nothing else. A standing granted back down
// a line carries no road at all, because the ground that granted it has none:
// it is reachable only down the line it opened.
func (f facts) standing() (wire.Invitation, error) {
	inv, err := f.keys()
	inv.Hints = []string{}
	return inv, err
}

func (f facts) invitation() (wire.Invitation, error) {
	inv, err := f.keys()
	if err != nil {
		return wire.Invitation{}, err
	}
	if len(f.Hints) == 0 {
		return wire.Invitation{}, errors.New("those facts carry no road")
	}
	inv.Hints = f.Hints
	return inv, nil
}

func (f facts) keys() (wire.Invitation, error) {
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
		// A clock and a source of randomness are lent to the warden for its
		// life, the way its keys are: an implementation that reached for
		// either could not be pinned to a test. Only differences of the clock
		// are ever taken of it.
		Clock:  func() int64 { return time.Now().UnixMilli() },
		Random: draw,
	})
}

// counter is an ordinary object. It never learns it has an address, judges
// nothing, sees no key and never touches a byte: its arguments arrive decoded
// and its answers leave as plain values.
type counter struct {
	warden.Attach
	total int64
}

func (c *counter) Bump(by int64) int64 {
	c.total += by
	return c.total
}

func (c *counter) Count() int64 { return c.total }

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
