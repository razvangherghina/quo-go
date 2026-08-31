package main_test

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The subject is driven the way a foreign language will drive it: as a process,
// over a real socket, reading nothing but the line it prints. Nothing here
// reaches into the kit — every fact this test uses came off stdout.

// build compiles the subject once and hands back the path to the binary.
func build(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "subject")
	out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput()
	if err != nil {
		t.Fatalf("the subject would not build: %v\n%s", err, out)
	}
	return bin
}

// line is one JSON object the subject printed.
type line map[string]any

// serve starts a door and hands back the facts line it printed on startup.
func serve(t *testing.T, bin string) (string, line) {
	t.Helper()
	cmd := exec.Command(bin, "serve")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	r := bufio.NewReader(out)
	raw, err := r.ReadString('\n')
	if err != nil {
		t.Fatalf("the door printed no facts: %v", err)
	}
	go func() { _, _ = io.Copy(io.Discard, r) }()

	var f line
	if err := json.Unmarshal([]byte(raw), &f); err != nil {
		t.Fatalf("the facts line is not JSON: %q", raw)
	}
	return strings.TrimSpace(raw), f
}

// speak runs the other mode and hands back every line it printed.
func speak(t *testing.T, bin string, args ...string) []line {
	t.Helper()
	cmd := exec.Command(bin, append([]string{"speak"}, args...)...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("speak failed: %v", err)
	}
	var lines []line
	for _, raw := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if raw == "" {
			continue
		}
		var l line
		if err := json.Unmarshal([]byte(raw), &l); err != nil {
			t.Fatalf("a reply line is not JSON: %q", raw)
		}
		lines = append(lines, l)
	}
	return lines
}

func text(t *testing.T, l line, name string) string {
	t.Helper()
	s, ok := l[name].(string)
	if !ok {
		t.Fatalf("%s is missing from %v", name, l)
	}
	return s
}

// TestTheFactsLineIsEverythingAStrangerNeeds holds what the line publishes:
// the five things a holder holds, and nothing about how the door is built. In
// particular it does not name the being — the invitation does not even name
// it, so a stranger rotates, describes, and finds what it now reaches.
func TestTheFactsLineIsEverythingAStrangerNeeds(t *testing.T) {
	_, f := serve(t, build(t))

	for _, name := range []string{"warden", "commitment", "padlock", "heir", "heirSecret"} {
		k, err := hex.DecodeString(text(t, f, name))
		if err != nil || len(k) != 32 {
			t.Fatalf("%s is not thirty-two bytes of hex: %v", name, f[name])
		}
	}
	hints, ok := f["hints"].([]any)
	if !ok || len(hints) == 0 {
		t.Fatal("the facts carry no road")
	}
	if _, named := f["being"]; named {
		t.Fatal("the facts name a being; the invitation does not even name one")
	}
}

// TestTwoSubjectsMeetAtASocket drives the whole crossing between two
// processes: one hangs a door, the other is handed its facts and nothing else,
// rotates into its standing, describes, learns the class by asking for the
// text that hashes to the digest, and then calls a field on the being it
// found. Neither process reads the other's memory.
func TestTwoSubjectsMeetAtASocket(t *testing.T) {
	bin := build(t)
	raw, _ := serve(t, bin)

	// One process, one standing: the whole conversation happens under the
	// voice this run rotated into, because an invitation is spent rather than
	// held.
	args := make([]byte, 8)
	binary.BigEndian.PutUint64(args, 7)
	lines := speak(t, bin, "-blueprint", "-being", "auto",
		"-method", "bump", "-args", hex.EncodeToString(args), raw)
	if len(lines) < 2 {
		t.Fatalf("the crossing printed %d lines: %v", len(lines), lines)
	}

	// The describe is the answer to a rotate-and-ask that asked nothing, and
	// the first legal number is one.
	describe := lines[0]
	if describe["step"] != "describe" || describe["seq"] != float64(1) {
		t.Fatalf("the first exchange is %v", describe)
	}
	classes, ok := describe["classes"].([]any)
	if !ok || len(classes) != 2 {
		// The public being is reachable by everyone, holders included, so the
		// estate holds the granted being's class and the Warden's own.
		t.Fatalf("the estate holds %v, want two classes", describe["classes"])
	}

	// The blueprint that is not the one every warden holds is the class the
	// door granted at, and its text came back because this voice reaches a
	// being of it.
	var counter, being string
	for _, l := range lines[1:] {
		if l["step"] != "blueprint" {
			continue
		}
		body := text(t, l, "text")
		if strings.HasPrefix(body, "Warden\n") {
			continue
		}
		counter = body
		digest := text(t, l, "digest")
		for _, c := range classes {
			f, _ := c.(map[string]any)
			if f["digest"] != digest {
				continue
			}
			beings, _ := f["beings"].([]any)
			if len(beings) != 1 {
				t.Fatalf("that class holds %v", f["beings"])
			}
			being, _ = beings[0].(string)
		}
	}
	if counter == "" || being == "" {
		t.Fatalf("the crossing never learnt a class to call: %v", lines)
	}
	if !strings.HasPrefix(counter, "Counter\n") {
		t.Fatalf("the blueprint that came back is %q", counter)
	}

	// And the real call on the being the describe found, its argument written
	// by the notation's own rules: one int, eight bytes, most significant
	// first.
	last := lines[len(lines)-1]
	if last["step"] != "ask" {
		t.Fatalf("the last exchange is %v", last)
	}
	data, err := hex.DecodeString(text(t, last, "data"))
	if err != nil || len(data) != 8 {
		t.Fatalf("the answer's data is %v", last["data"])
	}
	if got := binary.BigEndian.Uint64(data); got != 7 {
		t.Fatalf("the counter answered %d, want 7", got)
	}

	// The door signed its answer with its own name, so the caller knows the
	// door it asked is the door that spoke.
	if text(t, last, "warden") != text(t, describe, "warden") {
		t.Fatal("two different doors answered one address")
	}
}

// TestAnInvitationIsSpentNotHeld holds that a standing is transferred but
// never copied. The first process to show the secret becomes the holder and
// rotates to a key nobody else has ever seen; a second process handed the same
// facts is met with silence, because the key it presents is no longer the
// committed heir and the number it carries has already been spent.
func TestAnInvitationIsSpentNotHeld(t *testing.T) {
	bin := build(t)
	raw, _ := serve(t, bin)

	first := speak(t, bin, raw)
	if first[0]["silence"] == true {
		t.Fatalf("the first holder was refused: %v", first)
	}
	if first[0]["seq"] != float64(1) {
		t.Fatalf("the first legal number is one, got %v", first[0]["seq"])
	}

	second := speak(t, bin, raw)
	if second[0]["silence"] != true {
		t.Fatalf("a second holder was let in on a spent invitation: %v", second)
	}
}
