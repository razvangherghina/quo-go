package notation

import (
	"errors"
	"fmt"
	"strings"
)

// bom is U+FEFF, built from its bytes so this file carries none of its own.
// A mark stripped would be a second way to write one text, so a text wearing
// one is refused rather than cleaned.
var bom = string([]byte{0xEF, 0xBB, 0xBF})

// Parse reads a blueprint's canonical text. Anything that is not exactly
// canonical is refused, and so is anything this notation does not describe.
func Parse(text string) (*Blueprint, error) {
	blocks, err := split(text)
	if err != nil {
		return nil, err
	}

	b := &Blueprint{Name: blocks[0].name}
	if b.Fields, err = parseFields(blocks[0]); err != nil {
		return nil, err
	}
	for _, blk := range blocks[1:] {
		r := Record{Name: blk.name}
		if r.Members, err = parseMembers(blk); err != nil {
			return nil, err
		}
		b.Records = append(b.Records, r)
	}

	if err := b.validate(); err != nil {
		return nil, err
	}
	return b, nil
}

type block struct {
	name  string
	lines []string // the field lines, indent already stripped
}

// split cuts the text into blocks and enforces every rule about the shape of
// the page: the encoding, the line endings, the indent, the blank lines.
func split(text string) ([]block, error) {
	if strings.HasPrefix(text, bom) {
		return nil, errors.New("notation: a byte order mark")
	}
	if strings.ContainsRune(text, '\r') {
		return nil, errors.New("notation: a carriage return")
	}
	if strings.ContainsRune(text, '\t') {
		return nil, errors.New("notation: a tab")
	}
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("notation: no final newline")
	}

	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for _, l := range lines {
		if strings.HasSuffix(l, " ") {
			return nil, errors.New("notation: a trailing space")
		}
	}

	var blocks []block
	var cur *block
	for i, l := range lines {
		switch {
		case l == "":
			if cur == nil || len(cur.lines) == 0 {
				return nil, errors.New("notation: a blank line where a block was due")
			}
			if i == len(lines)-1 {
				return nil, errors.New("notation: a trailing blank line")
			}
			blocks = append(blocks, *cur)
			cur = nil
		case strings.HasPrefix(l, " "):
			if cur == nil {
				return nil, errors.New("notation: a field before its block")
			}
			if !strings.HasPrefix(l, "  ") || strings.HasPrefix(l, "   ") {
				return nil, errors.New("notation: the indent is two spaces")
			}
			cur.lines = append(cur.lines, l[2:])
		default:
			if cur != nil {
				return nil, errors.New("notation: a block header inside a block")
			}
			if !isIdentifier(l) {
				return nil, fmt.Errorf("notation: %q is not an identifier", l)
			}
			cur = &block{name: l}
		}
	}
	if cur == nil {
		return nil, errors.New("notation: the text ends mid-block")
	}
	if len(cur.lines) == 0 {
		return nil, errors.New("notation: an empty block")
	}
	return append(blocks, *cur), nil
}

// parseFields reads the class block: every field carries parentheses, and may
// answer nothing.
func parseFields(blk block) ([]Field, error) {
	fields := make([]Field, 0, len(blk.lines))
	seen := map[string]bool{}
	for _, l := range blk.lines {
		lo := strings.IndexByte(l, '(')
		hi := strings.IndexByte(l, ')')
		if lo < 0 || hi < lo {
			return nil, fmt.Errorf("notation: %q is not a class field", l)
		}
		f := Field{Name: l[:lo]}
		if !isIdentifier(f.Name) {
			return nil, fmt.Errorf("notation: %q is not an identifier", f.Name)
		}
		if seen[f.Name] {
			return nil, fmt.Errorf("notation: %q is named twice", f.Name)
		}
		seen[f.Name] = true

		args, err := parseArgs(l[lo+1 : hi])
		if err != nil {
			return nil, err
		}
		f.Args = args

		switch tail := l[hi+1:]; {
		case tail == "":
		case strings.HasPrefix(tail, " "):
			t, err := parseType(tail[1:])
			if err != nil {
				return nil, err
			}
			f.Answer = &t
		default:
			return nil, fmt.Errorf("notation: %q trails its field", tail)
		}
		fields = append(fields, f)
	}
	return fields, nil
}

func parseArgs(s string) ([]Arg, error) {
	if s == "" {
		return nil, nil
	}
	parts := strings.Split(s, ", ")
	args := make([]Arg, 0, len(parts))
	seen := map[string]bool{}
	for _, p := range parts {
		name, typeText, ok := strings.Cut(p, " ")
		if !ok {
			return nil, fmt.Errorf("notation: %q is not an argument", p)
		}
		if !isIdentifier(name) {
			return nil, fmt.Errorf("notation: %q is not an identifier", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("notation: the argument %q is named twice", name)
		}
		seen[name] = true
		t, err := parseType(typeText)
		if err != nil {
			return nil, err
		}
		args = append(args, Arg{Name: name, Type: t})
	}
	return args, nil
}

// parseMembers reads a record block: no field carries parentheses.
func parseMembers(blk block) ([]Member, error) {
	members := make([]Member, 0, len(blk.lines))
	seen := map[string]bool{}
	for _, l := range blk.lines {
		name, typeText, ok := strings.Cut(l, " ")
		if !ok {
			return nil, fmt.Errorf("notation: %q is not a record field", l)
		}
		if !isIdentifier(name) {
			return nil, fmt.Errorf("notation: %q is not an identifier", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("notation: %q is named twice", name)
		}
		seen[name] = true
		t, err := parseType(typeText)
		if err != nil {
			return nil, err
		}
		members = append(members, Member{Name: name, Type: t})
	}
	return members, nil
}

// parseType reads one type: a closed type, a record name, or either
// combinator wrapped around another type. The two compose freely.
func parseType(s string) (Type, error) {
	depth := 0
	for strings.HasSuffix(s, "?") {
		s = strings.TrimSuffix(s, "?")
		depth++
	}

	var t Type
	switch {
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") || len(s) < 3 {
			return Type{}, fmt.Errorf("notation: %q is not a list", s)
		}
		elem, err := parseType(s[1 : len(s)-1])
		if err != nil {
			return Type{}, err
		}
		t = List(elem)
	case primitives[s] != 0:
		t = Type{Kind: primitives[s]}
	case isIdentifier(s):
		t = RecordType(s)
	default:
		return Type{}, fmt.Errorf("notation: %q is not a type", s)
	}

	for range depth {
		t = Optional(t)
	}
	return t, nil
}

// isIdentifier holds the grammar to ASCII: a letter, then letters and digits.
// Unicode would bring normalization, and two normalizations are two digests.
func isIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		letter := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
		digit := c >= '0' && c <= '9'
		if !letter && !(digit && i > 0) {
			return false
		}
	}
	return true
}

// validate holds the rules that span blocks: the record blocks follow the
// class block in order of first use, depth-first through the fields; a record
// nothing uses is refused; and no record may reach itself.
func (b *Blueprint) validate() error {
	declared := map[string]*Record{}
	for i := range b.Records {
		r := &b.Records[i]
		if r.Name == b.Name {
			return fmt.Errorf("notation: the record %q wears the class's own name", r.Name)
		}
		if primitives[r.Name] != 0 {
			return fmt.Errorf("notation: the record %q wears a closed type's name", r.Name)
		}
		if declared[r.Name] != nil {
			return fmt.Errorf("notation: the record %q is declared twice", r.Name)
		}
		declared[r.Name] = r
	}

	var order []string
	emitted := map[string]bool{}
	onStack := map[string]bool{}

	var visit func(Type) error
	visit = func(t Type) error {
		t = t.base()
		if t.Kind != KindRecord {
			return nil
		}
		r := declared[t.Name]
		if r == nil {
			return fmt.Errorf("notation: no block declares %q", t.Name)
		}
		if onStack[t.Name] {
			return fmt.Errorf("notation: the record %q reaches itself", t.Name)
		}
		if emitted[t.Name] {
			return nil
		}
		emitted[t.Name] = true
		order = append(order, t.Name)
		onStack[t.Name] = true
		for _, m := range r.Members {
			if err := visit(m.Type); err != nil {
				return err
			}
		}
		onStack[t.Name] = false
		return nil
	}

	for _, f := range b.Fields {
		for _, a := range f.Args {
			if err := visit(a.Type); err != nil {
				return err
			}
		}
		if f.Answer != nil {
			if err := visit(*f.Answer); err != nil {
				return err
			}
		}
	}

	if len(order) != len(b.Records) {
		return errors.New("notation: a record nothing uses")
	}
	for i, name := range order {
		if b.Records[i].Name != name {
			return fmt.Errorf("notation: the record %q is out of the derived order", b.Records[i].Name)
		}
	}
	return nil
}
