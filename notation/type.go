// Package notation reads, writes and hashes a Quo blueprint.
//
// A blueprint is one canonical text. Parse refuses everything that is not
// exactly canonical, because the digest is a hash of the bytes and a second
// legal spelling would be a second identity.
package notation

import "strings"

// Kind is one of the closed types, or one of the two combinators, or a record
// shape the blueprint itself declares.
type Kind uint8

const (
	KindBool Kind = iota + 1
	KindInt
	KindText
	KindBytes
	KindB32
	KindBeing
	KindInvitation
	KindCard
	KindList
	KindOptional
	KindRecord
)

var primitives = map[string]Kind{
	"bool":       KindBool,
	"int":        KindInt,
	"text":       KindText,
	"bytes":      KindBytes,
	"b32":        KindB32,
	"being":      KindBeing,
	"invitation": KindInvitation,
	"card":       KindCard,
}

var primitiveNames = map[Kind]string{
	KindBool:       "bool",
	KindInt:        "int",
	KindText:       "text",
	KindBytes:      "bytes",
	KindB32:        "b32",
	KindBeing:      "being",
	KindInvitation: "invitation",
	KindCard:       "card",
}

// Type is a closed type, a list, an optional, or a named record shape.
type Type struct {
	Kind Kind
	Elem *Type  // KindList and KindOptional only
	Name string // KindRecord only
}

// List wraps t in the many combinator.
func List(t Type) Type { return Type{Kind: KindList, Elem: &t} }

// Optional wraps t in the possibly-absent combinator.
func Optional(t Type) Type { return Type{Kind: KindOptional, Elem: &t} }

// RecordType names a record shape the blueprint declares.
func RecordType(name string) Type { return Type{Kind: KindRecord, Name: name} }

func (t Type) String() string {
	switch t.Kind {
	case KindList:
		return "[" + t.Elem.String() + "]"
	case KindOptional:
		return t.Elem.String() + "?"
	case KindRecord:
		return t.Name
	default:
		return primitiveNames[t.Kind]
	}
}

// base strips both combinators, leaving the type they ultimately wrap.
func (t Type) base() Type {
	for t.Kind == KindList || t.Kind == KindOptional {
		t = *t.Elem
	}
	return t
}

// Arg is one argument of a class field: a name and a type.
type Arg struct {
	Name string
	Type Type
}

// Field is one field of the class block. A field that answers nothing has a
// nil Answer, and answers zero bytes.
type Field struct {
	Name   string
	Args   []Arg
	Answer *Type
}

// Member is one field of a record block. A record's fields are carried rather
// than asked, so they take no arguments.
type Member struct {
	Name string
	Type Type
}

// Record is one record block.
type Record struct {
	Name    string
	Members []Member
}

// Blueprint is a class name, its fields, and the record shapes they use.
type Blueprint struct {
	Name    string
	Fields  []Field
	Records []Record
}

// Record returns the record block of the given name.
func (b *Blueprint) Record(name string) (*Record, bool) {
	for i := range b.Records {
		if b.Records[i].Name == name {
			return &b.Records[i], true
		}
	}
	return nil, false
}

// Text writes the blueprint's canonical form.
func (b *Blueprint) Text() string {
	var s strings.Builder
	s.WriteString(b.Name)
	s.WriteByte('\n')
	for _, f := range b.Fields {
		s.WriteString("  ")
		s.WriteString(f.Name)
		s.WriteByte('(')
		for i, a := range f.Args {
			if i > 0 {
				s.WriteString(", ")
			}
			s.WriteString(a.Name)
			s.WriteByte(' ')
			s.WriteString(a.Type.String())
		}
		s.WriteByte(')')
		if f.Answer != nil {
			s.WriteByte(' ')
			s.WriteString(f.Answer.String())
		}
		s.WriteByte('\n')
	}
	for _, r := range b.Records {
		s.WriteString("\n")
		s.WriteString(r.Name)
		s.WriteByte('\n')
		for _, m := range r.Members {
			s.WriteString("  ")
			s.WriteString(m.Name)
			s.WriteByte(' ')
			s.WriteString(m.Type.String())
			s.WriteByte('\n')
		}
	}
	return s.String()
}
