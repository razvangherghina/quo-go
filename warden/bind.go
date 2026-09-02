package warden

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

// A being is a plain Go value. What crosses to a stranger is its blueprint,
// and this file is the whole of what joins the two: a declared field is bound
// to the exported method of the same name, its arguments are decoded by the
// declared types into ordinary Go values, and its answer is encoded back by the
// declared answer type. The being never sees a byte and never touches a key.
//
// The binding is checked at Hold rather than at judgment: a class whose
// blueprint declares a field its object cannot answer is refused before the
// being is addressable, so the drift a registration table would allow has
// nowhere to happen.

// Cells and Take are what a being provides rather than receives: what of its
// state moves with it, and how it takes that state back. A being that provides
// neither moves with nothing but its name and its standings.
type Cells interface{ Cells() []byte }

// Take is the other half of Cells.
type Take interface{ Take(cells []byte) error }

// attaching is how a being is handed its closure. Embedding Attach satisfies
// it, and a being that embeds nothing simply never reaches its warden — which
// is the whole of what a being that only answers needs.
type attaching interface{ attach(*Quo) }

// Attach is embedded by a being that acts: it gives the being Quo(), the one
// API a being has to its warden. Nothing is injected behind an author's back —
// embedding it is the author saying this object is a being.
type Attach struct{ quo *Quo }

func (a *Attach) attach(q *Quo) { a.quo = q }

// Quo is the closure this being was handed. It is nil until a warden holds the
// object.
func (a *Attach) Quo() *Quo { return a.quo }

// bound is one blueprint bound to one object: which Go method answers each
// declared field, and the types either side of it.
type bound struct {
	bp     *notation.Blueprint
	fields map[string]*field
	object reflect.Value
}

type field struct {
	declared notation.Field
	method   reflect.Value
	// wantsContext is whether the method takes the call as its first argument.
	wantsContext bool
	// answers is whether the method hands a value back before its error.
	answers bool
	// errors is whether the method's last result is an error, which is the
	// being refusing and reaches the caller as the same silence as everything
	// else.
	errors bool
}

// exported is the Go method name for a declared field: the field's own name
// with its first letter raised, because Go reaches nothing unexported by name.
func exported(name string) string {
	if name == "" {
		return ""
	}
	return strings.ToUpper(name[:1]) + name[1:]
}

var (
	contextType = reflect.TypeOf((*context.Context)(nil)).Elem()
	errorType   = reflect.TypeOf((*error)(nil)).Elem()
	anyType     = reflect.TypeOf((*any)(nil)).Elem()
)

// bind reads the blueprint as the scope and the object as what fills it.
func bind(bp *notation.Blueprint, object any) (*bound, error) {
	b := &bound{bp: bp, fields: map[string]*field{}, object: reflect.ValueOf(object)}
	if object == nil {
		return b, nil
	}
	for _, declared := range bp.Fields {
		m := b.object.MethodByName(exported(declared.Name))
		if !m.IsValid() {
			return nil, fmt.Errorf("warden: %s declares %s and this object answers no %s", bp.Name, declared.Name, exported(declared.Name))
		}
		f, err := shape(declared, m)
		if err != nil {
			return nil, err
		}
		b.fields[declared.Name] = f
	}
	return b, nil
}

// shape checks one method against one declared field, so a mismatch is a
// refusal at Hold and never a surprise at the door.
func shape(declared notation.Field, m reflect.Value) (*field, error) {
	t := m.Type()
	f := &field{declared: declared, method: m}
	at := 0
	if t.NumIn() > 0 && t.In(0) == contextType {
		f.wantsContext = true
		at = 1
	}
	if t.NumIn()-at != len(declared.Args) {
		return nil, fmt.Errorf("warden: %s takes %d arguments and its method takes %d", declared.Name, len(declared.Args), t.NumIn()-at)
	}
	for i, arg := range declared.Args {
		want := goType(arg.Type)
		got := t.In(at + i)
		if got != want && got != anyType {
			return nil, fmt.Errorf("warden: %s's argument %s is %s, which is %s and not %s", declared.Name, arg.Name, arg.Type, want, got)
		}
	}
	out := t.NumOut()
	if out > 0 && t.Out(out-1) == errorType {
		f.errors = true
		out--
	}
	switch {
	case declared.Answer == nil && out != 0:
		return nil, fmt.Errorf("warden: %s answers nothing and its method answers something", declared.Name)
	case declared.Answer != nil && out != 1:
		return nil, fmt.Errorf("warden: %s answers %s and its method answers %d values", declared.Name, *declared.Answer, out)
	}
	f.answers = out == 1
	if f.answers {
		want := goType(*declared.Answer)
		if got := t.Out(0); got != want && got != anyType {
			return nil, fmt.Errorf("warden: %s answers %s, which is %s and not %s", declared.Name, *declared.Answer, want, got)
		}
	}
	return f, nil
}

// goType is the one Go type a declared type rides as. The set is closed
// because the notation's is: nothing here is configurable, so two beings of one
// class in one language have one signature.
func goType(t notation.Type) reflect.Type {
	switch t.Kind {
	case notation.KindBool:
		return reflect.TypeOf(false)
	case notation.KindInt:
		return reflect.TypeOf(int64(0))
	case notation.KindText:
		return reflect.TypeOf("")
	case notation.KindBytes:
		return reflect.TypeOf([]byte(nil))
	case notation.KindB32, notation.KindBeing:
		return reflect.TypeOf([32]byte{})
	case notation.KindInvitation:
		return reflect.TypeOf(wire.Invitation{})
	case notation.KindCard:
		return reflect.TypeOf(wire.Card{})
	case notation.KindList:
		return reflect.TypeOf([]any(nil))
	case notation.KindOptional:
		// An optional is absent or present, and `any` is the one Go type with
		// a spelling for both that every inner type can wear.
		return anyType
	case notation.KindRecord:
		return reflect.TypeOf(map[string]any(nil))
	}
	return anyType
}

// invoke calls the bound method with the arguments the blob carries, decoded by
// the field's declared types. The blob is the warden's; the values are the
// being's.
func (b *bound) invoke(ctx context.Context, name string, args []byte) ([]byte, error) {
	f, ok := b.fields[name]
	if !ok {
		return nil, fmt.Errorf("warden: that being's blueprint declares no field %q", name)
	}
	values, err := decodeArgs(b.bp, f.declared.Args, args)
	if err != nil {
		return nil, err
	}
	in := make([]reflect.Value, 0, len(values)+1)
	if f.wantsContext {
		in = append(in, reflect.ValueOf(ctx))
	}
	for _, v := range values {
		in = append(in, adapt(v, f.method.Type().In(len(in))))
	}
	out := f.method.Call(in)
	if f.errors {
		if e := out[len(out)-1]; !e.IsNil() {
			return nil, e.Interface().(error)
		}
		out = out[:len(out)-1]
	}
	if !f.answers {
		return nil, nil
	}
	return wire.Encode(b.bp, *f.declared.Answer, out[0].Interface())
}

// adapt puts a decoded value in the shape the method asked for. A method may
// always take `any`, which is what an optional rides as.
func adapt(v any, want reflect.Type) reflect.Value {
	if want == anyType {
		return reflect.ValueOf(&v).Elem()
	}
	if v == nil {
		return reflect.Zero(want)
	}
	return reflect.ValueOf(v).Convert(want)
}

// decodeArgs reads a field's arguments: its declared types in declared order,
// notation-encoded and concatenated, with nothing left over.
func decodeArgs(bp *notation.Blueprint, args []notation.Arg, blob []byte) ([]any, error) {
	if len(args) == 0 {
		if len(blob) != 0 {
			return nil, errors.New("warden: arguments to a field that takes none")
		}
		return nil, nil
	}
	if len(args) == 1 {
		v, err := wire.Decode(bp, args[0].Type, blob)
		if err != nil {
			return nil, err
		}
		return []any{v}, nil
	}
	return wire.DecodeAll(bp, types(args), blob)
}

// encodeArgs is the inverse: a caller's values written as the field declares.
func encodeArgs(bp *notation.Blueprint, args []notation.Arg, values []any) ([]byte, error) {
	if len(values) != len(args) {
		return nil, fmt.Errorf("warden: that field takes %d arguments and %d were given", len(args), len(values))
	}
	var out []byte
	for i, a := range args {
		b, err := wire.Encode(bp, a.Type, values[i])
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	if out == nil {
		out = []byte{}
	}
	return out, nil
}

func types(args []notation.Arg) []notation.Type {
	out := make([]notation.Type, len(args))
	for i, a := range args {
		out[i] = a.Type
	}
	return out
}

// cellsOf and takeInto are the migration contract, asked of the object rather
// than declared for it: what of its state moves with it, and how it takes that
// state back.
func cellsOf(object any) []byte {
	if c, ok := object.(Cells); ok {
		return c.Cells()
	}
	return []byte{}
}

func takeInto(object any, cells []byte) error {
	if t, ok := object.(Take); ok {
		return t.Take(cells)
	}
	return nil
}
