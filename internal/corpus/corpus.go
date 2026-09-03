// Package corpus reads the pinned vectors a Quo kit must reproduce.
//
// The corpus is language-neutral data, shared by every kit; its own README
// states the format. Bytes are hex throughout.
package corpus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// File is one area of the corpus.
type File struct {
	Area     string   `json:"area"`
	Encoding string   `json:"encoding"`
	Vectors  []Vector `json:"vectors"`
}

// Vector is one case: its input, its exact output, and the section of the
// constitution that rules it.
//
// The fields named here are the ones every area shares. What an area asks for
// beyond them differs case by case, so the whole object is kept as well and
// read through Hex, Text and Has.
type Vector struct {
	Name      string          `json:"name"`
	Law       string          `json:"law"`
	Blueprint string          `json:"blueprint"`
	Canonical string          `json:"canonical"`
	Digest    string          `json:"digest"`
	Value     json.RawMessage `json:"value"`
	Bytes     string          `json:"bytes"`
	Refuses   bool            `json:"refuses"`
	Unpinned  bool            `json:"unpinned"`

	raw map[string]json.RawMessage
}

// UnmarshalJSON keeps the whole object beside the shared fields.
func (v *Vector) UnmarshalJSON(b []byte) error {
	type plain Vector
	if err := json.Unmarshal(b, (*plain)(v)); err != nil {
		return err
	}
	return json.Unmarshal(b, &v.raw)
}

// Has says whether the vector carries that member at all.
func (v Vector) Has(name string) bool {
	_, ok := v.raw[name]
	return ok
}

// Raw hands back a member exactly as the file wrote it, for the areas whose
// members are objects rather than hex.
func (v Vector) Raw(name string) (json.RawMessage, bool) {
	raw, ok := v.raw[name]
	return raw, ok
}

// Text reads a member written as a JSON string.
func (v Vector) Text(name string) (string, error) {
	raw, ok := v.raw[name]
	if !ok {
		return "", fmt.Errorf("corpus: %q carries no %s", v.Name, name)
	}
	var s string
	err := json.Unmarshal(raw, &s)
	return s, err
}

// Hex reads a member written as hex.
func (v Vector) Hex(name string) ([]byte, error) {
	s, err := v.Text(name)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(s)
}

// Key reads a member written as thirty-two bytes of hex.
func (v Vector) Key(name string) ([32]byte, error) {
	var k [32]byte
	b, err := v.Hex(name)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("corpus: %s is %d bytes rather than thirty-two", name, len(b))
	}
	copy(k[:], b)
	return k, nil
}

// Material is the fixed keys area. It carries no vectors: every member of
// its one object is thirty-two bytes of hex, named.
type Material struct {
	Area     string            `json:"area"`
	Encoding string            `json:"encoding"`
	Keys     map[string]string `json:"material"`
}

// Key reads one named entry as thirty-two bytes.
func (m Material) Key(name string) ([32]byte, error) {
	var k [32]byte
	s, ok := m.Keys[name]
	if !ok {
		return k, fmt.Errorf("corpus: the material carries no %s", name)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return k, err
	}
	if len(b) != 32 {
		return k, fmt.Errorf("corpus: %s is %d bytes rather than thirty-two", name, len(b))
	}
	copy(k[:], b)
	return k, nil
}

// LoadMaterial reads the fixed keys, from the same two homes Load reads.
func LoadMaterial() (Material, error) {
	raw, err := read("material")
	if err != nil {
		return Material{}, err
	}
	var m Material
	err = json.Unmarshal(raw, &m)
	return m, err
}

// Load reads one area by name, such as "notation" or "wire".
//
// The corpus has one home — kits/js/vectors, beside the kit that generates it
// — and that is what is read wherever the two kits stand together, in this
// repo and in the published one. The Go kit is also emitted on its own, as the
// module quo.systems/kit, where no sibling JS kit exists; that emit carries a
// copy beside this file, and it is only ever reached when the shared corpus is
// not there. Preferring the shared one is what keeps the copy a copy.
func Load(area string) (File, error) {
	raw, err := read(area)
	if err != nil {
		return File{}, err
	}
	var f File
	err = json.Unmarshal(raw, &f)
	return f, err
}

func read(area string) ([]byte, error) {
	_, self, _, _ := runtime.Caller(0)
	dir := filepath.Dir(self)

	var raw []byte
	var err error
	for _, path := range []string{
		filepath.Join(dir, "..", "..", "..", "js", "vectors", area+".json"),
		filepath.Join(dir, "vectors", area+".json"),
	} {
		raw, err = os.ReadFile(path)
		if err == nil {
			return raw, nil
		}
	}
	return nil, err
}
