package notation_test

import (
	"encoding/hex"
	"testing"

	"quo.systems/kit/internal/corpus"
	"quo.systems/kit/notation"
)

func TestCorpus(t *testing.T) {
	file, err := corpus.Load("notation")
	if err != nil {
		t.Fatal(err)
	}
	if len(file.Vectors) == 0 {
		t.Fatal("the corpus is empty")
	}

	for _, v := range file.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			b, err := notation.Parse(v.Blueprint)
			if v.Refuses {
				if err == nil {
					t.Fatalf("accepted what the corpus refuses: %q", v.Blueprint)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused what the corpus accepts: %v", err)
			}

			if got := hex.EncodeToString([]byte(b.Text())); got != v.Canonical {
				t.Errorf("canonical text\n got %s\nwant %s", got, v.Canonical)
			}
			digest := b.Digest()
			if got := hex.EncodeToString(digest[:]); got != v.Digest {
				t.Errorf("digest\n got %s\nwant %s", got, v.Digest)
			}

			// The other direction: what this kit printed, this kit reads.
			again, err := notation.Parse(b.Text())
			if err != nil {
				t.Fatalf("refused its own canonical text: %v", err)
			}
			if again.Text() != b.Text() {
				t.Error("printing is not stable")
			}
		})
	}
}

func TestRefusesTheEmptyText(t *testing.T) {
	for _, text := range []string{"", "\n", "\n\n", "  yes() bool\n"} {
		if _, err := notation.Parse(text); err == nil {
			t.Errorf("accepted %q", text)
		}
	}
}
