package notation_test

import (
	"crypto/sha256"
	"strings"
	"testing"

	"quo.systems/kit/notation"
)

// Everything here is asserted from the constitution's own words, under "The
// notation". The corpus pins bytes; these pin the rules the bytes came from,
// and a refusal is asserted as strictly as an acceptance.

// accepts parses a text the law makes legal and hands back the blueprint.
func accepts(t *testing.T, text string) *notation.Blueprint {
	t.Helper()
	bp, err := notation.Parse(text)
	if err != nil {
		t.Fatalf("refused a legal text: %v\n%s", err, text)
	}
	return bp
}

// refuses holds a text the law makes illegal. Where this text does not say
// what something means, it is refused.
func refuses(t *testing.T, why, text string) {
	t.Helper()
	if _, err := notation.Parse(text); err == nil {
		t.Errorf("accepted %s:\n%s", why, text)
	}
}

// TestTheDigestIsSHA256OverTheCanonicalBytes holds the one sentence the law
// only ever says in two halves: a blueprint's identity is its digest, and the
// hash is SHA-256 over the canonical UTF-8 text.
func TestTheDigestIsSHA256OverTheCanonicalBytes(t *testing.T) {
	bp := accepts(t, "ToDo\n  add(title text) bool\n")
	want := sha256.Sum256([]byte(bp.Text()))
	if bp.Digest() != want {
		t.Fatal("the digest is not the hash of the canonical bytes")
	}
}

// TestFieldOrderIsPartOfTheIdentity holds that reordering the fields makes a
// different class, which is honest: the digest was never a summary of meaning.
func TestFieldOrderIsPartOfTheIdentity(t *testing.T) {
	one := accepts(t, "C\n  a() bool\n  b() int\n")
	two := accepts(t, "C\n  b() int\n  a() bool\n")
	if one.Digest() == two.Digest() {
		t.Fatal("two field orders produced one digest")
	}
}

// TestTheClassNameIsPartOfTheIdentity holds the same for the name: two classes
// that look alike are not one class.
func TestTheClassNameIsPartOfTheIdentity(t *testing.T) {
	one := accepts(t, "C\n  a() bool\n")
	two := accepts(t, "D\n  a() bool\n")
	if one.Digest() == two.Digest() {
		t.Fatal("two class names produced one digest")
	}
}

// TestRecordBlocksFollowFirstUseDepthFirst holds the order the law derives
// from the content so that no author chooses it.
func TestRecordBlocksFollowFirstUseDepthFirst(t *testing.T) {
	bp := accepts(t, "C\n  one() b\n  two() a\n\nb\n  x int\n\na\n  y int\n")
	if len(bp.Records) != 2 || bp.Records[0].Name != "b" || bp.Records[1].Name != "a" {
		t.Fatalf("the blocks are not in order of first use: %v", names(bp))
	}

	// Depth-first: a record reached through another comes before a record the
	// next field reaches.
	deep := accepts(t, "C\n  one() outer\n  two() other\n\nouter\n  inner inner\n\ninner\n  x int\n\nother\n  y int\n")
	if got := names(deep); strings.Join(got, ",") != "outer,inner,other" {
		t.Fatalf("depth-first order is %v", got)
	}
}

// TestFirstUseRunsLeftToRightWithinOneField holds the ruling that changes the
// digest of every blueprint whose field takes a record: the arguments in their
// declared order, then what the field answers.
func TestFirstUseRunsLeftToRightWithinOneField(t *testing.T) {
	bp := accepts(t, "C\n  one(a arg) answer\n\narg\n  x int\n\nanswer\n  y int\n")
	if got := names(bp); strings.Join(got, ",") != "arg,answer" {
		t.Fatalf("first use inside a field is %v, want arg then answer", got)
	}

	if strings.Index(bp.Text(), "\narg\n") > strings.Index(bp.Text(), "\nanswer\n") {
		t.Fatal("the canonical text puts the answer's record before the argument's")
	}
	// A kit that walked the answer first still produces a canonical-looking
	// text, which is why the wrong order is refused rather than repaired:
	// canonical means literally canonical, so a text out of the derived order
	// is not this class written differently, it is not this class.
	refuses(t, "the answer's record before the argument's", "C\n  one(a arg) answer\n\nanswer\n  y int\n\narg\n  x int\n")
}

// TestTwoArgumentsSeparateWithACommaAndOneSpace holds the pinned spelling, and
// holds that a second spelling canonicalises to it rather than being a second
// class.
func TestTwoArgumentsSeparateWithACommaAndOneSpace(t *testing.T) {
	bp := accepts(t, "C\n  f(a int, b int) bool\n")
	if !strings.Contains(bp.Text(), "f(a int, b int) bool") {
		t.Fatalf("the canonical spelling is %q", bp.Text())
	}
	refuses(t, "two arguments separated by a comma alone", "C\n  f(a int,b int) bool\n")
	refuses(t, "two arguments separated by two spaces", "C\n  f(a int,  b int) bool\n")
}

// TestEveryClassFieldCarriesParenthesesAndNoRecordMemberDoes holds the
// distinction the law draws: a class's fields are asked, a record's are
// carried.
func TestEveryClassFieldCarriesParenthesesAndNoRecordMemberDoes(t *testing.T) {
	accepts(t, "C\n  f() bool\n")
	refuses(t, "a zero-argument class field without parentheses", "C\n  f bool\n")
	refuses(t, "a record member with parentheses", "C\n  f() r\n\nr\n  x() int\n")
}

// TestAFieldMayAnswerNothing holds that a command owed no reply is ordinary,
// and that a dummy answer would be an opinion.
func TestAFieldMayAnswerNothing(t *testing.T) {
	bp := accepts(t, "C\n  fire(at text)\n")
	if bp.Fields[0].Answer != nil {
		t.Fatal("a field written with no answer type answers something")
	}
	if !strings.Contains(bp.Text(), "fire(at text)\n") {
		t.Fatalf("the canonical spelling is %q", bp.Text())
	}
}

// TestTheCombinatorsComposeFreely holds that refusing a composition would be
// the opinion: their encodings compose mechanically.
func TestTheCombinatorsComposeFreely(t *testing.T) {
	for _, spelling := range []string{"[int?]", "[int]?", "[[int]]", "int??", "[[int?]?]?"} {
		accepts(t, "C\n  f() "+spelling+"\n")
	}
}

// TestAnIdentifierIsASCIILetterThenLettersAndDigits holds the grammar pinned
// where two honest writers could differ: Unicode brings normalization, and two
// normalizations are two digests.
func TestAnIdentifierIsASCIILetterThenLettersAndDigits(t *testing.T) {
	accepts(t, "C1\n  f2(a3 int) bool\n")
	refuses(t, "a class name starting with a digit", "1C\n  f() bool\n")
	refuses(t, "an underscore in a field name", "C\n  a_b() bool\n")
	refuses(t, "a hyphen in an argument name", "C\n  f(a-b int) bool\n")
	refuses(t, "a non-ASCII class name", "Ça\n  f() bool\n")
	refuses(t, "a non-ASCII field name", "C\n  café() bool\n")
}

// TestARecordNothingUsesIsRefused holds one half of the rule that two texts
// with one meaning would be two digests for one class.
func TestARecordNothingUsesIsRefused(t *testing.T) {
	refuses(t, "a record block nothing reaches", "C\n  f() bool\n\nspare\n  x int\n")
}

// TestAnEmptyBlockIsRefused holds the other half: a class that declares
// nothing exists for nothing.
func TestAnEmptyBlockIsRefused(t *testing.T) {
	refuses(t, "a class with no fields", "C\n")
	refuses(t, "a record with no members", "C\n  f() r\n\nr\n")
}

// TestARecordMayNotReachItself holds that recursion forces every language's
// codec to carry unbounded depth, and deep structure is what beings and lists
// are for.
func TestARecordMayNotReachItself(t *testing.T) {
	refuses(t, "a record holding itself", "C\n  f() r\n\nr\n  again r\n")
	refuses(t, "a record holding itself through a list", "C\n  f() r\n\nr\n  again [r]\n")
	refuses(t, "a record holding itself through an optional", "C\n  f() r\n\nr\n  again r?\n")
	refuses(t, "a cycle through another record", "C\n  f() a\n\na\n  b b\n\nb\n  a a\n")
}

// TestARecordMayNotWearTheClassName holds one of the four the law names
// explicitly as refused under the standing answer.
func TestARecordMayNotWearTheClassName(t *testing.T) {
	refuses(t, "a record block wearing the class's own name", "C\n  f() C\n\nC\n  x int\n")
}

// TestANameMayNotAppearTwiceInOneBlock holds the rest of that list.
func TestANameMayNotAppearTwiceInOneBlock(t *testing.T) {
	refuses(t, "a field name twice in one class", "C\n  f() bool\n  f() int\n")
	refuses(t, "a member name twice in one record", "C\n  f() r\n\nr\n  x int\n  x bool\n")
	refuses(t, "a record declared twice", "C\n  f() r\n\nr\n  x int\n\nr\n  y int\n")
}

// TestTheTypesAreClosed holds that a set that grows is a set that diverges: a
// type the law does not name is not a type, and no block declares it.
func TestTheTypesAreClosed(t *testing.T) {
	for _, name := range []string{"bool", "int", "text", "bytes", "b32", "being", "invitation", "card"} {
		accepts(t, "C\n  f() "+name+"\n")
		// A closed type's name is not a block's to take.
		refuses(t, "a record wearing "+name+"'s name", "C\n  f() "+name+"\n\n"+name+"\n  x int\n")
	}
	// Both combinators compose freely over a card, as over everything else.
	accepts(t, "C\n  f() [card]\n")
	accepts(t, "C\n  f(c card?) [card]?\n")
	refuses(t, "a type nothing declares", "C\n  f() float\n")
	refuses(t, "a type nothing declares as an argument", "C\n  f(a uint) bool\n")
}

// TestCanonicalMeansLiterallyCanonical holds every spelling the law rules
// out, because anything the hash does not cover is a place two wardens can
// differ.
func TestCanonicalMeansLiterallyCanonical(t *testing.T) {
	refuses(t, "a byte order mark", "\ufeffC\n  f() bool\n")
	refuses(t, "four spaces of indent", "C\n    f() bool\n")
	refuses(t, "one space of indent", "C\n f() bool\n")
	refuses(t, "a tab of indent", "C\n\tf() bool\n")
	refuses(t, "two spaces between tokens", "C\n  f()  bool\n")
	refuses(t, "a trailing space", "C\n  f() bool \n")
	refuses(t, "no final newline", "C\n  f() bool")
	refuses(t, "two blank lines between blocks", "C\n  f() r\n\n\nr\n  x int\n")
	refuses(t, "no blank line between blocks", "C\n  f() r\nr\n  x int\n")
	refuses(t, "a blank line inside a block", "C\n  f() bool\n\n  g() int\n")
	refuses(t, "a comment", "C\n  f() bool # the field\n")
	refuses(t, "a carriage return", "C\r\n  f() bool\r\n")
	refuses(t, "a trailing blank line", "C\n  f() bool\n\n")
}

// TestPrintingIsTheParsersInverse holds the property the digest rests on: one
// text in, the same text out, and nothing a second pass would change.
func TestPrintingIsTheParsersInverse(t *testing.T) {
	text := "ToDo\n  add(title text) item\n  complete(id text) bool\n  items() [item]\n  members() [being]\n\nitem\n  id text\n  title text\n  done bool\n"
	bp := accepts(t, text)
	if bp.Text() != text {
		t.Fatalf("the canonical text changed:\n%q", bp.Text())
	}
	again := accepts(t, bp.Text())
	if again.Digest() != bp.Digest() {
		t.Fatal("a second pass produced a second digest")
	}
}

func names(bp *notation.Blueprint) []string {
	out := make([]string, 0, len(bp.Records))
	for _, r := range bp.Records {
		out = append(out, r.Name)
	}
	return out
}
