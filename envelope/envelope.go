// Package envelope assembles what crosses between two doors: an ephemeral
// public key, and then one ciphertext sealed to the recipient's padlock,
// holding a payload and one signature over it.
//
// It adds nothing to the arithmetic. Both records it carries are written in
// the notation and ride through the notation's own encoder, because two
// encoders in one protocol is two places to diverge.
package envelope

import (
	"errors"
	"fmt"

	"quo.systems/kit/arithmetic"
	"quo.systems/kit/notation"
	"quo.systems/kit/wire"
)

// Shapes is the notation `say` and `answer` are written in. Neither is a
// class, neither is described, and no digest of either is ever computed — the
// class block here only gives the two record blocks somewhere to hang, so one
// parser and one encoder serve them as they serve everything else.
const Shapes = `Envelope
  say() say
  answer() answer

say
  voice b32
  recipient b32
  commitment b32?
  seq int
  padlock b32
  hints [text]
  allowance allowance
  being being?
  method method?

allowance
  time int
  hops int

method
  name text
  args bytes

answer
  warden being
  seq int
  data bytes?
`

var shapes = mustParse(Shapes)

var (
	sayType    = notation.RecordType("say")
	answerType = notation.RecordType("answer")
)

// Allowance is the caller's own leash: a time budget in milliseconds, and a
// hop count. Every door hands onward less than it received.
type Allowance struct {
	Time int64
	Hops int64
}

// Method is the field named on the being, and its arguments as one opaque,
// length-prefixed blob whose meaning belongs to the blueprint. The blob is
// empty when the method takes nothing.
type Method struct {
	Name string
	Args []byte
}

// Say is one utterance from a voice to a door. Nothing in it marks it as an
// ask or a rotation: the kind is read off the voice at the door that receives
// it.
//
// Commitment, Being and Method are the three that may be absent, and nil is
// how they are.
type Say struct {
	Voice      [32]byte
	Recipient  [32]byte
	Commitment *[32]byte
	Seq        int64
	Padlock    [32]byte
	Hints      []string
	Allowance  Allowance
	Being      *[32]byte
	Method     *Method
}

// Answer is what a door sends back: its own name, the number of the ask it
// answers, and the data — absent when the field answers nothing.
//
// A nil Data is that absence; an empty but non-nil Data is a present answer of
// zero bytes, which is what a field answering `bytes` with none returns.
type Answer struct {
	Warden [32]byte
	Seq    int64
	Data   []byte
}

// The signed payload begins with one byte naming the record it carries, and
// the signature covers that byte with the rest. Position decides nothing: on a
// held line an ask and an answer arrive the same way, so the payload says what
// it is, and what it signs can never be read as the other record.
const (
	SayTag    byte = 0
	AnswerTag byte = 1
)

// ErrWrongRecord is what any other first byte gets, and what a record
// presented under the wrong byte gets — one refusal, because the reader always
// knows which record it is reading.
var ErrWrongRecord = errors.New("envelope: the payload names another record")

func tagged(tag byte, record []byte) []byte {
	return append([]byte{tag}, record...)
}

func untag(tag byte, payload []byte) ([]byte, error) {
	if len(payload) < 1 || payload[0] != tag {
		return nil, ErrWrongRecord
	}
	return payload[1:], nil
}

// EncodeSayPayload is what a voice signs: the record byte, then the say.
func EncodeSayPayload(s Say) ([]byte, error) {
	record, err := EncodeSay(s)
	if err != nil {
		return nil, err
	}
	return tagged(SayTag, record), nil
}

// DecodeSayPayload reads one back, refusing any other byte in front of it.
func DecodeSayPayload(payload []byte) (Say, error) {
	record, err := untag(SayTag, payload)
	if err != nil {
		return Say{}, err
	}
	return DecodeSay(record)
}

// EncodeAnswerPayload is the answer's own half of the same pair.
func EncodeAnswerPayload(a Answer) ([]byte, error) {
	record, err := EncodeAnswer(a)
	if err != nil {
		return nil, err
	}
	return tagged(AnswerTag, record), nil
}

// DecodeAnswerPayload reads one back.
func DecodeAnswerPayload(payload []byte) (Answer, error) {
	record, err := untag(AnswerTag, payload)
	if err != nil {
		return Answer{}, err
	}
	return DecodeAnswer(record)
}

// EncodeSay writes the record alone: the say's fields in the order the
// envelope section lists them, each by the notation's own rules. What is
// signed is this with the record byte in front of it.
func EncodeSay(s Say) ([]byte, error) {
	return wire.Encode(shapes, sayType, sayValue(s))
}

// DecodeSay reads a payload and refuses any byte left after it.
func DecodeSay(b []byte) (Say, error) {
	v, err := wire.Decode(shapes, sayType, b)
	if err != nil {
		return Say{}, err
	}
	return readSay(v)
}

// EncodeAnswer writes an answer.
func EncodeAnswer(a Answer) ([]byte, error) {
	return wire.Encode(shapes, answerType, answerValue(a))
}

// DecodeAnswer reads an answer and refuses any byte left after it.
func DecodeAnswer(b []byte) (Answer, error) {
	v, err := wire.Decode(shapes, answerType, b)
	if err != nil {
		return Answer{}, err
	}
	return readAnswer(v)
}

// Seal staples the ephemeral public key to the lid: that key, and then the
// plaintext boxed under what it agrees with the padlock, with the key itself
// as the additional data. The ephemeral key must be outside, because it is
// what the recipient agrees with to open the seal.
func Seal(ephemeralSecret, padlock [32]byte, plaintext []byte) ([]byte, error) {
	ephemeral, err := arithmetic.SealingKey(ephemeralSecret)
	if err != nil {
		return nil, err
	}
	shared, err := arithmetic.Agree(ephemeralSecret, padlock)
	if err != nil {
		return nil, err
	}
	box, err := arithmetic.Box(shared, ephemeral[:], plaintext)
	if err != nil {
		return nil, err
	}
	return append(ephemeral[:], box...), nil
}

// Unseal opens a message with the door's own secret.
func Unseal(padlockSecret [32]byte, message []byte) ([]byte, error) {
	if len(message) < 32 {
		return nil, errors.New("envelope: no room for the ephemeral key")
	}
	var ephemeral [32]byte
	copy(ephemeral[:], message[:32])
	shared, err := arithmetic.Agree(padlockSecret, ephemeral)
	if err != nil {
		return nil, err
	}
	return arithmetic.Unbox(shared, ephemeral[:], message[32:])
}

// SealSay is the whole message a caller sends: the payload, the voice's
// signature over it as the last sixty-four bytes inside the seal, and the two
// of them sealed to the door's padlock.
func SealSay(ephemeralSecret, padlock, voiceSecret [32]byte, s Say) ([]byte, error) {
	payload, err := EncodeSayPayload(s)
	if err != nil {
		return nil, err
	}
	sig := arithmetic.Sign(voiceSecret, payload)
	return Seal(ephemeralSecret, padlock, append(payload, sig[:]...))
}

// OpenSay unseals a message and verifies the signature with the voice the
// payload carries. Anything it will not do, it refuses; the reason stays here
// and never travels.
func OpenSay(padlockSecret [32]byte, message []byte) (Say, error) {
	plain, err := Unseal(padlockSecret, message)
	if err != nil {
		return Say{}, err
	}
	payload, sig, err := split(plain)
	if err != nil {
		return Say{}, err
	}
	s, err := DecodeSayPayload(payload)
	if err != nil {
		return Say{}, err
	}
	if !arithmetic.Verify(s.Voice, payload, sig) {
		return Say{}, errors.New("envelope: the voice did not sign this payload")
	}
	return s, nil
}

// SealAnswer mirrors SealSay: the same boundary, signed by the warden's own
// name, because the caller must know that the door it asked is the door that
// spoke.
func SealAnswer(ephemeralSecret, returnPadlock, nameSecret [32]byte, a Answer) ([]byte, error) {
	payload, err := EncodeAnswerPayload(a)
	if err != nil {
		return nil, err
	}
	sig := arithmetic.Sign(nameSecret, payload)
	return Seal(ephemeralSecret, returnPadlock, append(payload, sig[:]...))
}

// OpenAnswer unseals an answer and verifies it under the name the answer
// carries.
func OpenAnswer(padlockSecret [32]byte, message []byte) (Answer, error) {
	plain, err := Unseal(padlockSecret, message)
	if err != nil {
		return Answer{}, err
	}
	payload, sig, err := split(plain)
	if err != nil {
		return Answer{}, err
	}
	a, err := DecodeAnswerPayload(payload)
	if err != nil {
		return Answer{}, err
	}
	if !arithmetic.Verify(a.Warden, payload, sig) {
		return Answer{}, errors.New("envelope: the warden did not sign this answer")
	}
	return a, nil
}

// split takes the signature off the end. It is fixed size, so it needs no
// marker and no length in front of the payload.
func split(plain []byte) ([]byte, [arithmetic.SignatureSize]byte, error) {
	var sig [arithmetic.SignatureSize]byte
	if len(plain) < arithmetic.SignatureSize {
		return nil, sig, errors.New("envelope: no room for a signature")
	}
	cut := len(plain) - arithmetic.SignatureSize
	copy(sig[:], plain[cut:])
	return plain[:cut], sig, nil
}

func sayValue(s Say) map[string]any {
	v := map[string]any{
		"voice":     s.Voice,
		"recipient": s.Recipient,
		"seq":       s.Seq,
		"padlock":   s.Padlock,
		"hints":     hintList(s.Hints),
		"allowance": map[string]any{"time": s.Allowance.Time, "hops": s.Allowance.Hops},
	}
	v["commitment"] = optional32(s.Commitment)
	v["being"] = optional32(s.Being)
	if s.Method != nil {
		v["method"] = map[string]any{"name": s.Method.Name, "args": bytesOrEmpty(s.Method.Args)}
	} else {
		v["method"] = nil
	}
	return v
}

func answerValue(a Answer) map[string]any {
	v := map[string]any{"warden": a.Warden, "seq": a.Seq}
	if a.Data == nil {
		v["data"] = nil
	} else {
		v["data"] = a.Data
	}
	return v
}

func readSay(v any) (Say, error) {
	f, ok := v.(map[string]any)
	if !ok {
		return Say{}, fmt.Errorf("envelope: %T is not a say", v)
	}
	var s Say
	var err error
	if s.Voice, err = key(f, "voice"); err != nil {
		return Say{}, err
	}
	if s.Recipient, err = key(f, "recipient"); err != nil {
		return Say{}, err
	}
	if s.Commitment, err = maybeKey(f, "commitment"); err != nil {
		return Say{}, err
	}
	if s.Seq, err = number(f, "seq"); err != nil {
		return Say{}, err
	}
	if s.Padlock, err = key(f, "padlock"); err != nil {
		return Say{}, err
	}
	if s.Hints, err = hints(f["hints"]); err != nil {
		return Say{}, err
	}
	allowance, ok := f["allowance"].(map[string]any)
	if !ok {
		return Say{}, errors.New("envelope: the allowance is not a record")
	}
	if s.Allowance.Time, err = number(allowance, "time"); err != nil {
		return Say{}, err
	}
	if s.Allowance.Hops, err = number(allowance, "hops"); err != nil {
		return Say{}, err
	}
	if s.Being, err = maybeKey(f, "being"); err != nil {
		return Say{}, err
	}
	if f["method"] != nil {
		method, ok := f["method"].(map[string]any)
		if !ok {
			return Say{}, errors.New("envelope: the method is not a record")
		}
		name, ok := method["name"].(string)
		if !ok {
			return Say{}, errors.New("envelope: the method has no name")
		}
		args, ok := method["args"].([]byte)
		if !ok {
			return Say{}, errors.New("envelope: the method has no arguments")
		}
		s.Method = &Method{Name: name, Args: args}
	}
	return s, nil
}

func readAnswer(v any) (Answer, error) {
	f, ok := v.(map[string]any)
	if !ok {
		return Answer{}, fmt.Errorf("envelope: %T is not an answer", v)
	}
	var a Answer
	var err error
	if a.Warden, err = key(f, "warden"); err != nil {
		return Answer{}, err
	}
	if a.Seq, err = number(f, "seq"); err != nil {
		return Answer{}, err
	}
	if f["data"] != nil {
		data, ok := f["data"].([]byte)
		if !ok {
			return Answer{}, errors.New("envelope: the data is not bytes")
		}
		a.Data = data
	}
	return a, nil
}

func key(f map[string]any, name string) ([32]byte, error) {
	k, ok := f[name].([32]byte)
	if !ok {
		return [32]byte{}, fmt.Errorf("envelope: %s is not a key", name)
	}
	return k, nil
}

func maybeKey(f map[string]any, name string) (*[32]byte, error) {
	if f[name] == nil {
		return nil, nil
	}
	k, err := key(f, name)
	if err != nil {
		return nil, err
	}
	return &k, nil
}

func number(f map[string]any, name string) (int64, error) {
	n, ok := f[name].(int64)
	if !ok {
		return 0, fmt.Errorf("envelope: %s is not a number", name)
	}
	return n, nil
}

func hints(v any) ([]string, error) {
	items, ok := v.([]any)
	if !ok {
		return nil, errors.New("envelope: the hints are not a list")
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		s, ok := item.(string)
		if !ok {
			return nil, errors.New("envelope: a hint is not text")
		}
		out = append(out, s)
	}
	return out, nil
}

func hintList(hints []string) []any {
	out := make([]any, 0, len(hints))
	for _, h := range hints {
		out = append(out, h)
	}
	return out
}

func optional32(k *[32]byte) any {
	if k == nil {
		return nil
	}
	return *k
}

func bytesOrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return b
}

func mustParse(text string) *notation.Blueprint {
	bp, err := notation.Parse(text)
	if err != nil {
		panic(err)
	}
	return bp
}
