// Package carriage is the one common carriage every warden answers: HTTPS,
// chosen for reach rather than for fit.
//
// Quo needs almost nothing from HTTP. The hint a warden published is the whole
// address, posted to exactly as given — no path appended, no query added, no
// header read, no status code carrying meaning. The request body is one sealed
// message, the response body is the sealed answer, and an empty body is
// silence's wire form. Those two are the whole of what the carriage says back.
//
// Any meaning in the carriage would be meaning outside the seal, and there is
// none. Nothing in this package looks inside a message; it moves bytes and
// hands them to a door.
package carriage

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

// Answer is a door. The bytes that arrived go in, the sealed answer comes out,
// and nil is silence — which is the whole of every refusal.
//
// It is a function rather than an interface because the warden's own judgment
// needs randomness the host draws, and a carriage that reached for that would
// be a carriage deciding something.
type Answer func(message []byte) []byte

// Handler answers one POST. Anything that is not a POST, and any body larger
// than the limit the door publishes, is silence — an empty body, exactly as a
// refusal is, because a door that explained itself would be a door that can be
// probed.
//
// A limit of zero or less takes no body at all: a door that read an unbounded
// body would be a door anyone can exhaust, and the size limit is the warden's
// own by the same rule that makes it a published field.
func Handler(limit int64, answer Answer) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "0")
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusOK)
			return
		}
		message, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
		if err != nil || int64(len(message)) > limit {
			w.WriteHeader(http.StatusOK)
			return
		}
		reply := answer(message)
		if len(reply) == 0 {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.Header().Del("Content-Length")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(reply)
	})
}

// Caller posts a message down the roads a peer offered. Its zero value works
// and uses http.DefaultClient; a host that wants its own timeouts, its own
// proxy or its own TLS gives its own client, because delivery is not Quo's.
type Caller struct {
	Client *http.Client
}

// ErrNoRoad is what a caller gets when every hint it was given failed to
// carry. It is a fact about the weather, never an answer from a door: a door
// that answered silence answered, and Send hands that back as no bytes and no
// error.
var ErrNoRoad = errors.New("carriage: no hint carried this message")

// Send posts the message to each hint in turn and hands back the first
// response body a road actually returned.
//
// A hint is a guess about the weather, so a warden offers as many roads as it
// has and a caller tries them. Only a road that failed to carry moves the
// caller to the next: an empty body is silence, which is a door speaking, and
// a caller that tried the next road after it would ask one question twice and
// spend two numbers on it.
func (c Caller) Send(hints []string, message []byte) ([]byte, error) {
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	var last error
	for _, hint := range hints {
		// The hint is the whole address, posted to exactly as given.
		req, err := http.NewRequest(http.MethodPost, hint, bytes.NewReader(message))
		if err != nil {
			last = err
			continue
		}
		res, err := client.Do(req)
		if err != nil {
			last = err
			continue
		}
		body, err := io.ReadAll(res.Body)
		res.Body.Close()
		if err != nil {
			last = err
			continue
		}
		// No status code carries meaning, so none is read. What came back is
		// the body, and an empty one is silence.
		if len(body) == 0 {
			return nil, nil
		}
		return body, nil
	}
	if last == nil {
		last = ErrNoRoad
	}
	return nil, last
}
