package warden

// Two counts the bench reads and no host does. They are here rather than on
// the door because a door's surface is what a host, a being or a peer calls to
// do its job, and neither of these is called to do anything: they are how an
// assertion sees a field it must not reach into.

// ArmsHeld is how many commitments this door is holding a claim open for.
func ArmsHeld(w *Warden) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.arms)
}

// AsksOut is how many asks this ground has out down one relation with no
// answer heard yet.
func AsksOut(w *Warden, far [32]byte) int {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := 0
	for _, rel := range w.record.out {
		if rel.warden == far {
			out += len(rel.awaiting)
		}
	}
	return out
}
