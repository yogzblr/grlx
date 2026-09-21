package user

// diffMembership computes the additions and removals needed to change a
// membership list from current to exactly desired, preserving desired's
// order for additions. It is pure and OS-independent so it can be unit
// tested without a live Windows host; the Windows provider is the only
// current caller (see userPresent_windows.go), reconciling a user's local
// group membership to match the "groups" property exactly, the same
// exact-set semantics as the Unix provider's `usermod -G`.
func diffMembership(current, desired []string) (toAdd, toRemove []string) {
	have := make(map[string]bool, len(current))
	for _, c := range current {
		have[c] = true
	}
	want := make(map[string]bool, len(desired))
	for _, d := range desired {
		want[d] = true
	}
	for _, d := range desired {
		if !have[d] {
			toAdd = append(toAdd, d)
		}
	}
	for _, c := range current {
		if !want[c] {
			toRemove = append(toRemove, c)
		}
	}
	return toAdd, toRemove
}
