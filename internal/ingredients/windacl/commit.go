//go:build windows

package windacl

import (
	"fmt"

	"github.com/hectane/go-acl/api"
	"golang.org/x/sys/windows"
)

// commitACL writes entries as name's explicit DACL, preserving the
// object's current inheritance-protection state (protected). It never
// writes an empty ACL: SetEntriesInAcl dereferences entries[0]
// internally, and an object silently left with zero explicit ACEs (and
// therefore reliant on whatever it inherits, or on nothing at all) is
// exactly the kind of surprising, over/under-broad result this
// ingredient's callers shouldn't get without asking for it explicitly.
func commitACL(seObjType int32, name string, entries []aceEntry, protected bool) error {
	if len(entries) == 0 {
		return fmt.Errorf("%w: %s", ErrWouldClearDACL, name)
	}
	explicit := make([]api.ExplicitAccess, len(entries))
	for i, e := range entries {
		explicit[i] = e.toExplicitAccess()
	}
	newACL, err := setEntriesInACLRaw(explicit)
	if err != nil {
		return err
	}
	defer windows.LocalFree(newACL)
	return setDACL(seObjType, name, newACL, protected)
}
