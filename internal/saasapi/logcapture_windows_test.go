//go:build windows

package saasapi

import "testing"

// captureStderr's fd-level redirect trick (see the unix build) relies on
// syscall.Dup2, which the standard "syscall" package doesn't expose on
// Windows. cmd/saasapi is a Linux/server-side deployment target (see its
// package doc comment); skip rather than fake the capture on Windows.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	t.Skip("captureStderr requires syscall.Dup2, unavailable on windows; saasapi targets Linux/server deployment")
	fn()
	return ""
}
