package pxc

import "testing"

func TestOpenDBEmptyDSN(t *testing.T) {
	if _, err := OpenDB(""); err == nil {
		t.Error("expected an error for an empty DSN")
	}
}
