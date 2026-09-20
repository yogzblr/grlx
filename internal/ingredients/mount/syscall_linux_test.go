//go:build linux

package mount

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsNetworkFSType(t *testing.T) {
	cases := map[string]bool{
		"nfs": true, "NFS4": true, "cifs": true, "SMB3": true,
		"ext4": false, "xfs": false, "": false,
	}
	for fstype, want := range cases {
		if got := isNetworkFSType(fstype); got != want {
			t.Errorf("isNetworkFSType(%q) = %v, want %v", fstype, got, want)
		}
	}
}

func TestSplitMountOptions(t *testing.T) {
	flags, data := splitMountOptions([]string{"ro", "noatime", "nosuid", "size=100m"})
	wantFlags := uintptr(unix.MS_RDONLY | unix.MS_NOATIME | unix.MS_NOSUID)
	if flags != wantFlags {
		t.Errorf("flags = %#x, want %#x", flags, wantFlags)
	}
	if data != "size=100m" {
		t.Errorf("data = %q, want %q", data, "size=100m")
	}
}

func TestSplitMountOptionsDefaultsAndRW(t *testing.T) {
	flags, data := splitMountOptions([]string{"defaults", "rw", "async"})
	if flags != 0 {
		t.Errorf("flags = %#x, want 0", flags)
	}
	if data != "" {
		t.Errorf("data = %q, want empty", data)
	}
}

func TestSplitMountOptionsBind(t *testing.T) {
	flags, _ := splitMountOptions([]string{"bind"})
	if flags != unix.MS_BIND {
		t.Errorf("flags = %#x, want MS_BIND", flags)
	}
}
