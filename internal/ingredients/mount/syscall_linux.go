//go:build linux

package mount

import (
	"os/exec"
	"strings"

	"golang.org/x/sys/unix"
)

// networkFSTypes lists filesystem types whose real mount helper
// (mount.nfs, mount.cifs, ...) does work that the bare mount(2) syscall
// does not: resolving the server, negotiating the protocol version,
// looking up credentials, etc. For these we shell out to the mount binary
// instead of calling unix.Mount directly.
var networkFSTypes = map[string]bool{
	"nfs":   true,
	"nfs4":  true,
	"nfsd":  true,
	"cifs":  true,
	"smbfs": true,
	"smb3":  true,
}

func isNetworkFSType(fstype string) bool {
	return networkFSTypes[strings.ToLower(fstype)]
}

// mountFlagBits maps mount option names to their MS_* flag bits. Any option
// not in this table is passed through in the filesystem-specific "data"
// string instead (e.g. "size=100m" for tmpfs).
var mountFlagBits = map[string]uintptr{
	"ro":          unix.MS_RDONLY,
	"noatime":     unix.MS_NOATIME,
	"nodiratime":  unix.MS_NODIRATIME,
	"nosuid":      unix.MS_NOSUID,
	"nodev":       unix.MS_NODEV,
	"noexec":      unix.MS_NOEXEC,
	"sync":        unix.MS_SYNCHRONOUS,
	"dirsync":     unix.MS_DIRSYNC,
	"remount":     unix.MS_REMOUNT,
	"bind":        unix.MS_BIND,
	"rbind":       unix.MS_BIND | unix.MS_REC,
	"relatime":    unix.MS_RELATIME,
	"norelatime":  0, // handled as absence of relatime; kept for symmetry
	"strictatime": unix.MS_STRICTATIME,
	"silent":      unix.MS_SILENT,
	"private":     unix.MS_PRIVATE,
	"shared":      unix.MS_SHARED,
	"slave":       unix.MS_SLAVE,
	"unbindable":  unix.MS_UNBINDABLE,
}

// splitMountOptions turns a fstab-style option list into the (flags, data)
// pair unix.Mount expects: known flag names become MS_* bits, anything else
// (rw, defaults, noop, or filesystem-specific options like "size=100m") is
// joined back into the data string passed through to the filesystem.
func splitMountOptions(opts []string) (uintptr, string) {
	var flags uintptr
	var data []string
	for _, o := range opts {
		o = strings.TrimSpace(o)
		switch o {
		case "", "defaults", "rw", "async":
			continue
		}
		if bit, ok := mountFlagBits[o]; ok {
			flags |= bit
			continue
		}
		data = append(data, o)
	}
	return flags, strings.Join(data, ",")
}

// mountFunc and unmountFunc wrap the raw syscalls behind package vars so
// tests can substitute fakes without needing real mount privileges.
var (
	mountFunc   = unix.Mount
	unmountFunc = unix.Unmount
)

// execCommandContext is a test-overridable factory for the cmd-based
// fallback path (network filesystems).
var execCommandContext = exec.CommandContext
