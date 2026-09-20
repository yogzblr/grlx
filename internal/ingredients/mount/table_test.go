//go:build linux

package mount

import (
	"bytes"
	"strings"
	"testing"
)

const sampleFstab = `# /etc/fstab
UUID=1234  /            ext4    defaults        0 1

/dev/sdb1	/data	xfs	rw,noatime	0 2
`

func TestParseTable(t *testing.T) {
	lines, err := ParseTable(strings.NewReader(sampleFstab))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var entries []*Entry
	for _, l := range lines {
		if l.Entry != nil {
			entries = append(entries, l.Entry)
		}
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].Device != "UUID=1234" || entries[0].MountPoint != "/" || entries[0].FSType != "ext4" {
		t.Errorf("unexpected first entry: %+v", entries[0])
	}
	if entries[1].Device != "/dev/sdb1" || entries[1].MountPoint != "/data" {
		t.Errorf("unexpected second entry: %+v", entries[1])
	}
	if len(entries[1].Options) != 2 || entries[1].Options[0] != "rw" || entries[1].Options[1] != "noatime" {
		t.Errorf("unexpected options: %v", entries[1].Options)
	}
	if entries[1].Pass != 2 {
		t.Errorf("expected pass 2, got %d", entries[1].Pass)
	}
}

func TestParseTablePreservesComments(t *testing.T) {
	lines, err := ParseTable(strings.NewReader(sampleFstab))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if lines[0].Entry != nil || !strings.HasPrefix(lines[0].Raw, "#") {
		t.Errorf("expected first line to be a preserved comment, got %+v", lines[0])
	}
}

func TestEscapeUnescapeField(t *testing.T) {
	path := "/mnt/my dir"
	esc := escapeField(path)
	if esc != `/mnt/my\040dir` {
		t.Fatalf("unexpected escape: %q", esc)
	}
	if got := unescapeField(esc); got != path {
		t.Fatalf("round-trip mismatch: got %q, want %q", got, path)
	}
}

func TestFindByMountPoint(t *testing.T) {
	lines, _ := ParseTable(strings.NewReader(sampleFstab))
	e := FindByMountPoint(lines, "/data")
	if e == nil || e.Device != "/dev/sdb1" {
		t.Fatalf("expected to find /data entry, got %+v", e)
	}
	if FindByMountPoint(lines, "/nope") != nil {
		t.Fatal("expected nil for missing mount point")
	}
}

func TestUpsertByMountPointAppend(t *testing.T) {
	lines, _ := ParseTable(strings.NewReader(sampleFstab))
	newEntry := Entry{Device: "/dev/sdc1", MountPoint: "/backup", FSType: "ext4", Options: []string{"defaults"}}
	updated, changed := UpsertByMountPoint(lines, newEntry)
	if !changed {
		t.Fatal("expected changed=true for new entry")
	}
	if FindByMountPoint(updated, "/backup") == nil {
		t.Fatal("expected new entry to be present")
	}
	if len(updated) != len(lines)+1 {
		t.Fatalf("expected one more line, got %d vs %d", len(updated), len(lines))
	}
}

func TestUpsertByMountPointReplace(t *testing.T) {
	lines, _ := ParseTable(strings.NewReader(sampleFstab))
	newEntry := Entry{Device: "/dev/sdb2", MountPoint: "/data", FSType: "xfs", Options: []string{"rw"}}
	updated, changed := UpsertByMountPoint(lines, newEntry)
	if !changed {
		t.Fatal("expected changed=true when device differs")
	}
	if len(updated) != len(lines) {
		t.Fatalf("expected same line count, got %d vs %d", len(updated), len(lines))
	}
	e := FindByMountPoint(updated, "/data")
	if e == nil || e.Device != "/dev/sdb2" {
		t.Fatalf("expected replaced entry, got %+v", e)
	}
}

func TestUpsertByMountPointNoChange(t *testing.T) {
	lines, _ := ParseTable(strings.NewReader(sampleFstab))
	existing := FindByMountPoint(lines, "/data")
	updated, changed := UpsertByMountPoint(lines, *existing)
	if changed {
		t.Fatal("expected changed=false for identical entry")
	}
	if len(updated) != len(lines) {
		t.Fatal("expected unchanged line count")
	}
}

func TestRemoveByMountPoint(t *testing.T) {
	lines, _ := ParseTable(strings.NewReader(sampleFstab))
	updated, removed := RemoveByMountPoint(lines, "/data")
	if !removed {
		t.Fatal("expected removed=true")
	}
	if FindByMountPoint(updated, "/data") != nil {
		t.Fatal("expected /data entry to be gone")
	}
	// Comments should survive.
	found := false
	for _, l := range updated {
		if l.Entry == nil && strings.Contains(l.Raw, "/etc/fstab") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected leading comment to survive removal")
	}

	_, removedAgain := RemoveByMountPoint(updated, "/data")
	if removedAgain {
		t.Fatal("expected removed=false when entry already gone")
	}
}

func TestWriteTableRoundTrip(t *testing.T) {
	lines, err := ParseTable(strings.NewReader(sampleFstab))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var buf bytes.Buffer
	if err := WriteTable(&buf, lines); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	reparsed, err := ParseTable(&buf)
	if err != nil {
		t.Fatalf("unexpected error reparsing: %v", err)
	}
	if len(reparsed) != len(lines) {
		t.Fatalf("expected %d lines, got %d", len(lines), len(reparsed))
	}
	e := FindByMountPoint(reparsed, "/data")
	if e == nil || e.Device != "/dev/sdb1" || e.Pass != 2 {
		t.Fatalf("unexpected reparsed entry: %+v", e)
	}
}

func TestFormatEntryDefaultsOptions(t *testing.T) {
	line := FormatEntry(Entry{Device: "/dev/sda1", MountPoint: "/", FSType: "ext4"})
	if !strings.Contains(line, "defaults") {
		t.Fatalf("expected default options in formatted line, got %q", line)
	}
}
