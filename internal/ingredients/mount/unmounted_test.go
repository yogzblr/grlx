//go:build linux

package mount

import (
	"context"
	"testing"
)

func TestUnmountedApplyMounted(t *testing.T) {
	withTempTables(t, "/dev/sdb1\t/data\text4\tdefaults\t0\t0\n",
		"/dev/sdb1 /data ext4 rw 0 0\n")
	calls := withMockUnmount(t, nil)

	m := Mount{id: "t", method: "unmounted", params: map[string]interface{}{"name": "/data"}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 1 || (*calls)[0] != "/data" {
		t.Fatalf("unexpected unmount calls: %v", *calls)
	}
	lines, _ := readFstab()
	if FindByMountPoint(lines, "/data") != nil {
		t.Fatal("expected fstab entry to be removed by default (persist=true)")
	}
}

func TestUnmountedApplyAlreadyUnmounted(t *testing.T) {
	withTempTables(t, "", "")
	calls := withMockUnmount(t, nil)

	m := Mount{id: "t", method: "unmounted", params: map[string]interface{}{"name": "/data"}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("expected no-op result, got %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no unmount calls, got %d", len(*calls))
	}
}

func TestUnmountedApplyKeepsFstabWhenNotPersist(t *testing.T) {
	withTempTables(t, "/dev/sdb1\t/data\text4\tdefaults\t0\t0\n",
		"/dev/sdb1 /data ext4 rw 0 0\n")
	withMockUnmount(t, nil)

	m := Mount{id: "t", method: "unmounted", params: map[string]interface{}{
		"name": "/data", "persist": false,
	}}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines, _ := readFstab()
	if FindByMountPoint(lines, "/data") == nil {
		t.Fatal("expected fstab entry to survive when persist=false")
	}
}

func TestUnmountedTestModeDoesNotMutate(t *testing.T) {
	withTempTables(t, "/dev/sdb1\t/data\text4\tdefaults\t0\t0\n",
		"/dev/sdb1 /data ext4 rw 0 0\n")
	calls := withMockUnmount(t, nil)

	m := Mount{id: "t", method: "unmounted", params: map[string]interface{}{"name": "/data"}}
	result, err := m.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected changed=true, got %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("test mode must not call unmount(2), got %d calls", len(*calls))
	}
	lines, _ := readFstab()
	if FindByMountPoint(lines, "/data") == nil {
		t.Fatal("test mode must not mutate fstab")
	}
}
