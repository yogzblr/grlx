//go:build linux

package mount

import (
	"context"
	"fmt"
	"testing"
)

func TestMountedApplyNewLocal(t *testing.T) {
	withTempTables(t, "", "")
	calls := withMockMount(t, nil)
	withMockMkdirAll(t)

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4",
		"opts": []interface{}{"noatime"},
	}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 1 {
		t.Fatalf("expected 1 mount call, got %d", len(*calls))
	}
	if (*calls)[0].source != "/dev/sdb1" || (*calls)[0].target != "/data" {
		t.Errorf("unexpected mount call: %+v", (*calls)[0])
	}

	lines, err := readFstab()
	if err != nil {
		t.Fatalf("unexpected error reading fstab: %v", err)
	}
	e := FindByMountPoint(lines, "/data")
	if e == nil || e.Device != "/dev/sdb1" {
		t.Fatalf("expected fstab entry to be created, got %+v", e)
	}
}

func TestMountedApplyAlreadyMounted(t *testing.T) {
	withTempTables(t, "/dev/sdb1\t/data\text4\tdefaults\t0\t0\n",
		"/dev/sdb1 /data ext4 rw,noatime 0 0\n")
	calls := withMockMount(t, nil)

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4",
	}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("expected no mount syscall for already-mounted target, got %d", len(*calls))
	}
	if result.Changed {
		t.Fatalf("expected no change: fstab entry already matches, mount already active")
	}
}

func TestMountedApplyConflictingExistingMount(t *testing.T) {
	withTempTables(t, "", "/dev/sda1 /data ext4 rw 0 0\n")

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4",
	}}
	result, err := m.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error for conflicting mount")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestMountedApplyForceRemountReplacesConflicting(t *testing.T) {
	withTempTables(t, "", "/dev/sda1 /data ext4 rw 0 0\n")
	mountCalls := withMockMount(t, nil)
	unmountCalls := withMockUnmount(t, nil)
	withMockMkdirAll(t)

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4", "force_remount": true,
	}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Failed || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*unmountCalls) != 1 || (*unmountCalls)[0] != "/data" {
		t.Fatalf("expected one unmount of /data, got %v", *unmountCalls)
	}
	if len(*mountCalls) != 1 || (*mountCalls)[0].source != "/dev/sdb1" {
		t.Fatalf("expected remount from /dev/sdb1, got %v", *mountCalls)
	}
}

func TestMountedTestModeForceRemount(t *testing.T) {
	withTempTables(t, "", "/dev/sda1 /data ext4 rw 0 0\n")
	mountCalls := withMockMount(t, nil)
	unmountCalls := withMockUnmount(t, nil)

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4", "force_remount": true,
	}}
	result, err := m.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*unmountCalls) != 0 || len(*mountCalls) != 0 {
		t.Fatalf("test mode must not call mount(2)/unmount(2), got unmount=%v mount=%v", *unmountCalls, *mountCalls)
	}
}

func TestMountedApplyForceRemountUnmountFailure(t *testing.T) {
	withTempTables(t, "", "/dev/sda1 /data ext4 rw 0 0\n")
	withMockMount(t, nil)
	withMockUnmount(t, fmt.Errorf("device busy"))

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4", "force_remount": true,
	}}
	result, err := m.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error when unmount fails during force_remount")
	}
	if !result.Failed {
		t.Fatalf("expected Failed=true, got %+v", result)
	}
}

func TestMountedApplyNetworkFSUsesCmdFallback(t *testing.T) {
	withTempTables(t, "", "")
	mountCalls := withMockMount(t, nil)
	execCalls := withMockExecSuccess(t)
	withMockMkdirAll(t)

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/mnt/nfs", "device": "nfsserver:/export", "fstype": "nfs",
		"persist": false,
	}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*mountCalls) != 0 {
		t.Fatalf("expected mount(2) not to be called for nfs, got %d calls", len(*mountCalls))
	}
	if len(*execCalls) != 1 || (*execCalls)[0][0] != "mount" {
		t.Fatalf("expected one exec call to the mount binary, got %v", *execCalls)
	}
}

func TestMountedTestModeDoesNotMutate(t *testing.T) {
	withTempTables(t, "", "")
	calls := withMockMount(t, nil)

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4",
	}}
	result, err := m.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(*calls) != 0 {
		t.Fatalf("test mode must not call mount(2), got %d calls", len(*calls))
	}
	lines, _ := readFstab()
	if FindByMountPoint(lines, "/data") != nil {
		t.Fatal("test mode must not write fstab")
	}
}

func TestMountedApplyNoPersistSkipsFstab(t *testing.T) {
	withTempTables(t, "", "")
	withMockMount(t, nil)
	withMockMkdirAll(t)

	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4", "persist": false,
	}}
	if _, err := m.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	lines, _ := readFstab()
	if FindByMountPoint(lines, "/data") != nil {
		t.Fatal("expected no fstab entry when persist=false")
	}
}
