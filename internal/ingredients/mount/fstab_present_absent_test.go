//go:build linux

package mount

import (
	"context"
	"testing"
)

func TestFstabPresentAdds(t *testing.T) {
	withTempTables(t, "", "")

	m := Mount{id: "t", method: "fstab_present", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4",
		"opts": []interface{}{"ro"},
	}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	lines, _ := readFstab()
	e := FindByMountPoint(lines, "/data")
	if e == nil || e.Options[0] != "ro" {
		t.Fatalf("expected fstab entry with ro option, got %+v", e)
	}
}

func TestFstabPresentIdempotent(t *testing.T) {
	withTempTables(t, "/dev/sdb1\t/data\text4\tro\t0\t0\n", "")

	m := Mount{id: "t", method: "fstab_present", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4",
		"opts": []interface{}{"ro"},
	}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("expected no-op, got %+v", result)
	}
}

func TestFstabPresentTestMode(t *testing.T) {
	withTempTables(t, "", "")

	m := Mount{id: "t", method: "fstab_present", params: map[string]interface{}{
		"name": "/data", "device": "/dev/sdb1", "fstype": "ext4",
	}}
	result, err := m.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Changed {
		t.Fatalf("expected changed=true, got %+v", result)
	}
	lines, _ := readFstab()
	if FindByMountPoint(lines, "/data") != nil {
		t.Fatal("test mode must not write fstab")
	}
}

func TestFstabAbsentRemoves(t *testing.T) {
	withTempTables(t, "/dev/sdb1\t/data\text4\tdefaults\t0\t0\n", "")

	m := Mount{id: "t", method: "fstab_absent", params: map[string]interface{}{"name": "/data"}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("unexpected result: %+v", result)
	}
	lines, _ := readFstab()
	if FindByMountPoint(lines, "/data") != nil {
		t.Fatal("expected entry to be removed")
	}
}

func TestFstabAbsentNoEntry(t *testing.T) {
	withTempTables(t, "", "")

	m := Mount{id: "t", method: "fstab_absent", params: map[string]interface{}{"name": "/data"}}
	result, err := m.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("expected no-op, got %+v", result)
	}
}

func TestMountParseMissingRequiredFields(t *testing.T) {
	m := Mount{}
	if _, err := m.Parse("t", "mounted", map[string]interface{}{"name": "/data"}); err == nil {
		t.Fatal("expected error for missing device/fstype")
	}
	if _, err := m.Parse("t", "mounted", map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing name")
	}
}

func TestMountUndefinedMethod(t *testing.T) {
	m := Mount{id: "t", method: "bogus", params: map[string]interface{}{}}
	if _, err := m.Apply(context.Background()); err == nil {
		t.Fatal("expected error for undefined method")
	}
	if _, err := m.Test(context.Background()); err == nil {
		t.Fatal("expected error for undefined method")
	}
}

func TestMountMethodsAndProperties(t *testing.T) {
	m := Mount{id: "t", method: "mounted", params: map[string]interface{}{"name": "/data"}}
	name, methods := m.Methods()
	if name != "mount" {
		t.Fatalf("expected ingredient name 'mount', got %q", name)
	}
	if len(methods) != 4 {
		t.Fatalf("expected 4 methods, got %d", len(methods))
	}
	props, err := m.Properties()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if props["name"] != "/data" {
		t.Fatalf("unexpected properties: %+v", props)
	}
}
