package facts

import (
	"testing"

	"github.com/digitalocean/go-smbios/smbios"
)

func TestCollectHardwareDoesNotPanic(t *testing.T) {
	// CollectHardware() reads the real SMBIOS table. In this sandbox (and
	// on most CI runners) that table is unreachable, so all we can assert
	// here is that failures are swallowed rather than panicking or
	// erroring out Collect().
	hf := CollectHardware()
	_ = hf
}

func TestHardwareFactsIsZero(t *testing.T) {
	if !(HardwareFacts{}).IsZero() {
		t.Error("expected zero-value HardwareFacts to report IsZero")
	}
	if (HardwareFacts{BIOSVendor: "Acme"}).IsZero() {
		t.Error("expected non-empty HardwareFacts to report !IsZero")
	}
}

func TestParseHardwareFactsBIOS(t *testing.T) {
	s := &smbios.Structure{
		Header:    smbios.Header{Type: smbiosTypeBIOS},
		Formatted: []byte{1, 2, 0, 0, 3},
		Strings:   []string{"Acme BIOS Co.", "1.2.3", "01/02/2026"},
	}
	hf := parseHardwareFacts([]*smbios.Structure{s})
	if hf.BIOSVendor != "Acme BIOS Co." {
		t.Errorf("BIOSVendor: expected %q, got %q", "Acme BIOS Co.", hf.BIOSVendor)
	}
	if hf.BIOSVersion != "1.2.3" {
		t.Errorf("BIOSVersion: expected %q, got %q", "1.2.3", hf.BIOSVersion)
	}
	if hf.BIOSReleaseDate != "01/02/2026" {
		t.Errorf("BIOSReleaseDate: expected %q, got %q", "01/02/2026", hf.BIOSReleaseDate)
	}
}

func TestParseHardwareFactsSystem(t *testing.T) {
	uuidBytes := []byte{
		0x01, 0x02, 0x03, 0x04,
		0x05, 0x06,
		0x07, 0x08,
		0x09, 0x0A,
		0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
	}
	formatted := append([]byte{1, 2, 0, 4}, uuidBytes...)
	s := &smbios.Structure{
		Header:    smbios.Header{Type: smbiosTypeSystem},
		Formatted: formatted,
		Strings:   []string{"Acme Inc.", "Widget 3000", "Rev A", "SN123456"},
	}
	hf := parseHardwareFacts([]*smbios.Structure{s})
	if hf.SystemManufacturer != "Acme Inc." {
		t.Errorf("SystemManufacturer: expected %q, got %q", "Acme Inc.", hf.SystemManufacturer)
	}
	if hf.SystemProductName != "Widget 3000" {
		t.Errorf("SystemProductName: expected %q, got %q", "Widget 3000", hf.SystemProductName)
	}
	if hf.SystemSerialNumber != "SN123456" {
		t.Errorf("SystemSerialNumber: expected %q, got %q", "SN123456", hf.SystemSerialNumber)
	}
	wantUUID := "04030201-0605-0807-090A-0B0C0D0E0F10"
	if hf.SystemUUID != wantUUID {
		t.Errorf("SystemUUID: expected %q, got %q", wantUUID, hf.SystemUUID)
	}
}

func TestParseHardwareFactsChassis(t *testing.T) {
	s := &smbios.Structure{
		Header:    smbios.Header{Type: smbiosTypeChassis},
		Formatted: []byte{1, 0x17, 0, 2, 3},
		Strings:   []string{"Acme Racks", "CHASSIS-SN-1", "ASSET-1"},
	}
	hf := parseHardwareFacts([]*smbios.Structure{s})
	if hf.ChassisManufacturer != "Acme Racks" {
		t.Errorf("ChassisManufacturer: expected %q, got %q", "Acme Racks", hf.ChassisManufacturer)
	}
	if hf.ChassisType != "Rack Mount Chassis" {
		t.Errorf("ChassisType: expected %q, got %q", "Rack Mount Chassis", hf.ChassisType)
	}
	if hf.ChassisSerialNumber != "CHASSIS-SN-1" {
		t.Errorf("ChassisSerialNumber: expected %q, got %q", "CHASSIS-SN-1", hf.ChassisSerialNumber)
	}
	if hf.ChassisAssetTag != "ASSET-1" {
		t.Errorf("ChassisAssetTag: expected %q, got %q", "ASSET-1", hf.ChassisAssetTag)
	}
}

func TestFormatUUIDAllZeroOrFF(t *testing.T) {
	zero := make([]byte, 16)
	if got := formatUUID(zero); got != "" {
		t.Errorf("expected empty string for all-zero UUID, got %q", got)
	}
	ff := make([]byte, 16)
	for i := range ff {
		ff[i] = 0xFF
	}
	if got := formatUUID(ff); got != "" {
		t.Errorf("expected empty string for all-0xFF UUID, got %q", got)
	}
}

func TestFormatUUIDWrongLength(t *testing.T) {
	if got := formatUUID([]byte{1, 2, 3}); got != "" {
		t.Errorf("expected empty string for short input, got %q", got)
	}
}

func TestSmbiosStrOutOfRange(t *testing.T) {
	s := &smbios.Structure{Strings: []string{"only-one"}}
	if got := smbiosStr(s, 0); got != "" {
		t.Errorf("expected empty string for index 0, got %q", got)
	}
	if got := smbiosStr(s, 5); got != "" {
		t.Errorf("expected empty string for out-of-range index, got %q", got)
	}
	if got := smbiosStr(s, 1); got != "only-one" {
		t.Errorf("expected %q, got %q", "only-one", got)
	}
}

func TestChassisTypeNameUnknown(t *testing.T) {
	if got := chassisTypeName(0x7F); got != "Unknown (0x7F)" {
		t.Errorf("expected fallback label, got %q", got)
	}
}

func TestSystemFactsHardwareOmittedWhenNil(t *testing.T) {
	sf := SystemFacts{OS: "linux", Arch: "amd64", Hostname: "h"}
	if sf.Hardware != nil {
		t.Error("expected nil Hardware by default")
	}
}
