package facts

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/digitalocean/go-smbios/smbios"
)

// SMBIOS structure types this file decodes. See DMTF DSP0134 ("System
// Management BIOS (SMBIOS) Reference Specification"), table 0 for the
// full type list.
const (
	smbiosTypeBIOS    = 0
	smbiosTypeSystem  = 1
	smbiosTypeChassis = 3
)

// HardwareFacts holds BIOS/system-identity facts decoded from the local
// SMBIOS/DMI table. It covers the subset win_smbios/win_system expose via
// WMI on Salt (BIOS vendor/version, system manufacturer/serial/UUID,
// chassis identity) — not the broader win_disk surface, which needs live
// disk I/O rather than static SMBIOS data.
type HardwareFacts struct {
	BIOSVendor          string `json:"bios_vendor,omitempty"`
	BIOSVersion         string `json:"bios_version,omitempty"`
	BIOSReleaseDate     string `json:"bios_release_date,omitempty"`
	SystemManufacturer  string `json:"system_manufacturer,omitempty"`
	SystemProductName   string `json:"system_product_name,omitempty"`
	SystemSerialNumber  string `json:"system_serial_number,omitempty"`
	SystemUUID          string `json:"system_uuid,omitempty"`
	ChassisManufacturer string `json:"chassis_manufacturer,omitempty"`
	ChassisType         string `json:"chassis_type,omitempty"`
	ChassisSerialNumber string `json:"chassis_serial_number,omitempty"`
	ChassisAssetTag     string `json:"chassis_asset_tag,omitempty"`
}

// IsZero reports whether no hardware facts were collected, e.g. because
// the SMBIOS table wasn't reachable (unprivileged container, unsupported
// platform, virtualized environment without a DMI table).
func (h HardwareFacts) IsZero() bool {
	return h == HardwareFacts{}
}

// CollectHardware reads and decodes the local SMBIOS/DMI table and
// returns the identity facts found in it. Errors are swallowed and an
// empty HardwareFacts is returned instead: hardware facts are a
// best-effort enrichment of Collect(), not a hard requirement for sprout
// operation.
func CollectHardware() HardwareFacts {
	rc, _, err := smbios.Stream()
	if err != nil {
		return HardwareFacts{}
	}
	defer rc.Close()

	structures, err := smbios.NewDecoder(rc).Decode()
	if err != nil {
		return HardwareFacts{}
	}
	return parseHardwareFacts(structures)
}

// parseHardwareFacts extracts HardwareFacts from already-decoded SMBIOS
// structures. Split out from CollectHardware so the parsing logic can be
// unit tested without a real (or mocked) SMBIOS stream.
func parseHardwareFacts(structures []*smbios.Structure) HardwareFacts {
	var hf HardwareFacts
	for _, s := range structures {
		if s == nil {
			continue
		}
		switch s.Header.Type {
		case smbiosTypeBIOS:
			parseBIOS(s, &hf)
		case smbiosTypeSystem:
			parseSystem(s, &hf)
		case smbiosTypeChassis:
			parseChassis(s, &hf)
		}
	}
	return hf
}

// parseBIOS decodes SMBIOS Type 0 (BIOS Information).
func parseBIOS(s *smbios.Structure, hf *HardwareFacts) {
	if len(s.Formatted) > 1 {
		hf.BIOSVendor = smbiosStr(s, s.Formatted[0])
		hf.BIOSVersion = smbiosStr(s, s.Formatted[1])
	}
	if len(s.Formatted) > 4 {
		hf.BIOSReleaseDate = smbiosStr(s, s.Formatted[4])
	}
}

// parseSystem decodes SMBIOS Type 1 (System Information).
func parseSystem(s *smbios.Structure, hf *HardwareFacts) {
	if len(s.Formatted) > 0 {
		hf.SystemManufacturer = smbiosStr(s, s.Formatted[0])
	}
	if len(s.Formatted) > 1 {
		hf.SystemProductName = smbiosStr(s, s.Formatted[1])
	}
	if len(s.Formatted) > 3 {
		hf.SystemSerialNumber = smbiosStr(s, s.Formatted[3])
	}
	if len(s.Formatted) >= 20 {
		hf.SystemUUID = formatUUID(s.Formatted[4:20])
	}
}

// parseChassis decodes SMBIOS Type 3 (System Enclosure or Chassis).
func parseChassis(s *smbios.Structure, hf *HardwareFacts) {
	if len(s.Formatted) > 0 {
		hf.ChassisManufacturer = smbiosStr(s, s.Formatted[0])
	}
	if len(s.Formatted) > 1 {
		// Bit 7 is the "chassis lock present" flag, not part of the type.
		hf.ChassisType = chassisTypeName(s.Formatted[1] & 0x7f)
	}
	if len(s.Formatted) > 3 {
		hf.ChassisSerialNumber = smbiosStr(s, s.Formatted[3])
	}
	if len(s.Formatted) > 4 {
		hf.ChassisAssetTag = smbiosStr(s, s.Formatted[4])
	}
}

// smbiosStr resolves a 1-based SMBIOS string-table index (0 means "not
// specified") against a structure's string set.
func smbiosStr(s *smbios.Structure, idx byte) string {
	if idx == 0 || int(idx) > len(s.Strings) {
		return ""
	}
	return strings.TrimSpace(s.Strings[idx-1])
}

// formatUUID renders a 16-byte SMBIOS Type 1 UUID field as a standard
// hyphenated UUID string. Per DSP0134 (system versions 2.6+, which is
// effectively universal today), the first three fields are little-endian
// and the last two are big-endian/wire-order — the reverse of a plain
// byte dump, and the same mixed-endian convention dmidecode uses.
func formatUUID(b []byte) string {
	if len(b) != 16 {
		return ""
	}
	allZero, allFF := true, true
	for _, v := range b {
		if v != 0x00 {
			allZero = false
		}
		if v != 0xff {
			allFF = false
		}
	}
	if allZero || allFF {
		// Per spec, all-0x00 or all-0xFF means "UUID not present".
		return ""
	}
	return fmt.Sprintf("%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%s",
		b[3], b[2], b[1], b[0],
		b[5], b[4],
		b[7], b[6],
		b[8], b[9],
		strings.ToUpper(hex.EncodeToString(b[10:16])),
	)
}

// chassisTypeNames maps the SMBIOS Type 3 "Type" enumeration (DSP0134
// table 21) to human-readable names, for the values in common use.
var chassisTypeNames = map[byte]string{
	0x01: "Other",
	0x02: "Unknown",
	0x03: "Desktop",
	0x04: "Low Profile Desktop",
	0x05: "Pizza Box",
	0x06: "Mini Tower",
	0x07: "Tower",
	0x08: "Portable",
	0x09: "Laptop",
	0x0A: "Notebook",
	0x0B: "Hand Held",
	0x0C: "Docking Station",
	0x0D: "All in One",
	0x0E: "Sub Notebook",
	0x0F: "Space-saving",
	0x10: "Lunch Box",
	0x11: "Main Server Chassis",
	0x12: "Expansion Chassis",
	0x13: "SubChassis",
	0x14: "Bus Expansion Chassis",
	0x15: "Peripheral Chassis",
	0x16: "RAID Chassis",
	0x17: "Rack Mount Chassis",
	0x18: "Sealed-case PC",
	0x19: "Multi-system Chassis",
	0x1A: "Compact PCI",
	0x1B: "Advanced TCA",
	0x1C: "Blade",
	0x1D: "Blade Enclosure",
	0x1E: "Tablet",
	0x1F: "Convertible",
	0x20: "Detachable",
	0x21: "IoT Gateway",
	0x22: "Embedded PC",
	0x23: "Mini PC",
	0x24: "Stick PC",
}

// chassisTypeName resolves a raw SMBIOS chassis type byte to a name,
// falling back to a numeric label for values outside the known table.
func chassisTypeName(t byte) string {
	if name, ok := chassisTypeNames[t]; ok {
		return name
	}
	return fmt.Sprintf("Unknown (0x%02X)", t)
}
