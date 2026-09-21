package facts

import (
	"encoding/json"
	"fmt"

	log "github.com/gogrlx/grlx/v2/internal/log"
	"github.com/nats-io/nats.go"

	"github.com/gogrlx/grlx/v2/internal/props"
)

// natsCoreQueueGroup is the queue group every farmer replica shares for
// grlx.sprouts.*.facts — the same well-known group name
// internal/natsapi/router.go's Subscribe uses for its own request/response
// handlers (that constant is unexported there, so this package defines its
// own copy of the same value rather than depending across packages for a
// string literal).
const natsCoreQueueGroup = "grlx-core"

// RegisterFarmerListener subscribes to sprout facts publications and stores
// them as props on the farmer side.
//
// This used to intentionally use plain Subscribe (fan-out), not
// QueueSubscribe, on the reasoning that props.SetProp wrote into an
// in-process, in-memory cache, so every farmer replica needed its own copy
// of every sprout's facts. That reasoning stopped being true once
// workstream A moved props to PXC-backed, read-through storage with no
// in-memory cache (see internal/props/store.go's own header comment) —
// every replica now reads and writes the same shared row regardless of
// which one received a given facts event. Fan-out therefore meant every
// replica redundantly re-processing (and racing to UPSERT) the same event,
// exactly the class of write race the PXC migration was meant to remove.
// QueueSubscribe under the shared "grlx-core" group (matching
// internal/natsapi/router.go's own request/response handlers) makes
// exactly one replica handle each event instead.
func RegisterFarmerListener(nc *nats.Conn) {
	_, err := nc.QueueSubscribe("grlx.sprouts.*.facts", natsCoreQueueGroup, func(msg *nats.Msg) {
		var sf SystemFacts
		if unmarshalErr := json.Unmarshal(msg.Data, &sf); unmarshalErr != nil {
			log.Errorf("facts: failed to unmarshal: %v", unmarshalErr)
			return
		}
		if sf.SproutID == "" {
			log.Error("facts: received facts with empty sprout ID")
			return
		}
		storeFacts(sf)
		log.Noticef("facts: received system facts from %s (os=%s arch=%s)", sf.SproutID, sf.OS, sf.Arch)
	})
	if err != nil {
		log.Errorf("facts: failed to subscribe: %v", err)
	}
}

// storeFacts writes system facts into the props store.
func storeFacts(sf SystemFacts) {
	sid := sf.SproutID
	props.SetProp(sid, "os", sf.OS)
	props.SetProp(sid, "arch", sf.Arch)
	props.SetProp(sid, "hostname", sf.Hostname)
	props.SetProp(sid, "go_version", sf.GoVersion)
	props.SetProp(sid, "num_cpu", fmt.Sprintf("%d", sf.NumCPU))
	if len(sf.IPAddresses) > 0 {
		ipsJSON, _ := json.Marshal(sf.IPAddresses)
		props.SetProp(sid, "ip_addresses", string(ipsJSON))
	}
	storeHardwareFacts(sid, sf.Hardware)
}

// storeHardwareFacts writes non-empty hardware/BIOS facts into the props
// store. hw is nil when the sprout couldn't reach its SMBIOS table.
func storeHardwareFacts(sid string, hw *HardwareFacts) {
	if hw == nil || hw.IsZero() {
		return
	}
	fields := map[string]string{
		"bios_vendor":           hw.BIOSVendor,
		"bios_version":          hw.BIOSVersion,
		"bios_release_date":     hw.BIOSReleaseDate,
		"system_manufacturer":   hw.SystemManufacturer,
		"system_product_name":   hw.SystemProductName,
		"system_serial_number":  hw.SystemSerialNumber,
		"system_uuid":           hw.SystemUUID,
		"chassis_manufacturer":  hw.ChassisManufacturer,
		"chassis_type":          hw.ChassisType,
		"chassis_serial_number": hw.ChassisSerialNumber,
		"chassis_asset_tag":     hw.ChassisAssetTag,
	}
	for key, value := range fields {
		if value == "" {
			continue
		}
		props.SetProp(sid, key, value)
	}
}
