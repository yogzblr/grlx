package facts

import (
	"encoding/json"
	"fmt"

	log "github.com/gogrlx/grlx/v2/internal/log"
	"github.com/nats-io/nats.go"

	"github.com/gogrlx/grlx/v2/internal/props"
)

// RegisterFarmerListener subscribes to sprout facts publications and stores
// them as props on the farmer side.
//
// This intentionally uses plain Subscribe (fan-out), not QueueSubscribe,
// unlike internal/natsapi/router.go's request/response API handlers.
// props.SetProp writes into an in-process, in-memory cache (see
// internal/props), not shared storage, so each farmer replica needs its
// own copy of every sprout's facts to answer prop queries that land on
// that replica. Queue-grouping this subject would mean only one replica
// ever learned a given fact, leaving the others to serve stale or empty
// data for sprouts whose facts were routed elsewhere. This should be
// revisited alongside workstream A if/when the props cache moves to
// shared storage.
func RegisterFarmerListener(nc *nats.Conn) {
	_, err := nc.Subscribe("grlx.sprouts.*.facts", func(msg *nats.Msg) {
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
