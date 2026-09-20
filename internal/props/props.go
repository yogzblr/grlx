package props

import (
	"errors"
	"os"
	"time"
)

// DefaultPropTTL is the default time-to-live for properties.
const DefaultPropTTL = 5 * time.Minute

// ErrInvalidPropKey is returned when a sproutID or property name is empty.
var ErrInvalidPropKey = errors.New("sproutID and property name must not be empty")

func GetStringPropFunc(sproutID string) func(string) string {
	return func(name string) string {
		return getStringProp(sproutID, name)
	}
}

// GetStringProp returns the string value of a single property for a sprout.
// Returns an empty string if the sprout or property does not exist, or if the
// property has expired.
func GetStringProp(sproutID, name string) string {
	return getStringProp(sproutID, name)
}

func getStringProp(sproutID, name string) string {
	var row propRow
	err := db.Where("tenant_id = ? AND sprout_id = ? AND name = ? AND expiry > ?",
		tenantID(), sproutID, name, time.Now()).First(&row).Error
	if err != nil {
		return ""
	}
	return row.Value
}

func SetPropFunc(sproutID string) func(string, string) error {
	return func(name, value string) error {
		return setProp(sproutID, name, value)
	}
}

// SetProp sets a property for a sprout with the default TTL.
func SetProp(sproutID, name, value string) error {
	return setProp(sproutID, name, value)
}

func setProp(sproutID, name, value string) error {
	return setPropWithTTL(sproutID, name, value, DefaultPropTTL)
}

func setPropWithTTL(sproutID, name, value string, ttl time.Duration) error {
	if sproutID == "" || name == "" {
		return ErrInvalidPropKey
	}
	return upsertProp(propRow{
		TenantID: tenantID(),
		SproutID: sproutID,
		Name:     name,
		Value:    value,
		Expiry:   time.Now().Add(ttl),
	})
}

func GetDeletePropFunc(sproutID string) func(string) error {
	return func(name string) error {
		return deleteProp(sproutID, name)
	}
}

// DeleteProp removes a property for a sprout. Returns nil if the property
// does not exist.
func DeleteProp(sproutID, name string) error {
	return deleteProp(sproutID, name)
}

func deleteProp(sproutID, name string) error {
	if sproutID == "" || name == "" {
		return ErrInvalidPropKey
	}
	return db.Where("tenant_id = ? AND sprout_id = ? AND name = ?",
		tenantID(), sproutID, name).Delete(&propRow{}).Error
}

func GetPropsFunc(sproutID string) func() map[string]interface{} {
	return func() map[string]interface{} {
		return getProps(sproutID)
	}
}

// GetProps returns all non-expired properties for a sprout. Returns nil if the
// sprout has no properties.
func GetProps(sproutID string) map[string]interface{} {
	return getProps(sproutID)
}

func getProps(sproutID string) map[string]interface{} {
	var rows []propRow
	if err := db.Where("tenant_id = ? AND sprout_id = ? AND expiry > ?",
		tenantID(), sproutID, time.Now()).Find(&rows).Error; err != nil || len(rows) == 0 {
		return nil
	}
	result := make(map[string]interface{}, len(rows))
	for _, r := range rows {
		result[r.Name] = r.Value
	}
	return result
}

func GetHostnameFunc(sproutID string) func() string {
	return func() string {
		return hostname(sproutID)
	}
}

func hostname(sproutID string) string {
	hostname, err := os.Hostname()
	if err != nil {
		return "localhost"
	}
	return hostname
}
