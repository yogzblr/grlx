//go:build linux

package network

import (
	"strconv"
	"time"
)

func stringParam(params map[string]interface{}, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

func boolParam(params map[string]interface{}, key string, defaultVal bool) bool {
	v, ok := params[key]
	if !ok {
		return defaultVal
	}
	b, ok := v.(bool)
	if !ok {
		return defaultVal
	}
	return b
}

// intParam extracts an integer parameter (mtu, metric, table). These are
// commonly authored as either a JSON number or a string, so both are
// accepted.
func intParam(params map[string]interface{}, key string, defaultVal int) int {
	v, ok := params[key]
	if !ok {
		return defaultVal
	}
	switch vt := v.(type) {
	case float64:
		return int(vt)
	case int:
		return vt
	case string:
		if n, err := strconv.Atoi(vt); err == nil {
			return n
		}
	}
	return defaultVal
}

// durationParam extracts a time.Duration parameter (e.g. "5s"). An absent or
// unparseable value falls back to defaultVal rather than failing the step,
// since these are guard tuning knobs, not correctness-critical inputs.
func durationParam(params map[string]interface{}, key string, defaultVal time.Duration) time.Duration {
	s := stringParam(params, key)
	if s == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return defaultVal
	}
	return d
}
