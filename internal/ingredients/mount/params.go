//go:build linux

package mount

import "strconv"

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

// intParam extracts an integer parameter. fstab's dump/pass fields are
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

// stringSliceParam extracts a []string parameter, handling both []string
// and []interface{} (which is what JSON unmarshalling produces).
func stringSliceParam(params map[string]interface{}, key string) []string {
	v, ok := params[key]
	if !ok {
		return nil
	}
	switch vt := v.(type) {
	case []string:
		return vt
	case []interface{}:
		var out []string
		for _, item := range vt {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}
