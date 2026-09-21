package group

// stringParam extracts a string parameter from the params map.
func stringParam(params map[string]interface{}, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
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

// boolParam extracts a bool parameter with a default value.
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
