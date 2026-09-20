package cron

func stringParam(params map[string]interface{}, key string) string {
	v, ok := params[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// scheduleParam extracts a crontab schedule field (minute, hour, ...),
// defaulting to "*" when absent or empty, matching cron's own convention.
func scheduleParam(params map[string]interface{}, key string) string {
	v := stringParam(params, key)
	if v == "" {
		return "*"
	}
	return v
}
