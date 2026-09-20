//go:build windows

package registry

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
)

// coerceValue converts a raw property value (as decoded from JSON/YAML)
// into the canonical Go representation for vtype: string for
// string/expand_string, uint32 for dword, uint64 for qword, []string for
// multi_string, []byte for binary.
func coerceValue(vtype string, raw interface{}) (interface{}, error) {
	switch vtype {
	case "", "string", "expand_string":
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%w: vdata must be a string for vtype %q", ErrInvalidValueData, vtype)
		}
		return s, nil
	case "dword":
		n, err := toUint64(raw)
		if err != nil {
			return nil, err
		}
		if n > 0xFFFFFFFF {
			return nil, fmt.Errorf("%w: value %d overflows dword", ErrInvalidValueData, n)
		}
		return uint32(n), nil
	case "qword":
		return toUint64(raw)
	case "multi_string":
		return toStringSlice(raw)
	case "binary":
		s, ok := raw.(string)
		if !ok {
			return nil, fmt.Errorf("%w: vdata must be a base64-encoded string for vtype binary", ErrInvalidValueData)
		}
		b, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidValueData, err)
		}
		return b, nil
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedValueType, vtype)
	}
}

func toUint64(v interface{}) (uint64, error) {
	switch t := v.(type) {
	case float64:
		if t < 0 {
			return 0, fmt.Errorf("%w: negative value not allowed", ErrInvalidValueData)
		}
		return uint64(t), nil
	case int:
		if t < 0 {
			return 0, fmt.Errorf("%w: negative value not allowed", ErrInvalidValueData)
		}
		return uint64(t), nil
	case int64:
		if t < 0 {
			return 0, fmt.Errorf("%w: negative value not allowed", ErrInvalidValueData)
		}
		return uint64(t), nil
	case uint32:
		return uint64(t), nil
	case uint64:
		return t, nil
	case string:
		n, err := strconv.ParseUint(t, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("%w: %v", ErrInvalidValueData, err)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("%w: cannot convert %T to an integer", ErrInvalidValueData, v)
	}
}

func toStringSlice(v interface{}) ([]string, error) {
	switch t := v.(type) {
	case []string:
		return t, nil
	case []interface{}:
		out := make([]string, 0, len(t))
		for _, item := range t {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: multi_string values must all be strings", ErrInvalidValueData)
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: vdata must be a list of strings for vtype multi_string", ErrInvalidValueData)
	}
}

// readCurrentValue reads the current value of vname under k in the same
// canonical representation coerceValue produces, so the two can be
// compared directly.
func readCurrentValue(k regKey, vname, vtype string) (interface{}, error) {
	switch vtype {
	case "", "string", "expand_string":
		s, _, err := k.GetStringValue(vname)
		return s, err
	case "dword":
		n, _, err := k.GetIntegerValue(vname)
		return uint32(n), err
	case "qword":
		n, _, err := k.GetIntegerValue(vname)
		return n, err
	case "multi_string":
		ss, _, err := k.GetStringsValue(vname)
		return ss, err
	case "binary":
		b, _, err := k.GetBinaryValue(vname)
		return b, err
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedValueType, vtype)
	}
}

func valuesEqual(a, b interface{}) bool {
	if ab, ok := a.([]byte); ok {
		bb, ok2 := b.([]byte)
		return ok2 && bytes.Equal(ab, bb)
	}
	if as, ok := a.([]string); ok {
		bs, ok2 := b.([]string)
		if !ok2 || len(as) != len(bs) {
			return false
		}
		for i := range as {
			if as[i] != bs[i] {
				return false
			}
		}
		return true
	}
	return a == b
}

// setValue writes a coerceValue-shaped value to k under vname per vtype.
func setValue(k regKey, vname, vtype string, coerced interface{}) error {
	switch vtype {
	case "", "string":
		return k.SetStringValue(vname, coerced.(string))
	case "expand_string":
		return k.SetExpandStringValue(vname, coerced.(string))
	case "dword":
		return k.SetDWordValue(vname, coerced.(uint32))
	case "qword":
		return k.SetQWordValue(vname, coerced.(uint64))
	case "multi_string":
		return k.SetStringsValue(vname, coerced.([]string))
	case "binary":
		return k.SetBinaryValue(vname, coerced.([]byte))
	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedValueType, vtype)
	}
}
