package lgpo

import (
	"errors"
	"fmt"
)

// State is the desired configuration state of a policy, matching the
// three states gpedit.msc itself offers for an Administrative Template
// policy.
type State string

const (
	StateEnabled       State = "enabled"
	StateDisabled      State = "disabled"
	StateNotConfigured State = "not_configured"
)

var (
	ErrUnknownState        = errors.New("lgpo: unknown policy state")
	ErrMissingElementValue = errors.New("lgpo: missing value for required element")
	ErrElementValueType    = errors.New("lgpo: element value has the wrong type")
)

// Resolve computes the registry.pol changes needed to bring p to state,
// given values for any of p's Elements (keyed by Element.ID; ignored
// unless state is StateEnabled). It returns writes (entries to upsert)
// and deletes (key/valueName pairs to mark deleted via "**del.").
func Resolve(p Policy, state State, elementValues map[string]interface{}) (writes []Entry, deletes []keyValue, err error) {
	switch state {
	case StateEnabled:
		return resolveEnabled(p, elementValues)
	case StateDisabled:
		return resolveDisabled(p)
	case StateNotConfigured:
		return nil, touchedValues(p), nil
	default:
		return nil, nil, fmt.Errorf("%w: %q", ErrUnknownState, state)
	}
}

// keyValue identifies a single registry value a policy touches.
type keyValue struct {
	Key       string
	ValueName string
}

// touchedValues lists every key/valueName a policy could possibly write,
// across its plain value, list, and element forms — used to fully clear a
// policy back to Not Configured regardless of which state it was last in.
func touchedValues(p Policy) []keyValue {
	var kvs []keyValue
	if p.ValueName != "" && (p.EnabledValue != nil || p.DisabledValue != nil) {
		kvs = append(kvs, keyValue{p.Key, p.ValueName})
	}
	for _, it := range p.EnabledList {
		kvs = append(kvs, keyValue{it.Key, it.ValueName})
	}
	for _, it := range p.DisabledList {
		kvs = append(kvs, keyValue{it.Key, it.ValueName})
	}
	for _, e := range p.Elements {
		kvs = append(kvs, keyValue{e.Key, e.ValueName})
	}
	return dedupeKV(kvs)
}

func dedupeKV(in []keyValue) []keyValue {
	seen := make(map[keyValue]bool, len(in))
	out := make([]keyValue, 0, len(in))
	for _, kv := range in {
		if seen[kv] {
			continue
		}
		seen[kv] = true
		out = append(out, kv)
	}
	return out
}

func resolveDisabled(p Policy) ([]Entry, []keyValue, error) {
	var writes []Entry
	if p.ValueName != "" && p.DisabledValue != nil {
		e, err := entryFromValue(p.Key, p.ValueName, *p.DisabledValue)
		if err != nil {
			return nil, nil, err
		}
		writes = append(writes, e)
	}
	for _, it := range p.DisabledList {
		e, err := entryFromValue(it.Key, it.ValueName, it.Value)
		if err != nil {
			return nil, nil, err
		}
		writes = append(writes, e)
	}
	// A disabled policy carries no element values: clear anything an
	// enabled application of it may have written.
	var deletes []keyValue
	for _, e := range p.Elements {
		deletes = append(deletes, keyValue{e.Key, e.ValueName})
	}
	return writes, deletes, nil
}

func resolveEnabled(p Policy, elementValues map[string]interface{}) ([]Entry, []keyValue, error) {
	var writes []Entry
	if p.ValueName != "" && p.EnabledValue != nil {
		e, err := entryFromValue(p.Key, p.ValueName, *p.EnabledValue)
		if err != nil {
			return nil, nil, err
		}
		writes = append(writes, e)
	}
	for _, it := range p.EnabledList {
		e, err := entryFromValue(it.Key, it.ValueName, it.Value)
		if err != nil {
			return nil, nil, err
		}
		writes = append(writes, e)
	}
	for _, el := range p.Elements {
		raw, provided := elementValues[el.ID]
		if !provided {
			if el.Required {
				return nil, nil, fmt.Errorf("%w: element %q", ErrMissingElementValue, el.ID)
			}
			continue
		}
		e, err := entryFromElement(el, raw)
		if err != nil {
			return nil, nil, err
		}
		writes = append(writes, e)
	}
	return writes, nil, nil
}

func entryFromValue(key, valueName string, v PolicyValue) (Entry, error) {
	switch {
	case v.Decimal != nil:
		return Entry{Key: key, ValueName: valueName, Type: RegDWORD, Data: dwordBytes(*v.Decimal)}, nil
	case v.Text != nil:
		return Entry{Key: key, ValueName: valueName, Type: RegSZ, Data: utf16leString(*v.Text)}, nil
	default:
		return Entry{}, fmt.Errorf("lgpo: value for %s\\%s has neither a decimal nor a string", key, valueName)
	}
}

func entryFromElement(el Element, raw interface{}) (Entry, error) {
	switch el.Kind {
	case ElementBoolean:
		b, ok := raw.(bool)
		if !ok {
			return Entry{}, fmt.Errorf("%w: element %q wants a bool", ErrElementValueType, el.ID)
		}
		v := el.FalseValue
		if b {
			v = el.TrueValue
		}
		if v != nil {
			return entryFromValue(el.Key, el.ValueName, *v)
		}
		// ADMX default when trueValue/falseValue are omitted: REG_DWORD 1/0.
		n := uint32(0)
		if b {
			n = 1
		}
		return Entry{Key: el.Key, ValueName: el.ValueName, Type: RegDWORD, Data: dwordBytes(n)}, nil
	case ElementDecimal:
		n, err := toUint32(raw)
		if err != nil {
			return Entry{}, fmt.Errorf("%w: element %q: %v", ErrElementValueType, el.ID, err)
		}
		return Entry{Key: el.Key, ValueName: el.ValueName, Type: RegDWORD, Data: dwordBytes(n)}, nil
	case ElementText:
		s, ok := raw.(string)
		if !ok {
			return Entry{}, fmt.Errorf("%w: element %q wants a string", ErrElementValueType, el.ID)
		}
		return Entry{Key: el.Key, ValueName: el.ValueName, Type: RegSZ, Data: utf16leString(s)}, nil
	default:
		return Entry{}, fmt.Errorf("%w: element %q", ErrUnsupportedElem, el.ID)
	}
}

func toUint32(raw interface{}) (uint32, error) {
	switch n := raw.(type) {
	case uint32:
		return n, nil
	case int:
		if n < 0 {
			return 0, errors.New("negative value")
		}
		return uint32(n), nil
	case int64:
		if n < 0 {
			return 0, errors.New("negative value")
		}
		return uint32(n), nil
	case float64:
		if n < 0 {
			return 0, errors.New("negative value")
		}
		return uint32(n), nil
	default:
		return 0, fmt.Errorf("cannot use %T as a decimal", raw)
	}
}

func dwordBytes(v uint32) []byte {
	return []byte{byte(v), byte(v >> 8), byte(v >> 16), byte(v >> 24)}
}

// Apply mutates f in place to reflect writes/deletes as produced by
// Resolve.
func Apply(f *File, writes []Entry, deletes []keyValue) {
	for _, e := range writes {
		f.Upsert(e)
	}
	for _, kv := range deletes {
		f.MarkDeleted(kv.Key, kv.ValueName)
	}
}
