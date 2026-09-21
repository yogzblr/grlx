package lgpo

import (
	"encoding/xml"
	"errors"
	"fmt"
	"os"
)

// Policy is the subset of an ADMX <policy> element this package resolves
// into registry.pol entries.
//
// v1 scope: policies whose effect is expressed entirely as registry.pol
// values under a single key — the vast majority of Administrative
// Templates. A policy may carry:
//   - a plain enabled/disabled value pair (EnabledValue/DisabledValue) on
//     the policy's own Key/ValueName, and/or
//   - an enabled/disabled list of extra key/value pairs
//     (EnabledList/DisabledList), and/or
//   - a set of Elements (boolean, decimal, text only — see Element)
//     supplying additional per-instance values when the policy is enabled.
//
// Deliberately out of scope for v1 (see the PR description for the
// rationale): enum and list-typed elements, multiText elements, policies
// whose class is "Both" needing separate Machine/User resolution in one
// call, ADMX <using>/policyNamespaces cross-file references (each ADMX
// file is loaded standalone), and non-registry policies (Security
// Options/secedit, Group Policy Preferences) which win_lgpo handles via an
// entirely different mechanism than registry.pol.
type Policy struct {
	Name          string
	Class         string // "Machine", "User", or "Both"
	Key           string
	ValueName     string
	DisplayName   string // resolved via ADML, or the raw $(string.*) ref if no ADML was loaded
	ExplainText   string
	EnabledValue  *PolicyValue
	DisabledValue *PolicyValue
	EnabledList   []ListItem
	DisabledList  []ListItem
	Elements      []Element
}

// PolicyValue is a single decimal or string literal, as used by
// enabledValue/disabledValue and list items.
type PolicyValue struct {
	Decimal *uint32
	Text    *string
}

// ListItem is one <item> of an enabledList/disabledList, each an
// independent key/valueName/value triple (key defaults to the owning
// policy's Key when omitted, matching the ADMX schema).
type ListItem struct {
	Key       string
	ValueName string
	Value     PolicyValue
}

// ElementKind identifies which of the v1-supported element shapes an
// Element is.
type ElementKind int

const (
	ElementBoolean ElementKind = iota
	ElementDecimal
	ElementText
)

// Element is one <boolean>/<decimal>/<text> child of a policy's
// <elements>, the parameterized values a policy can carry when enabled.
type Element struct {
	ID        string
	Kind      ElementKind
	Key       string // defaults to the owning policy's Key when empty
	ValueName string
	Required  bool
	// TrueValue/FalseValue are only set for ElementBoolean; when both are
	// nil the element writes REG_DWORD 1/0, matching the ADMX default.
	TrueValue  *PolicyValue
	FalseValue *PolicyValue
}

var (
	ErrPolicyNotFound  = errors.New("lgpo: policy not found in ADMX file")
	ErrUnsupportedElem = errors.New("lgpo: unsupported ADMX element type")
)

// --- raw XML shape of an ADMX file (policyDefinitions namespace) ---

type admxDoc struct {
	XMLName  xml.Name     `xml:"policyDefinitions"`
	Policies []admxPolicy `xml:"policies>policy"`
}

type admxPolicy struct {
	Name          string         `xml:"name,attr"`
	Class         string         `xml:"class,attr"`
	DisplayName   string         `xml:"displayName,attr"`
	ExplainText   string         `xml:"explainText,attr"`
	Key           string         `xml:"key,attr"`
	ValueName     string         `xml:"valueName,attr"`
	EnabledValue  *admxValue     `xml:"enabledValue"`
	DisabledValue *admxValue     `xml:"disabledValue"`
	EnabledList   *admxValueList `xml:"enabledList"`
	DisabledList  *admxValueList `xml:"disabledList"`
	Elements      *admxElements  `xml:"elements"`
}

type admxValue struct {
	Decimal *admxDecimal `xml:"decimal"`
	String  *string      `xml:"string"`
}

type admxDecimal struct {
	Value uint32 `xml:"value,attr"`
}

type admxValueList struct {
	DefaultKey string         `xml:"defaultKey,attr"`
	Items      []admxListItem `xml:"item"`
}

type admxListItem struct {
	Key       string    `xml:"key,attr"`
	ValueName string    `xml:"valueName,attr"`
	Value     admxValue `xml:"value"`
}

type admxElements struct {
	Boolean []admxBooleanElem `xml:"boolean"`
	Decimal []admxDecimalElem `xml:"decimal"`
	Text    []admxTextElem    `xml:"text"`
}

type admxBooleanElem struct {
	ID         string     `xml:"id,attr"`
	Key        string     `xml:"key,attr"`
	ValueName  string     `xml:"valueName,attr"`
	Required   bool       `xml:"required,attr"`
	TrueValue  *admxValue `xml:"trueValue"`
	FalseValue *admxValue `xml:"falseValue"`
}

type admxDecimalElem struct {
	ID        string `xml:"id,attr"`
	Key       string `xml:"key,attr"`
	ValueName string `xml:"valueName,attr"`
	Required  bool   `xml:"required,attr"`
}

type admxTextElem struct {
	ID        string `xml:"id,attr"`
	Key       string `xml:"key,attr"`
	ValueName string `xml:"valueName,attr"`
	Required  bool   `xml:"required,attr"`
}

func toPolicyValue(v *admxValue) *PolicyValue {
	if v == nil {
		return nil
	}
	pv := PolicyValue{}
	if v.Decimal != nil {
		d := v.Decimal.Value
		pv.Decimal = &d
	}
	if v.String != nil {
		pv.Text = v.String
	}
	return &pv
}

func toListItems(l *admxValueList, defaultKey string) []ListItem {
	if l == nil {
		return nil
	}
	items := make([]ListItem, 0, len(l.Items))
	for _, it := range l.Items {
		key := it.Key
		if key == "" {
			key = l.DefaultKey
		}
		if key == "" {
			key = defaultKey
		}
		v := toPolicyValue(&it.Value)
		items = append(items, ListItem{Key: key, ValueName: it.ValueName, Value: *v})
	}
	return items
}

func toElements(e *admxElements, defaultKey string) []Element {
	if e == nil {
		return nil
	}
	var out []Element
	for _, b := range e.Boolean {
		key := b.Key
		if key == "" {
			key = defaultKey
		}
		out = append(out, Element{
			ID: b.ID, Kind: ElementBoolean, Key: key, ValueName: b.ValueName, Required: b.Required,
			TrueValue: toPolicyValue(b.TrueValue), FalseValue: toPolicyValue(b.FalseValue),
		})
	}
	for _, d := range e.Decimal {
		key := d.Key
		if key == "" {
			key = defaultKey
		}
		out = append(out, Element{ID: d.ID, Kind: ElementDecimal, Key: key, ValueName: d.ValueName, Required: d.Required})
	}
	for _, t := range e.Text {
		key := t.Key
		if key == "" {
			key = defaultKey
		}
		out = append(out, Element{ID: t.ID, Kind: ElementText, Key: key, ValueName: t.ValueName, Required: t.Required})
	}
	return out
}

// ParseADMX decodes an ADMX policyDefinitions document.
func ParseADMX(data []byte) ([]Policy, error) {
	var doc admxDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("lgpo: parsing ADMX: %w", err)
	}
	policies := make([]Policy, 0, len(doc.Policies))
	for _, p := range doc.Policies {
		policies = append(policies, Policy{
			Name:          p.Name,
			Class:         p.Class,
			Key:           p.Key,
			ValueName:     p.ValueName,
			DisplayName:   p.DisplayName,
			ExplainText:   p.ExplainText,
			EnabledValue:  toPolicyValue(p.EnabledValue),
			DisabledValue: toPolicyValue(p.DisabledValue),
			EnabledList:   toListItems(p.EnabledList, p.Key),
			DisabledList:  toListItems(p.DisabledList, p.Key),
			Elements:      toElements(p.Elements, p.Key),
		})
	}
	return policies, nil
}

// LoadADMX reads and parses an ADMX file from disk.
func LoadADMX(path string) ([]Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseADMX(data)
}

// FindPolicy looks up a policy by its ADMX <policy name="..."> among
// policies, applying ADML string resolution from res if non-nil.
func FindPolicy(policies []Policy, name string, res *Resources) (Policy, error) {
	for _, p := range policies {
		if p.Name == name {
			if res != nil {
				p.DisplayName = res.Resolve(p.DisplayName)
				p.ExplainText = res.Resolve(p.ExplainText)
			}
			return p, nil
		}
	}
	return Policy{}, fmt.Errorf("%w: %q", ErrPolicyNotFound, name)
}
