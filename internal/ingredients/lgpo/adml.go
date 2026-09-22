package lgpo

import (
	"encoding/xml"
	"os"
	"strings"
)

// Resources holds an ADML file's string table, used to resolve the
// "$(string.ID)" references an ADMX file's displayName/explainText
// attributes contain.
type Resources struct {
	strings map[string]string
}

type admlDoc struct {
	XMLName   xml.Name `xml:"policyDefinitionResources"`
	Resources struct {
		StringTable struct {
			Strings []admlString `xml:"string"`
		} `xml:"stringTable"`
	} `xml:"resources"`
}

type admlString struct {
	ID    string `xml:"id,attr"`
	Value string `xml:",chardata"`
}

// ParseADML decodes an ADML policyDefinitionResources document.
func ParseADML(data []byte) (*Resources, error) {
	var doc admlDoc
	if err := xml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	res := &Resources{strings: make(map[string]string, len(doc.Resources.StringTable.Strings))}
	for _, s := range doc.Resources.StringTable.Strings {
		res.strings[s.ID] = s.Value
	}
	return res, nil
}

// LoadADML reads and parses an ADML file from disk.
func LoadADML(path string) (*Resources, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseADML(data)
}

// Resolve expands a single "$(string.ID)" reference to its ADML text. Any
// other input (already-resolved text, or a reference this table has no
// entry for) is returned unchanged.
func (r *Resources) Resolve(ref string) string {
	if r == nil || ref == "" {
		return ref
	}
	const prefix, suffix = "$(string.", ")"
	if !strings.HasPrefix(ref, prefix) || !strings.HasSuffix(ref, suffix) {
		return ref
	}
	id := strings.TrimSuffix(strings.TrimPrefix(ref, prefix), suffix)
	if s, ok := r.strings[id]; ok {
		return s
	}
	return ref
}
