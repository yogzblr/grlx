package lgpo

import "testing"

func loadExamplePolicy(t *testing.T, name string) Policy {
	t.Helper()
	policies, err := LoadADMX("testdata/example.admx")
	if err != nil {
		t.Fatalf("LoadADMX() error: %v", err)
	}
	p, err := FindPolicy(policies, name, nil)
	if err != nil {
		t.Fatalf("FindPolicy(%q) error: %v", name, err)
	}
	return p
}

func TestResolveEnabledBooleanValue(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleBoolean")
	writes, deletes, err := Resolve(p, StateEnabled, nil)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if len(deletes) != 0 {
		t.Errorf("expected no deletes, got %v", deletes)
	}
	if len(writes) != 1 {
		t.Fatalf("expected 1 write, got %d", len(writes))
	}
	w := writes[0]
	if w.Key != p.Key || w.ValueName != p.ValueName || w.Type != RegDWORD {
		t.Errorf("unexpected write: %+v", w)
	}
	if len(w.Data) != 4 || w.Data[0] != 1 {
		t.Errorf("expected dword 1, got %v", w.Data)
	}
}

func TestResolveDisabledBooleanValue(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleBoolean")
	writes, _, err := Resolve(p, StateDisabled, nil)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if len(writes) != 1 || writes[0].Data[0] != 0 {
		t.Errorf("expected dword 0, got %+v", writes)
	}
}

func TestResolveNotConfiguredMarksDelete(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleBoolean")
	writes, deletes, err := Resolve(p, StateNotConfigured, nil)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if len(writes) != 0 {
		t.Errorf("expected no writes, got %v", writes)
	}
	if len(deletes) != 1 || deletes[0].Key != p.Key || deletes[0].ValueName != p.ValueName {
		t.Errorf("unexpected deletes: %+v", deletes)
	}
}

func TestResolveList(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleList")
	writes, _, err := Resolve(p, StateEnabled, nil)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if len(writes) != 2 {
		t.Fatalf("expected 2 writes, got %d", len(writes))
	}
	found := map[string]Entry{}
	for _, w := range writes {
		found[w.ValueName] = w
	}
	if found["ListA"].Type != RegDWORD || found["ListA"].Data[0] != 1 {
		t.Errorf("ListA = %+v", found["ListA"])
	}
	if found["ListB"].Type != RegSZ {
		t.Errorf("ListB = %+v", found["ListB"])
	}
}

func TestResolveElementsRequiredMissing(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleElements")
	if _, _, err := Resolve(p, StateEnabled, nil); err == nil {
		t.Fatal("expected an error when a required element value is missing")
	}
}

func TestResolveElementsFull(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleElements")
	writes, deletes, err := Resolve(p, StateEnabled, map[string]interface{}{
		"MyBool": true,
		"MyNum":  float64(7),
		"MyText": "hello",
	})
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if len(deletes) != 0 {
		t.Errorf("expected no deletes, got %v", deletes)
	}
	if len(writes) != 3 {
		t.Fatalf("expected 3 writes, got %d", len(writes))
	}
	byName := map[string]Entry{}
	for _, w := range writes {
		byName[w.ValueName] = w
	}
	if byName["MyBoolVal"].Data[0] != 1 {
		t.Errorf("MyBoolVal = %+v, want dword 1", byName["MyBoolVal"])
	}
	if byName["MyNumVal"].Data[0] != 7 {
		t.Errorf("MyNumVal = %+v, want dword 7", byName["MyNumVal"])
	}
	if byName["MyTextVal"].Type != RegSZ {
		t.Errorf("MyTextVal = %+v, want REG_SZ", byName["MyTextVal"])
	}
}

func TestResolveElementsOptionalOmitted(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleElements")
	writes, _, err := Resolve(p, StateEnabled, map[string]interface{}{
		"MyNum": 3,
	})
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if len(writes) != 1 {
		t.Fatalf("expected 1 write (optional elements omitted), got %d", len(writes))
	}
}

func TestResolveElementsWrongType(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleElements")
	_, _, err := Resolve(p, StateEnabled, map[string]interface{}{
		"MyNum": "not a number",
	})
	if err == nil {
		t.Fatal("expected an error for a wrong-typed element value")
	}
}

func TestResolveDisabledClearsElements(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleElements")
	_, deletes, err := Resolve(p, StateDisabled, nil)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	if len(deletes) != 3 {
		t.Fatalf("expected disabling to clear all 3 element values, got %d", len(deletes))
	}
}

func TestResolveUnknownState(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleBoolean")
	if _, _, err := Resolve(p, State("bogus"), nil); err == nil {
		t.Fatal("expected an error for an unknown state")
	}
}

func TestApplyToFile(t *testing.T) {
	p := loadExamplePolicy(t, "ExampleBoolean")
	writes, _, err := Resolve(p, StateEnabled, nil)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	f := NewFile()
	Apply(f, writes, nil)
	if len(f.Entries) != 1 {
		t.Fatalf("expected 1 entry after Apply, got %d", len(f.Entries))
	}

	_, deletes, err := Resolve(p, StateNotConfigured, nil)
	if err != nil {
		t.Fatalf("Resolve() error: %v", err)
	}
	Apply(f, nil, deletes)
	if len(f.Entries) != 1 {
		t.Fatalf("expected the delete marker to replace the entry in place, got %d", len(f.Entries))
	}
	if _, ok := f.Entries[0].IsDeleteMarker(); !ok {
		t.Error("expected the entry to become a delete marker")
	}
}
