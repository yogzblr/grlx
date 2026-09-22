package probe

import (
	"context"
	"testing"
)

func TestMethods(t *testing.T) {
	name, methods := Probe{}.Methods()
	if name != "probe" {
		t.Fatalf("expected ingredient name probe, got %s", name)
	}
	want := map[string]bool{"http": true, "database": true}
	if len(methods) != len(want) {
		t.Fatalf("expected %d methods, got %v", len(want), methods)
	}
	for _, m := range methods {
		if !want[m] {
			t.Errorf("unexpected method %s", m)
		}
	}
}

func TestParseValidatesRequiredProperties(t *testing.T) {
	if _, err := (Probe{}).Parse("id", "http", map[string]interface{}{}); err == nil {
		t.Error("expected error for missing url")
	}
	if _, err := (Probe{}).Parse("id", "http", map[string]interface{}{"url": "http://example.com"}); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if _, err := (Probe{}).Parse("id", "database", map[string]interface{}{"driver": "x"}); err == nil {
		t.Error("expected error for missing dsn/query")
	}
}

func TestParseUnknownMethod(t *testing.T) {
	if _, err := (Probe{}).Parse("id", "nope", nil); err == nil {
		t.Error("expected error for unknown method")
	}
}

func TestApplyDelegatesToTest(t *testing.T) {
	p, err := (Probe{}).Parse("id", "http", map[string]interface{}{"url": "not-a-real-url"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	_, applyErr := p.Apply(context.Background())
	_, testErr := p.Test(context.Background())
	if (applyErr == nil) != (testErr == nil) {
		t.Errorf("expected Apply and Test to behave identically, applyErr=%v testErr=%v", applyErr, testErr)
	}
}

func TestPropertiesRoundTrips(t *testing.T) {
	p, err := (Probe{}).Parse("id", "http", map[string]interface{}{"url": "http://example.com"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	props, err := p.Properties()
	if err != nil {
		t.Fatalf("Properties: %v", err)
	}
	if props["url"] != "http://example.com" {
		t.Errorf("unexpected properties: %+v", props)
	}
}

func TestPropertiesForMethodUnknown(t *testing.T) {
	if _, err := (Probe{}).PropertiesForMethod("bogus"); err == nil {
		t.Error("expected error for unknown method")
	}
}
