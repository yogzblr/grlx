package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newProbe(t *testing.T, params map[string]interface{}) Probe {
	t.Helper()
	c, err := (Probe{}).Parse("t", "http", params)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c.(Probe)
}

func TestProbeHTTPSuccess(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello world"))
	}))
	defer srv.Close()

	p := newProbe(t, map[string]interface{}{
		"url":                  srv.URL,
		"expect_body_contains": "hello",
		"expect_header":        map[string]interface{}{"X-Test": "yes"},
	})
	res, err := p.Apply(context.Background())
	if err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if !res.Succeeded {
		t.Fatalf("expected success, got %+v", res)
	}
	found := false
	for _, n := range res.Notes {
		if strings.Contains(n.String(), "hello world") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected response body captured in notes, got %+v", res.Notes)
	}
}

func TestProbeHTTPUnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	p := newProbe(t, map[string]interface{}{"url": srv.URL})
	res, err := p.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected failure for 500 response, got res=%+v err=%v", res, err)
	}
}

func TestProbeHTTPExplicitExpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := newProbe(t, map[string]interface{}{"url": srv.URL, "expect_status": 404})
	res, err := p.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected success matching explicit expect_status, got res=%+v err=%v", res, err)
	}
}

func TestProbeHTTPBodyMismatch(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("nothing relevant"))
	}))
	defer srv.Close()

	p := newProbe(t, map[string]interface{}{"url": srv.URL, "expect_body_contains": "needle"})
	res, err := p.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected body mismatch failure, got res=%+v err=%v", res, err)
	}
}

func TestProbeHTTPMethodAndHeaders(t *testing.T) {
	var gotMethod, gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotHeader = r.Header.Get("X-Custom")
	}))
	defer srv.Close()

	p := newProbe(t, map[string]interface{}{
		"url":     srv.URL,
		"method":  "post",
		"headers": map[string]interface{}{"X-Custom": "abc"},
	})
	if _, err := p.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %s, want POST", gotMethod)
	}
	if gotHeader != "abc" {
		t.Errorf("header = %s, want abc", gotHeader)
	}
}

func TestProbeHTTPMissingURL(t *testing.T) {
	if _, err := (Probe{}).Parse("t", "http", map[string]interface{}{}); err == nil {
		t.Fatal("expected parse error for missing url")
	}
}

func TestProbeHTTPInvalidTimeout(t *testing.T) {
	p := newProbe(t, map[string]interface{}{"url": "http://example.com", "timeout": "not-a-duration"})
	if _, err := p.Apply(context.Background()); err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestProbeHTTPConnectionFailure(t *testing.T) {
	p := newProbe(t, map[string]interface{}{"url": "http://127.0.0.1:1", "timeout": "500ms"})
	res, err := p.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected connection failure, got res=%+v err=%v", res, err)
	}
}
