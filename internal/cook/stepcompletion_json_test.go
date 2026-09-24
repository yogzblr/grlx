package cook

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestStepCompletionJSON_RoundTripWithError(t *testing.T) {
	in := StepCompletion{
		ID:               "x",
		CompletionStatus: StepFailed,
		ChangesMade:      true,
		Changes:          []string{"a", "b"},
		Started:          time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
		Duration:         2 * time.Second,
		Error:            errors.New("boom"),
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(b), `"Error":"boom"`) {
		t.Errorf("expected Error encoded as its message, got %s", b)
	}

	var out StepCompletion
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Error == nil || out.Error.Error() != "boom" {
		t.Errorf("Error = %v, want boom", out.Error)
	}
	if out.ID != in.ID || out.CompletionStatus != in.CompletionStatus ||
		out.ChangesMade != in.ChangesMade || len(out.Changes) != 2 ||
		!out.Started.Equal(in.Started) || out.Duration != in.Duration {
		t.Errorf("fields not preserved: got %+v, want %+v", out, in)
	}
}

func TestStepCompletionJSON_KeepsFieldNames(t *testing.T) {
	b, err := json.Marshal(StepCompletion{ID: "x", Started: time.Unix(0, 0).UTC(), Duration: time.Second})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"ID", "CompletionStatus", "ChangesMade", "Changes", "started", "duration", "Error"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing key %q in %s", k, b)
		}
	}
	if len(m) != 7 {
		t.Errorf("expected 7 keys, got %d: %s", len(m), b)
	}
	if string(m["Error"]) != "null" {
		t.Errorf("nil Error should encode as null, got %s", m["Error"])
	}
}

func TestStepCompletionJSON_NilErrorRoundTrip(t *testing.T) {
	b, err := json.Marshal(StepCompletion{ID: "ok", CompletionStatus: StepCompleted})
	if err != nil {
		t.Fatal(err)
	}
	var out StepCompletion
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Error != nil {
		t.Errorf("Error = %v, want nil", out.Error)
	}
}

func TestStepCompletionJSON_PointerAndSlice(t *testing.T) {
	// The methods must apply however the value is reached.
	steps := []SproutStepCompletion{{
		SproutID:      "s1",
		CompletedStep: StepCompletion{ID: "x", CompletionStatus: StepFailed, Error: errors.New("boom")},
	}}
	b, err := json.Marshal(&steps)
	if err != nil {
		t.Fatal(err)
	}
	var out []SproutStepCompletion
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(out) != 1 || out[0].CompletedStep.Error == nil || out[0].CompletedStep.Error.Error() != "boom" {
		t.Errorf("got %+v", out)
	}
}

func TestStepCompletionJSON_EmptyMessageStaysNonNil(t *testing.T) {
	b, err := json.Marshal(StepCompletion{ID: "x", Error: errors.New("")})
	if err != nil {
		t.Fatal(err)
	}
	var out StepCompletion
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Error == nil {
		t.Error("a non-nil error with an empty message should decode as non-nil")
	}
}

func TestStepCompletionJSON_LegacyPayloads(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		wantNil bool
		wantMsg string
	}{
		{"null error (existing job logs)", `{"ID":"a","CompletionStatus":2,"Error":null}`, true, ""},
		{"empty object (old sprouts)", `{"ID":"a","CompletionStatus":3,"Error":{}}`, false, errLegacyStepError.Error()},
		{"absent key", `{"ID":"a","CompletionStatus":2}`, true, ""},
		{"lowercase key", `{"ID":"a","error":"boom"}`, false, "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out StepCompletion
			if err := json.Unmarshal([]byte(tt.payload), &out); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			if out.ID != "a" {
				t.Errorf("ID = %q, want a", out.ID)
			}
			if tt.wantNil {
				if out.Error != nil {
					t.Errorf("Error = %v, want nil", out.Error)
				}
				return
			}
			if out.Error == nil || out.Error.Error() != tt.wantMsg {
				t.Errorf("Error = %v, want %q", out.Error, tt.wantMsg)
			}
		})
	}
}

func TestStepCompletionJSON_InvalidJSON(t *testing.T) {
	var out StepCompletion
	if err := json.Unmarshal([]byte(`{"ID":`), &out); err == nil {
		t.Error("expected an error for truncated JSON")
	}
	if err := json.Unmarshal([]byte(`{"CompletionStatus":"nope"}`), &out); err == nil {
		t.Error("expected an error for a mistyped field")
	}
}

func TestStepCompletionJSON_TimeoutLosesSentinelIdentity(t *testing.T) {
	// Documented behavior: the message survives, errors.Is does not.
	// Nothing in the repo compares a decoded Error against a sentinel.
	b, err := json.Marshal(StepCompletion{ID: "timeout-j", CompletionStatus: StepFailed, Error: ErrCookTimeout})
	if err != nil {
		t.Fatal(err)
	}
	var out StepCompletion
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.Error == nil || out.Error.Error() != ErrCookTimeout.Error() {
		t.Errorf("Error = %v, want %q", out.Error, ErrCookTimeout)
	}
	if errors.Is(out.Error, ErrCookTimeout) {
		t.Error("decoded error unexpectedly matches the sentinel; update the StepCompletion.Error doc comment")
	}
}
