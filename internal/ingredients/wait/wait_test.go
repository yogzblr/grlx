package wait

import (
	"context"
	"os"
	"testing"
	"time"
)

func newWait(t *testing.T, params map[string]interface{}) Wait {
	t.Helper()
	c, err := (Wait{}).Parse("t", "poll", params)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c.(Wait)
}

func TestMethods(t *testing.T) {
	name, methods := Wait{}.Methods()
	if name != "wait" || len(methods) != 1 || methods[0] != "poll" {
		t.Fatalf("unexpected Methods(): %s %v", name, methods)
	}
}

func TestParseMissingCmd(t *testing.T) {
	if _, err := (Wait{}).Parse("t", "poll", map[string]interface{}{}); err == nil {
		t.Fatal("expected error for missing cmd")
	}
}

func TestParseUnknownMethod(t *testing.T) {
	if _, err := (Wait{}).Parse("t", "bogus", map[string]interface{}{"cmd": "true"}); err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestPollSucceedsImmediately(t *testing.T) {
	w := newWait(t, map[string]interface{}{"cmd": "true", "interval": "10ms", "timeout": "1s"})
	res, err := w.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected immediate success, got res=%+v err=%v", res, err)
	}
}

func TestPollSucceedsAfterRetries(t *testing.T) {
	// Poll a command that starts failing and flips to succeeding after a
	// short delay, via a marker file the shell command checks for.
	marker := t.TempDir() + "/ready"
	go func() {
		time.Sleep(30 * time.Millisecond)
		_ = os.WriteFile(marker, []byte("ready"), 0o644)
	}()

	w := newWait(t, map[string]interface{}{
		"cmd": "test -f " + marker, "interval": "10ms", "timeout": "2s",
	})
	res, err := w.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected eventual success, got res=%+v err=%v", res, err)
	}
}

func TestPollTimesOut(t *testing.T) {
	w := newWait(t, map[string]interface{}{"cmd": "false", "interval": "10ms", "timeout": "50ms"})
	res, err := w.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected timeout failure, got res=%+v err=%v", res, err)
	}
}

func TestPollNegate(t *testing.T) {
	w := newWait(t, map[string]interface{}{"cmd": "false", "negate": true, "interval": "10ms", "timeout": "1s"})
	res, err := w.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected success waiting for failure with negate, got res=%+v err=%v", res, err)
	}
}

func TestPollInvalidTimeout(t *testing.T) {
	w := newWait(t, map[string]interface{}{"cmd": "true", "timeout": "not-a-duration"})
	if _, err := w.Apply(context.Background()); err == nil {
		t.Fatal("expected error for invalid timeout")
	}
}

func TestPollInvalidInterval(t *testing.T) {
	w := newWait(t, map[string]interface{}{"cmd": "true", "interval": "not-a-duration"})
	if _, err := w.Apply(context.Background()); err == nil {
		t.Fatal("expected error for invalid interval")
	}
}

func TestPollTestModeDoesNotExecute(t *testing.T) {
	w := newWait(t, map[string]interface{}{"cmd": "false", "timeout": "1s", "interval": "10ms"})
	res, err := w.Test(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected Test to report success without executing, got res=%+v err=%v", res, err)
	}
}
