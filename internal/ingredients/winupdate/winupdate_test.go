//go:build windows

package winupdate

import (
	"context"
	"errors"
	"testing"
)

type fakeBackend struct {
	searchResults  []updateInfo
	searchErr      error
	installOutcome installOutcome
	installErr     error
	installCalls   int
	lastCriteria   string
	lastWanted     map[string]bool
	lastAcceptEula bool
}

func (f *fakeBackend) Search(criteria string) ([]updateInfo, error) {
	f.lastCriteria = criteria
	if f.searchErr != nil {
		return nil, f.searchErr
	}
	return f.searchResults, nil
}

func (f *fakeBackend) Install(criteria string, wanted map[string]bool, acceptEula bool) (installOutcome, error) {
	f.installCalls++
	f.lastCriteria = criteria
	f.lastWanted = wanted
	f.lastAcceptEula = acceptEula
	if f.installErr != nil {
		return installOutcome{}, f.installErr
	}
	return f.installOutcome, nil
}

func installFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	fb := &fakeBackend{}
	orig := backend
	backend = fb
	t.Cleanup(func() { backend = orig })
	return fb
}

func newUpdate(method string, params map[string]interface{}) Update {
	return Update{id: "test-id", method: method, params: params}
}

// --- Methods / PropertiesForMethod ---

func TestUpdateMethods(t *testing.T) {
	name, methods := Update{}.Methods()
	if name != ingredientName {
		t.Errorf("name = %q, want %q", name, ingredientName)
	}
	if len(methods) != 1 || methods[0] != methodInstalled {
		t.Errorf("methods = %v, want [installed]", methods)
	}
}

// --- Parse / validate ---

func TestParseInstalledMissingKBIDs(t *testing.T) {
	_, err := Update{}.Parse("id", methodInstalled, map[string]interface{}{})
	if !errors.Is(err, ErrMissingKBIDs) {
		t.Fatalf("err = %v, want ErrMissingKBIDs", err)
	}
}

func TestParseInstalledOK(t *testing.T) {
	_, err := Update{}.Parse("id", methodInstalled, map[string]interface{}{
		"kb_ids": []string{"KB5001330"},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseUndefinedMethod(t *testing.T) {
	_, err := Update{}.Parse("id", "removed", map[string]interface{}{"kb_ids": []string{"KB1"}})
	if !errors.Is(err, ErrUpdateMethodUndefined) {
		t.Fatalf("err = %v, want ErrUpdateMethodUndefined", err)
	}
}

// --- normalizeKB / matchesAnyKB ---

func TestNormalizeKB(t *testing.T) {
	cases := map[string]string{
		"KB5001330": "5001330",
		"kb5001330": "5001330",
		" 5001330 ": "5001330",
	}
	for in, want := range cases {
		if got := normalizeKB(in); got != want {
			t.Errorf("normalizeKB(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchesAnyKB(t *testing.T) {
	wanted := buildWantedSet([]string{"KB5001330"})
	u := updateInfo{KBArticleIDs: []string{"5001330"}}
	if !matchesAnyKB(u, wanted) {
		t.Error("expected match")
	}
	other := updateInfo{KBArticleIDs: []string{"9999999"}}
	if matchesAnyKB(other, wanted) {
		t.Error("expected no match")
	}
}

// --- installed ---

func TestInstalledAllAlreadyInstalled(t *testing.T) {
	fb := installFakeBackend(t)
	fb.searchResults = []updateInfo{
		{Title: "Update A", KBArticleIDs: []string{"5001330"}, IsInstalled: true},
	}

	u := newUpdate(methodInstalled, map[string]interface{}{"kb_ids": []string{"KB5001330"}})
	result, err := u.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("result = %+v, want succeeded and unchanged", result)
	}
	if fb.installCalls != 0 {
		t.Fatalf("installCalls = %d, want 0", fb.installCalls)
	}
}

func TestInstalledTestModeDoesNotInstall(t *testing.T) {
	fb := installFakeBackend(t)
	fb.searchResults = []updateInfo{
		{Title: "Update A", KBArticleIDs: []string{"5001330"}, IsInstalled: false},
	}

	u := newUpdate(methodInstalled, map[string]interface{}{"kb_ids": []string{"KB5001330"}})
	result, err := u.Test(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if fb.installCalls != 0 {
		t.Fatalf("installCalls = %d, want 0 in test mode", fb.installCalls)
	}
}

func TestInstalledInstallsMissing(t *testing.T) {
	fb := installFakeBackend(t)
	fb.searchResults = []updateInfo{
		{Title: "Update A", KBArticleIDs: []string{"5001330"}, IsInstalled: false},
	}
	fb.installOutcome = installOutcome{Installed: []string{"Update A"}, RebootRequired: true}

	u := newUpdate(methodInstalled, map[string]interface{}{"kb_ids": []string{"KB5001330"}})
	result, err := u.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || !result.Changed {
		t.Fatalf("result = %+v, want succeeded+changed", result)
	}
	if fb.installCalls != 1 {
		t.Fatalf("installCalls = %d, want 1", fb.installCalls)
	}
	if !fb.lastWanted["5001330"] {
		t.Errorf("lastWanted = %v, want 5001330 present", fb.lastWanted)
	}
	if len(result.Notes) < 2 {
		t.Errorf("Notes = %v, want a reboot-required note", result.Notes)
	}
}

func TestInstalledSkipsUnmatchedUpdates(t *testing.T) {
	fb := installFakeBackend(t)
	fb.searchResults = []updateInfo{
		{Title: "Unrelated", KBArticleIDs: []string{"9999999"}, IsInstalled: false},
	}

	u := newUpdate(methodInstalled, map[string]interface{}{"kb_ids": []string{"KB5001330"}})
	result, err := u.Apply(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Succeeded || result.Changed {
		t.Fatalf("result = %+v, want succeeded and unchanged (no matching update found)", result)
	}
	if fb.installCalls != 0 {
		t.Fatalf("installCalls = %d, want 0", fb.installCalls)
	}
}

func TestInstalledSearchError(t *testing.T) {
	fb := installFakeBackend(t)
	fb.searchErr = errors.New("boom")

	u := newUpdate(methodInstalled, map[string]interface{}{"kb_ids": []string{"KB5001330"}})
	result, err := u.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if result.Succeeded || !result.Failed {
		t.Fatalf("result = %+v, want failed", result)
	}
}

func TestInstalledInstallError(t *testing.T) {
	fb := installFakeBackend(t)
	fb.searchResults = []updateInfo{
		{Title: "Update A", KBArticleIDs: []string{"5001330"}, IsInstalled: false},
	}
	fb.installErr = errors.New("boom")

	u := newUpdate(methodInstalled, map[string]interface{}{"kb_ids": []string{"KB5001330"}})
	result, err := u.Apply(context.Background())
	if err == nil {
		t.Fatal("expected error")
	}
	if result.Succeeded || !result.Failed {
		t.Fatalf("result = %+v, want failed", result)
	}
}

func TestInstalledDefaultSearchCriteria(t *testing.T) {
	fb := installFakeBackend(t)
	u := newUpdate(methodInstalled, map[string]interface{}{"kb_ids": []string{"KB5001330"}})
	if _, err := u.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fb.lastCriteria != defaultSearchCriteria {
		t.Errorf("criteria = %q, want default %q", fb.lastCriteria, defaultSearchCriteria)
	}
}

func TestInstalledCustomSearchCriteria(t *testing.T) {
	fb := installFakeBackend(t)
	u := newUpdate(methodInstalled, map[string]interface{}{
		"kb_ids":          []string{"KB5001330"},
		"search_criteria": "IsInstalled=0",
	})
	if _, err := u.Apply(context.Background()); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fb.lastCriteria != "IsInstalled=0" {
		t.Errorf("criteria = %q, want override", fb.lastCriteria)
	}
}
