package probe

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"io"
	"testing"
)

// fakeDBDriver is a minimal database/sql/driver.Driver used to exercise
// probe.database without pulling in a real (licensed, dependency-adding)
// SQL driver. It only implements enough of the driver interfaces to
// support QueryContext.
type fakeDBDriver struct{}

func (fakeDBDriver) Open(name string) (driver.Conn, error) {
	return &fakeDBConn{dsn: name}, nil
}

type fakeDBConn struct{ dsn string }

func (c *fakeDBConn) Prepare(query string) (driver.Stmt, error) {
	return nil, errors.New("fakeDBConn: Prepare not implemented")
}

func (c *fakeDBConn) Close() error { return nil }

func (c *fakeDBConn) Begin() (driver.Tx, error) {
	return nil, errors.New("fakeDBConn: Begin not implemented")
}

func (c *fakeDBConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	switch query {
	case "SELECT ok":
		return &fakeDBRows{cols: []string{"col"}, data: [][]driver.Value{{"ok-value"}}}, nil
	case "SELECT two_rows":
		return &fakeDBRows{cols: []string{"col"}, data: [][]driver.Value{{"a"}, {"b"}}}, nil
	case "SELECT empty":
		return &fakeDBRows{cols: []string{"col"}}, nil
	case "SELECT boom":
		return nil, errors.New("simulated query failure")
	default:
		return &fakeDBRows{cols: []string{"col"}, data: [][]driver.Value{{"default"}}}, nil
	}
}

type fakeDBRows struct {
	cols []string
	data [][]driver.Value
	pos  int
}

func (r *fakeDBRows) Columns() []string { return r.cols }
func (r *fakeDBRows) Close() error      { return nil }
func (r *fakeDBRows) Next(dest []driver.Value) error {
	if r.pos >= len(r.data) {
		return io.EOF
	}
	copy(dest, r.data[r.pos])
	r.pos++
	return nil
}

func init() {
	sql.Register("fakeprobe", fakeDBDriver{})
}

func newDBProbe(t *testing.T, params map[string]interface{}) Probe {
	t.Helper()
	base := map[string]interface{}{"driver": "fakeprobe", "dsn": "fake"}
	for k, v := range params {
		base[k] = v
	}
	c, err := (Probe{}).Parse("t", "database", base)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return c.(Probe)
}

func TestProbeDatabaseSuccess(t *testing.T) {
	p := newDBProbe(t, map[string]interface{}{"query": "SELECT ok", "expect_value": "ok-value"})
	res, err := p.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected success, got res=%+v err=%v", res, err)
	}
}

func TestProbeDatabaseRowCount(t *testing.T) {
	p := newDBProbe(t, map[string]interface{}{"query": "SELECT two_rows", "expect_row_count": 2})
	res, err := p.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected success, got res=%+v err=%v", res, err)
	}

	p = newDBProbe(t, map[string]interface{}{"query": "SELECT two_rows", "expect_row_count": 1})
	res, err = p.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected row count mismatch failure, got res=%+v err=%v", res, err)
	}
}

func TestProbeDatabaseValueMismatch(t *testing.T) {
	p := newDBProbe(t, map[string]interface{}{"query": "SELECT ok", "expect_value": "wrong-value"})
	res, err := p.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected value mismatch failure, got res=%+v err=%v", res, err)
	}
}

func TestProbeDatabaseEmptyResult(t *testing.T) {
	p := newDBProbe(t, map[string]interface{}{"query": "SELECT empty", "expect_row_count": 0})
	res, err := p.Apply(context.Background())
	if err != nil || !res.Succeeded {
		t.Fatalf("expected success on empty result with expect_row_count=0, got res=%+v err=%v", res, err)
	}
}

func TestProbeDatabaseQueryError(t *testing.T) {
	p := newDBProbe(t, map[string]interface{}{"query": "SELECT boom"})
	res, err := p.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected query error, got res=%+v err=%v", res, err)
	}
}

func TestProbeDatabaseUnknownDriver(t *testing.T) {
	c, err := (Probe{}).Parse("t", "database", map[string]interface{}{
		"driver": "does-not-exist", "dsn": "fake", "query": "SELECT ok",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	res, err := c.Apply(context.Background())
	if err == nil || res.Succeeded {
		t.Fatalf("expected error for unregistered driver, got res=%+v err=%v", res, err)
	}
}

func TestProbeDatabaseMissingProperties(t *testing.T) {
	if _, err := (Probe{}).Parse("t", "database", map[string]interface{}{}); err == nil {
		t.Fatal("expected parse error for missing driver/dsn/query")
	}
}
