package objectstore_test

import (
	"context"
	"testing"

	"github.com/gogrlx/grlx/v2/internal/objectstore"
	"github.com/gogrlx/grlx/v2/internal/objectstore/objectstoretest"
)

func TestGetPutRoundTrip(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	if err := store.Put(ctx, "web.nginx.grlx", []byte("hello recipe")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := store.Get(ctx, "web.nginx.grlx")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "hello recipe" {
		t.Errorf("Get() = %q, want %q", got, "hello recipe")
	}
}

func TestGetNotFound(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	_, err := store.Get(ctx, "does-not-exist.grlx")
	if err == nil {
		t.Fatal("expected an error for a missing key")
	}
	if !objectstore.IsNotExist(err) {
		t.Errorf("expected IsNotExist(err) to be true, got: %v", err)
	}
}

func TestExists(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	ok, err := store.Exists(ctx, "web.nginx.grlx")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if ok {
		t.Error("expected Exists=false before Put")
	}

	if err := store.Put(ctx, "web.nginx.grlx", []byte("content")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	ok, err = store.Exists(ctx, "web.nginx.grlx")
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !ok {
		t.Error("expected Exists=true after Put")
	}
}

func TestSize(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	if err := store.Put(ctx, "web.nginx.grlx", []byte("0123456789")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	size, err := store.Size(ctx, "web.nginx.grlx")
	if err != nil {
		t.Fatalf("Size: %v", err)
	}
	if size != 10 {
		t.Errorf("Size() = %d, want 10", size)
	}

	if _, err := store.Size(ctx, "does-not-exist.grlx"); err == nil {
		t.Error("expected an error for a missing key")
	}
}

func TestList(t *testing.T) {
	store := objectstoretest.NewStore(t)
	ctx := context.Background()

	for _, key := range []string{"web/init.grlx", "web/nginx.grlx", "db/init.grlx"} {
		if err := store.Put(ctx, key, []byte("x")); err != nil {
			t.Fatalf("Put(%s): %v", key, err)
		}
	}

	keys, err := store.List(ctx, "web/")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys under web/, got %d: %v", len(keys), keys)
	}
}

func TestOpenValidation(t *testing.T) {
	if _, err := objectstore.Open(objectstore.Config{Bucket: "recipes"}); err == nil {
		t.Error("expected an error for an empty endpoint")
	}
	if _, err := objectstore.Open(objectstore.Config{Endpoint: "localhost:9000"}); err == nil {
		t.Error("expected an error for an empty bucket")
	}
}
