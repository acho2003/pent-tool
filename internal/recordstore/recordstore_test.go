package recordstore

import (
	"context"
	"errors"
	"testing"
)

// storeForTest connects to the prototype Postgres, skipping when unreachable so
// the suite still passes without a database.
func storeForTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(context.Background(), DSN())
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	if err := s.Ping(context.Background()); err != nil {
		s.Close()
		t.Skipf("postgres unreachable: %v", err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestRoundTrip(t *testing.T) {
	s := storeForTest(t)
	ctx := context.Background()
	const col = "test_roundtrip"
	// clean slate
	ids, _ := s.ListIDs(ctx, col)
	for _, id := range ids {
		_ = s.Delete(ctx, col, id)
	}

	if err := s.PutJSON(ctx, col, "a", []byte(`{"n":1}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.PutBytes(ctx, col, "b", []byte{0x00, 0x01, 0xff}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetJSON(ctx, col, "a")
	if err != nil || string(got) != `{"n": 1}` {
		t.Fatalf("GetJSON = %q, %v", got, err)
	}
	blob, err := s.GetBytes(ctx, col, "b")
	if err != nil || len(blob) != 3 || blob[2] != 0xff {
		t.Fatalf("GetBytes = %v, %v", blob, err)
	}
	if _, err := s.GetJSON(ctx, col, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing = %v, want ErrNotFound", err)
	}
	n, err := s.Count(ctx, col)
	if err != nil || n != 2 {
		t.Fatalf("Count = %d, %v", n, err)
	}
	if err := s.Delete(ctx, col, "a"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GetJSON(ctx, col, "a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after delete = %v, want ErrNotFound", err)
	}
	for _, id := range []string{"a", "b"} {
		_ = s.Delete(ctx, col, id)
	}
}
