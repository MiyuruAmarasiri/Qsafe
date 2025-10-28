package replay

import "testing"

func TestWindowAccept(t *testing.T) {
	w := New(Config{Depth: 4})

	if err := w.Accept(1); err != nil {
		t.Fatalf("expected accept: %v", err)
	}
	if err := w.Accept(2); err != nil {
		t.Fatalf("expected accept: %v", err)
	}
	if err := w.Accept(2); err != ErrDuplicate {
		t.Fatalf("expected duplicate error, got %v", err)
	}
	if err := w.Accept(5); err != nil {
		t.Fatalf("expected accept new max: %v", err)
	}
	if err := w.Accept(1); err != ErrStale {
		t.Fatalf("expected stale error, got %v", err)
	}
}
