package policy

import (
	"testing"
	"time"
)

func TestEnforcer(t *testing.T) {
	enforcer := New(Config{
		AllowedModes: []string{"strict", "hybrid"},
		AllowedAEAD:  []string{"xchacha20poly1305"},
		MinRotation:  time.Minute,
		MaxRotation:  10 * time.Minute,
	})

	if err := enforcer.Validate(Parameters{
		Mode:           "strict",
		AEAD:           "xchacha20poly1305",
		RotationWindow: 5 * time.Minute,
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := enforcer.Validate(Parameters{
		Mode:           "legacy",
		AEAD:           "xchacha20poly1305",
		RotationWindow: 5 * time.Minute,
	}); err == nil {
		t.Fatal("expected mode validation failure")
	}

	if err := enforcer.Validate(Parameters{
		Mode:           "strict",
		AEAD:           "aes-gcm",
		RotationWindow: 5 * time.Minute,
	}); err == nil {
		t.Fatal("expected AEAD validation failure")
	}

	if err := enforcer.Validate(Parameters{
		Mode:           "strict",
		AEAD:           "xchacha20poly1305",
		RotationWindow: 30 * time.Second,
	}); err == nil {
		t.Fatal("expected rotation min failure")
	}
}
