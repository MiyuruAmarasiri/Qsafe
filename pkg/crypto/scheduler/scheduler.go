package scheduler

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/zeebo/blake3"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Config tunes key derivation characteristics.
type Config struct {
	Mode             string
	RotationInterval time.Duration
	ClientKeySize    int
	ServerKeySize    int
	ExporterSize     int
	Salt             []byte
}

// Keys represents derived symmetric materials.
type Keys struct {
	SessionID      []byte
	ClientToServer []byte
	ServerToClient []byte
	ExporterSecret []byte
	TranscriptHash []byte
	SharedSecret   []byte
	EstablishedAt  time.Time
	NextRotation   time.Time
}

// Derive uses HKDF-SHA3 to produce symmetric keys tied to the transcript hash.
func Derive(sharedSecret, transcriptHash []byte, cfg Config) (Keys, error) {
	var zero Keys
	if len(sharedSecret) == 0 {
		return zero, errors.New("scheduler: shared secret required")
	}
	if len(transcriptHash) == 0 {
		return zero, errors.New("scheduler: transcript hash required")
	}
	if cfg.ClientKeySize <= 0 {
		cfg.ClientKeySize = 32
	}
	if cfg.ServerKeySize <= 0 {
		cfg.ServerKeySize = 32
	}
	if cfg.ExporterSize <= 0 {
		cfg.ExporterSize = 32
	}
	if cfg.RotationInterval <= 0 {
		cfg.RotationInterval = 15 * time.Minute
	}

	hash := sha3.New512
	info := buildInfo(cfg.Mode, transcriptHash)
	kdf := hkdf.New(hash, sharedSecret, cfg.Salt, info)

	clientKey := make([]byte, cfg.ClientKeySize)
	if err := readFull(kdf, clientKey); err != nil {
		return zero, fmt.Errorf("scheduler: derive client key: %w", err)
	}

	serverKey := make([]byte, cfg.ServerKeySize)
	if err := readFull(kdf, serverKey); err != nil {
		return zero, fmt.Errorf("scheduler: derive server key: %w", err)
	}

	exporter := make([]byte, cfg.ExporterSize)
	if err := readFull(kdf, exporter); err != nil {
		return zero, fmt.Errorf("scheduler: derive exporter: %w", err)
	}

	sessionID := deriveSessionID(transcriptHash, sharedSecret)

	now := time.Now().UTC()
	return Keys{
		SessionID:      sessionID,
		ClientToServer: clientKey,
		ServerToClient: serverKey,
		ExporterSecret: exporter,
		TranscriptHash: transcriptHash,
		SharedSecret:   append([]byte(nil), sharedSecret...),
		EstablishedAt:  now,
		NextRotation:   now.Add(cfg.RotationInterval),
	}, nil
}

func readFull(r io.Reader, buf []byte) error {
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return nil
}

func buildInfo(mode string, transcriptHash []byte) []byte {
	if mode == "" {
		mode = "strict"
	}
	info := make([]byte, 0, len(mode)+len(transcriptHash)+8)
	info = append(info, []byte("qsafe-handshake")...)
	info = append(info, 0)
	info = append(info, []byte(mode)...)
	info = append(info, 0)
	info = append(info, transcriptHash...)
	return info
}

func deriveSessionID(transcriptHash, sharedSecret []byte) []byte {
	h := blake3.New()
	_, _ = h.Write([]byte("qsafe-session-id"))
	_, _ = h.Write(sharedSecret)
	_, _ = h.Write(transcriptHash)
	return h.Sum(nil)
}

// Confirm computes a key-confirmation tag bound to the transcript hash.
func Confirm(key, transcriptHash []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, errors.New("scheduler: confirmation key empty")
	}
	if len(transcriptHash) == 0 {
		return nil, errors.New("scheduler: transcript hash empty")
	}
	hasher := blake3.New()
	_, _ = hasher.Write(key)
	if _, err := hasher.Write(transcriptHash); err != nil {
		return nil, fmt.Errorf("scheduler: confirm: %w", err)
	}
	return hasher.Sum(nil), nil
}
