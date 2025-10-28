package state

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/zeebo/blake3"

	"github.com/example/qsafe/pkg/crypto/scheduler"
	"github.com/example/qsafe/pkg/session/policy"
	"github.com/example/qsafe/pkg/session/replay"
	"github.com/example/qsafe/pkg/session/rotation"
)

// Role identifies the local perspective within a session.
type Role uint8

const (
	// RoleClient encrypts with client->server keys.
	RoleClient Role = iota
	// RoleServer encrypts with server->client keys.
	RoleServer
)

func (r Role) String() string {
	switch r {
	case RoleClient:
		return "client"
	case RoleServer:
		return "server"
	default:
		return fmt.Sprintf("unknown(%d)", r)
	}
}

func (r Role) peer() Role {
	if r == RoleClient {
		return RoleServer
	}
	return RoleClient
}

// Envelope mirrors the transport message structure produced per frame.
type Envelope struct {
	Ciphertext []byte
	Nonce      []byte
	Sequence   uint64
	Epoch      uint64
	Metadata   map[string]string
}

// SessionConfig governs session construction.
type SessionConfig struct {
	Role     Role
	Mode     string
	AEAD     string
	Keys     scheduler.Keys
	Rotation rotation.Config
	Replay   replay.Config
	Policy   *policy.Enforcer
	Epoch    uint64
}

// Session orchestrates encrypt/decrypt paths with replay and rotation enforcement.
type Session struct {
	role      Role
	mode      string
	aeadName  string
	sessionID []byte

	sendCipher cipherAEAD
	recvCipher cipherAEAD

	sendMu   sync.Mutex
	sendSeq  uint64
	rotation *rotation.Manager

	recvWindow *replay.Window

	policy *policy.Enforcer

	established time.Time
}

type cipherAEAD interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
}

// NewSession builds a Session using the provided configuration.
func NewSession(cfg SessionConfig) (*Session, error) {
	if cfg.Role != RoleClient && cfg.Role != RoleServer {
		return nil, fmt.Errorf("session: invalid role %d", cfg.Role)
	}
	if cfg.Mode == "" {
		cfg.Mode = "strict"
	}
	if cfg.AEAD == "" {
		cfg.AEAD = "xchacha20poly1305"
	}

	if cfg.Policy != nil {
		if err := cfg.Policy.Validate(policy.Parameters{
			Mode:           cfg.Mode,
			AEAD:           cfg.AEAD,
			RotationWindow: cfg.Keys.NextRotation.Sub(cfg.Keys.EstablishedAt),
		}); err != nil {
			return nil, err
		}
	}

	sendKey, recvKey := directionalKeys(cfg.Role, cfg.Keys)
	sendCipher, recvCipher, err := buildCiphers(cfg.AEAD, sendKey, recvKey)
	if err != nil {
		return nil, err
	}

	window := replay.New(cfg.Replay)

	interval := cfg.Keys.NextRotation.Sub(cfg.Keys.EstablishedAt)
	if interval <= 0 {
		interval = cfg.Rotation.Interval
	}
	if interval <= 0 {
		interval = 15 * time.Minute
	}
	rotationCfg := cfg.Rotation
	if rotationCfg.Interval <= 0 {
		rotationCfg.Interval = interval
	}

	manager := rotation.New(rotationCfg, cfg.Keys.EstablishedAt, cfg.Epoch)

	return &Session{
		role:        cfg.Role,
		mode:        cfg.Mode,
		aeadName:    cfg.AEAD,
		sessionID:   append([]byte(nil), cfg.Keys.SessionID...),
		sendCipher:  sendCipher,
		recvCipher:  recvCipher,
		rotation:    manager,
		recvWindow:  window,
		policy:      cfg.Policy,
		established: cfg.Keys.EstablishedAt,
	}, nil
}

// Encrypt protects the payload, returning an envelope and whether rotation should be triggered.
func (s *Session) Encrypt(ctx context.Context, plaintext []byte, metadata map[string]string) (Envelope, bool, error) {
	if plaintext == nil {
		plaintext = []byte{}
	}
	metaCopy := copyMap(metadata)
	aad := metadataAAD(metaCopy)

	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	s.sendSeq++
	seq := s.sendSeq

	nonce := computeNonce(s.sessionID, seq, s.role)
	shouldRotate := s.rotation.Record(time.Now().UTC())

	ciphertext := s.sendCipher.Seal(nil, nonce[:], plaintext, aad)

	env := Envelope{
		Ciphertext: ciphertext,
		Nonce:      append([]byte(nil), nonce[:]...),
		Sequence:   seq,
		Epoch:      s.rotation.NextEpoch(),
		Metadata:   metaCopy,
	}
	return env, shouldRotate, nil
}

// Decrypt authenticates and opens an envelope, returning plaintext and rotation hint.
func (s *Session) Decrypt(ctx context.Context, env Envelope) ([]byte, bool, error) {
	if env.Sequence == 0 {
		return nil, false, errors.New("session: sequence must start at 1")
	}
	if err := s.recvWindow.Accept(env.Sequence); err != nil {
		return nil, false, err
	}

	expectedNonce := computeNonce(s.sessionID, env.Sequence, s.role.peer())
	if len(env.Nonce) > 0 && !bytes.Equal(env.Nonce, expectedNonce[:]) {
		return nil, false, errors.New("session: nonce mismatch")
	}

	aad := metadataAAD(env.Metadata)
	plaintext, err := s.recvCipher.Open(nil, expectedNonce[:], env.Ciphertext, aad)
	if err != nil {
		return nil, false, fmt.Errorf("session: decrypt: %w", err)
	}

	rotate := s.rotation.ShouldRotate(time.Now().UTC())
	return plaintext, rotate, nil
}

// SessionID exposes the unique session identifier.
func (s *Session) SessionID() []byte {
	return append([]byte(nil), s.sessionID...)
}

// EstablishedAt returns the handshake completion timestamp.
func (s *Session) EstablishedAt() time.Time {
	return s.established
}

func directionalKeys(role Role, keys scheduler.Keys) (send []byte, recv []byte) {
	switch role {
	case RoleClient:
		return keys.ClientToServer, keys.ServerToClient
	default:
		return keys.ServerToClient, keys.ClientToServer
	}
}

func buildCiphers(name string, sendKey, recvKey []byte) (cipherAEAD, cipherAEAD, error) {
	switch name {
	case "xchacha20poly1305":
		send, err := chacha20poly1305.NewX(sendKey)
		if err != nil {
			return nil, nil, fmt.Errorf("session: new send cipher: %w", err)
		}
		recv, err := chacha20poly1305.NewX(recvKey)
		if err != nil {
			return nil, nil, fmt.Errorf("session: new recv cipher: %w", err)
		}
		return send, recv, nil
	default:
		return nil, nil, fmt.Errorf("session: unsupported AEAD %q", name)
	}
}

func metadataAAD(metadata map[string]string) []byte {
	if len(metadata) == 0 {
		return []byte("meta:v1;")
	}
	keys := make([]string, 0, len(metadata))
	for k := range metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	buf.WriteString("meta:v1;")
	for _, k := range keys {
		buf.WriteString(k)
		buf.WriteByte('=')
		buf.WriteString(metadata[k])
		buf.WriteByte(';')
	}
	return buf.Bytes()
}

func copyMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func computeNonce(sessionID []byte, seq uint64, role Role) [24]byte {
	var nonce [24]byte
	var seqBuf [8]byte
	binary.BigEndian.PutUint64(seqBuf[:], seq)

	hasher, err := blake3.NewKeyed(sessionID)
	if err != nil {
		panic("blake3: invalid session key length")
	}
	_, _ = hasher.Write(seqBuf[:])
	_, _ = hasher.Write([]byte{byte(role)})
	digest := hasher.Digest()
	if _, err := digest.Read(nonce[:]); err != nil {
		panic("blake3: nonce read failed")
	}
	return nonce
}
