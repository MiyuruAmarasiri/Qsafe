package state

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/zeebo/blake3"

	"github.com/example/qsafe/pkg/crypto/kem"
	"github.com/example/qsafe/pkg/crypto/scheduler"
	"github.com/example/qsafe/pkg/crypto/sign"
	"github.com/example/qsafe/pkg/session/transcript"
)

// CapabilitySet enumerates algorithm preferences advertised during handshake.
type CapabilitySet struct {
	PQKEM      string   `json:"pq_kem"`
	PQSigs     string   `json:"pq_sigs"`
	AEAD       string   `json:"aead"`
	Transports []string `json:"transports"`
}

// ClientInit is emitted by the agent.
type ClientInit struct {
	Version      uint32        `json:"version"`
	Mode         string        `json:"mode"`
	Timestamp    time.Time     `json:"timestamp"`
	Nonce        []byte        `json:"nonce"`
	Ciphertext   []byte        `json:"ciphertext"`
	Capabilities CapabilitySet `json:"capabilities"`
}

// ServerPayload carries the fields covered by the transcript hash and signature.
type ServerPayload struct {
	Version      uint32        `json:"version"`
	Mode         string        `json:"mode"`
	Timestamp    time.Time     `json:"timestamp"`
	Nonce        []byte        `json:"nonce"`
	RotationSecs uint32        `json:"rotation_secs"`
	Capabilities CapabilitySet `json:"capabilities"`
}

// ServerResponse is the complete gateway reply.
type ServerResponse struct {
	Payload        ServerPayload `json:"payload"`
	TranscriptHash []byte        `json:"transcript_hash"`
	Signature      []byte        `json:"signature"`
	Confirmation   []byte        `json:"confirmation"`
}

// ClientConfig bundles materials required by the agent.
type ClientConfig struct {
	Mode               string
	KEMSuite           kem.Suite
	ServerPublicKey    []byte
	Scheduler          scheduler.Config
	SignatureScheme    sign.Scheme
	ServerSignatureKey []byte
	Capabilities       CapabilitySet
}

// ServerConfig supplies required gateway primitives.
type ServerConfig struct {
	Mode             string
	KEMSuite         kem.Suite
	KEMKeyPair       kem.KeyPair
	SignatureScheme  sign.Scheme
	SignatureKeyPair sign.KeyPair
	Capabilities     CapabilitySet
	Scheduler        scheduler.Config
}

// Client handles handshake initiation on the agent side.
type Client struct {
	cfg ClientConfig
}

// Server handles handshake acceptance on the gateway side.
type Server struct {
	cfg ServerConfig
}

// Config exposes the server configuration (read-only copy).
func (s *Server) Config() ServerConfig {
	return s.cfg
}

// PendingClient captures state between Initiate and Finish.
type PendingClient struct {
	transcript   *transcript.Accumulator
	sharedSecret []byte
	cfg          ClientConfig
	clientNonce  []byte
}

// NewClient constructs a handshake client.
func NewClient(cfg ClientConfig) (*Client, error) {
	if cfg.KEMSuite == nil {
		return nil, errors.New("handshake: client kem suite required")
	}
	if len(cfg.ServerPublicKey) == 0 {
		return nil, errors.New("handshake: server public key missing")
	}
	if cfg.SignatureScheme == nil {
		return nil, errors.New("handshake: signature scheme required")
	}
	if len(cfg.ServerSignatureKey) == 0 {
		return nil, errors.New("handshake: server signature key missing")
	}
	if cfg.Mode == "" {
		cfg.Mode = "strict"
	}
	return &Client{cfg: cfg}, nil
}

// NewServer constructs a handshake server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.KEMSuite == nil {
		return nil, errors.New("handshake: server kem suite required")
	}
	if len(cfg.KEMKeyPair.Public) == 0 || len(cfg.KEMKeyPair.Private) == 0 {
		return nil, errors.New("handshake: kem keypair required")
	}
	if cfg.SignatureScheme == nil {
		return nil, errors.New("handshake: signature scheme required")
	}
	if len(cfg.SignatureKeyPair.Public) == 0 || len(cfg.SignatureKeyPair.Private) == 0 {
		return nil, errors.New("handshake: signature keypair required")
	}
	if cfg.Mode == "" {
		cfg.Mode = "strict"
	}
	return &Server{cfg: cfg}, nil
}

// Initiate produces ClientInit and retains state for finalisation.
func (c *Client) Initiate(ctx context.Context) (*ClientInit, *PendingClient, error) {
	trans := transcript.New("qsafe-handshake")

	clientNonce, err := randomBytes(32)
	if err != nil {
		return nil, nil, err
	}

	ciphertext, shared, err := c.cfg.KEMSuite.Encapsulate(c.cfg.ServerPublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: encapsulate: %w", err)
	}

	init := &ClientInit{
		Version:      1,
		Mode:         c.cfg.Mode,
		Timestamp:    time.Now().UTC(),
		Nonce:        clientNonce,
		Ciphertext:   ciphertext,
		Capabilities: c.cfg.Capabilities,
	}
	if err := trans.Append("client_init", initWithoutCiphertext(*init)); err != nil {
		return nil, nil, err
	}

	pending := &PendingClient{
		transcript:   trans,
		sharedSecret: shared,
		cfg:          c.cfg,
		clientNonce:  clientNonce,
	}
	return init, pending, nil
}

// Finish validates the server response and derives symmetric keys.
func (p *PendingClient) Finish(ctx context.Context, resp ServerResponse) (scheduler.Keys, error) {
	if resp.Payload.Mode != p.cfg.Mode {
		return scheduler.Keys{}, fmt.Errorf("handshake: mode mismatch (expected %s got %s)", p.cfg.Mode, resp.Payload.Mode)
	}
	if err := p.transcript.Append("server_payload", resp.Payload); err != nil {
		return scheduler.Keys{}, err
	}

	calculated := p.transcript.Snapshot()
	if !constantTimeEqual(calculated, resp.TranscriptHash) {
		return scheduler.Keys{}, errors.New("handshake: transcript hash mismatch")
	}

	if err := p.cfg.SignatureScheme.Verify(p.cfg.ServerSignatureKey, resp.TranscriptHash, resp.Signature); err != nil {
		return scheduler.Keys{}, fmt.Errorf("handshake: signature verify: %w", err)
	}

	keys, err := scheduler.Derive(p.sharedSecret, resp.TranscriptHash, p.cfg.Scheduler)
	if err != nil {
		return scheduler.Keys{}, fmt.Errorf("handshake: derive keys: %w", err)
	}

	confirm, err := scheduler.Confirm(keys.ServerToClient, resp.TranscriptHash)
	if err != nil {
		return scheduler.Keys{}, err
	}
	if !constantTimeEqual(confirm, resp.Confirmation) {
		return scheduler.Keys{}, errors.New("handshake: confirmation mismatch")
	}
	return keys, nil
}

// Accept processes the client init and returns the server response + symmetric keys.
func (s *Server) Accept(ctx context.Context, init ClientInit) (ServerResponse, scheduler.Keys, error) {
	trans := transcript.New("qsafe-handshake")
	if err := trans.Append("client_init", initWithoutCiphertext(init)); err != nil {
		return ServerResponse{}, scheduler.Keys{}, err
	}

	if init.Mode != s.cfg.Mode {
		return ServerResponse{}, scheduler.Keys{}, fmt.Errorf("handshake: mode mismatch (expected %s got %s)", s.cfg.Mode, init.Mode)
	}

	shared, err := s.cfg.KEMSuite.Decapsulate(s.cfg.KEMKeyPair.Private, init.Ciphertext)
	if err != nil {
		return ServerResponse{}, scheduler.Keys{}, fmt.Errorf("handshake: decapsulate: %w", err)
	}

	serverNonce, err := randomBytes(32)
	if err != nil {
		return ServerResponse{}, scheduler.Keys{}, err
	}

	payload := ServerPayload{
		Version:      1,
		Mode:         s.cfg.Mode,
		Timestamp:    time.Now().UTC(),
		Nonce:        serverNonce,
		RotationSecs: uint32(s.cfg.Scheduler.RotationInterval.Seconds()),
		Capabilities: s.cfg.Capabilities,
	}

	if err := trans.Append("server_payload", payload); err != nil {
		return ServerResponse{}, scheduler.Keys{}, err
	}

	transHash := trans.Snapshot()

	keys, err := scheduler.Derive(shared, transHash, s.cfg.Scheduler)
	if err != nil {
		return ServerResponse{}, scheduler.Keys{}, fmt.Errorf("handshake: derive keys: %w", err)
	}

	signature, err := s.cfg.SignatureScheme.Sign(s.cfg.SignatureKeyPair.Private, transHash)
	if err != nil {
		return ServerResponse{}, scheduler.Keys{}, fmt.Errorf("handshake: sign transcript: %w", err)
	}

	confirm, err := scheduler.Confirm(keys.ServerToClient, transHash)
	if err != nil {
		return ServerResponse{}, scheduler.Keys{}, err
	}

	response := ServerResponse{
		Payload:        payload,
		TranscriptHash: transHash,
		Signature:      signature,
		Confirmation:   confirm,
	}
	return response, keys, nil
}

func initWithoutCiphertext(init ClientInit) map[string]any {
	return map[string]any{
		"version":         init.Version,
		"mode":            init.Mode,
		"timestamp":       init.Timestamp.UTC(),
		"nonce":           init.Nonce,
		"capabilities":    init.Capabilities,
		"ciphertext_hash": hashBytes(init.Ciphertext),
	}
}

func randomBytes(size int) ([]byte, error) {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, fmt.Errorf("handshake: random: %w", err)
	}
	return buf, nil
}

func constantTimeEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func hashBytes(data []byte) []byte {
	h := blake3.New()
	_, _ = h.Write(data)
	return h.Sum(nil)
}
