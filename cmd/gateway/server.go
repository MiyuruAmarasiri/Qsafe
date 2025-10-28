package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"go.uber.org/zap"

	"github.com/example/qsafe/pkg/crypto/kem"
	"github.com/example/qsafe/pkg/crypto/scheduler"
	"github.com/example/qsafe/pkg/crypto/sign"
	"github.com/example/qsafe/pkg/session/policy"
	"github.com/example/qsafe/pkg/session/replay"
	"github.com/example/qsafe/pkg/session/rotation"
	"github.com/example/qsafe/pkg/session/state"
)

// GatewayConfig wires runtime parameters for the gateway server.
type GatewayConfig struct {
	Address  string
	Mode     string
	AEAD     string
	Rotation time.Duration
	Logger   *zap.Logger
}

// GatewayServer hosts the HTTP interface for handshake negotiation and messaging.
type GatewayServer struct {
	cfg     GatewayConfig
	logger  *zap.Logger
	httpSrv *http.Server

	kemSuite  kem.Suite
	sigScheme sign.Scheme

	serverState *state.Server

	schedulerCfg scheduler.Config
	rotationCfg  rotation.Config
	replayCfg    replay.Config
	policy       *policy.Enforcer

	capabilities state.CapabilitySet

	sessions map[string]*state.Session
	mu       sync.RWMutex
}

// NewGatewayServer constructs the gateway and prepares HTTP handlers.
func NewGatewayServer(cfg GatewayConfig) (*GatewayServer, error) {
	if cfg.Logger == nil {
		cfg.Logger = zap.NewNop()
	}
	if cfg.Address == "" {
		cfg.Address = ":8443"
	}
	if cfg.Mode == "" {
		cfg.Mode = "strict"
	}
	if cfg.AEAD == "" {
		cfg.AEAD = "xchacha20poly1305"
	}
	if cfg.Rotation <= 0 {
		cfg.Rotation = 5 * time.Minute
	}

	kemSuite := kem.NewKyber768()
	kemKeyPair, err := kemSuite.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("gateway: generate KEM keypair: %w", err)
	}

	sigScheme := sign.NewDilithium3()
	sigKeyPair, err := sigScheme.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("gateway: generate signature keypair: %w", err)
	}

	schedulerCfg := scheduler.Config{
		Mode:             cfg.Mode,
		RotationInterval: cfg.Rotation,
		ClientKeySize:    32,
		ServerKeySize:    32,
		ExporterSize:     32,
	}

	capabilities := state.CapabilitySet{
		PQKEM:      kemSuite.Name(),
		PQSigs:     sigScheme.Name(),
		AEAD:       cfg.AEAD,
		Transports: []string{"http"},
	}

	serverState, err := state.NewServer(state.ServerConfig{
		Mode:             cfg.Mode,
		KEMSuite:         kemSuite,
		KEMKeyPair:       kemKeyPair,
		SignatureScheme:  sigScheme,
		SignatureKeyPair: sigKeyPair,
		Capabilities:     capabilities,
		Scheduler:        schedulerCfg,
	})
	if err != nil {
		return nil, fmt.Errorf("gateway: construct handshake server: %w", err)
	}

	policyEnforcer := policy.New(policy.Config{
		AllowedModes: []string{cfg.Mode},
		AllowedAEAD:  []string{cfg.AEAD},
		MinRotation:  time.Minute,
		MaxRotation:  2 * time.Hour,
	})

	rotationCfg := rotation.Config{
		Interval:   cfg.Rotation,
		MaxPackets: 1 << 20,
		Skew:       10 * time.Second,
	}

	replayCfg := replay.Config{
		Depth: 4096,
	}

	g := &GatewayServer{
		cfg:          cfg,
		logger:       cfg.Logger,
		kemSuite:     kemSuite,
		sigScheme:    sigScheme,
		serverState:  serverState,
		schedulerCfg: schedulerCfg,
		rotationCfg:  rotationCfg,
		replayCfg:    replayCfg,
		policy:       policyEnforcer,
		capabilities: capabilities,
		sessions:     make(map[string]*state.Session),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", g.handleHealth)
	mux.HandleFunc("/handshake/config", g.handleHandshakeConfig)
	mux.HandleFunc("/handshake/init", g.handleHandshakeInit)
	mux.HandleFunc("/message", g.handleMessage)

	g.httpSrv = &http.Server{
		Addr:         cfg.Address,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	return g, nil
}

// Start begins serving HTTP endpoints.
func (g *GatewayServer) Start() error {
	return g.httpSrv.ListenAndServe()
}

// Stop gracefully shuts down the HTTP server.
func (g *GatewayServer) Stop(ctx context.Context) error {
	return g.httpSrv.Shutdown(ctx)
}

func (g *GatewayServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

type handshakeMetadata struct {
	Mode            string              `json:"mode"`
	AEAD            string              `json:"aead"`
	Capabilities    state.CapabilitySet `json:"capabilities"`
	KEMPublic       []byte              `json:"kem_public"`
	SignaturePublic []byte              `json:"signature_public"`
	RotationSeconds uint32              `json:"rotation_seconds"`
}

func (g *GatewayServer) handleHandshakeConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	serverCfg := g.serverState.Config()
	meta := handshakeMetadata{
		Mode:            g.cfg.Mode,
		AEAD:            g.cfg.AEAD,
		Capabilities:    g.capabilities,
		KEMPublic:       serverCfg.KEMKeyPair.Public,
		SignaturePublic: serverCfg.SignatureKeyPair.Public,
		RotationSeconds: uint32(g.schedulerCfg.RotationInterval.Seconds()),
	}
	writeJSON(w, meta, http.StatusOK)
}

type handshakeInitResponse struct {
	ServerResponse state.ServerResponse `json:"server_response"`
	SessionID      string               `json:"session_id"`
}

func (g *GatewayServer) handleHandshakeInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var init state.ClientInit
	if err := json.NewDecoder(r.Body).Decode(&init); err != nil {
		http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	resp, keys, err := g.serverState.Accept(r.Context(), init)
	if err != nil {
		g.logger.Warn("handshake failed", zap.Error(err))
		http.Error(w, "handshake failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	session, err := state.NewSession(state.SessionConfig{
		Role:     state.RoleServer,
		Mode:     g.cfg.Mode,
		AEAD:     g.cfg.AEAD,
		Keys:     keys,
		Rotation: g.rotationCfg,
		Replay:   g.replayCfg,
		Policy:   g.policy,
		Epoch:    1,
	})
	if err != nil {
		g.logger.Error("session setup failed", zap.Error(err))
		http.Error(w, "session setup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	sessionID := hex.EncodeToString(session.SessionID())
	g.storeSession(sessionID, session)

	g.logger.Info("handshake complete",
		zap.String("session_id", sessionID),
		zap.String("mode", g.cfg.Mode),
		zap.String("aead", g.cfg.AEAD),
	)

	writeJSON(w, handshakeInitResponse{
		ServerResponse: resp,
		SessionID:      sessionID,
	}, http.StatusOK)
}

type messageRequest struct {
	SessionID string         `json:"session_id"`
	Envelope  state.Envelope `json:"envelope"`
}

type messageResponse struct {
	Plaintext []byte    `json:"plaintext"`
	Rotate    bool      `json:"rotate"`
	Received  time.Time `json:"received_at"`
}

func (g *GatewayServer) handleMessage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req messageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid payload: "+err.Error(), http.StatusBadRequest)
		return
	}
	if req.SessionID == "" {
		http.Error(w, "session_id required", http.StatusBadRequest)
		return
	}

	session, ok := g.loadSession(req.SessionID)
	if !ok {
		http.Error(w, "unknown session", http.StatusNotFound)
		return
	}

	plaintext, rotate, err := session.Decrypt(r.Context(), req.Envelope)
	if err != nil {
		if errors.Is(err, replay.ErrDuplicate) || errors.Is(err, replay.ErrStale) {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		http.Error(w, "decrypt failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	g.logger.Info("message received",
		zap.String("session_id", req.SessionID),
		zap.Int("bytes", len(plaintext)),
		zap.Bool("rotate", rotate),
	)

	writeJSON(w, messageResponse{
		Plaintext: plaintext,
		Rotate:    rotate,
		Received:  time.Now().UTC(),
	}, http.StatusOK)
}

func (g *GatewayServer) storeSession(id string, session *state.Session) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sessions[id] = session
}

func (g *GatewayServer) loadSession(id string) (*state.Session, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	session, ok := g.sessions[id]
	return session, ok
}

func writeJSON(w http.ResponseWriter, v any, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
