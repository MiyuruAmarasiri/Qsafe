package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"go.uber.org/zap"

	"github.com/example/qsafe/internal/platform/logging"
	"github.com/example/qsafe/pkg/crypto/kem"
	"github.com/example/qsafe/pkg/crypto/scheduler"
	"github.com/example/qsafe/pkg/crypto/sign"
	"github.com/example/qsafe/pkg/session/policy"
	"github.com/example/qsafe/pkg/session/replay"
	"github.com/example/qsafe/pkg/session/rotation"
	"github.com/example/qsafe/pkg/session/state"
)

type handshakeMetadata struct {
	Mode            string              `json:"mode"`
	AEAD            string              `json:"aead"`
	Capabilities    state.CapabilitySet `json:"capabilities"`
	KEMPublic       []byte              `json:"kem_public"`
	SignaturePublic []byte              `json:"signature_public"`
	RotationSeconds uint32              `json:"rotation_seconds"`
}

type handshakeInitResponse struct {
	ServerResponse state.ServerResponse `json:"server_response"`
	SessionID      string               `json:"session_id"`
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

func main() {
	var (
		gatewayURL = flag.String("gateway", "http://localhost:8443", "Gateway base URL")
		message    = flag.String("message", "hello from agent", "Message to send after handshake")
	)
	flag.Parse()

	logger, cleanup, err := logging.Global(logging.Config{
		ServiceName: "agent",
		Environment: "dev",
		Level:       "info",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "logger init: %v\n", err)
		os.Exit(1)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = cleanup(ctx)
	}()

	ctx := context.Background()
	client := &http.Client{Timeout: 10 * time.Second}

	meta, err := fetchMetadata(client, *gatewayURL)
	if err != nil {
		logger.Fatal("fetch metadata", zap.Error(err))
	}
	logger.Info("fetched gateway metadata",
		zap.String("mode", meta.Mode),
		zap.String("aead", meta.AEAD),
	)

	kemSuite := kem.NewKyber768()
	sigScheme := sign.NewDilithium3()

	schedCfg := scheduler.Config{
		Mode:             meta.Mode,
		RotationInterval: time.Duration(meta.RotationSeconds) * time.Second,
		ClientKeySize:    32,
		ServerKeySize:    32,
		ExporterSize:     32,
	}

	clientState, err := state.NewClient(state.ClientConfig{
		Mode:               meta.Mode,
		KEMSuite:           kemSuite,
		ServerPublicKey:    meta.KEMPublic,
		Scheduler:          schedCfg,
		SignatureScheme:    sigScheme,
		ServerSignatureKey: meta.SignaturePublic,
		Capabilities:       meta.Capabilities,
	})
	if err != nil {
		logger.Fatal("client init", zap.Error(err))
	}

	initMsg, pending, err := clientState.Initiate(ctx)
	if err != nil {
		logger.Fatal("handshake initiate", zap.Error(err))
	}

	resp, err := sendHandshake(client, *gatewayURL, initMsg)
	if err != nil {
		logger.Fatal("handshake exchange", zap.Error(err))
	}

	keys, err := pending.Finish(ctx, resp.ServerResponse)
	if err != nil {
		logger.Fatal("handshake finish", zap.Error(err))
	}

	policyEnforcer := policy.New(policy.Config{
		AllowedModes: []string{meta.Mode},
		AllowedAEAD:  []string{meta.AEAD},
		MinRotation:  time.Minute,
		MaxRotation:  2 * time.Hour,
	})

	session, err := state.NewSession(state.SessionConfig{
		Role:     state.RoleClient,
		Mode:     meta.Mode,
		AEAD:     meta.AEAD,
		Keys:     keys,
		Rotation: rotation.Config{Interval: time.Duration(meta.RotationSeconds) * time.Second, MaxPackets: 1 << 20, Skew: 10 * time.Second},
		Replay:   replay.Config{Depth: 4096},
		Policy:   policyEnforcer,
		Epoch:    1,
	})
	if err != nil {
		logger.Fatal("session setup", zap.Error(err))
	}

	env, rotate, err := session.Encrypt(ctx, []byte(*message), map[string]string{"intent": "demo"})
	if err != nil {
		logger.Fatal("encrypt", zap.Error(err))
	}
	logger.Info("message sealed",
		zap.String("session_id", hex.EncodeToString(session.SessionID())),
		zap.Bool("rotate_suggested", rotate),
	)

	msgResp, err := sendMessage(client, *gatewayURL, resp.SessionID, env)
	if err != nil {
		logger.Fatal("send message", zap.Error(err))
	}

	logger.Info("gateway response",
		zap.Int("plaintext_bytes", len(msgResp.Plaintext)),
		zap.Bool("rotate", msgResp.Rotate),
	)
	fmt.Printf("Gateway responded: %s (rotate=%v)\n", string(msgResp.Plaintext), msgResp.Rotate)
}

func fetchMetadata(client *http.Client, baseURL string) (handshakeMetadata, error) {
	req, err := http.NewRequest(http.MethodGet, baseURL+"/handshake/config", nil)
	if err != nil {
		return handshakeMetadata{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return handshakeMetadata{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return handshakeMetadata{}, fmt.Errorf("metadata status %d: %s", resp.StatusCode, string(body))
	}
	var meta handshakeMetadata
	if err := json.NewDecoder(resp.Body).Decode(&meta); err != nil {
		return handshakeMetadata{}, err
	}
	return meta, nil
}

func sendHandshake(client *http.Client, baseURL string, initMsg *state.ClientInit) (handshakeInitResponse, error) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(initMsg); err != nil {
		return handshakeInitResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/handshake/init", buf)
	if err != nil {
		return handshakeInitResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return handshakeInitResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return handshakeInitResponse{}, fmt.Errorf("handshake status %d: %s", resp.StatusCode, string(body))
	}

	var result handshakeInitResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return handshakeInitResponse{}, err
	}
	return result, nil
}

func sendMessage(client *http.Client, baseURL, sessionID string, env state.Envelope) (messageResponse, error) {
	reqBody := messageRequest{
		SessionID: sessionID,
		Envelope:  env,
	}
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(reqBody); err != nil {
		return messageResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/message", buf)
	if err != nil {
		return messageResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return messageResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return messageResponse{}, fmt.Errorf("message status %d: %s", resp.StatusCode, string(body))
	}

	var result messageResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return messageResponse{}, err
	}
	return result, nil
}
