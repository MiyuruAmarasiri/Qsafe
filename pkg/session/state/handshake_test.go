package state

import (
	"context"
	"testing"
	"time"

	"github.com/example/qsafe/pkg/crypto/kem"
	"github.com/example/qsafe/pkg/crypto/scheduler"
	"github.com/example/qsafe/pkg/crypto/sign"
)

func TestHandshakeSuccess(t *testing.T) {
	ctx := context.Background()

	kemSuite := kem.NewKyber768()
	serverKp, err := kemSuite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate kem keypair: %v", err)
	}

	sigSuite := sign.NewDilithium3()
	sigKeys, err := sigSuite.GenerateKeyPair()
	if err != nil {
		t.Fatalf("generate signature keypair: %v", err)
	}

	schedCfg := scheduler.Config{
		Mode:             "strict",
		RotationInterval: 10 * time.Minute,
	}

	server, err := NewServer(ServerConfig{
		Mode:             "strict",
		KEMSuite:         kemSuite,
		KEMKeyPair:       serverKp,
		SignatureScheme:  sigSuite,
		SignatureKeyPair: sigKeys,
		Capabilities: CapabilitySet{
			PQKEM:      kemSuite.Name(),
			PQSigs:     sigSuite.Name(),
			AEAD:       "xchacha20poly1305",
			Transports: []string{"grpc"},
		},
		Scheduler: schedCfg,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}

	client, err := NewClient(ClientConfig{
		Mode:               "strict",
		KEMSuite:           kemSuite,
		ServerPublicKey:    serverKp.Public,
		Scheduler:          schedCfg,
		SignatureScheme:    sigSuite,
		ServerSignatureKey: sigKeys.Public,
		Capabilities: CapabilitySet{
			PQKEM:      kemSuite.Name(),
			PQSigs:     sigSuite.Name(),
			AEAD:       "xchacha20poly1305",
			Transports: []string{"grpc"},
		},
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	clientInit, pending, err := client.Initiate(ctx)
	if err != nil {
		t.Fatalf("client initiate: %v", err)
	}

	resp, serverKeys, err := server.Accept(ctx, *clientInit)
	if err != nil {
		t.Fatalf("server accept: %v", err)
	}

	clientKeys, err := pending.Finish(ctx, resp)
	if err != nil {
		t.Fatalf("client finish: %v", err)
	}

	if !bytesEqual(serverKeys.SessionID, clientKeys.SessionID) {
		t.Fatal("session id mismatch")
	}
	if !bytesEqual(serverKeys.ClientToServer, clientKeys.ClientToServer) {
		t.Fatal("client->server key mismatch")
	}
	if !bytesEqual(serverKeys.ServerToClient, clientKeys.ServerToClient) {
		t.Fatal("server->client key mismatch")
	}
	if !bytesEqual(serverKeys.ExporterSecret, clientKeys.ExporterSecret) {
		t.Fatal("exporter key mismatch")
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
