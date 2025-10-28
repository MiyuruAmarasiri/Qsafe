package state

import (
	"context"
	"testing"
	"time"

	"github.com/example/qsafe/pkg/crypto/kem"
	"github.com/example/qsafe/pkg/crypto/scheduler"
	"github.com/example/qsafe/pkg/crypto/sign"
	"github.com/example/qsafe/pkg/session/policy"
	"github.com/example/qsafe/pkg/session/replay"
	"github.com/example/qsafe/pkg/session/rotation"
)

func TestSessionEncryptDecrypt(t *testing.T) {
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
		RotationInterval: 2 * time.Minute,
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

	initMsg, pending, err := client.Initiate(ctx)
	if err != nil {
		t.Fatalf("client initiate: %v", err)
	}

	resp, serverKeys, err := server.Accept(ctx, *initMsg)
	if err != nil {
		t.Fatalf("server accept: %v", err)
	}

	clientKeys, err := pending.Finish(ctx, resp)
	if err != nil {
		t.Fatalf("client finish: %v", err)
	}

	policyEnforcer := policy.New(policy.Config{
		AllowedModes: []string{"strict"},
		AllowedAEAD:  []string{"xchacha20poly1305"},
		MinRotation:  time.Minute,
		MaxRotation:  10 * time.Minute,
	})

	clientSession, err := NewSession(SessionConfig{
		Role:     RoleClient,
		Mode:     "strict",
		AEAD:     "xchacha20poly1305",
		Keys:     clientKeys,
		Rotation: rotation.Config{Interval: 2 * time.Minute},
		Replay:   replay.Config{Depth: 32},
		Policy:   policyEnforcer,
	})
	if err != nil {
		t.Fatalf("client session: %v", err)
	}

	serverSession, err := NewSession(SessionConfig{
		Role:     RoleServer,
		Mode:     "strict",
		AEAD:     "xchacha20poly1305",
		Keys:     serverKeys,
		Rotation: rotation.Config{Interval: 2 * time.Minute},
		Replay:   replay.Config{Depth: 32},
		Policy:   policyEnforcer,
	})
	if err != nil {
		t.Fatalf("server session: %v", err)
	}

	if !bytesEqual(clientSession.SessionID(), serverSession.SessionID()) {
		t.Fatal("session IDs differ")
	}

	env, rotateSend, err := clientSession.Encrypt(ctx, []byte("hello quantum"), map[string]string{"t": "greeting"})
	if err != nil {
		t.Fatalf("client encrypt: %v", err)
	}
	if rotateSend {
		t.Fatal("rotation triggered unexpectedly")
	}

	plaintext, rotateRecv, err := serverSession.Decrypt(ctx, env)
	if err != nil {
		t.Fatalf("server decrypt: %v", err)
	}
	if rotateRecv {
		t.Fatal("server should not rotate yet")
	}
	if string(plaintext) != "hello quantum" {
		t.Fatalf("unexpected plaintext: %s", plaintext)
	}

	respEnv, _, err := serverSession.Encrypt(ctx, []byte("ack"), nil)
	if err != nil {
		t.Fatalf("server encrypt: %v", err)
	}

	reply, _, err := clientSession.Decrypt(ctx, respEnv)
	if err != nil {
		t.Fatalf("client decrypt: %v", err)
	}
	if string(reply) != "ack" {
		t.Fatalf("unexpected reply: %s", reply)
	}
}
