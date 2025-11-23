package sign

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// KeyPair holds Dilithium key material in binary form.
type KeyPair struct {
	Public  []byte
	Private []byte
}

// Scheme exposes signing and verification primitives.
type Scheme interface {
	Name() string
	PublicKeyLength() int
	PrivateKeyLength() int
	SignatureLength() int
	GenerateKeyPair() (KeyPair, error)
	Sign(privateKey, message []byte) ([]byte, error)
	Verify(publicKey, message, signature []byte) error
}

// Dilithium3 implements ML-DSA (Dilithium level 3).
type Dilithium3 struct{}

// NewDilithium3 constructs scheme instance.
func NewDilithium3() *Dilithium3 { return &Dilithium3{} }

func (d *Dilithium3) Name() string { return "Dilithium3" }

func (d *Dilithium3) PublicKeyLength() int {
	return mode3.PublicKeySize
}

func (d *Dilithium3) PrivateKeyLength() int {
	return mode3.PrivateKeySize
}

func (d *Dilithium3) SignatureLength() int {
	return mode3.SignatureSize
}

func (d *Dilithium3) GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := mode3.GenerateKey(nil)
	if err != nil {
		return KeyPair{}, fmt.Errorf("dilithium: generate keypair: %w", err)
	}
	return KeyPair{Public: pub.Bytes(), Private: priv.Bytes()}, nil
}

func (d *Dilithium3) Sign(privateKey, message []byte) ([]byte, error) {
	var priv mode3.PrivateKey
	if err := priv.UnmarshalBinary(privateKey); err != nil {
		return nil, fmt.Errorf("dilithium: parse private key: %w", err)
	}
	sig := make([]byte, mode3.SignatureSize)
	mode3.SignTo(&priv, message, sig)
	return sig, nil
}

func (d *Dilithium3) Verify(publicKey, message, signature []byte) error {
	var pub mode3.PublicKey
	if err := pub.UnmarshalBinary(publicKey); err != nil {
		return fmt.Errorf("dilithium: parse public key: %w", err)
	}
	if !mode3.Verify(&pub, message, signature) {
		return fmt.Errorf("dilithium: signature verification failed")
	}
	return nil
}
