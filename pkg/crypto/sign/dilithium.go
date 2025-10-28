package sign

import (
	"fmt"

	"github.com/cloudflare/circl/sign/dilithium"
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
type Dilithium3 struct {
	mode dilithium.Mode
}

// NewDilithium3 constructs scheme instance.
func NewDilithium3() *Dilithium3 {
	mode := dilithium.ModeByName("Dilithium3")
	if mode == nil {
		panic("dilithium: mode Dilithium3 not available")
	}
	return &Dilithium3{mode: mode}
}

func (d *Dilithium3) Name() string {
	return d.mode.Name()
}

func (d *Dilithium3) PublicKeyLength() int {
	return d.mode.PublicKeySize()
}

func (d *Dilithium3) PrivateKeyLength() int {
	return d.mode.PrivateKeySize()
}

func (d *Dilithium3) SignatureLength() int {
	return d.mode.SignatureSize()
}

func (d *Dilithium3) GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := d.mode.GenerateKey(nil)
	if err != nil {
		return KeyPair{}, fmt.Errorf("dilithium: generate keypair: %w", err)
	}
	return KeyPair{Public: pub.Bytes(), Private: priv.Bytes()}, nil
}

func (d *Dilithium3) Sign(privateKey, message []byte) ([]byte, error) {
	priv := d.mode.PrivateKeyFromBytes(privateKey)
	sig := d.mode.Sign(priv, message)
	return sig, nil
}

func (d *Dilithium3) Verify(publicKey, message, signature []byte) error {
	pub := d.mode.PublicKeyFromBytes(publicKey)
	if !d.mode.Verify(pub, message, signature) {
		return fmt.Errorf("dilithium: signature verification failed")
	}
	return nil
}
