package kem

import (
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
)

// KeyPair bundles public/private keys in raw encoded form.
type KeyPair struct {
	Public  []byte
	Private []byte
}

// Suite describes the operations all KEM providers must expose.
type Suite interface {
	Name() string
	PublicKeyLength() int
	PrivateKeyLength() int
	CiphertextLength() int
	SharedKeyLength() int
	GenerateKeyPair() (KeyPair, error)
	Encapsulate(publicKey []byte) (ciphertext []byte, sharedSecret []byte, err error)
	Decapsulate(privateKey, ciphertext []byte) (sharedSecret []byte, err error)
}

// Kyber768 implements ML-KEM-768 via Cloudflare CIRCL.
type Kyber768 struct {
	scheme kem.Scheme
}

// NewKyber768 constructs a Kyber suite instance.
func NewKyber768() *Kyber768 {
	return &Kyber768{
		scheme: kyber768.Scheme(),
	}
}

func (k *Kyber768) Name() string {
	return k.scheme.Name()
}

func (k *Kyber768) PublicKeyLength() int {
	return k.scheme.PublicKeySize()
}

func (k *Kyber768) PrivateKeyLength() int {
	return k.scheme.PrivateKeySize()
}

func (k *Kyber768) CiphertextLength() int {
	return k.scheme.CiphertextSize()
}

func (k *Kyber768) SharedKeyLength() int {
	return k.scheme.SharedKeySize()
}

func (k *Kyber768) GenerateKeyPair() (KeyPair, error) {
	pub, priv, err := k.scheme.GenerateKeyPair()
	if err != nil {
		return KeyPair{}, fmt.Errorf("kyber: generate keypair: %w", err)
	}

	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return KeyPair{}, fmt.Errorf("kyber: marshal public: %w", err)
	}

	privBytes, err := priv.MarshalBinary()
	if err != nil {
		return KeyPair{}, fmt.Errorf("kyber: marshal private: %w", err)
	}

	return KeyPair{Public: pubBytes, Private: privBytes}, nil
}

func (k *Kyber768) Encapsulate(publicKey []byte) ([]byte, []byte, error) {
	pub, err := k.scheme.UnmarshalBinaryPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("kyber: parse public key: %w", err)
	}

	ct, ss, err := k.scheme.Encapsulate(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("kyber: encapsulate: %w", err)
	}
	return ct, ss, nil
}

func (k *Kyber768) Decapsulate(privateKey, ciphertext []byte) ([]byte, error) {
	priv, err := k.scheme.UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("kyber: parse private key: %w", err)
	}

	shared, err := k.scheme.Decapsulate(priv, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("kyber: decapsulate: %w", err)
	}
	return shared, nil
}
