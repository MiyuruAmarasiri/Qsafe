package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// Config controls Vault client behaviour.
type Config struct {
	Address           string
	Token             string
	TokenFile         string
	Namespace         string
	MountPath         string
	DefaultTTL        time.Duration
	LeaseSafetyBuffer time.Duration
}

// Manager caches secrets and coordinates lease renewals.
type Manager struct {
	client            *vault.Client
	mount             string
	defaultTTL        time.Duration
	leaseSafetyBuffer time.Duration

	cache map[string]cacheEntry
	mu    sync.RWMutex
}

type cacheEntry struct {
	value  map[string]string
	expiry time.Time
}

// New initialises Vault client with caching semantics.
func New(cfg Config) (*Manager, error) {
	if cfg.Address == "" {
		return nil, errors.New("secrets: vault address required")
	}
	if cfg.MountPath == "" {
		cfg.MountPath = "secret"
	}

	token := cfg.Token
	if token == "" && cfg.TokenFile != "" {
		b, err := os.ReadFile(cfg.TokenFile)
		if err != nil {
			return nil, fmt.Errorf("secrets: read token file: %w", err)
		}
		token = string(b)
	}
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		return nil, errors.New("secrets: vault token unavailable")
	}

	client, err := vault.NewClient(&vault.Config{Address: cfg.Address})
	if err != nil {
		return nil, fmt.Errorf("secrets: create client: %w", err)
	}
	client.SetToken(token)
	if cfg.Namespace != "" {
		client.SetNamespace(cfg.Namespace)
	}

	defaultTTL := cfg.DefaultTTL
	if defaultTTL <= 0 {
		defaultTTL = 5 * time.Minute
	}

	leaseBuffer := cfg.LeaseSafetyBuffer
	if leaseBuffer <= 0 {
		leaseBuffer = 15 * time.Second
	}

	return &Manager{
		client:            client,
		mount:             cfg.MountPath,
		defaultTTL:        defaultTTL,
		leaseSafetyBuffer: leaseBuffer,
		cache:             make(map[string]cacheEntry),
	}, nil
}

// GetKV retrieves KV v2 secret material, caching result until TTL expires.
func (m *Manager) GetKV(ctx context.Context, path string) (map[string]string, error) {
	if m == nil {
		return nil, errors.New("secrets: manager is nil")
	}
	if cached, ok := m.cached(path); ok {
		return cached, nil
	}
	secret, err := m.client.KVv2(m.mount).Get(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("secrets: kv get %q: %w", path, err)
	}

	payload := map[string]string{}
	for k, v := range secret.Data {
		if str, ok := v.(string); ok {
			payload[k] = str
		}
	}

	ttl := m.defaultTTL
	if secret.CustomMetadata != nil {
		if rawTTL, ok := secret.CustomMetadata["ttl"]; ok {
			if ttlStr, ok := rawTTL.(string); ok {
				if parsed, err := time.ParseDuration(ttlStr); err == nil {
					ttl = parsed
				}
			}
		}
	}
	m.store(path, payload, ttl)
	return payload, nil
}

// IssueCertificate requests PKI certificate for supplied role parameters.
func (m *Manager) IssueCertificate(ctx context.Context, role string, params map[string]any) (*vault.Secret, error) {
	if m == nil {
		return nil, errors.New("secrets: manager is nil")
	}
	if role == "" {
		return nil, errors.New("secrets: role required")
	}
	path := fmt.Sprintf("pki/issue/%s", role)
	secret, err := m.client.Logical().WriteWithContext(ctx, path, params)
	if err != nil {
		return nil, fmt.Errorf("secrets: issue cert: %w", err)
	}
	return secret, nil
}

// Renew attempts to renew leases for provided secret identifiers.
func (m *Manager) Renew(ctx context.Context, leaseIDs ...string) error {
	if m == nil {
		return errors.New("secrets: manager is nil")
	}
	for _, id := range leaseIDs {
		if id == "" {
			continue
		}
		_, err := m.client.Logical().WriteWithContext(ctx, "sys/leases/renew", map[string]any{
			"lease_id": id,
		})
		if err != nil {
			return fmt.Errorf("secrets: renew lease %q: %w", id, err)
		}
	}
	return nil
}

func (m *Manager) cached(key string) (map[string]string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	entry, ok := m.cache[key]
	if !ok || time.Now().After(entry.expiry) {
		return nil, false
	}
	copy := make(map[string]string, len(entry.value))
	for k, v := range entry.value {
		copy[k] = v
	}
	return copy, true
}

func (m *Manager) store(key string, value map[string]string, ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	copy := make(map[string]string, len(value))
	for k, v := range value {
		copy[k] = v
	}
	expiry := time.Now().Add(ttl)
	if ttl > m.leaseSafetyBuffer {
		expiry = time.Now().Add(ttl - m.leaseSafetyBuffer)
	}
	m.cache[key] = cacheEntry{
		value:  copy,
		expiry: expiry,
	}
}
