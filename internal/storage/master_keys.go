// internal/storage/master_keys.go
package storage

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"sync"

	"github.com/google/uuid"
)

// MasterKey represents a master key with an ID and the key bytes.
type MasterKey struct {
	ID  string
	Key []byte
}

// MasterKeyStore manages master keys in memory.
type MasterKeyStore struct {
	masterKeys  map[string]MasterKey
	activeKeyID string
	mu          sync.RWMutex
}

// NewMasterKeyStore initializes a new MasterKeyStore with the provided master keys.
// It sets the first key in the slice as the active key.
func NewMasterKeyStore(keys []MasterKey) (*MasterKeyStore, error) {
	if len(keys) == 0 {
		return nil, errors.New("no master keys provided")
	}

	mkMap := make(map[string]MasterKey)
	for _, key := range keys {
		if len(key.Key) != 32 { // AES-256 requires 32 bytes key
			return nil, errors.New("master key must be 32 bytes for AES-256")
		}
		mkMap[key.ID] = key
	}

	return &MasterKeyStore{
		masterKeys:  mkMap,
		activeKeyID: keys[0].ID,
	}, nil
}

// GetActiveKey returns the currently active master key.
func (m *MasterKeyStore) GetActiveKey() (MasterKey, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	key, exists := m.masterKeys[m.activeKeyID]
	if !exists {
		return MasterKey{}, errors.New("active master key not found")
	}
	return key, nil
}

// EncryptDataKey encrypts the DEK using the active master key.
// Returns the encrypted DEK, the master key ID used, and any error encountered.
func (m *MasterKeyStore) EncryptDataKey(dek []byte) ([]byte, string, error) {
	m.mu.RLock()
	activeKey, exists := m.masterKeys[m.activeKeyID]
	m.mu.RUnlock()
	if !exists {
		return nil, "", errors.New("active master key not found")
	}

	block, err := aes.NewCipher(activeKey.Key)
	if err != nil {
		return nil, "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	// Generate a random nonce for security
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}

	// Encrypt the DEK
	ciphertext := aesGCM.Seal(nonce, nonce, dek, nil)

	return ciphertext, activeKey.ID, nil
}

// DecryptDataKey decrypts the encrypted DEK using the specified master key ID.
// Returns the decrypted DEK and any error encountered.
func (m *MasterKeyStore) DecryptDataKey(encryptedDEK []byte, masterKeyID string) ([]byte, error) {
	m.mu.RLock()
	masterKey, exists := m.masterKeys[masterKeyID]
	m.mu.RUnlock()
	if !exists {
		return nil, errors.New("specified master key not found")
	}

	block, err := aes.NewCipher(masterKey.Key)
	if err != nil {
		return nil, err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := aesGCM.NonceSize()
	if len(encryptedDEK) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encryptedDEK[:nonceSize], encryptedDEK[nonceSize:]

	dek, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return dek, nil
}

// RotateMasterKey generates a new master key, adds it to the store, and sets it as active.
// Returns the new MasterKey and any error encountered.
func (m *MasterKeyStore) RotateMasterKey() (MasterKey, error) {
	newKeyBytes := make([]byte, 32) // AES-256 requires 32 bytes
	if _, err := rand.Read(newKeyBytes); err != nil {
		return MasterKey{}, err
	}

	newKeyID := uuid.New().String()

	newMasterKey := MasterKey{
		ID:  newKeyID,
		Key: newKeyBytes,
	}

	m.mu.Lock()
	m.masterKeys[newKeyID] = newMasterKey
	m.activeKeyID = newKeyID
	m.mu.Unlock()

	return newMasterKey, nil
}

// Close releases any resources held by MasterKeyStore.
// Currently, it's a no-op. Implement if you add resources like DB connections.
func (m *MasterKeyStore) Close(ctx context.Context) error {
	// If MasterKeyStore holds any resources like DB connections, close them here.
	return nil
}
