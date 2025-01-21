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
// It sets the first key as the active key.
func NewMasterKeyStore(keys []MasterKey) (*MasterKeyStore, error) {
	if len(keys) == 0 {
		return nil, errors.New("no master keys provided")
	}

	mkMap := make(map[string]MasterKey)
	for _, k := range keys {
		if len(k.Key) != 32 {
			return nil, errors.New("master key must be 32 bytes for AES-256")
		}
		mkMap[k.ID] = k
	}

	return &MasterKeyStore{
		masterKeys:  mkMap,
		activeKeyID: keys[0].ID,
	}, nil
}

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

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, dek, nil)
	return ciphertext, activeKey.ID, nil
}

// DecryptDataKey decrypts the DEK with the specified master key ID.
func (m *MasterKeyStore) DecryptDataKey(encryptedDEK []byte, masterKeyID string) ([]byte, error) {
	m.mu.RLock()
	mk, exists := m.masterKeys[masterKeyID]
	m.mu.RUnlock()
	if !exists {
		return nil, errors.New("specified master key not found")
	}

	block, err := aes.NewCipher(mk.Key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(encryptedDEK) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := encryptedDEK[:gcm.NonceSize()], encryptedDEK[gcm.NonceSize():]
	dek, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return dek, nil
}

// RotateMasterKey generates a new master key, adds it to the store, and sets it active.
func (m *MasterKeyStore) RotateMasterKey() (MasterKey, error) {
	newKeyBytes := make([]byte, 32)
	if _, err := rand.Read(newKeyBytes); err != nil {
		return MasterKey{}, err
	}

	newKeyID := uuid.New().String()
	newMK := MasterKey{
		ID:  newKeyID,
		Key: newKeyBytes,
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.masterKeys[newKeyID] = newMK
	m.activeKeyID = newKeyID
	return newMK, nil
}

// Close is a no-op unless you store external resources in MasterKeyStore.
func (m *MasterKeyStore) Close(ctx context.Context) error {
	// No DB connections to close here
	return nil
}
