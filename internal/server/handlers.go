// internal/server/handlers.go
package server

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"my-kms/internal/auth"
	"my-kms/internal/crypto"
)

// ===========================
//  Generate Data Key
// ===========================

// GenerateDataKeyRequest represents the request payload for generating a data key.
type GenerateDataKeyRequest struct {
	// KeyID can be used to specify a particular master key, if needed.
	// For simplicity, it's optional here.
	KeyID string `json:"keyID,omitempty"`
}

// GenerateDataKeyResponse represents the response payload after generating a data key.
type GenerateDataKeyResponse struct {
	PlaintextDEK string `json:"plaintextDEK"` // Base64-encoded DEK
	EncryptedDEK string `json:"encryptedDEK"` // Base64-encoded encrypted DEK
	MasterKeyID  string `json:"masterKeyID"`  // ID of the master key used
}

// GenerateDataKeyHandler handles the /generate-data-key endpoint.
func (s *Server) GenerateDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	// [AUDIT] log
	log.Printf("[AUDIT] /generate-data-key called by %s", r.RemoteAddr)

	// 1. Retrieve the Identity from context
	ctxIdentity := r.Context().Value("identity")
	id, ok := ctxIdentity.(auth.Identity)
	if !ok {
		http.Error(w, "could not read identity", http.StatusInternalServerError)
		return
	}

	// 2. Check authorization
	if err := auth.IsAuthorized(id, auth.ActionGenerateDataKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to generate data key", id.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// 3. Parse the request (optional KeyID)
	var req GenerateDataKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// 4. Determine which master key to use (active key)
	// activeKey, err := s.KeyStore.GetActiveKey()
	// if err != nil {
	// 	log.Printf("Failed to get active master key: %v", err)
	// 	http.Error(w, "internal server error", http.StatusInternalServerError)
	// 	return
	// }

	// 5. Generate DEK
	dek, err := crypto.GenerateKey()
	if err != nil {
		log.Printf("Failed to generate DEK: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// 6. Encrypt (wrap) the DEK using the MasterKeyStore
	encryptedDEK, usedMasterKeyID, err := s.KeyStore.EncryptDataKey(dek)
	if err != nil {
		log.Printf("Failed to encrypt DEK: %v", err)
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	// 7. Return base64-encoded DEK and encrypted DEK
	resp := GenerateDataKeyResponse{
		PlaintextDEK: base64.StdEncoding.EncodeToString(dek),
		EncryptedDEK: base64.StdEncoding.EncodeToString(encryptedDEK),
		MasterKeyID:  usedMasterKeyID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ===========================
//  Encrypt
// ===========================

// EncryptRequest represents the request payload for encrypting data.
type EncryptRequest struct {
	MasterKeyID  string `json:"masterKeyID"`  // ID of the master key to use
	EncryptedDEK string `json:"encryptedDEK"` // Base64-encoded encrypted DEK
	Plaintext    string `json:"plaintext"`    // Base64-encoded plaintext to encrypt
}

// EncryptResponse represents the response payload after encryption.
type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"` // Base64-encoded ciphertext
}

// EncryptHandler handles the /encrypt endpoint.
func (s *Server) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	// [AUDIT] log
	log.Printf("[AUDIT] /encrypt called by %s", r.RemoteAddr)

	// 1. Retrieve the Identity from context
	ctxIdentity := r.Context().Value("identity")
	id, ok := ctxIdentity.(auth.Identity)
	if !ok {
		http.Error(w, "could not read identity", http.StatusInternalServerError)
		return
	}

	// 2. Check authorization
	if err := auth.IsAuthorized(id, auth.ActionEncrypt); err != nil {
		log.Printf("Unauthorized attempt by role=%s to encrypt data", id.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// 3. Parse request
	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// 4. Decode base64 inputs
	encryptedDEKBytes, err := base64.StdEncoding.DecodeString(req.EncryptedDEK)
	if err != nil {
		http.Error(w, "invalid base64 for EncryptedDEK", http.StatusBadRequest)
		return
	}
	plaintextBytes, err := base64.StdEncoding.DecodeString(req.Plaintext)
	if err != nil {
		http.Error(w, "invalid base64 for plaintext", http.StatusBadRequest)
		return
	}

	// 5. Unwrap the DEK using MasterKeyStore
	dek, err := s.KeyStore.DecryptDataKey(encryptedDEKBytes, req.MasterKeyID)
	if err != nil {
		log.Printf("Failed to decrypt DEK: %v", err)
		http.Error(w, "failed to decrypt DEK", http.StatusBadRequest)
		return
	}

	// 6. Encrypt the plaintext with DEK using AES-256-GCM
	ciphertextBytes, err := crypto.EncryptAES256GCM(dek, plaintextBytes)
	if err != nil {
		log.Printf("Failed to encrypt plaintext: %v", err)
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	// 7. Return base64-encoded ciphertext
	resp := EncryptResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ===========================
//  Decrypt
// ===========================

// DecryptRequest represents the request payload for decrypting data.
type DecryptRequest struct {
	MasterKeyID  string `json:"masterKeyID"`  // ID of the master key to use
	EncryptedDEK string `json:"encryptedDEK"` // Base64-encoded encrypted DEK
	Ciphertext   string `json:"ciphertext"`   // Base64-encoded ciphertext to decrypt
}

// DecryptResponse represents the response payload after decryption.
type DecryptResponse struct {
	Plaintext string `json:"plaintext"` // Base64-encoded plaintext
}

// DecryptHandler handles the /decrypt endpoint.
func (s *Server) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	// [AUDIT] log
	log.Printf("[AUDIT] /decrypt called by %s", r.RemoteAddr)

	// 1. Retrieve the Identity from context
	ctxIdentity := r.Context().Value("identity")
	id, ok := ctxIdentity.(auth.Identity)
	if !ok {
		http.Error(w, "could not read identity", http.StatusInternalServerError)
		return
	}

	// 2. Check authorization
	if err := auth.IsAuthorized(id, auth.ActionDecrypt); err != nil {
		log.Printf("Unauthorized attempt by role=%s to decrypt data", id.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// 3. Parse request
	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// 4. Decode base64 inputs
	encryptedDEKBytes, err := base64.StdEncoding.DecodeString(req.EncryptedDEK)
	if err != nil {
		http.Error(w, "invalid base64 for EncryptedDEK", http.StatusBadRequest)
		return
	}
	ciphertextBytes, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "invalid base64 for ciphertext", http.StatusBadRequest)
		return
	}

	// 5. Unwrap the DEK using MasterKeyStore
	dek, err := s.KeyStore.DecryptDataKey(encryptedDEKBytes, req.MasterKeyID)
	if err != nil {
		log.Printf("Failed to decrypt DEK: %v", err)
		http.Error(w, "failed to decrypt DEK", http.StatusBadRequest)
		return
	}

	// 6. Decrypt the ciphertext with DEK using AES-256-GCM
	plaintextBytes, err := crypto.DecryptAES256GCM(dek, ciphertextBytes)
	if err != nil {
		log.Printf("Failed to decrypt ciphertext: %v", err)
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}

	// 7. Return base64-encoded plaintext
	resp := DecryptResponse{
		Plaintext: base64.StdEncoding.EncodeToString(plaintextBytes),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ===========================
//  Rotate Master Key
// ===========================

// RotateKeyResponse represents the response payload after rotating the master key.
type RotateKeyResponse struct {
	NewMasterKeyID string `json:"newMasterKeyID"` // ID of the new master key
}

// RotateMasterKeyHandler handles the /rotate-master-key endpoint.
func (s *Server) RotateMasterKeyHandler(w http.ResponseWriter, r *http.Request) {
	// [AUDIT] log
	log.Printf("[AUDIT] /rotate-master-key called by %s", r.RemoteAddr)

	// 1. Retrieve the Identity from context
	ctxIdentity := r.Context().Value("identity")
	id, ok := ctxIdentity.(auth.Identity)
	if !ok {
		http.Error(w, "could not read identity", http.StatusInternalServerError)
		return
	}

	// 2. Check authorization
	if err := auth.IsAuthorized(id, auth.ActionRotateMasterKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to rotate master key", id.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// 3. Rotate the master key via MasterKeyStore
	newKey, err := s.KeyStore.RotateMasterKey()
	if err != nil {
		log.Printf("Failed to rotate master key: %v", err)
		http.Error(w, "master key rotation failed", http.StatusInternalServerError)
		return
	}

	// 4. Respond with new master key ID
	resp := RotateKeyResponse{
		NewMasterKeyID: newKey.ID,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}
