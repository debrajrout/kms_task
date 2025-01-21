package server

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"net/http"

	"my-kms/internal/auth"
	"my-kms/internal/crypto"
)

// ---------------------------------------------------------------------
// Generate Data Key
// ---------------------------------------------------------------------

type GenerateDataKeyResponse struct {
	DEKID       string `json:"dekID"`
	MasterKeyID string `json:"masterKeyID"`
}

func (s *Server) GenerateDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /generate-data-key called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionGenerateDataKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to generate data key", identity.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	// Generate new DEK
	dek, err := crypto.GenerateKey()
	if err != nil {
		log.Printf("Failed to generate DEK: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	// Encrypt (wrap) DEK using master key
	encryptedDEK, masterKeyID, err := s.KeyStore.EncryptDataKey(dek)
	if err != nil {
		log.Printf("Failed to encrypt DEK: %v", err)
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	// Store in Mongo
	dekID, err := s.DEKStore.InsertDEK(r.Context(), encryptedDEK, masterKeyID)
	if err != nil {
		log.Printf("Failed to store DEK in MongoDB: %v", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	resp := GenerateDataKeyResponse{
		DEKID:       dekID,
		MasterKeyID: masterKeyID,
	}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Encrypt JSON
// ---------------------------------------------------------------------

type EncryptRequest struct {
	DEKID    string          `json:"dekID"`
	JSONData json.RawMessage `json:"jsonData"` // raw JSON to encrypt
}

type EncryptResponse struct {
	Ciphertext string `json:"ciphertext"` // base64-encoded
}

func (s *Server) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /encrypt called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionEncrypt); err != nil {
		log.Printf("Unauthorized attempt by role=%s to encrypt data", identity.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req EncryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	// Retrieve DEK from Mongo
	dekDoc, err := s.DEKStore.GetDEK(r.Context(), req.DEKID)
	if err != nil {
		log.Printf("Failed to get DEK: %v", err)
		http.Error(w, "DEK not found", http.StatusBadRequest)
		return
	}

	// Unwrap the DEK
	dek, err := s.KeyStore.DecryptDataKey(dekDoc.DEK, dekDoc.MasterKeyID)
	if err != nil {
		log.Printf("Failed to decrypt DEK: %v", err)
		http.Error(w, "failed to unwrap DEK", http.StatusInternalServerError)
		return
	}

	// Encrypt the raw JSON
	ciphertextBytes, err := crypto.EncryptAES256GCM(dek, req.JSONData)
	if err != nil {
		log.Printf("Failed to encrypt JSON: %v", err)
		http.Error(w, "encryption failed", http.StatusInternalServerError)
		return
	}

	resp := EncryptResponse{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextBytes),
	}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Decrypt JSON
// ---------------------------------------------------------------------

type DecryptRequest struct {
	DEKID      string `json:"dekID"`
	Ciphertext string `json:"ciphertext"` // base64
}

type DecryptResponse struct {
	JSONData json.RawMessage `json:"jsonData"`
}

func (s *Server) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /decrypt called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionDecrypt); err != nil {
		log.Printf("Unauthorized attempt by role=%s to decrypt data", identity.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	dekDoc, err := s.DEKStore.GetDEK(r.Context(), req.DEKID)
	if err != nil {
		log.Printf("Failed to get DEK: %v", err)
		http.Error(w, "DEK not found", http.StatusBadRequest)
		return
	}

	// Unwrap the DEK
	dek, err := s.KeyStore.DecryptDataKey(dekDoc.DEK, dekDoc.MasterKeyID)
	if err != nil {
		log.Printf("Failed to decrypt DEK: %v", err)
		http.Error(w, "failed to unwrap DEK", http.StatusInternalServerError)
		return
	}

	// Decode ciphertext
	ciphertextBytes, err := base64.StdEncoding.DecodeString(req.Ciphertext)
	if err != nil {
		http.Error(w, "invalid base64 ciphertext", http.StatusBadRequest)
		return
	}

	// Decrypt
	plaintextBytes, err := crypto.DecryptAES256GCM(dek, ciphertextBytes)
	if err != nil {
		log.Printf("Failed to decrypt data: %v", err)
		http.Error(w, "decryption failed", http.StatusInternalServerError)
		return
	}

	resp := DecryptResponse{
		JSONData: plaintextBytes,
	}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Rotate Master Key
// ---------------------------------------------------------------------

type RotateKeyResponse struct {
	NewMasterKeyID string `json:"newMasterKeyID"`
}

func (s *Server) RotateMasterKeyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /rotate-master-key called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := auth.IsAuthorized(identity, auth.ActionRotateMasterKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to rotate master key", identity.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	newKey, err := s.KeyStore.RotateMasterKey()
	if err != nil {
		log.Printf("Failed to rotate master key: %v", err)
		http.Error(w, "master key rotation failed", http.StatusInternalServerError)
		return
	}

	resp := RotateKeyResponse{NewMasterKeyID: newKey.ID}
	writeJSON(w, resp)
}

// ---------------------------------------------------------------------
// Delete Data Key
// ---------------------------------------------------------------------

type DeleteDEKRequest struct {
	DEKID string `json:"dekID"`
}

func (s *Server) DeleteDataKeyHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("[AUDIT] /delete-data-key called by %s", r.RemoteAddr)

	identity, err := getIdentity(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// If you want to restrict deletion to Admins or a special action, define a new action or reuse an existing one:
	// For example, re-use ActionRotateMasterKey or define ActionDeleteDataKey
	if err := auth.IsAuthorized(identity, auth.ActionRotateMasterKey); err != nil {
		log.Printf("Unauthorized attempt by role=%s to delete DEK", identity.Role)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	var req DeleteDEKRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := s.DEKStore.DeleteDEK(r.Context(), req.DEKID); err != nil {
		log.Printf("Failed to delete DEK: %v", err)
		http.Error(w, "failed to delete DEK", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------

func getIdentity(r *http.Request) (auth.Identity, error) {
	ctxVal := r.Context().Value("identity")
	id, ok := ctxVal.(auth.Identity)
	if !ok {
		return auth.Identity{}, ErrNoIdentity
	}
	return id, nil
}

var ErrNoIdentity = &jsonError{"could not read identity"}

type jsonError struct {
	Message string `json:"message"`
}

func (e *jsonError) Error() string {
	return e.Message
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("writeJSON error: %v", err)
	}
}
