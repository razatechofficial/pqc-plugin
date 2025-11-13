package backend

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func getTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Unable to create backend: %v", err)
	}

	return b, config.StorageView
}

func TestBackend_KeyCreate(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	tests := []struct {
		name      string
		keyName   string
		algorithm string
		keyType   string
		wantErr   bool
	}{
		{"Create encryption key", "test-enc-key", "kyber768", "encryption", false},
		{"Create signing key", "test-sig-key", "dilithium3", "signing", false},
		{"Invalid algorithm", "test-key", "invalid", "encryption", true},
		{"Invalid key type", "test-key", "kyber768", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "keys/" + tt.keyName,
				Storage:   storage,
				Data: map[string]interface{}{
					"name":      tt.keyName,
					"algorithm": tt.algorithm,
					"key_type":  tt.keyType,
				},
			}

			resp, err := b.HandleRequest(ctx, req)
			if (err != nil) != tt.wantErr {
				t.Errorf("HandleRequest() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr {
				if resp == nil {
					t.Fatal("Response is nil")
				}
				if resp.Data["name"] != tt.keyName {
					t.Errorf("Expected name %s, got %v", tt.keyName, resp.Data["name"])
				}
				if resp.Data["algorithm"] != tt.algorithm {
					t.Errorf("Expected algorithm %s, got %v", tt.algorithm, resp.Data["algorithm"])
				}
			}
		})
	}
}

func TestBackend_KeyRead(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a key first
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "test-key",
			"algorithm": "kyber768",
			"key_type":  "encryption",
		},
	}
	_, err := b.HandleRequest(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Read the key
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name": "test-key",
		},
	}

	resp, err := b.HandleRequest(ctx, readReq)
	if err != nil {
		t.Fatalf("Failed to read key: %v", err)
	}

	if resp == nil {
		t.Fatal("Response is nil")
	}

	if resp.Data["name"] != "test-key" {
		t.Errorf("Expected name 'test-key', got %v", resp.Data["name"])
	}

	// Verify public key is present but private key is not
	if resp.Data["public_key"] == nil {
		t.Error("Public key should be present in response")
	}
	if resp.Data["private_key"] != nil {
		t.Error("Private key should not be present in response")
	}
}

func TestBackend_KeyList(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create multiple keys
	keys := []string{"key1", "key2", "key3"}
	for _, keyName := range keys {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "keys/" + keyName,
			Storage:   storage,
			Data: map[string]interface{}{
				"name":      keyName,
				"algorithm": "kyber768",
				"key_type":  "encryption",
			},
		}
		_, err := b.HandleRequest(ctx, req)
		if err != nil {
			t.Fatalf("Failed to create key %s: %v", keyName, err)
		}
	}

	// List keys
	listReq := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "keys/",
		Storage:   storage,
	}

	resp, err := b.HandleRequest(ctx, listReq)
	if err != nil {
		t.Fatalf("Failed to list keys: %v", err)
	}

	if resp == nil {
		t.Fatal("Response is nil")
	}

	keysList := resp.Data["keys"].([]string)
	if len(keysList) != len(keys) {
		t.Errorf("Expected %d keys, got %d", len(keys), len(keysList))
	}
}

func TestBackend_KeyDelete(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create a key
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "test-key",
			"algorithm": "kyber768",
			"key_type":  "encryption",
		},
	}
	_, err := b.HandleRequest(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Delete the key
	deleteReq := &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "keys/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name": "test-key",
		},
	}

	_, err = b.HandleRequest(ctx, deleteReq)
	if err != nil {
		t.Fatalf("Failed to delete key: %v", err)
	}

	// Verify key is deleted
	readReq := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "keys/test-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name": "test-key",
		},
	}

	resp, err := b.HandleRequest(ctx, readReq)
	if err == nil && resp != nil {
		t.Error("Key should be deleted")
	}
}

func TestBackend_EncryptDecrypt(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create encryption key
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/enc-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "enc-key",
			"algorithm": "kyber768",
			"key_type":  "encryption",
		},
	}
	_, err := b.HandleRequest(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Encrypt
	plaintext := []byte("Hello, Post-Quantum World!")
	plaintextB64 := base64.StdEncoding.EncodeToString(plaintext)

	encryptReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/enc-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "enc-key",
			"plaintext": plaintextB64,
		},
	}

	encryptResp, err := b.HandleRequest(ctx, encryptReq)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	ciphertextB64 := encryptResp.Data["ciphertext"].(string)
	if ciphertextB64 == "" {
		t.Error("Ciphertext is empty")
	}

	// Decrypt
	decryptReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "decrypt/enc-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":       "enc-key",
			"ciphertext": ciphertextB64,
		},
	}

	decryptResp, err := b.HandleRequest(ctx, decryptReq)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	decryptedB64 := decryptResp.Data["plaintext"].(string)
	decrypted, err := base64.StdEncoding.DecodeString(decryptedB64)
	if err != nil {
		t.Fatalf("Failed to decode decrypted text: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypted text doesn't match. Got: %s, Want: %s", decrypted, plaintext)
	}
}

func TestBackend_SignVerify(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create signing key
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/sig-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "sig-key",
			"algorithm": "dilithium3",
			"key_type":  "signing",
		},
	}
	_, err := b.HandleRequest(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Sign
	message := []byte("Important document")
	messageB64 := base64.StdEncoding.EncodeToString(message)

	signReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/sig-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":  "sig-key",
			"input": messageB64,
		},
	}

	signResp, err := b.HandleRequest(ctx, signReq)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	signatureB64 := signResp.Data["signature"].(string)
	if signatureB64 == "" {
		t.Error("Signature is empty")
	}

	// Verify
	verifyReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "verify/sig-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "sig-key",
			"input":     messageB64,
			"signature": signatureB64,
		},
	}

	verifyResp, err := b.HandleRequest(ctx, verifyReq)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	valid := verifyResp.Data["valid"].(bool)
	if !valid {
		t.Error("Signature should be valid")
	}

	// Verify with wrong message
	wrongMessage := []byte("Wrong message")
	wrongMessageB64 := base64.StdEncoding.EncodeToString(wrongMessage)

	verifyWrongReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "verify/sig-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "sig-key",
			"input":     wrongMessageB64,
			"signature": signatureB64,
		},
	}

	verifyWrongResp, err := b.HandleRequest(ctx, verifyWrongReq)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	validWrong := verifyWrongResp.Data["valid"].(bool)
	if validWrong {
		t.Error("Signature should be invalid for wrong message")
	}
}

func TestBackend_EncryptWithSigningKey(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create signing key (should not work for encryption)
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/sig-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "sig-key",
			"algorithm": "dilithium3",
			"key_type":  "signing",
		},
	}
	_, err := b.HandleRequest(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Try to encrypt with signing key
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte("test"))

	encryptReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/sig-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "sig-key",
			"plaintext": plaintextB64,
		},
	}

	_, err = b.HandleRequest(ctx, encryptReq)
	if err == nil {
		t.Error("Expected error when encrypting with signing key")
	}
}

func TestBackend_SignWithEncryptionKey(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create encryption key (should not work for signing)
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/enc-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "enc-key",
			"algorithm": "kyber768",
			"key_type":  "encryption",
		},
	}
	_, err := b.HandleRequest(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Try to sign with encryption key
	messageB64 := base64.StdEncoding.EncodeToString([]byte("test"))

	signReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/enc-key",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":  "enc-key",
			"input": messageB64,
		},
	}

	_, err = b.HandleRequest(ctx, signReq)
	if err == nil {
		t.Error("Expected error when signing with encryption key")
	}
}

func TestBackend_NonExistentKey(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Try to encrypt with non-existent key
	plaintextB64 := base64.StdEncoding.EncodeToString([]byte("test"))

	encryptReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "encrypt/non-existent",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "non-existent",
			"plaintext": plaintextB64,
		},
	}

	_, err := b.HandleRequest(ctx, encryptReq)
	if err == nil {
		t.Error("Expected error for non-existent key")
	}
}

func TestBackend_DuplicateKey(t *testing.T) {
	b, storage := getTestBackend(t)
	ctx := context.Background()

	// Create key
	createReq := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "keys/duplicate",
		Storage:   storage,
		Data: map[string]interface{}{
			"name":      "duplicate",
			"algorithm": "kyber768",
			"key_type":  "encryption",
		},
	}
	_, err := b.HandleRequest(ctx, createReq)
	if err != nil {
		t.Fatalf("Failed to create key: %v", err)
	}

	// Try to create duplicate
	_, err = b.HandleRequest(ctx, createReq)
	if err == nil {
		t.Error("Expected error when creating duplicate key")
	}
}

