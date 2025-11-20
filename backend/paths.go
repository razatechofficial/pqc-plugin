package backend

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// KeyData represents stored key information
type KeyData struct {
	Name             string `json:"name"`
	Algorithm        string `json:"algorithm"` // kyber512, kyber768, kyber1024, dilithium2, dilithium3, dilithium5
	KeyType          string `json:"key_type"`  // encryption, signing
	PublicKey        []byte `json:"public_key"`
	PrivateKey       []byte `json:"private_key"`        // Plain private key (only in memory)
	EncryptedPrivKey []byte `json:"encrypted_priv_key"` // Encrypted with PQC KEK (stored)
	Version          int    `json:"version"`
}

// KeyMetadata tracks key versions and rotation information
type KeyMetadata struct {
	Name              string `json:"name"`
	Algorithm         string `json:"algorithm"`
	KeyType           string `json:"key_type"`
	LatestVersion     int    `json:"latest_version"`
	MinVersion        int    `json:"min_version"`         // Minimum version to keep
	MinDecryptVersion int    `json:"min_decrypt_version"` // Minimum version for decryption
	Versions          []int  `json:"versions"`            // List of all versions
}

// KEKData represents the Key Encryption Key (stored as a named key)
// KEKs are just regular keys with key_type="kek"
type KEKData struct {
	Name             string `json:"name"`
	PublicKey        []byte `json:"public_key"`
	PrivateKey       []byte `json:"private_key"`        // Plain private key (only in memory)
	EncryptedPrivKey []byte `json:"encrypted_priv_key"` // Encrypted with master KEK (stored)
	Version          int    `json:"version"`
	Algorithm        string `json:"algorithm"` // Always kyber1024 for KEK
}

// keyPaths returns the paths for key management
func keyPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "keys/?$",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "list",
				OperationSuffix: "keys",
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathKeysList,
				},
			},
			HelpSynopsis:    "List all post-quantum keys",
			HelpDescription: "Lists all keys in the post-quantum secrets engine",
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "manage",
				OperationSuffix: "key",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key",
					Required:    true,
				},
				"algorithm": {
					Type:        framework.TypeString,
					Description: "Algorithm to use: kyber512, kyber768, kyber1024, dilithium2, dilithium3, dilithium5",
					Required:    true,
				},
				"key_type": {
					Type:        framework.TypeString,
					Description: "Type of key: encryption or signing",
					Required:    true,
				},
			},
			ExistenceCheck: b.pathKeyExistenceCheck,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathKeyRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathKeyCreate,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeyCreate,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathKeyDelete,
				},
			},
			HelpSynopsis:    "Manage post-quantum keys",
			HelpDescription: "Create, read, update, or delete post-quantum cryptographic keys",
		},
		{
			Pattern: "keys/" + framework.GenericNameRegex("name") + "/rotate",
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "rotate",
				OperationSuffix: "key",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key to rotate",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathKeyRotate,
				},
			},
			HelpSynopsis:    "Rotate a post-quantum key",
			HelpDescription: "Creates a new version of the key while keeping old versions for decryption",
		},
	}
}

// encryptPaths returns the paths for encryption operations
func encryptPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "encrypt/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "encrypt",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key to use for encryption",
					Required:    true,
				},
				"plaintext": {
					Type:        framework.TypeString,
					Description: "Base64-encoded plaintext to encrypt",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathEncrypt,
				},
			},
			HelpSynopsis:    "Encrypt data using post-quantum cryptography",
			HelpDescription: "Encrypts data using the specified post-quantum key",
		},
	}
}

// decryptPaths returns the paths for decryption operations
func decryptPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "decrypt/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "decrypt",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key to use for decryption",
					Required:    true,
				},
				"ciphertext": {
					Type:        framework.TypeString,
					Description: "Base64-encoded ciphertext to decrypt",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathDecrypt,
				},
			},
			HelpSynopsis:    "Decrypt data using post-quantum cryptography",
			HelpDescription: "Decrypts data using the specified post-quantum key",
		},
	}
}

// signPaths returns the paths for signing operations
func signPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "sign/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "sign",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key to use for signing",
					Required:    true,
				},
				"input": {
					Type:        framework.TypeString,
					Description: "Base64-encoded data to sign",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathSign,
				},
			},
			HelpSynopsis:    "Sign data using post-quantum cryptography",
			HelpDescription: "Signs data using the specified post-quantum signing key",
		},
	}
}

// verifyPaths returns the paths for verification operations
func verifyPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "verify/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "verify",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the key to use for verification",
					Required:    true,
				},
				"input": {
					Type:        framework.TypeString,
					Description: "Base64-encoded data that was signed",
					Required:    true,
				},
				"signature": {
					Type:        framework.TypeString,
					Description: "Base64-encoded signature to verify",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathVerify,
				},
			},
			HelpSynopsis:    "Verify signature using post-quantum cryptography",
			HelpDescription: "Verifies a signature using the specified post-quantum signing key",
		},
	}
}

// pathKeysList lists all keys
func (b *PostQuantumBackend) pathKeysList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "keys/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(keys), nil
}

// kekPaths returns paths for KEK management (Transit-like)
// Note: KEKs are just regular encryption keys, so they use the same keyPaths
// This is kept for future extensibility
func kekPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{}
}

// datakeyPaths returns paths for DEK generation (Transit-like datakey)
func datakeyPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "datakey/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "generate",
				OperationSuffix: "datakey",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the KEK to use for encrypting the DEK",
					Required:    true,
				},
				"bits": {
					Type:        framework.TypeInt,
					Description: "Size of the DEK in bits (default: 256)",
					Default:     256,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathDatakey,
				},
			},
			HelpSynopsis:    "Generate a data encryption key (DEK)",
			HelpDescription: "Generates a random DEK and encrypts it with the specified KEK. Returns both plaintext and ciphertext DEK.",
		},
	}
}

// rewrapPaths returns paths for key rewrapping
func rewrapPaths(b *PostQuantumBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "rewrap/" + framework.GenericNameRegex("name"),
			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "pqc",
				OperationVerb:   "rewrap",
			},
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the KEK",
					Required:    true,
				},
				"ciphertext": {
					Type:        framework.TypeString,
					Description: "Base64-encoded ciphertext to rewrap",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRewrap,
				},
			},
			HelpSynopsis:    "Rewrap ciphertext with the latest KEK version",
			HelpDescription: "Decrypts ciphertext with old KEK and re-encrypts with current KEK version",
		},
	}
}

// KEK helper functions

// getOrCreateMasterKEK gets the master KEK (used to encrypt private keys) or creates it if it doesn't exist
// This is an internal KEK, separate from user-created KEKs
func (b *PostQuantumBackend) getOrCreateMasterKEK(ctx context.Context, storage logical.Storage) (*KEKData, error) {
	const kekPath = "kek/master"

	// Try to get existing KEK
	entry, err := storage.Get(ctx, kekPath)
	if err != nil {
		return nil, err
	}

	if entry != nil {
		var kekData KEKData
		if err := json.Unmarshal(entry.Value, &kekData); err != nil {
			return nil, err
		}
		return &kekData, nil
	}

	// Create new KEK
	kekPubKey, kekPrivKey, err := generateKEK()
	if err != nil {
		return nil, fmt.Errorf("failed to generate KEK: %w", err)
	}

	kekData := KEKData{
		PublicKey:  kekPubKey,
		PrivateKey: kekPrivKey,
		Version:    1,
	}

	kekJSON, err := json.Marshal(kekData)
	if err != nil {
		return nil, err
	}

	entry = &logical.StorageEntry{
		Key:   kekPath,
		Value: kekJSON,
	}

	if err := storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &kekData, nil
}

// getMasterKEK retrieves the master KEK (returns error if not found)
func (b *PostQuantumBackend) getMasterKEK(ctx context.Context, storage logical.Storage) (*KEKData, error) {
	const kekPath = "kek/master"

	entry, err := storage.Get(ctx, kekPath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, fmt.Errorf("KEK not found - backend may need initialization")
	}

	var kekData KEKData
	if err := json.Unmarshal(entry.Value, &kekData); err != nil {
		return nil, err
	}

	return &kekData, nil
}

// getPrivateKey retrieves and decrypts a private key, handling backward compatibility
func (b *PostQuantumBackend) getPrivateKey(ctx context.Context, storage logical.Storage, keyData *KeyData) ([]byte, error) {
	// Backward compatibility: if PrivateKey exists (old format), use it directly
	if len(keyData.PrivateKey) > 0 {
		return keyData.PrivateKey, nil
	}

	// New format: decrypt with KEK
	if len(keyData.EncryptedPrivKey) == 0 {
		return nil, fmt.Errorf("key has no private key data")
	}

	kekData, err := b.getMasterKEK(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEK: %w", err)
	}

	privateKey, err := decryptPrivateKeyWithKEK(keyData.EncryptedPrivKey, kekData.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt private key with KEK: %w", err)
	}

	return privateKey, nil
}

// getKeyMetadata retrieves key metadata
func (b *PostQuantumBackend) getKeyMetadata(ctx context.Context, storage logical.Storage, name string) (*KeyMetadata, error) {
	path := fmt.Sprintf("keys/%s/metadata", name)
	entry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var metadata KeyMetadata
	if err := json.Unmarshal(entry.Value, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

// saveKeyMetadata saves key metadata
func (b *PostQuantumBackend) saveKeyMetadata(ctx context.Context, storage logical.Storage, metadata *KeyMetadata) error {
	path := fmt.Sprintf("keys/%s/metadata", metadata.Name)
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		return err
	}

	entry := &logical.StorageEntry{
		Key:   path,
		Value: metadataJSON,
	}
	return storage.Put(ctx, entry)
}

// getKeyVersion retrieves a specific key version
func (b *PostQuantumBackend) getKeyVersion(ctx context.Context, storage logical.Storage, name string, version int) (*KeyData, error) {
	path := fmt.Sprintf("keys/%s/versions/%d", name, version)
	entry, err := storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("key version %d not found", version)
	}

	var keyData KeyData
	if err := json.Unmarshal(entry.Value, &keyData); err != nil {
		return nil, err
	}
	return &keyData, nil
}

// saveKeyVersion saves a specific key version
func (b *PostQuantumBackend) saveKeyVersion(ctx context.Context, storage logical.Storage, keyData *KeyData) error {
	path := fmt.Sprintf("keys/%s/versions/%d", keyData.Name, keyData.Version)
	keyJSON, err := json.Marshal(keyData)
	if err != nil {
		return err
	}

	entry := &logical.StorageEntry{
		Key:   path,
		Value: keyJSON,
	}
	return storage.Put(ctx, entry)
}

// getLatestKeyVersion gets the latest version of a key
func (b *PostQuantumBackend) getLatestKeyVersion(ctx context.Context, storage logical.Storage, name string) (*KeyData, error) {
	metadata, err := b.getKeyMetadata(ctx, storage, name)
	if err != nil {
		return nil, err
	}
	if metadata == nil {
		// Backward compatibility: try old format
		oldPath := fmt.Sprintf("keys/%s", name)
		entry, err := storage.Get(ctx, oldPath)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, fmt.Errorf("key not found")
		}
		var keyData KeyData
		if err := json.Unmarshal(entry.Value, &keyData); err != nil {
			return nil, err
		}
		return &keyData, nil
	}

	return b.getKeyVersion(ctx, storage, name, metadata.LatestVersion)
}

// pathKeyExistenceCheck checks if a key exists
func (b *PostQuantumBackend) pathKeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)

	// Check new format (metadata)
	metadata, err := b.getKeyMetadata(ctx, req.Storage, name)
	if err != nil {
		return false, err
	}
	if metadata != nil {
		return true, nil
	}

	// Check old format (backward compatibility)
	path := fmt.Sprintf("keys/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return false, err
	}

	return entry != nil, nil
}

// pathKeyRead reads a key
func (b *PostQuantumBackend) pathKeyRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Try to get metadata (new format)
	metadata, err := b.getKeyMetadata(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if metadata != nil {
		// Get latest version
		keyData, err := b.getKeyVersion(ctx, req.Storage, name, metadata.LatestVersion)
		if err != nil {
			return nil, err
		}

		return &logical.Response{
			Data: map[string]interface{}{
				"name":                keyData.Name,
				"algorithm":           keyData.Algorithm,
				"key_type":            keyData.KeyType,
				"public_key":          base64.StdEncoding.EncodeToString(keyData.PublicKey),
				"version":             keyData.Version,
				"latest_version":      metadata.LatestVersion,
				"min_version":         metadata.MinVersion,
				"min_decrypt_version": metadata.MinDecryptVersion,
			},
		}, nil
	}

	// Backward compatibility: try old format
	path := fmt.Sprintf("keys/%s", name)
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, fmt.Errorf("key not found")
	}

	var keyData KeyData
	if err := json.Unmarshal(entry.Value, &keyData); err != nil {
		return nil, err
	}

	// Don't return private key in read operation
	return &logical.Response{
		Data: map[string]interface{}{
			"name":       keyData.Name,
			"algorithm":  keyData.Algorithm,
			"key_type":   keyData.KeyType,
			"public_key": base64.StdEncoding.EncodeToString(keyData.PublicKey),
			"version":    keyData.Version,
		},
	}, nil
}

// pathKeyCreate creates a new key
func (b *PostQuantumBackend) pathKeyCreate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	algorithm := d.Get("algorithm").(string)
	keyType := d.Get("key_type").(string)

	path := fmt.Sprintf("keys/%s", name)

	// Check if key already exists
	entry, err := req.Storage.Get(ctx, path)
	if err != nil {
		return nil, err
	}
	if entry != nil && req.Operation == logical.CreateOperation {
		return nil, fmt.Errorf("key already exists")
	}

	// Get or create master KEK for encrypting private keys
	kekData, err := b.getOrCreateMasterKEK(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEK: %w", err)
	}

	// Generate key pair based on algorithm and type
	var keyData KeyData
	keyData.Name = name
	keyData.Algorithm = algorithm
	keyData.KeyType = keyType
	keyData.Version = 1

	var privateKey []byte
	if keyType == "encryption" {
		publicKey, privKey, err := generateEncryptionKey(algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		keyData.PublicKey = publicKey
		privateKey = privKey
	} else if keyType == "signing" {
		publicKey, privKey, err := generateSigningKey(algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}
		keyData.PublicKey = publicKey
		privateKey = privKey
	} else {
		return nil, fmt.Errorf("invalid key_type: must be 'encryption' or 'signing'")
	}

	// Encrypt private key with PQC KEK before storage
	encryptedPrivKey, err := encryptPrivateKeyWithKEK(privateKey, kekData.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key with KEK: %w", err)
	}
	keyData.EncryptedPrivKey = encryptedPrivKey
	// Don't store plain private key
	keyData.PrivateKey = nil

	// Check if this is an update to existing key (migrate to versioned format)
	existingMetadata, err := b.getKeyMetadata(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if existingMetadata != nil {
		// Key exists with versioning - create new version
		keyData.Version = existingMetadata.LatestVersion + 1
		existingMetadata.LatestVersion = keyData.Version
		existingMetadata.Versions = append(existingMetadata.Versions, keyData.Version)

		// Save new version
		if err := b.saveKeyVersion(ctx, req.Storage, &keyData); err != nil {
			return nil, err
		}

		// Update metadata
		if err := b.saveKeyMetadata(ctx, req.Storage, existingMetadata); err != nil {
			return nil, err
		}
	} else {
		// New key - create metadata and version 1
		metadata := &KeyMetadata{
			Name:              name,
			Algorithm:         algorithm,
			KeyType:           keyType,
			LatestVersion:     1,
			MinVersion:        1,
			MinDecryptVersion: 1,
			Versions:          []int{1},
		}

		// Save version 1
		if err := b.saveKeyVersion(ctx, req.Storage, &keyData); err != nil {
			return nil, err
		}

		// Save metadata
		if err := b.saveKeyMetadata(ctx, req.Storage, metadata); err != nil {
			return nil, err
		}
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":       keyData.Name,
			"algorithm":  keyData.Algorithm,
			"key_type":   keyData.KeyType,
			"public_key": base64.StdEncoding.EncodeToString(keyData.PublicKey),
			"version":    keyData.Version,
		},
	}, nil
}

// pathKeyRotate rotates a key by creating a new version
func (b *PostQuantumBackend) pathKeyRotate(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Get metadata
	metadata, err := b.getKeyMetadata(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if metadata == nil {
		// Try to migrate old format key
		oldPath := fmt.Sprintf("keys/%s", name)
		entry, err := req.Storage.Get(ctx, oldPath)
		if err != nil {
			return nil, err
		}
		if entry == nil {
			return nil, fmt.Errorf("key not found")
		}

		var oldKeyData KeyData
		if err := json.Unmarshal(entry.Value, &oldKeyData); err != nil {
			return nil, err
		}

		// Migrate to versioned format
		metadata = &KeyMetadata{
			Name:              name,
			Algorithm:         oldKeyData.Algorithm,
			KeyType:           oldKeyData.KeyType,
			LatestVersion:     1,
			MinVersion:        1,
			MinDecryptVersion: 1,
			Versions:          []int{1},
		}

		oldKeyData.Version = 1
		if err := b.saveKeyVersion(ctx, req.Storage, &oldKeyData); err != nil {
			return nil, err
		}
		if err := b.saveKeyMetadata(ctx, req.Storage, metadata); err != nil {
			return nil, err
		}

		// Delete old format
		req.Storage.Delete(ctx, oldPath)
	}

	// Get latest version to copy algorithm and key type
	latestKey, err := b.getKeyVersion(ctx, req.Storage, name, metadata.LatestVersion)
	if err != nil {
		return nil, err
	}

	// Get or create master KEK
	kekData, err := b.getOrCreateMasterKEK(ctx, req.Storage)
	if err != nil {
		return nil, fmt.Errorf("failed to get KEK: %w", err)
	}

	// Generate new key pair
	var newKeyData KeyData
	newKeyData.Name = name
	newKeyData.Algorithm = latestKey.Algorithm
	newKeyData.KeyType = latestKey.KeyType
	newKeyData.Version = metadata.LatestVersion + 1

	var privateKey []byte
	if newKeyData.KeyType == "encryption" {
		publicKey, privKey, err := generateEncryptionKey(newKeyData.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		newKeyData.PublicKey = publicKey
		privateKey = privKey
	} else if newKeyData.KeyType == "signing" {
		publicKey, privKey, err := generateSigningKey(newKeyData.Algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}
		newKeyData.PublicKey = publicKey
		privateKey = privKey
	}

	// Encrypt private key
	encryptedPrivKey, err := encryptPrivateKeyWithKEK(privateKey, kekData.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt private key with KEK: %w", err)
	}
	newKeyData.EncryptedPrivKey = encryptedPrivKey
	newKeyData.PrivateKey = nil

	// Save new version
	if err := b.saveKeyVersion(ctx, req.Storage, &newKeyData); err != nil {
		return nil, err
	}

	// Update metadata
	metadata.LatestVersion = newKeyData.Version
	metadata.Versions = append(metadata.Versions, newKeyData.Version)
	if err := b.saveKeyMetadata(ctx, req.Storage, metadata); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":           newKeyData.Name,
			"algorithm":      newKeyData.Algorithm,
			"key_type":       newKeyData.KeyType,
			"public_key":     base64.StdEncoding.EncodeToString(newKeyData.PublicKey),
			"version":        newKeyData.Version,
			"latest_version": metadata.LatestVersion,
		},
	}, nil
}

// pathKeyDelete deletes a key
func (b *PostQuantumBackend) pathKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)

	// Delete metadata and all versions
	metadata, err := b.getKeyMetadata(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if metadata != nil {
		// Delete all versions
		for _, version := range metadata.Versions {
			versionPath := fmt.Sprintf("keys/%s/versions/%d", name, version)
			req.Storage.Delete(ctx, versionPath)
		}
		// Delete metadata
		metadataPath := fmt.Sprintf("keys/%s/metadata", name)
		req.Storage.Delete(ctx, metadataPath)
	} else {
		// Backward compatibility: delete old format
		path := fmt.Sprintf("keys/%s", name)
		if err := req.Storage.Delete(ctx, path); err != nil {
			return nil, err
		}
	}

	return nil, nil
}

// pathEncrypt encrypts data
func (b *PostQuantumBackend) pathEncrypt(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	plaintextB64 := d.Get("plaintext").(string)

	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 plaintext: %w", err)
	}

	// Get the latest key version
	keyData, err := b.getLatestKeyVersion(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if keyData.KeyType != "encryption" {
		return nil, fmt.Errorf("key is not an encryption key")
	}

	// Encrypt the data using latest version
	ciphertext, err := encryptData(plaintext, keyData.PublicKey, keyData.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": base64.StdEncoding.EncodeToString(ciphertext),
		},
	}, nil
}

// pathDecrypt decrypts data
func (b *PostQuantumBackend) pathDecrypt(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ciphertextB64 := d.Get("ciphertext").(string)

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	// Get metadata to try all versions
	metadata, err := b.getKeyMetadata(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	var versionsToTry []int
	if metadata != nil {
		// Try versions from latest to min_decrypt_version
		for v := metadata.LatestVersion; v >= metadata.MinDecryptVersion; v-- {
			versionsToTry = append(versionsToTry, v)
		}
	} else {
		// Backward compatibility: try old format
		keyData, err := b.getLatestKeyVersion(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		versionsToTry = []int{keyData.Version}
	}

	// Try each version until one works
	var lastErr error
	for _, version := range versionsToTry {
		keyData, err := b.getKeyVersion(ctx, req.Storage, name, version)
		if err != nil {
			lastErr = err
			continue
		}

		if keyData.KeyType != "encryption" {
			lastErr = fmt.Errorf("key is not an encryption key")
			continue
		}

		// Get and decrypt private key
		privateKey, err := b.getPrivateKey(ctx, req.Storage, keyData)
		if err != nil {
			lastErr = err
			continue
		}

		// Try to decrypt
		plaintext, err := decryptData(ciphertext, privateKey, keyData.Algorithm)
		if err == nil {
			// Success!
			return &logical.Response{
				Data: map[string]interface{}{
					"plaintext": base64.StdEncoding.EncodeToString(plaintext),
				},
			}, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("decryption failed with all key versions: %w", lastErr)
}

// pathSign signs data
func (b *PostQuantumBackend) pathSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	inputB64 := d.Get("input").(string)

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 input: %w", err)
	}

	// Get the latest key version
	keyData, err := b.getLatestKeyVersion(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if keyData.KeyType != "signing" {
		return nil, fmt.Errorf("key is not a signing key")
	}

	// Get and decrypt private key
	privateKey, err := b.getPrivateKey(ctx, req.Storage, keyData)
	if err != nil {
		return nil, err
	}

	// Sign the data
	signature, err := signData(input, privateKey, keyData.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"signature": base64.StdEncoding.EncodeToString(signature),
		},
	}, nil
}

// pathVerify verifies a signature
func (b *PostQuantumBackend) pathVerify(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	inputB64 := d.Get("input").(string)
	signatureB64 := d.Get("signature").(string)

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 input: %w", err)
	}

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 signature: %w", err)
	}

	// Get metadata to try all versions for verification
	metadata, err := b.getKeyMetadata(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	var versionsToTry []int
	if metadata != nil {
		// Try versions from latest to min_decrypt_version
		for v := metadata.LatestVersion; v >= metadata.MinDecryptVersion; v-- {
			versionsToTry = append(versionsToTry, v)
		}
	} else {
		// Backward compatibility: try old format
		keyData, err := b.getLatestKeyVersion(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		versionsToTry = []int{keyData.Version}
	}

	// Try each version until one works
	var lastErr error
	for _, version := range versionsToTry {
		keyData, err := b.getKeyVersion(ctx, req.Storage, name, version)
		if err != nil {
			lastErr = err
			continue
		}

		if keyData.KeyType != "signing" {
			lastErr = fmt.Errorf("key is not a signing key")
			continue
		}

		// Verify the signature
		valid, err := verifySignature(input, signature, keyData.PublicKey, keyData.Algorithm)
		if err == nil {
			// Success!
			return &logical.Response{
				Data: map[string]interface{}{
					"valid": valid,
				},
			}, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("verification failed with all key versions: %w", lastErr)
}

// pathDatakey generates a DEK (Data Encryption Key) and encrypts it with the specified KEK
// Returns both plaintext and ciphertext DEK (Transit-like behavior)
func (b *PostQuantumBackend) pathDatakey(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	bits := d.Get("bits").(int)

	// Validate bits
	if bits != 128 && bits != 256 && bits != 512 {
		return nil, fmt.Errorf("bits must be 128, 256, or 512")
	}

	// Get the latest KEK version (must be an encryption key)
	keyData, err := b.getLatestKeyVersion(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("KEK not found: %s", name)
	}

	if keyData.KeyType != "encryption" {
		return nil, fmt.Errorf("key is not an encryption key (cannot be used as KEK)")
	}

	// Generate random DEK
	dekSize := bits / 8
	plaintextDEK := make([]byte, dekSize)
	if _, err := rand.Read(plaintextDEK); err != nil {
		return nil, fmt.Errorf("failed to generate DEK: %w", err)
	}

	// Encrypt DEK with KEK using PQC KEM
	encryptedDEK, err := encryptData(plaintextDEK, keyData.PublicKey, keyData.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt DEK with KEK: %w", err)
	}

	// Return both plaintext and ciphertext DEK (like Transit)
	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext":  base64.StdEncoding.EncodeToString(plaintextDEK),
			"ciphertext": base64.StdEncoding.EncodeToString(encryptedDEK),
		},
	}, nil
}

// pathRewrap rewraps ciphertext with the latest KEK version
func (b *PostQuantumBackend) pathRewrap(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	ciphertextB64 := d.Get("ciphertext").(string)

	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 ciphertext: %w", err)
	}

	// Get the latest KEK version
	keyData, err := b.getLatestKeyVersion(ctx, req.Storage, name)
	if err != nil {
		return nil, fmt.Errorf("KEK not found: %s", name)
	}

	if keyData.KeyType != "encryption" {
		return nil, fmt.Errorf("key is not an encryption key")
	}

	// Get and decrypt private key to decrypt the DEK
	privateKey, err := b.getPrivateKey(ctx, req.Storage, keyData)
	if err != nil {
		return nil, err
	}

	// Decrypt the DEK
	plaintextDEK, err := decryptData(ciphertext, privateKey, keyData.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt DEK: %w", err)
	}

	// Re-encrypt with the same KEK (latest version)
	rewrappedDEK, err := encryptData(plaintextDEK, keyData.PublicKey, keyData.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to re-encrypt DEK: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"ciphertext": base64.StdEncoding.EncodeToString(rewrappedDEK),
		},
	}, nil
}
