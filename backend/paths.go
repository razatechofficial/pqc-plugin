package backend

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// KeyData represents stored key information
type KeyData struct {
	Name       string `json:"name"`
	Algorithm  string `json:"algorithm"` // kyber512, kyber768, kyber1024, dilithium2, dilithium3, dilithium5
	KeyType    string `json:"key_type"`  // encryption, signing
	PublicKey  []byte `json:"public_key"`
	PrivateKey []byte `json:"private_key"`
	Version    int    `json:"version"`
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

// pathKeyExistenceCheck checks if a key exists
func (b *PostQuantumBackend) pathKeyExistenceCheck(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
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
			"name":      keyData.Name,
			"algorithm": keyData.Algorithm,
			"key_type":  keyData.KeyType,
			"public_key": base64.StdEncoding.EncodeToString(keyData.PublicKey),
			"version":   keyData.Version,
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

	// Generate key pair based on algorithm and type
	var keyData KeyData
	keyData.Name = name
	keyData.Algorithm = algorithm
	keyData.KeyType = keyType
	keyData.Version = 1

	if keyType == "encryption" {
		publicKey, privateKey, err := generateEncryptionKey(algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate encryption key: %w", err)
		}
		keyData.PublicKey = publicKey
		keyData.PrivateKey = privateKey
	} else if keyType == "signing" {
		publicKey, privateKey, err := generateSigningKey(algorithm)
		if err != nil {
			return nil, fmt.Errorf("failed to generate signing key: %w", err)
		}
		keyData.PublicKey = publicKey
		keyData.PrivateKey = privateKey
	} else {
		return nil, fmt.Errorf("invalid key_type: must be 'encryption' or 'signing'")
	}

	// Store the key
	keyJSON, err := json.Marshal(keyData)
	if err != nil {
		return nil, err
	}

	entry = &logical.StorageEntry{
		Key:   path,
		Value: keyJSON,
	}

	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"name":      keyData.Name,
			"algorithm": keyData.Algorithm,
			"key_type":  keyData.KeyType,
			"public_key": base64.StdEncoding.EncodeToString(keyData.PublicKey),
			"version":   keyData.Version,
		},
	}, nil
}

// pathKeyDelete deletes a key
func (b *PostQuantumBackend) pathKeyDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	path := fmt.Sprintf("keys/%s", name)

	if err := req.Storage.Delete(ctx, path); err != nil {
		return nil, err
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

	// Get the key
	keyPath := fmt.Sprintf("keys/%s", name)
	entry, err := req.Storage.Get(ctx, keyPath)
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

	if keyData.KeyType != "encryption" {
		return nil, fmt.Errorf("key is not an encryption key")
	}

	// Encrypt the data
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

	// Get the key
	keyPath := fmt.Sprintf("keys/%s", name)
	entry, err := req.Storage.Get(ctx, keyPath)
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

	if keyData.KeyType != "encryption" {
		return nil, fmt.Errorf("key is not an encryption key")
	}

	// Decrypt the data
	plaintext, err := decryptData(ciphertext, keyData.PrivateKey, keyData.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"plaintext": base64.StdEncoding.EncodeToString(plaintext),
		},
	}, nil
}

// pathSign signs data
func (b *PostQuantumBackend) pathSign(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	inputB64 := d.Get("input").(string)

	input, err := base64.StdEncoding.DecodeString(inputB64)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 input: %w", err)
	}

	// Get the key
	keyPath := fmt.Sprintf("keys/%s", name)
	entry, err := req.Storage.Get(ctx, keyPath)
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

	if keyData.KeyType != "signing" {
		return nil, fmt.Errorf("key is not a signing key")
	}

	// Sign the data
	signature, err := signData(input, keyData.PrivateKey, keyData.Algorithm)
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

	// Get the key
	keyPath := fmt.Sprintf("keys/%s", name)
	entry, err := req.Storage.Get(ctx, keyPath)
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

	if keyData.KeyType != "signing" {
		return nil, fmt.Errorf("key is not a signing key")
	}

	// Verify the signature
	valid, err := verifySignature(input, signature, keyData.PublicKey, keyData.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("verification failed: %w", err)
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"valid": valid,
		},
	}, nil
}

