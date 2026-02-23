package backend

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem"
	"golang.org/x/crypto/hkdf"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium"
)

const (
	// aeadMagic identifies AEAD ciphertext (KDF + AES-GCM). Legacy XOR ciphertext has no magic.
	aeadMagic     = "PQ1"
	aeadNonceSize = 12
	aeadKeySize   = 32 // AES-256
)

// generateEncryptionKey generates a post-quantum encryption key pair
func generateEncryptionKey(algorithm string) ([]byte, []byte, error) {
	var scheme kem.Scheme

	switch algorithm {
	case "kyber512":
		scheme = kyber512.Scheme()
	case "kyber768":
		scheme = kyber768.Scheme()
	case "kyber1024":
		scheme = kyber1024.Scheme()
	default:
		return nil, nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}

	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return pubKeyBytes, privKeyBytes, nil
}

// generateSigningKey generates a post-quantum signing key pair
func generateSigningKey(algorithm string) ([]byte, []byte, error) {
	var mode dilithium.Mode

	switch algorithm {
	case "dilithium2":
		mode = dilithium.Mode2
	case "dilithium3":
		mode = dilithium.Mode3
	case "dilithium5":
		mode = dilithium.Mode5
	default:
		return nil, nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	publicKey, privateKey, err := mode.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Dilithium keys are already byte slices
	pubKeyBytes := publicKey.Bytes()
	privKeyBytes := privateKey.Bytes()

	return pubKeyBytes, privKeyBytes, nil
}

// aeadEncrypt encrypts plaintext with sharedSecret using HKDF-SHA256 and AES-256-GCM (production-safe).
func aeadEncrypt(plaintext []byte, sharedSecret []byte, context string) (noncePlusCiphertext []byte, err error) {
	key := make([]byte, aeadKeySize)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(context))
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aeadNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	return append(nonce, ciphertext...), nil
}

// aeadDecrypt decrypts noncePlusCiphertext (nonce || ciphertext+tag) with sharedSecret.
func aeadDecrypt(noncePlusCiphertext []byte, sharedSecret []byte, context string) ([]byte, error) {
	if len(noncePlusCiphertext) < aeadNonceSize {
		return nil, errors.New("ciphertext too short")
	}
	key := make([]byte, aeadKeySize)
	kdf := hkdf.New(sha256.New, sharedSecret, nil, []byte(context))
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := noncePlusCiphertext[:aeadNonceSize]
	ciphertext := noncePlusCiphertext[aeadNonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

// encryptData encrypts data using a post-quantum public key
func encryptData(plaintext []byte, publicKeyBytes []byte, algorithm string) ([]byte, error) {
	var scheme kem.Scheme

	switch algorithm {
	case "kyber512":
		scheme = kyber512.Scheme()
	case "kyber768":
		scheme = kyber768.Scheme()
	case "kyber1024":
		scheme = kyber1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}

	publicKey, err := scheme.UnmarshalBinaryPublicKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	// Encapsulate shared secret (KEM Encapsulate takes only public key)
	kemCiphertext, sharedSecret, err := scheme.Encapsulate(publicKey)
	if err != nil {
		return nil, err
	}

	// Encrypt with HKDF + AES-256-GCM (industry standard; NIST/HPKE-style)
	encrypted, err := aeadEncrypt(plaintext, sharedSecret, "pqc-plugin-kem-aead-v1")
	if err != nil {
		return nil, err
	}
	// Wire format: KEM ciphertext || magic || nonce || AES-GCM ciphertext+tag
	result := append(append(kemCiphertext, aeadMagic...), encrypted...)
	return result, nil
}

// decryptData decrypts data using a post-quantum private key
func decryptData(ciphertextWithData []byte, privateKeyBytes []byte, algorithm string) ([]byte, error) {
	var scheme kem.Scheme

	switch algorithm {
	case "kyber512":
		scheme = kyber512.Scheme()
	case "kyber768":
		scheme = kyber768.Scheme()
	case "kyber1024":
		scheme = kyber1024.Scheme()
	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}

	privateKey, err := scheme.UnmarshalBinaryPrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	// Extract KEM ciphertext and payload
	ciphertextSize := scheme.CiphertextSize()
	if len(ciphertextWithData) < ciphertextSize {
		return nil, errors.New("invalid ciphertext length")
	}
	kemCiphertext := ciphertextWithData[:ciphertextSize]
	payload := ciphertextWithData[ciphertextSize:]

	// Decapsulate shared secret
	sharedSecret, err := scheme.Decapsulate(privateKey, kemCiphertext)
	if err != nil {
		return nil, err
	}

	// AEAD format: magic(3) || nonce(12) || ciphertext+tag; otherwise legacy XOR
	if len(payload) >= len(aeadMagic) && string(payload[:len(aeadMagic)]) == aeadMagic {
		return aeadDecrypt(payload[len(aeadMagic):], sharedSecret, "pqc-plugin-kem-aead-v1")
	}
	// Legacy XOR (backward compatibility)
	plaintext := make([]byte, len(payload))
	for i := range payload {
		plaintext[i] = payload[i] ^ sharedSecret[i%len(sharedSecret)]
	}
	return plaintext, nil
}

// signData signs data using a post-quantum private key
func signData(data []byte, privateKeyBytes []byte, algorithm string) ([]byte, error) {
	var mode dilithium.Mode

	switch algorithm {
	case "dilithium2":
		mode = dilithium.Mode2
	case "dilithium3":
		mode = dilithium.Mode3
	case "dilithium5":
		mode = dilithium.Mode5
	default:
		return nil, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	// Unpack private key from bytes
	if len(privateKeyBytes) != mode.PrivateKeySize() {
		return nil, fmt.Errorf("invalid private key size: expected %d, got %d", mode.PrivateKeySize(), len(privateKeyBytes))
	}
	privateKey := mode.PrivateKeyFromBytes(privateKeyBytes)

	signature := mode.Sign(privateKey, data)
	return signature, nil
}

// verifySignature verifies a signature using a post-quantum public key
func verifySignature(data []byte, signature []byte, publicKeyBytes []byte, algorithm string) (bool, error) {
	var mode dilithium.Mode

	switch algorithm {
	case "dilithium2":
		mode = dilithium.Mode2
	case "dilithium3":
		mode = dilithium.Mode3
	case "dilithium5":
		mode = dilithium.Mode5
	default:
		return false, fmt.Errorf("unsupported signing algorithm: %s", algorithm)
	}

	// Unpack public key from bytes
	if len(publicKeyBytes) != mode.PublicKeySize() {
		return false, fmt.Errorf("invalid public key size: expected %d, got %d", mode.PublicKeySize(), len(publicKeyBytes))
	}
	publicKey := mode.PublicKeyFromBytes(publicKeyBytes)

	isValid := mode.Verify(publicKey, data, signature)
	return isValid, nil
}

// KEK (Key Encryption Key) functions for encrypting private keys with PQC

// generateKEK generates a PQC KEK for encrypting private keys
// Uses Kyber1024 for maximum security as KEK
func generateKEK() ([]byte, []byte, error) {
	scheme := kyber1024.Scheme()
	publicKey, privateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}

	pubKeyBytes, err := publicKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	privKeyBytes, err := privateKey.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}

	return pubKeyBytes, privKeyBytes, nil
}

// encryptPrivateKeyWithKEK encrypts a private key using a PQC KEK
func encryptPrivateKeyWithKEK(privateKey []byte, kekPublicKey []byte) ([]byte, error) {
	scheme := kyber1024.Scheme()

	// Unmarshal KEK public key
	kekPubKey, err := scheme.UnmarshalBinaryPublicKey(kekPublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KEK public key: %w", err)
	}

	// Encapsulate shared secret using KEK
	kemCiphertext, sharedSecret, err := scheme.Encapsulate(kekPubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encapsulate with KEK: %w", err)
	}

	// Encrypt with HKDF + AES-256-GCM (production-safe)
	encrypted, err := aeadEncrypt(privateKey, sharedSecret, "pqc-plugin-kek-aead-v1")
	if err != nil {
		return nil, err
	}
	result := append(append(kemCiphertext, aeadMagic...), encrypted...)
	return result, nil
}

// decryptPrivateKeyWithKEK decrypts a private key using a PQC KEK
func decryptPrivateKeyWithKEK(encryptedPrivateKey []byte, kekPrivateKey []byte) ([]byte, error) {
	scheme := kyber1024.Scheme()

	// Unmarshal KEK private key
	kekPrivKey, err := scheme.UnmarshalBinaryPrivateKey(kekPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal KEK private key: %w", err)
	}

	// Extract KEM ciphertext and payload
	ciphertextSize := scheme.CiphertextSize()
	if len(encryptedPrivateKey) < ciphertextSize {
		return nil, errors.New("invalid encrypted private key length")
	}
	kemCiphertext := encryptedPrivateKey[:ciphertextSize]
	payload := encryptedPrivateKey[ciphertextSize:]

	// Decapsulate shared secret
	sharedSecret, err := scheme.Decapsulate(kekPrivKey, kemCiphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decapsulate with KEK: %w", err)
	}

	// AEAD format: magic(3) || nonce(12) || ciphertext+tag; otherwise legacy XOR
	if len(payload) >= len(aeadMagic) && string(payload[:len(aeadMagic)]) == aeadMagic {
		return aeadDecrypt(payload[len(aeadMagic):], sharedSecret, "pqc-plugin-kek-aead-v1")
	}
	// Legacy XOR (backward compatibility)
	privateKey := make([]byte, len(payload))
	for i := range payload {
		privateKey[i] = payload[i] ^ sharedSecret[i%len(sharedSecret)]
	}
	return privateKey, nil
}
