package backend

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/kyber/kyber512"
	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/kem/kyber/kyber1024"
	"github.com/cloudflare/circl/sign/dilithium"
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
	ciphertext, sharedSecret, err := scheme.Encapsulate(publicKey)
	if err != nil {
		return nil, err
	}

	// Use shared secret to encrypt plaintext (simple XOR for demonstration)
	// In production, use a proper AEAD like AES-GCM with the shared secret
	encrypted := make([]byte, len(plaintext))
	for i := range plaintext {
		encrypted[i] = plaintext[i] ^ sharedSecret[i%len(sharedSecret)]
	}

	// Combine ciphertext and encrypted data
	result := append(ciphertext, encrypted...)
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

	// Extract ciphertext and encrypted data
	ciphertextSize := scheme.CiphertextSize()
	if len(ciphertextWithData) < ciphertextSize {
		return nil, errors.New("invalid ciphertext length")
	}

	ciphertext := ciphertextWithData[:ciphertextSize]
	encrypted := ciphertextWithData[ciphertextSize:]

	// Decapsulate shared secret
	sharedSecret, err := scheme.Decapsulate(privateKey, ciphertext)
	if err != nil {
		return nil, err
	}

	// Decrypt using shared secret
	plaintext := make([]byte, len(encrypted))
	for i := range encrypted {
		plaintext[i] = encrypted[i] ^ sharedSecret[i%len(sharedSecret)]
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

