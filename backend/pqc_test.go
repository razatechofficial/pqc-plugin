package backend

import (
	"encoding/base64"
	"testing"
)

func TestGenerateEncryptionKey(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"Kyber512", "kyber512", false},
		{"Kyber768", "kyber768", false},
		{"Kyber1024", "kyber1024", false},
		{"Invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, privateKey, err := generateEncryptionKey(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateEncryptionKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(publicKey) == 0 {
					t.Error("generateEncryptionKey() publicKey is empty")
				}
				if len(privateKey) == 0 {
					t.Error("generateEncryptionKey() privateKey is empty")
				}
			}
		})
	}
}

func TestGenerateSigningKey(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
		wantErr   bool
	}{
		{"Dilithium2", "dilithium2", false},
		{"Dilithium3", "dilithium3", false},
		{"Dilithium5", "dilithium5", false},
		{"Invalid", "invalid", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publicKey, privateKey, err := generateSigningKey(tt.algorithm)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateSigningKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(publicKey) == 0 {
					t.Error("generateSigningKey() publicKey is empty")
				}
				if len(privateKey) == 0 {
					t.Error("generateSigningKey() privateKey is empty")
				}
			}
		})
	}
}

func TestEncryptDecrypt(t *testing.T) {
	algorithms := []string{"kyber512", "kyber768", "kyber1024"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			// Generate key pair
			publicKey, privateKey, err := generateEncryptionKey(alg)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Test data
			testMessages := [][]byte{
				[]byte("Hello, World!"),
				[]byte(""),
				[]byte("A"),
				make([]byte, 1000), // Large message
			}

			for _, plaintext := range testMessages {
				// Encrypt
				ciphertext, err := encryptData(plaintext, publicKey, alg)
				if err != nil {
					t.Fatalf("Encryption failed: %v", err)
				}
				if len(ciphertext) == 0 {
					t.Error("Ciphertext is empty")
				}

				// Decrypt
				decrypted, err := decryptData(ciphertext, privateKey, alg)
				if err != nil {
					t.Fatalf("Decryption failed: %v", err)
				}

				// Verify
				if string(decrypted) != string(plaintext) {
					t.Errorf("Decrypted text doesn't match. Got: %s, Want: %s", decrypted, plaintext)
				}
			}
		})
	}
}

func TestEncryptDecryptInvalidKey(t *testing.T) {
	// Try to encrypt with invalid key
	invalidKey := []byte("invalid-key")
	_, err := encryptData([]byte("test"), invalidKey, "kyber768")
	if err == nil {
		t.Error("Expected error for invalid public key")
	}

	// Try to decrypt with invalid key
	_, err = decryptData([]byte("invalid-ciphertext"), invalidKey, "kyber768")
	if err == nil {
		t.Error("Expected error for invalid private key")
	}
}

func TestSignVerify(t *testing.T) {
	algorithms := []string{"dilithium2", "dilithium3", "dilithium5"}

	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			// Generate key pair
			publicKey, privateKey, err := generateSigningKey(alg)
			if err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}

			// Test data
			testMessages := [][]byte{
				[]byte("Hello, World!"),
				[]byte(""),
				[]byte("A"),
				make([]byte, 1000), // Large message
			}

			for _, message := range testMessages {
				// Sign
				signature, err := signData(message, privateKey, alg)
				if err != nil {
					t.Fatalf("Signing failed: %v", err)
				}
				if len(signature) == 0 {
					t.Error("Signature is empty")
				}

				// Verify
				valid, err := verifySignature(message, signature, publicKey, alg)
				if err != nil {
					t.Fatalf("Verification failed: %v", err)
				}
				if !valid {
					t.Error("Signature verification failed")
				}

				// Verify with wrong message
				wrongMessage := []byte("wrong message")
				valid, err = verifySignature(wrongMessage, signature, publicKey, alg)
				if err != nil {
					t.Fatalf("Verification failed: %v", err)
				}
				if valid {
					t.Error("Signature should be invalid for wrong message")
				}
			}
		})
	}
}

func TestSignVerifyInvalidKey(t *testing.T) {
	// Try to sign with invalid key
	invalidKey := []byte("invalid-key")
	_, err := signData([]byte("test"), invalidKey, "dilithium3")
	if err == nil {
		t.Error("Expected error for invalid private key")
	}

	// Try to verify with invalid key
	_, err = verifySignature([]byte("test"), []byte("signature"), invalidKey, "dilithium3")
	if err == nil {
		t.Error("Expected error for invalid public key")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	// Test multiple round trips with same key
	publicKey, privateKey, err := generateEncryptionKey("kyber768")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	plaintext := []byte("Round trip test message")
	
	for i := 0; i < 10; i++ {
		ciphertext, err := encryptData(plaintext, publicKey, "kyber768")
		if err != nil {
			t.Fatalf("Encryption failed on iteration %d: %v", i, err)
		}

		decrypted, err := decryptData(ciphertext, privateKey, "kyber768")
		if err != nil {
			t.Fatalf("Decryption failed on iteration %d: %v", i, err)
		}

		if string(decrypted) != string(plaintext) {
			t.Errorf("Round trip failed on iteration %d", i)
		}
	}
}

func TestBase64Encoding(t *testing.T) {
	// Test that keys can be base64 encoded/decoded
	publicKey, privateKey, err := generateEncryptionKey("kyber768")
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Encode
	pubB64 := base64.StdEncoding.EncodeToString(publicKey)
	privB64 := base64.StdEncoding.EncodeToString(privateKey)

	// Decode
	pubDecoded, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil {
		t.Fatalf("Failed to decode public key: %v", err)
	}

	privDecoded, err := base64.StdEncoding.DecodeString(privB64)
	if err != nil {
		t.Fatalf("Failed to decode private key: %v", err)
	}

	// Verify
	if string(pubDecoded) != string(publicKey) {
		t.Error("Public key encoding/decoding failed")
	}
	if string(privDecoded) != string(privateKey) {
		t.Error("Private key encoding/decoding failed")
	}
}

func BenchmarkEncryptKyber512(b *testing.B) {
	publicKey, _, _ := generateEncryptionKey("kyber512")
	plaintext := []byte("Benchmark test message")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encryptData(plaintext, publicKey, "kyber512")
	}
}

func BenchmarkDecryptKyber512(b *testing.B) {
	publicKey, privateKey, _ := generateEncryptionKey("kyber512")
	plaintext := []byte("Benchmark test message")
	ciphertext, _ := encryptData(plaintext, publicKey, "kyber512")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = decryptData(ciphertext, privateKey, "kyber512")
	}
}

func BenchmarkSignDilithium3(b *testing.B) {
	_, privateKey, _ := generateSigningKey("dilithium3")
	message := []byte("Benchmark test message")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signData(message, privateKey, "dilithium3")
	}
}

func BenchmarkVerifyDilithium3(b *testing.B) {
	publicKey, privateKey, _ := generateSigningKey("dilithium3")
	message := []byte("Benchmark test message")
	signature, _ := signData(message, privateKey, "dilithium3")
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = verifySignature(message, signature, publicKey, "dilithium3")
	}
}

