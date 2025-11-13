# Testing Guide

This document describes the test suite for the Post-Quantum Cryptography Vault Plugin.

## Test Structure

The test suite is organized into three main test files:

1. **`backend/pqc_test.go`** - Unit tests for post-quantum cryptographic operations
2. **`backend/backend_test.go`** - Integration tests for the Vault backend
3. **`backend/paths_test.go`** - Tests for API path handlers and validation

## Running Tests

### Run All Tests

```bash
go test ./backend -v
```

### Run Specific Test

```bash
go test ./backend -v -run TestBackend_KeyCreate
```

### Run Tests with Coverage

```bash
go test ./backend -cover
```

### Generate Coverage Report

```bash
go test ./backend -coverprofile=coverage.out
go tool cover -html=coverage.out
```

## Test Categories

### 1. Cryptographic Operations Tests (`pqc_test.go`)

#### Key Generation Tests
- `TestGenerateEncryptionKey` - Tests key generation for all Kyber variants
- `TestGenerateSigningKey` - Tests key generation for all Dilithium variants

#### Encryption/Decryption Tests
- `TestEncryptDecrypt` - Tests encryption/decryption round-trips for all algorithms
- `TestEncryptDecryptInvalidKey` - Tests error handling for invalid keys
- `TestEncryptDecryptRoundTrip` - Tests multiple round trips with the same key

#### Signing/Verification Tests
- `TestSignVerify` - Tests signing and verification for all algorithms
- `TestSignVerifyInvalidKey` - Tests error handling for invalid keys

#### Utility Tests
- `TestBase64Encoding` - Tests base64 encoding/decoding of keys

#### Performance Benchmarks
- `BenchmarkEncryptKyber512` - Benchmarks encryption performance
- `BenchmarkDecryptKyber512` - Benchmarks decryption performance
- `BenchmarkSignDilithium3` - Benchmarks signing performance
- `BenchmarkVerifyDilithium3` - Benchmarks verification performance

### 2. Backend Integration Tests (`backend_test.go`)

#### Key Management Tests
- `TestBackend_KeyCreate` - Tests key creation with various parameters
- `TestBackend_KeyRead` - Tests reading key information
- `TestBackend_KeyList` - Tests listing all keys
- `TestBackend_KeyDelete` - Tests key deletion
- `TestBackend_DuplicateKey` - Tests duplicate key prevention

#### Cryptographic Operation Tests
- `TestBackend_EncryptDecrypt` - Tests encryption/decryption through the API
- `TestBackend_SignVerify` - Tests signing/verification through the API

#### Error Handling Tests
- `TestBackend_EncryptWithSigningKey` - Tests using wrong key type
- `TestBackend_SignWithEncryptionKey` - Tests using wrong key type
- `TestBackend_NonExistentKey` - Tests operations with non-existent keys

### 3. Path Handler Tests (`paths_test.go`)

#### Validation Tests
- `TestPathValidation` - Tests missing required fields
- `TestInvalidBase64Input` - Tests invalid base64 input handling
- `TestEmptyInput` - Tests handling of empty inputs
- `TestLargeData` - Tests handling of large data (1MB)

## Test Coverage

The test suite aims to cover:

- ✅ All supported algorithms (Kyber512/768/1024, Dilithium2/3/5)
- ✅ Key generation, storage, and retrieval
- ✅ Encryption and decryption operations
- ✅ Signing and verification operations
- ✅ Error handling and edge cases
- ✅ Input validation
- ✅ Large data handling
- ✅ Base64 encoding/decoding

## Writing New Tests

### Example: Adding a New Test

```go
func TestNewFeature(t *testing.T) {
    b, storage := getTestBackend(t)
    ctx := context.Background()
    
    // Setup
    // ... create necessary keys or data
    
    // Execute
    req := &logical.Request{
        Operation: logical.CreateOperation,
        Path:      "path/to/resource",
        Storage:   storage,
        Data:      map[string]interface{}{
            "field": "value",
        },
    }
    
    resp, err := b.HandleRequest(ctx, req)
    
    // Assert
    if err != nil {
        t.Fatalf("Unexpected error: %v", err)
    }
    
    if resp == nil {
        t.Fatal("Response is nil")
    }
    
    // Verify response data
    if resp.Data["expected_field"] != "expected_value" {
        t.Errorf("Expected %v, got %v", "expected_value", resp.Data["expected_field"])
    }
}
```

### Best Practices

1. **Use `t.Helper()`** in helper functions to improve error messages
2. **Clean up resources** after tests when necessary
3. **Test both success and failure cases**
4. **Use descriptive test names** that explain what is being tested
5. **Group related tests** using subtests with `t.Run()`
6. **Test edge cases** like empty inputs, large inputs, invalid inputs

## Continuous Integration

Tests should be run:
- Before committing code
- In CI/CD pipelines
- Before releasing new versions

### Example CI Configuration

```yaml
# .github/workflows/test.yml
name: Test
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-go@v2
        with:
          go-version: '1.21'
      - run: go test ./backend -v -cover
```

## Performance Testing

Run benchmarks to measure performance:

```bash
# Run all benchmarks
go test ./backend -bench=.

# Run specific benchmark
go test ./backend -bench=BenchmarkEncryptKyber512

# Run with memory profiling
go test ./backend -bench=. -memprofile=mem.prof
```

## Debugging Tests

### Verbose Output

```bash
go test ./backend -v
```

### Run Single Test

```bash
go test ./backend -v -run TestBackend_KeyCreate
```

### Debug with Delve

```bash
dlv test ./backend -- -test.run TestBackend_KeyCreate
```

## Known Issues and Limitations

1. **Encryption Implementation**: Current implementation uses XOR for demonstration. Production should use AEAD.
2. **Key Rotation**: Not yet implemented in tests
3. **Concurrent Operations**: Limited concurrent operation testing

## Future Test Additions

- [ ] Key rotation tests
- [ ] Concurrent operation tests
- [ ] Performance regression tests
- [ ] Security fuzzing tests
- [ ] Integration tests with actual Vault instance
- [ ] Load testing

