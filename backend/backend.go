package backend

import (
	"context"
	"sync"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// PostQuantumBackend implements the logical.Backend interface
type PostQuantumBackend struct {
	*framework.Backend
	logger hclog.Logger
	lock   sync.RWMutex
}

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend creates a new backend
func Backend(conf *logical.BackendConfig) *PostQuantumBackend {
	var b PostQuantumBackend
	b.logger = conf.Logger

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        "Post-Quantum Cryptography Secrets Engine",
		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"keys/",
			},
		},
		Paths: framework.PathAppend(
			keyPaths(&b),
			encryptPaths(&b),
			decryptPaths(&b),
			signPaths(&b),
			verifyPaths(&b),
		),
		Secrets: []*framework.Secret{},
	}

	return &b
}

// WALRollback rolls back WAL entries
func (b *PostQuantumBackend) WALRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	return nil
}

// Initialize is called when the backend is initialized
func (b *PostQuantumBackend) Initialize(ctx context.Context, req *logical.InitializationRequest) error {
	b.logger.Info("Initializing post-quantum backend")
	return nil
}

