package backend

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	telemetryHeartbeatInterval = 60 * time.Second
	autoHealInterval           = 2 * time.Minute
)

// telemetryState holds simple in-memory counters for emitted metrics
type telemetryState struct {
	sync.Mutex
	counters map[string]int64
}

func newTelemetryState() *telemetryState {
	return &telemetryState{
		counters: make(map[string]int64),
	}
}

func (t *telemetryState) inc(name string, labels map[string]string, delta int64) {
	if t == nil {
		return
	}
	t.Lock()
	defer t.Unlock()
	key := name
	if len(labels) > 0 {
		var sb strings.Builder
		sb.WriteString(name)
		sb.WriteString("{")
		first := true
		for k, v := range labels {
			if !first {
				sb.WriteString(",")
			}
			first = false
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
		}
		sb.WriteString("}")
		key = sb.String()
	}
	t.counters[key] += delta
}

func (t *telemetryState) snapshotAndReset() map[string]int64 {
	if t == nil {
		return nil
	}
	t.Lock()
	defer t.Unlock()
	if len(t.counters) == 0 {
		return nil
	}
	copy := make(map[string]int64, len(t.counters))
	for k, v := range t.counters {
		copy[k] = v
	}
	t.counters = make(map[string]int64)
	return copy
}

func (b *PostQuantumBackend) startControllers() {
	controllerMu := b.controllerLock()
	controllerMu.Lock()
	defer controllerMu.Unlock()

	if b.controllerCancel != nil || b.storage == nil {
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	b.controllerCtx = ctx
	b.controllerCancel = cancel

	// Telemetry heartbeat
	b.controllerWg.Add(1)
	go func() {
		defer b.controllerWg.Done()
		b.telemetryHeartbeatLoop(ctx)
	}()

	// Metadata auto-heal loop
	b.controllerWg.Add(1)
	go func() {
		defer b.controllerWg.Done()
		b.metadataAutoHealLoop(ctx)
	}()
}

func (b *PostQuantumBackend) stopControllers() {
	controllerMu := b.controllerLock()
	controllerMu.Lock()
	cancel := b.controllerCancel
	b.controllerCancel = nil
	ctx := b.controllerCtx
	b.controllerCtx = nil
	controllerMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if ctx != nil {
		b.controllerWg.Wait()
	}
}

func (b *PostQuantumBackend) telemetryHeartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(telemetryHeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snapshot := b.telemetry.snapshotAndReset()
			if len(snapshot) == 0 {
				continue
			}
			for metric, value := range snapshot {
				b.logger.Info("telemetry_snapshot", "metric", metric, "value", value)
			}
		}
	}
}

func (b *PostQuantumBackend) metadataAutoHealLoop(ctx context.Context) {
	ticker := time.NewTicker(autoHealInterval)
	defer ticker.Stop()

	for {
		if err := b.runMetadataAudit(ctx); err != nil {
			b.logger.Error("metadata_autoheal_error", "error", err)
			b.telemetry.inc("autoheal_failures_total", map[string]string{"action": "metadata_audit"}, 1)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (b *PostQuantumBackend) runMetadataAudit(ctx context.Context) error {
	if b.storage == nil {
		return fmt.Errorf("storage not initialized")
	}

	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	keys, err := b.storage.List(childCtx, "keys/")
	if err != nil {
		return fmt.Errorf("list keys: %w", err)
	}

	for _, key := range keys {
		if key == "" || strings.HasPrefix(key, "metadata") || strings.HasPrefix(key, "versions") || key == "kek" {
			continue
		}
		if err := b.ensureKeyMetadata(childCtx, key); err != nil {
			b.logger.Warn("metadata_autoheal_failed", "key", key, "error", err)
			b.telemetry.inc("autoheal_failures_total", map[string]string{"action": "ensure_metadata"}, 1)
			continue
		}
	}
	return nil
}

func (b *PostQuantumBackend) ensureKeyMetadata(ctx context.Context, key string) error {
	metadata, err := b.getKeyMetadata(ctx, b.storage, key)
	if err != nil {
		return fmt.Errorf("get metadata: %w", err)
	}

	if metadata == nil {
		if err := b.rebuildKeyMetadata(ctx, key); err != nil {
			return err
		}
		b.logger.Info("metadata_autoheal_rebuilt", "key", key)
		b.telemetry.inc("autoheal_actions_total", map[string]string{"action": "rebuild_metadata"}, 1)
		return nil
	}

	updated, err := b.validateKeyVersions(ctx, key, metadata)
	if err != nil {
		return err
	}
	if updated {
		if err := b.saveKeyMetadata(ctx, b.storage, metadata); err != nil {
			return fmt.Errorf("save metadata: %w", err)
		}
		b.logger.Info("metadata_autoheal_updated", "key", key)
		b.telemetry.inc("autoheal_actions_total", map[string]string{"action": "update_metadata"}, 1)
	}
	return nil
}

func (b *PostQuantumBackend) rebuildKeyMetadata(ctx context.Context, key string) error {
	versionPath := fmt.Sprintf("keys/%s/versions/", key)
	versionEntries, err := b.storage.List(ctx, versionPath)
	if err != nil {
		return fmt.Errorf("list versions: %w", err)
	}

	var versions []int
	for _, v := range versionEntries {
		if v == "" {
			continue
		}
		num, err := strconv.Atoi(strings.TrimSuffix(v, "/"))
		if err != nil {
			continue
		}
		versions = append(versions, num)
	}

	// Backward compatibility: look for old single entry
	if len(versions) == 0 {
		oldPath := fmt.Sprintf("keys/%s", key)
		entry, err := b.storage.Get(ctx, oldPath)
		if err != nil {
			return fmt.Errorf("get legacy key: %w", err)
		}
		if entry == nil {
			return fmt.Errorf("no key data found for %s", key)
		}
		var keyData KeyData
		if err := entry.DecodeJSON(&keyData); err != nil {
			return fmt.Errorf("decode legacy key: %w", err)
		}
		keyData.Version = 1
		if err := b.saveKeyVersion(ctx, b.storage, &keyData); err != nil {
			return fmt.Errorf("save migrated version: %w", err)
		}
		if err := b.storage.Delete(ctx, oldPath); err != nil {
			return fmt.Errorf("delete legacy key: %w", err)
		}
		versions = append(versions, 1)
	}

	latestVersion := 0
	for _, v := range versions {
		if v > latestVersion {
			latestVersion = v
		}
	}

	latestKey, err := b.getKeyVersion(ctx, b.storage, key, latestVersion)
	if err != nil {
		return fmt.Errorf("get latest key: %w", err)
	}

	metadata := &KeyMetadata{
		Name:              key,
		Algorithm:         latestKey.Algorithm,
		KeyType:           latestKey.KeyType,
		LatestVersion:     latestVersion,
		MinVersion:        1,
		MinDecryptVersion: 1,
		Versions:          versions,
	}
	return b.saveKeyMetadata(ctx, b.storage, metadata)
}

func (b *PostQuantumBackend) validateKeyVersions(ctx context.Context, key string, metadata *KeyMetadata) (bool, error) {
	versionPath := fmt.Sprintf("keys/%s/versions/", key)
	versionEntries, err := b.storage.List(ctx, versionPath)
	if err != nil {
		return false, fmt.Errorf("list versions: %w", err)
	}

	var versions []int
	for _, v := range versionEntries {
		if v == "" {
			continue
		}
		num, err := strconv.Atoi(strings.TrimSuffix(v, "/"))
		if err != nil {
			continue
		}
		versions = append(versions, num)
	}

	if len(versions) == 0 {
		return false, nil
	}

	changed := false
	latestVersion := metadata.LatestVersion
	for _, v := range versions {
		if v > latestVersion {
			latestVersion = v
		}
	}
	if latestVersion != metadata.LatestVersion {
		metadata.LatestVersion = latestVersion
		changed = true
	}

	if metadata.MinVersion < 1 {
		metadata.MinVersion = 1
		changed = true
	}
	if metadata.MinDecryptVersion < metadata.MinVersion {
		metadata.MinDecryptVersion = metadata.MinVersion
		changed = true
	}
	if metadata.MinDecryptVersion > metadata.LatestVersion {
		metadata.MinDecryptVersion = metadata.LatestVersion
		changed = true
	}

	if !equalIntSlices(metadata.Versions, versions) {
		metadata.Versions = versions
		changed = true
	}

	return changed, nil
}

func equalIntSlices(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	lookup := make(map[int]int, len(a))
	for _, v := range a {
		lookup[v]++
	}
	for _, v := range b {
		if lookup[v] == 0 {
			return false
		}
		lookup[v]--
	}
	for _, v := range lookup {
		if v != 0 {
			return false
		}
	}
	return true
}
