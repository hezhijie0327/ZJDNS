package cache

import (
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"zjdns/internal/dnsutil"
	"zjdns/internal/log"
)

type persistedCacheSnapshot struct {
	Version int                  `json:"version"`
	SavedAt int64                `json:"saved_at"`
	Entries []persistedCacheItem `json:"entries"`
}

type persistedCacheItem struct {
	Key   string      `json:"key"`
	Entry *CacheEntry `json:"entry,omitempty"`
	PTRs  []ptrRecord `json:"ptrs,omitempty"`
}

func (mc *MemoryCache) startPersistWorker() {
	if mc.persistPath == "" {
		return
	}
	mc.persistStop = make(chan struct{})
	mc.persistDone = make(chan struct{})
	go func() {
		defer dnsutil.HandlePanic("cache persist worker")
		defer close(mc.persistDone)
		ticker := time.NewTicker(mc.persistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				gen := mc.persistGen.Swap(0)
				if gen == 0 {
					continue
				}
				if err := mc.persistSnapshot(); err != nil {
					mc.persistGen.Add(gen)
					log.Errorf("CACHE: persist snapshot failed: %v", err)
				}
			case <-mc.persistStop:
				return
			}
		}
	}()
}

func (mc *MemoryCache) loadSnapshotFromDisk() (int, error) {
	file, err := os.Open(mc.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer func() { _ = file.Close() }()

	header := make([]byte, len(cacheSnapshotMagic))
	if _, err := io.ReadFull(file, header); err != nil {
		return 0, err
	}
	if string(header) != cacheSnapshotMagic {
		return 0, fmt.Errorf("invalid cache snapshot format")
	}

	var snapshot persistedCacheSnapshot
	if err := gob.NewDecoder(file).Decode(&snapshot); err != nil {
		return 0, err
	}
	if snapshot.Version != cacheSnapshotVersion {
		return 0, fmt.Errorf("unsupported snapshot version: %d", snapshot.Version)
	}
	if len(snapshot.Entries) == 0 {
		return 0, nil
	}

	now := time.Now().Unix()
	loaded := 0

	mc.mu.Lock()
	for _, item := range snapshot.Entries {
		if item.Key == "" || item.Entry == nil || item.Entry.TTL <= 0 {
			continue
		}
		if now-item.Entry.Timestamp > int64(item.Entry.TTL+StaleMaxAge) {
			continue
		}
		if _, exists := mc.entries[item.Key]; exists {
			continue
		}
		entryCopy := cloneEntry(item.Entry)
		ci := &cacheItem{entry: entryCopy}
		ci.lastAccess.Store(time.Now().UnixNano())
		mc.entries[item.Key] = ci
		mc.storePTRLocked(item.Key, item.PTRs)
		ci.size = estimateEntrySize(item.Key, entryCopy, item.PTRs)
		mc.currentSize += ci.size
		loaded++
	}
	mc.evictToBudget()
	mc.mu.Unlock()
	mc.persistGen.Store(0)
	return loaded, nil
}

func (mc *MemoryCache) persistSnapshot() error {
	if mc.persistPath == "" {
		return nil
	}
	now := time.Now().Unix()
	snapshot := persistedCacheSnapshot{
		Version: cacheSnapshotVersion,
		SavedAt: now,
	}

	mc.mu.RLock()
	if mc.entries != nil {
		snapshot.Entries = make([]persistedCacheItem, 0, len(mc.entries))
		for key, item := range mc.entries {
			if item == nil || item.entry == nil || item.entry.TTL <= 0 {
				continue
			}
			if now-item.entry.Timestamp > int64(item.entry.TTL+StaleMaxAge) {
				continue
			}
			snapshot.Entries = append(snapshot.Entries, persistedCacheItem{
				Key:   key,
				Entry: cloneEntry(item.entry),
				PTRs:  clonePTRs(mc.entryPTRs[key]),
			})
		}
	}
	mc.mu.RUnlock()

	dir := filepath.Dir(mc.persistPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := mc.persistPath + ".tmp"
	file, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(cacheSnapshotMagic); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := gob.NewEncoder(file).Encode(&snapshot); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, mc.persistPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
