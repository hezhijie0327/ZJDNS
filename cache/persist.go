package cache

import (
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"zjdns/config"
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

func (m *MemoryCache) startPersistWorker() {
	if m.persistPath == "" {
		return
	}
	m.persistStop = make(chan struct{})
	m.persistDone = make(chan struct{})
	go func() {
		defer dnsutil.HandlePanic("cache persist worker")
		defer close(m.persistDone)
		ticker := time.NewTicker(m.persistInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				// Peek without resetting: Load()+Add(-gen) preserves
				// concurrent Set() increments during persistSnapshot().
				gen := m.persistGen.Load()
				if gen == 0 {
					continue
				}
				if err := m.persistSnapshot(); err != nil {
					// Leave the counter as-is so the next tick retries.
					log.Errorf("CACHE: persist snapshot failed: %v", err)
				} else {
					// Subtract only what we just persisted; increments during
					// persistSnapshot() remain for the next tick.
					m.persistGen.Add(-gen)
				}
			case <-m.persistStop:
				return
			}
		}
	}()
}

func (m *MemoryCache) loadSnapshotFromDisk() (int, error) {
	file, err := os.Open(m.persistPath)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	defer func() { dnsutil.CloseWithLog(file, "persist snapshot", "CACHE") }()

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

	m.mu.Lock()
	for _, item := range snapshot.Entries {
		if item.Key == "" || item.Entry == nil || item.Entry.TTL <= 0 {
			continue
		}
		if now-item.Entry.Timestamp > int64(item.Entry.TTL+config.DefaultStaleMaxAge) {
			continue
		}
		if _, exists := m.entries[item.Key]; exists {
			continue
		}
		entryCopy := cloneEntry(item.Entry)
		ci := &cacheItem{entry: entryCopy}
		ci.lastAccess.Store(time.Now().UnixNano())
		m.entries[item.Key] = ci
		m.storePTRLocked(item.Key, item.PTRs)
		ci.size = estimateEntrySize(item.Key, entryCopy, item.PTRs)
		m.currentSize += ci.size
		loaded++
	}
	beforeEvict := m.currentSize
	m.evictToBudget()
	evicted := beforeEvict - m.currentSize
	m.mu.Unlock()
	if evicted > 0 {
		// Budget was reduced — set gen=1 so the next persist tick writes
		// a trimmed snapshot instead of waiting for new entries to arrive.
		log.Infof("CACHE: evicted %d MB to match new budget (%d MB), next persist will trim snapshot",
			evicted/(1024*1024), m.limitBytes/(1024*1024))
		m.persistGen.Store(1)
	} else {
		m.persistGen.Store(0)
	}
	return loaded, nil
}

func (m *MemoryCache) persistSnapshot() error {
	if m.persistPath == "" {
		return nil
	}
	now := time.Now().Unix()
	snapshot := persistedCacheSnapshot{
		Version: cacheSnapshotVersion,
		SavedAt: now,
	}

	m.mu.RLock()
	if m.entries != nil {
		snapshot.Entries = make([]persistedCacheItem, 0, len(m.entries))
		for key, item := range m.entries {
			if item == nil || item.entry == nil || item.entry.TTL <= 0 {
				continue
			}
			if now-item.entry.Timestamp > int64(item.entry.TTL+config.DefaultStaleMaxAge) {
				continue
			}
			snapshot.Entries = append(snapshot.Entries, persistedCacheItem{
				Key:   key,
				Entry: cloneEntryForPersist(item.entry),
				PTRs:  clonePTRs(m.entryPTRs[key]),
			})
		}
	}
	m.mu.RUnlock()

	dir := filepath.Dir(m.persistPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp := m.persistPath + ".tmp"
	file, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(cacheSnapshotMagic); err != nil {
		dnsutil.CloseWithLog(file, "persist snapshot", "CACHE")
		_ = os.Remove(tmp)
		return err
	}
	if err := gob.NewEncoder(file).Encode(&snapshot); err != nil {
		dnsutil.CloseWithLog(file, "persist snapshot", "CACHE")
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Sync(); err != nil {
		dnsutil.CloseWithLog(file, "persist snapshot", "CACHE")
		_ = os.Remove(tmp)
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, m.persistPath); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
