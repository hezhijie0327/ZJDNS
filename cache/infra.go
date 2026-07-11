package cache

import (
	"zjdns/internal/log"
)

// InfraCacheRow holds a row from the infra_cache table.
type InfraCacheRow struct {
	RTTMs        int
	EDNSVersion  int
	TimeoutCount int
	LastTimeout  int64
	LastSuccess  int64
}

// InfraGet fetches a row from the infra_cache table by server address.
func (s *SQLiteCache) InfraGet(addr string) *InfraCacheRow {
	if s.db.IsClosed() {
		return nil
	}
	row := s.db.StmtInfraGet.QueryRow(addr)
	var r InfraCacheRow
	if err := row.Scan(&r.RTTMs, &r.EDNSVersion, &r.TimeoutCount, &r.LastTimeout, &r.LastSuccess); err != nil {
		return nil
	}
	return &r
}

// InfraUpsert inserts or replaces a row in the infra_cache table.
func (s *SQLiteCache) InfraUpsert(addr string, rttMs, ednsVersion, timeoutCount int, lastTimeout, lastSuccess int64) error {
	if s.db.IsClosed() {
		return nil
	}
	_, err := s.db.StmtInfraUpsert.Exec(addr, rttMs, ednsVersion, timeoutCount, lastTimeout, lastSuccess)
	if err != nil {
		log.Debugf("INFRA: upsert %s failed: %v", addr, err)
	}
	return err
}
