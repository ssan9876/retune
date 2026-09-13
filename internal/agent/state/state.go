// Package state is the agent's durable local store: results waiting to be
// sent, which commands have already run, and the last inventory hash.
package state

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	bolt "go.etcd.io/bbolt"

	"retune/internal/agent/policy"
	"retune/internal/protocol"
)

// Ledger states.
const (
	LedgerStarted   = "started"
	LedgerCompleted = "completed"
)

var (
	bucketResults  = []byte("results")
	bucketLedger   = []byte("ledger")
	bucketMeta     = []byte("meta")
	bucketItems    = []byte("items")
	bucketScripts  = []byte("scripts")
	bucketPrior    = []byte("policy_prior")
	bucketProfiles = []byte("policy_profiles")
	bucketApps     = []byte("apps")
	keyInventory   = []byte("inventory_hash")
)

// Store is the agent's bbolt database.
type Store struct {
	db   *bolt.DB
	path string
}

// QueuedResult is a command result waiting to reach the server.
type QueuedResult struct {
	CommandID string                 `json:"command_id"`
	Result    protocol.CommandResult `json:"result"`
}

type ledgerEntry struct {
	State string    `json:"state"`
	At    time.Time `json:"at"`
}

// Open creates or opens the state database.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open agent state %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketResults, bucketLedger, bucketMeta, bucketItems, bucketScripts,
			bucketPrior, bucketProfiles, bucketApps} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, path: path}, nil
}

// Close releases the database file.
func (s *Store) Close() error { return s.db.Close() }

// Destroy closes the database and deletes it, for unenrollment.
func (s *Store) Destroy() error {
	if err := s.db.Close(); err != nil {
		return err
	}
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// QueueResult stores a result to send at the next opportunity.
func (s *Store) QueueResult(r QueuedResult) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b, err := json.Marshal(r)
		if err != nil {
			return err
		}
		return tx.Bucket(bucketResults).Put([]byte(r.CommandID), b)
	})
}

// PendingResults returns queued results ordered by command ID (UUIDv7 IDs sort
// oldest first).
func (s *Store) PendingResults() ([]QueuedResult, error) {
	var out []QueuedResult
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketResults).ForEach(func(_, v []byte) error {
			var r QueuedResult
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	return out, err
}

// DeleteResult drops a result the server has accepted.
func (s *Store) DeleteResult(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketResults).Delete([]byte(id))
	})
}

// MarkStarted records that a command is about to run. It reports false when the
// command was already seen, which is how repeat deliveries are ignored.
func (s *Store) MarkStarted(id string, at time.Time) (bool, error) {
	first := false
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketLedger)
		if b.Get([]byte(id)) != nil {
			return nil
		}
		first = true
		return putJSON(b, id, ledgerEntry{State: LedgerStarted, At: at})
	})
	return first, err
}

// MarkCompleted records that a command finished and its result is stored.
func (s *Store) MarkCompleted(id string, at time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketLedger), id, ledgerEntry{State: LedgerCompleted, At: at})
	})
}

// LedgerState returns LedgerStarted, LedgerCompleted, or "" if unknown.
func (s *Store) LedgerState(id string) (string, error) {
	var e ledgerEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketLedger).Get([]byte(id))
		if v == nil {
			return nil
		}
		return json.Unmarshal(v, &e)
	})
	return e.State, err
}

// PruneLedger removes entries older than before and returns how many went.
func (s *Store) PruneLedger(before time.Time) (int, error) {
	removed := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketLedger).Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var e ledgerEntry
			if err := json.Unmarshal(v, &e); err != nil || e.At.Before(before) {
				if err := c.Delete(); err != nil {
					return err
				}
				removed++
			}
		}
		return nil
	})
	return removed, err
}

// InventoryHash is the hash the server acknowledged for the last upload.
func (s *Store) InventoryHash() (string, error) {
	var hash string
	err := s.db.View(func(tx *bolt.Tx) error {
		hash = string(tx.Bucket(bucketMeta).Get(keyInventory))
		return nil
	})
	return hash, err
}

// SetInventoryHash records the hash the server acknowledged.
func (s *Store) SetInventoryHash(hash string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(keyInventory, []byte(hash))
	})
}

func putJSON(b *bolt.Bucket, key string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), raw)
}

// ItemState is what the agent remembers about one assigned item, and is how it
// decides whether that item needs to run again.
type ItemState struct {
	Version    int       `json:"version"`
	LastRunAt  time.Time `json:"last_run_at"`
	LastStatus string    `json:"last_status"`
	// Failures counts consecutive failures of this version.
	Failures int `json:"failures"`
}

// ItemState returns what is remembered about an item. An item never seen
// before reports the zero value rather than an error, because "never run" is
// the normal starting point.
func (s *Store) ItemState(id string) (ItemState, error) {
	var out ItemState
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketItems).Get([]byte(id))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &out)
	})
	return out, err
}

// SetItemState records what happened to an item.
func (s *Store) SetItemState(id string, st ItemState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketItems), id, st)
	})
}

// AppState is what the agent remembers about one assigned app, and is how it
// decides whether that app needs installing, removing, or just rechecking.
type AppState struct {
	Version     int       `json:"version"`
	Intent      string    `json:"intent"`
	LastActedAt time.Time `json:"last_acted_at"`
	LastStatus  string    `json:"last_status"`
	// LastSeenAt is when Installed was last confirmed by detection, not just
	// assumed from an earlier install or uninstall.
	LastSeenAt time.Time `json:"last_seen_at"`
	Installed  bool      `json:"installed"`
	// Failures counts consecutive failures of this version under this intent.
	Failures int `json:"failures"`
}

// AppState returns what is remembered about an app. An app never seen before
// reports the zero value rather than an error, because "never acted on" is
// the normal starting point.
func (s *Store) AppState(id string) (AppState, error) {
	var out AppState
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketApps).Get([]byte(id))
		if raw == nil {
			return nil
		}
		return json.Unmarshal(raw, &out)
	})
	return out, err
}

// SetAppState records what happened to an app.
func (s *Store) SetAppState(id string, st AppState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketApps), id, st)
	})
}

// scriptKey identifies one cached script version.
func scriptKey(id string, version int) string {
	return id + "@" + strconv.Itoa(version)
}

// CachedScript returns a stored script version, reporting whether it was held.
// Bodies are cached per version, so a check-in only fetches one the agent has
// not seen.
func (s *Store) CachedScript(id string, version int) (protocol.ScriptVersionResponse, bool, error) {
	var out protocol.ScriptVersionResponse
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketScripts).Get([]byte(scriptKey(id, version)))
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return protocol.ScriptVersionResponse{}, false, err
	}
	return out, found, nil
}

// CacheScript stores a fetched script version and drops older cached versions
// of the same script, which will never be asked for again.
func (s *Store) CacheScript(id string, v protocol.ScriptVersionResponse) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketScripts)
		prefix := []byte(id + "@")
		keep := scriptKey(id, v.Version)
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if string(k) != keep {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return putJSON(b, keep, v)
	})
}

// PriorState returns what was recorded before Retune first changed a setting.
func (s *Store) PriorState(identity string) ([]byte, bool, error) {
	var out []byte
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketPrior).Get([]byte(identity))
		if raw == nil {
			return nil
		}
		found = true
		out = append([]byte(nil), raw...)
		return nil
	})
	return out, found, err
}

// SetPriorState records what was there before a setting was first applied.
func (s *Store) SetPriorState(identity string, raw []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPrior).Put([]byte(identity), raw)
	})
}

// DeletePriorState forgets a recorded previous state, after a revert.
func (s *Store) DeletePriorState(identity string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPrior).Delete([]byte(identity))
	})
}

// ProfileRecords returns what is remembered about every applied profile.
func (s *Store) ProfileRecords() (map[string]policy.Record, error) {
	out := map[string]policy.Record{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketProfiles).ForEach(func(k, v []byte) error {
			var rec policy.Record
			if err := json.Unmarshal(v, &rec); err != nil {
				// A record that cannot be read is no use; skip it rather than
				// failing every reconcile from now on.
				return nil
			}
			out[string(k)] = rec
			return nil
		})
	})
	return out, err
}

// SetProfileRecord remembers what a profile is responsible for.
func (s *Store) SetProfileRecord(profileID string, rec policy.Record) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return putJSON(tx.Bucket(bucketProfiles), profileID, rec)
	})
}

// DeleteProfileRecord forgets a profile that no longer applies.
func (s *Store) DeleteProfileRecord(profileID string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketProfiles).Delete([]byte(profileID))
	})
}

// CachedProfile returns a stored profile version, reporting whether it was held.
func (s *Store) CachedProfile(id string, version int) (protocol.ProfileVersionResponse, bool, error) {
	var out protocol.ProfileVersionResponse
	found := false
	err := s.db.View(func(tx *bolt.Tx) error {
		raw := tx.Bucket(bucketScripts).Get([]byte("profile:" + scriptKey(id, version)))
		if raw == nil {
			return nil
		}
		found = true
		return json.Unmarshal(raw, &out)
	})
	if err != nil {
		return protocol.ProfileVersionResponse{}, false, err
	}
	return out, found, nil
}

// CacheProfile stores a fetched profile version and drops older ones.
func (s *Store) CacheProfile(id string, v protocol.ProfileVersionResponse) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketScripts)
		prefix := []byte("profile:" + id + "@")
		keep := "profile:" + scriptKey(id, v.Version)
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			if string(k) != keep {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return putJSON(b, keep, v)
	})
}
