// Package log provides the append-only, signed evidence journal for scope.
package log

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Entry is a single signed journal record.
type Entry struct {
	Seq      uint64    `json:"seq"`
	TS       time.Time `json:"ts"`
	Target   string    `json:"target"`
	Resolved string    `json:"resolved"`
	Verdict  string    `json:"verdict"` // "allow" | "deny"
	Reason   string    `json:"reason"`
	Rule     string    `json:"rule"`
	Level    int       `json:"level"`
	PrevHash string    `json:"prev"`
	Sig      string    `json:"sig"`
}

// Journal is an append-only, signed JSONL log file.
type Journal struct {
	mu       sync.Mutex
	f        *os.File
	priv     ed25519.PrivateKey
	seq      uint64
	prevHash string
}

// Open opens (or creates) a journal file at path and returns a Journal.
// Open generates a fresh Ed25519 key pair for signing.
func Open(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("journal: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("journal: open: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("journal: keygen: %w", err)
	}

	j := &Journal{f: f, priv: priv}

	// Scan existing entries to find current seq and prevHash.
	if err := j.scanExisting(); err != nil {
		f.Close()
		return nil, fmt.Errorf("journal: scan: %w", err)
	}
	return j, nil
}

// OpenWithKey opens a journal with a specific signing key (for testing/verification).
func OpenWithKey(path string, priv ed25519.PrivateKey) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("journal: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("journal: open: %w", err)
	}
	j := &Journal{f: f, priv: priv}
	if err := j.scanExisting(); err != nil {
		f.Close()
		return nil, fmt.Errorf("journal: scan: %w", err)
	}
	return j, nil
}

// DefaultPath returns the default journal path for the current run.
func DefaultPath() string {
	ts := time.Now().UTC().Format(time.RFC3339)
	// RFC3339 contains colons which are invalid on Windows; replace them.
	safe := ""
	for _, c := range ts {
		if c == ':' {
			safe += "-"
		} else {
			safe += string(c)
		}
	}
	return filepath.Join(".scope", "runs", safe+".jsonl")
}

// Write appends a signed entry to the journal.
// Write returns an error if the write fails; callers must treat this as fatal.
func (j *Journal) Write(
	target, resolved, verdict, reason, rule string,
	level int,
	ts time.Time,
) error {
	j.mu.Lock()
	defer j.mu.Unlock()

	j.seq++
	e := Entry{
		Seq:      j.seq,
		TS:       ts.UTC(),
		Target:   target,
		Resolved: resolved,
		Verdict:  verdict,
		Reason:   reason,
		Rule:     rule,
		Level:    level,
		PrevHash: j.prevHash,
	}

	canonical, err := canonicalJSON(e)
	if err != nil {
		return fmt.Errorf("journal: canonical: %w", err)
	}
	sig := ed25519.Sign(j.priv, canonical)
	e.Sig = base64.StdEncoding.EncodeToString(sig)

	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("journal: marshal: %w", err)
	}
	line = append(line, '\n')

	if _, err := j.f.Write(line); err != nil {
		return fmt.Errorf("journal: write: %w", err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("journal: sync: %w", err)
	}

	// Update chain hash from the full serialized line.
	h := sha256.Sum256(line[:len(line)-1]) // exclude newline
	j.prevHash = fmt.Sprintf("%x", h)
	return nil
}

// Close closes the journal file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

// PublicKey returns the public key corresponding to the journal's signing key.
func (j *Journal) PublicKey() ed25519.PublicKey {
	return j.priv.Public().(ed25519.PublicKey)
}

// scanExisting reads existing entries to establish seq and prevHash.
func (j *Journal) scanExisting() error {
	// Seek to beginning to read.
	if _, err := j.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	data, err := io.ReadAll(j.f)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	lines := splitLines(data)
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		if e.Seq > j.seq {
			j.seq = e.Seq
		}
		h := sha256.Sum256(line)
		j.prevHash = fmt.Sprintf("%x", h)
	}
	return nil
}

// Verify verifies all entries in the journal at path.
// Verify checks sequence numbering, hash chaining, and Ed25519 signatures.
func Verify(path string, pub ed25519.PublicKey) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("verify: read: %w", err)
	}
	if len(data) == 0 {
		return nil // empty journal is valid
	}

	lines := splitLines(data)
	var prevHash string
	var prevSeq uint64

	for i, line := range lines {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			return fmt.Errorf("verify: seq %d: unmarshal: %w", i+1, err)
		}

		// Check sequence continuity.
		expectedSeq := prevSeq + 1
		if e.Seq != expectedSeq {
			return fmt.Errorf("verify: seq gap: expected %d got %d", expectedSeq, e.Seq)
		}

		// Check prev hash.
		if e.PrevHash != prevHash {
			return fmt.Errorf("verify: seq %d: prev hash mismatch", e.Seq)
		}

		// Verify signature.
		sigBytes, err := base64.StdEncoding.DecodeString(e.Sig)
		if err != nil {
			return fmt.Errorf("verify: seq %d: bad sig encoding: %w", e.Seq, err)
		}
		// Canonical entry without sig field.
		eSigned := e
		eSigned.Sig = ""
		canonical, err := canonicalJSON(eSigned)
		if err != nil {
			return fmt.Errorf("verify: seq %d: canonical: %w", e.Seq, err)
		}
		if !ed25519.Verify(pub, canonical, sigBytes) {
			return fmt.Errorf("verify: seq %d: signature invalid", e.Seq)
		}

		h := sha256.Sum256(line)
		prevHash = fmt.Sprintf("%x", h)
		prevSeq = e.Seq
	}
	return nil
}

// Tail reads the last n entries from the journal at path.
func Tail(path string, n int) ([]Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	lines := splitLines(data)
	start := 0
	if len(lines) > n {
		start = len(lines) - n
	}
	var entries []Entry
	for _, line := range lines[start:] {
		if len(line) == 0 {
			continue
		}
		var e Entry
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// canonicalJSON returns a deterministic JSON encoding with keys sorted alphabetically,
// no spaces, and the "sig" field omitted (set to empty string on input).
func canonicalJSON(e Entry) ([]byte, error) {
	// Build a map from json tags to values, then sort keys.
	type field struct {
		key string
		val interface{}
	}
	fields := []field{
		{"level", e.Level},
		{"prev", e.PrevHash},
		{"reason", e.Reason},
		{"resolved", e.Resolved},
		{"rule", e.Rule},
		{"seq", e.Seq},
		{"target", e.Target},
		{"ts", e.TS.UTC().Format(time.RFC3339Nano)},
		{"verdict", e.Verdict},
	}
	// sig is intentionally omitted.
	sort.Slice(fields, func(i, j int) bool {
		return fields[i].key < fields[j].key
	})

	m := make(map[string]interface{}, len(fields))
	for _, f := range fields {
		m[f.key] = f.val
	}
	return json.Marshal(m)
}

// splitLines splits data into non-empty lines.
func splitLines(data []byte) [][]byte {
	var lines [][]byte
	start := 0
	for i, b := range data {
		if b == '\n' {
			line := data[start:i]
			if len(line) > 0 {
				lines = append(lines, line)
			}
			start = i + 1
		}
	}
	if start < len(data) {
		line := data[start:]
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

