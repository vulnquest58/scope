package log_test

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	scopelog "github.com/vulnquest58/scope/internal/log"
)

func tmpJournalPath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "test.jsonl")
}

func writeEntry(t *testing.T, j *scopelog.Journal, target, verdict, reason string, seq int) {
	t.Helper()
	err := j.Write(target, "1.2.3.4", verdict, reason, "rule", 1, time.Now())
	if err != nil {
		t.Fatalf("Write seq %d: %v", seq, err)
	}
}

// ---------------------------------------------------------------------------
// Journal tests (§11.4)
// ---------------------------------------------------------------------------

// 1. Sequential Seq numbering.
func TestJournal_SequentialSeq(t *testing.T) {
	path := tmpJournalPath(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	j, err := scopelog.OpenWithKey(path, priv)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()

	for i := 0; i < 5; i++ {
		writeEntry(t, j, "example.com", "allow", "allow", i+1)
	}

	entries, err := scopelog.Tail(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatalf("want 5 entries, got %d", len(entries))
	}
	for i, e := range entries {
		if e.Seq != uint64(i+1) {
			t.Errorf("entry %d: Seq=%d, want %d", i, e.Seq, i+1)
		}
	}
}

// 2. Modifying an entry causes verify to fail.
func TestJournal_ModifiedEntryFails(t *testing.T) {
	path := tmpJournalPath(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)

	j, _ := scopelog.OpenWithKey(path, priv)
	writeEntry(t, j, "example.com", "allow", "allow", 1)
	writeEntry(t, j, "other.com", "deny", "outside-wildcard", 2)
	j.Close()

	// Read and tamper.
	data, _ := os.ReadFile(path)
	// Replace "allow" with "XXXXX" in the first line.
	tampered := make([]byte, len(data))
	copy(tampered, data)
	for i := range tampered {
		if i+5 <= len(tampered) && string(tampered[i:i+7]) == `"allow"` {
			copy(tampered[i:], `"XXXXX"`)
			break
		}
	}
	os.WriteFile(path, tampered, 0o600)

	if err := scopelog.Verify(path, pub); err == nil {
		t.Error("verify should fail after tampering")
	}
}

// 3. Empty journal verifies successfully.
func TestJournal_EmptyVerifies(t *testing.T) {
	path := tmpJournalPath(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)

	j, _ := scopelog.OpenWithKey(path, priv)
	j.Close()

	if err := scopelog.Verify(path, pub); err != nil {
		t.Errorf("empty journal should verify: %v", err)
	}
}

// 4. Signature with wrong key fails.
func TestJournal_WrongKeyFails(t *testing.T) {
	path := tmpJournalPath(t)
	_, priv, _ := ed25519.GenerateKey(nil)

	j, _ := scopelog.OpenWithKey(path, priv)
	writeEntry(t, j, "example.com", "allow", "allow", 1)
	j.Close()

	// Verify with a different public key.
	_, wrongPriv, _ := ed25519.GenerateKey(nil)
	wrongPub := wrongPriv.Public().(ed25519.PublicKey)

	if err := scopelog.Verify(path, wrongPub); err == nil {
		t.Error("verify should fail with wrong public key")
	}
}

// 5. PrevHash chaining: first entry has empty prev.
func TestJournal_PrevHashChaining(t *testing.T) {
	path := tmpJournalPath(t)
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)

	j, _ := scopelog.OpenWithKey(path, priv)
	writeEntry(t, j, "a.example.com", "allow", "allow", 1)
	writeEntry(t, j, "b.example.com", "deny", "outside-wildcard", 2)
	writeEntry(t, j, "c.example.com", "allow", "allow", 3)
	j.Close()

	// Verify the chain.
	if err := scopelog.Verify(path, pub); err != nil {
		t.Errorf("valid chain failed verify: %v", err)
	}

	// Check first entry has empty prev.
	entries, _ := scopelog.Tail(path, 10)
	if entries[0].PrevHash != "" {
		t.Errorf("first entry PrevHash should be empty, got %q", entries[0].PrevHash)
	}
	if entries[1].PrevHash == "" {
		t.Error("second entry PrevHash should not be empty")
	}
}

// 6. Tail returns last N entries.
func TestJournal_Tail(t *testing.T) {
	path := tmpJournalPath(t)
	_, priv, _ := ed25519.GenerateKey(nil)

	j, _ := scopelog.OpenWithKey(path, priv)
	for i := 0; i < 10; i++ {
		writeEntry(t, j, "example.com", "allow", "allow", i+1)
	}
	j.Close()

	entries, err := scopelog.Tail(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("want 3 tail entries, got %d", len(entries))
	}
	if entries[0].Seq != 8 || entries[2].Seq != 10 {
		t.Errorf("tail: want seq 8-10, got %d-%d", entries[0].Seq, entries[2].Seq)
	}
}

