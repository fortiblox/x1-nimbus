package poh

import (
	"crypto/sha256"
	"testing"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

func hashFromBytes(data []byte) types.Hash {
	return types.Hash(sha256.Sum256(data))
}

func TestNewVerifier(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	if v.CurrentHash() != initialHash {
		t.Errorf("expected initial hash %s, got %s", initialHash.String(), v.CurrentHash().String())
	}

	if v.TickCount() != 0 {
		t.Errorf("expected tick count 0, got %d", v.TickCount())
	}
}

func TestVerifyTickEntry(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// Create a tick entry (no transactions)
	numHashes := uint64(5)
	expectedHash := ComputeEntryHash(initialHash, numHashes, nil)

	entry := &types.Entry{
		NumHashes:    numHashes,
		Hash:         expectedHash,
		Transactions: nil,
	}

	if err := v.VerifyEntry(entry); err != nil {
		t.Errorf("expected successful verification, got error: %v", err)
	}

	if v.CurrentHash() != expectedHash {
		t.Errorf("expected current hash %s, got %s", expectedHash.String(), v.CurrentHash().String())
	}

	if v.TickCount() != 1 {
		t.Errorf("expected tick count 1, got %d", v.TickCount())
	}
}

func TestVerifyTickEntryWithWrongHash(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// Create a tick entry with wrong hash
	entry := &types.Entry{
		NumHashes:    5,
		Hash:         types.ZeroHash, // Wrong hash
		Transactions: nil,
	}

	if err := v.VerifyEntry(entry); err == nil {
		t.Error("expected hash mismatch error, got nil")
	}
}

func TestVerifyEntryWithZeroNumHashes(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	entry := &types.Entry{
		NumHashes:    0,
		Hash:         initialHash,
		Transactions: nil,
	}

	if err := v.VerifyEntry(entry); err != ErrInvalidNumHashes {
		t.Errorf("expected ErrInvalidNumHashes, got: %v", err)
	}
}

func TestVerifyNilEntry(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	if err := v.VerifyEntry(nil); err != ErrInvalidEntry {
		t.Errorf("expected ErrInvalidEntry, got: %v", err)
	}
}

func TestVerifyEntries(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// Create a chain of tick entries
	entries := make([]types.Entry, 3)
	currentHash := initialHash

	for i := range entries {
		numHashes := uint64(i + 1)
		nextHash := ComputeEntryHash(currentHash, numHashes, nil)
		entries[i] = types.Entry{
			NumHashes:    numHashes,
			Hash:         nextHash,
			Transactions: nil,
		}
		currentHash = nextHash
	}

	if err := v.VerifyEntries(entries); err != nil {
		t.Errorf("expected successful verification, got error: %v", err)
	}

	if v.CurrentHash() != currentHash {
		t.Errorf("expected current hash %s, got %s", currentHash.String(), v.CurrentHash().String())
	}

	if v.TickCount() != 3 {
		t.Errorf("expected tick count 3, got %d", v.TickCount())
	}
}

func TestReset(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// Verify some entries
	entry := &types.Entry{
		NumHashes:    5,
		Hash:         ComputeEntryHash(initialHash, 5, nil),
		Transactions: nil,
	}
	_ = v.VerifyEntry(entry)

	// Reset to a new hash
	newHash := hashFromBytes([]byte("new_start"))
	v.Reset(newHash)

	if v.CurrentHash() != newHash {
		t.Errorf("expected current hash %s after reset, got %s", newHash.String(), v.CurrentHash().String())
	}

	if v.TickCount() != 0 {
		t.Errorf("expected tick count 0 after reset, got %d", v.TickCount())
	}
}

func TestComputeEntryHash_Tick(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	// For tick entry, should iterate SHA256 numHashes times
	result := ComputeEntryHash(prevHash, 3, nil)

	// Manually compute expected
	expected := prevHash
	for i := 0; i < 3; i++ {
		expected = types.Hash(sha256.Sum256(expected[:]))
	}

	if result != expected {
		t.Errorf("tick hash mismatch: expected %s, got %s", expected.String(), result.String())
	}
}

func TestComputeEntryHash_ZeroHashes(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))
	result := ComputeEntryHash(prevHash, 0, nil)

	if result != prevHash {
		t.Errorf("zero hashes should return prevHash: expected %s, got %s", prevHash.String(), result.String())
	}
}

func TestVerifyTransactionEntry(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// Create a transaction with a signature
	var sig types.Signature
	sigHash := sha256.Sum256([]byte("test_signature"))
	copy(sig[:], sigHash[:])

	tx := types.Transaction{
		Signatures: []types.Signature{sig},
		Message: types.Message{
			Header: types.MessageHeader{
				NumRequiredSignatures: 1,
			},
		},
	}

	// Create entry with transaction
	numHashes := uint64(5)
	txs := []types.Transaction{tx}
	expectedHash := ComputeEntryHash(initialHash, numHashes, txs)

	entry := &types.Entry{
		NumHashes:    numHashes,
		Hash:         expectedHash,
		Transactions: txs,
	}

	if err := v.VerifyEntry(entry); err != nil {
		t.Errorf("expected successful verification, got error: %v", err)
	}

	// Transaction entry should not increment tick count
	if v.TickCount() != 0 {
		t.Errorf("expected tick count 0 for tx entry, got %d", v.TickCount())
	}
}

// Additional comprehensive tests for PoH

func TestVerifyEntries_MixedTickAndTransaction(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// Create a chain with both tick and transaction entries
	entries := make([]types.Entry, 5)
	currentHash := initialHash

	for i := range entries {
		numHashes := uint64(i + 1)
		var txs []types.Transaction

		// Every other entry has a transaction
		if i%2 == 1 {
			var sig types.Signature
			sigHash := sha256.Sum256([]byte("sig_" + string(rune('0'+i))))
			copy(sig[:], sigHash[:])

			txs = []types.Transaction{{
				Signatures: []types.Signature{sig},
				Message: types.Message{
					Header: types.MessageHeader{NumRequiredSignatures: 1},
				},
			}}
		}

		nextHash := ComputeEntryHash(currentHash, numHashes, txs)
		entries[i] = types.Entry{
			NumHashes:    numHashes,
			Hash:         nextHash,
			Transactions: txs,
		}
		currentHash = nextHash
	}

	if err := v.VerifyEntries(entries); err != nil {
		t.Errorf("expected successful verification, got error: %v", err)
	}

	// Should have 3 ticks (entries 0, 2, 4)
	if v.TickCount() != 3 {
		t.Errorf("expected tick count 3, got %d", v.TickCount())
	}
}

func TestVerifyEntries_FailsOnInvalidMiddleEntry(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	entries := make([]types.Entry, 5)
	currentHash := initialHash

	for i := range entries {
		numHashes := uint64(i + 1)
		nextHash := ComputeEntryHash(currentHash, numHashes, nil)

		// Corrupt entry at index 2
		if i == 2 {
			nextHash = types.ZeroHash
		}

		entries[i] = types.Entry{
			NumHashes:    numHashes,
			Hash:         nextHash,
			Transactions: nil,
		}

		if i != 2 {
			currentHash = nextHash
		}
	}

	err := v.VerifyEntries(entries)
	if err == nil {
		t.Error("expected error for invalid middle entry")
	}

	// Verifier should have stopped at entry 2
	// (entries 0 and 1 should be verified)
	if v.TickCount() != 2 {
		t.Errorf("expected tick count 2 (stopped at invalid), got %d", v.TickCount())
	}
}

func TestVerifyEntries_Empty(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	err := v.VerifyEntries(nil)
	if err != nil {
		t.Errorf("empty entries should verify without error: %v", err)
	}

	err = v.VerifyEntries([]types.Entry{})
	if err != nil {
		t.Errorf("empty slice should verify without error: %v", err)
	}

	if v.TickCount() != 0 {
		t.Errorf("tick count should remain 0 for empty entries")
	}
}

func TestComputeEntryHash_TransactionMerkleRoot(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	// Create multiple transactions
	txs := make([]types.Transaction, 4)
	for i := range txs {
		var sig types.Signature
		sigHash := sha256.Sum256([]byte("signature_" + string(rune('0'+i))))
		copy(sig[:], sigHash[:])
		txs[i] = types.Transaction{
			Signatures: []types.Signature{sig},
		}
	}

	hash1 := ComputeEntryHash(prevHash, 5, txs)
	if hash1 == types.ZeroHash {
		t.Error("transaction entry hash should not be zero")
	}

	// Different transactions should give different hash
	var differentSig types.Signature
	sigHash := sha256.Sum256([]byte("different_signature"))
	copy(differentSig[:], sigHash[:])
	txs[0] = types.Transaction{Signatures: []types.Signature{differentSig}}

	hash2 := ComputeEntryHash(prevHash, 5, txs)
	if hash1 == hash2 {
		t.Error("different transactions should produce different hash")
	}
}

func TestComputeEntryHash_Determinism(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	var sig types.Signature
	sigHash := sha256.Sum256([]byte("test_signature"))
	copy(sig[:], sigHash[:])

	txs := []types.Transaction{{Signatures: []types.Signature{sig}}}

	hash1 := ComputeEntryHash(prevHash, 10, txs)
	hash2 := ComputeEntryHash(prevHash, 10, txs)

	if hash1 != hash2 {
		t.Error("ComputeEntryHash should be deterministic")
	}
}

func TestComputeEntryHash_LargeNumHashes(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	// Test with larger numHashes value
	hash := ComputeEntryHash(prevHash, 1000, nil)
	if hash == types.ZeroHash {
		t.Error("large numHashes should not produce zero hash")
	}

	// Verify it's actually computed correctly
	expected := prevHash
	for i := 0; i < 1000; i++ {
		expected = types.Hash(sha256.Sum256(expected[:]))
	}

	if hash != expected {
		t.Error("large numHashes computation is incorrect")
	}
}

func TestVerifyEntry_ChainContinuity(t *testing.T) {
	// Test that entries must form a continuous chain
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// First entry
	entry1 := &types.Entry{
		NumHashes: 5,
		Hash:      ComputeEntryHash(initialHash, 5, nil),
	}

	err := v.VerifyEntry(entry1)
	if err != nil {
		t.Fatalf("first entry should verify: %v", err)
	}

	// Second entry must continue from first entry's hash
	entry2 := &types.Entry{
		NumHashes: 3,
		Hash:      ComputeEntryHash(entry1.Hash, 3, nil),
	}

	err = v.VerifyEntry(entry2)
	if err != nil {
		t.Errorf("second entry should verify: %v", err)
	}

	// Third entry with wrong previous hash should fail
	wrongPrevHash := hashFromBytes([]byte("wrong"))
	entry3 := &types.Entry{
		NumHashes: 2,
		Hash:      ComputeEntryHash(wrongPrevHash, 2, nil), // Wrong previous hash
	}

	err = v.VerifyEntry(entry3)
	if err == nil {
		t.Error("entry with wrong previous hash should fail")
	}
}

func TestComputeEntryHash_EmptyTransactions(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	// Empty transaction slice should behave like tick
	hashEmpty := ComputeEntryHash(prevHash, 5, []types.Transaction{})
	hashNil := ComputeEntryHash(prevHash, 5, nil)

	if hashEmpty != hashNil {
		t.Error("empty transaction slice should equal nil (tick behavior)")
	}
}

func TestComputeEntryHash_TransactionWithNoSignature(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	// Transaction with no signature should use zero hash as leaf
	tx := types.Transaction{
		Signatures: nil,
		Message:    types.Message{},
	}

	hash := ComputeEntryHash(prevHash, 5, []types.Transaction{tx})
	if hash == types.ZeroHash {
		t.Error("entry hash should not be zero even with signature-less tx")
	}
}

func TestComputeEntryHash_SingleHash(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	// With numHashes = 1, result should be SHA256(prevHash)
	result := ComputeEntryHash(prevHash, 1, nil)
	expected := types.Hash(sha256.Sum256(prevHash[:]))

	if result != expected {
		t.Errorf("single hash should equal SHA256(prevHash)")
	}
}

func TestVerifier_TickCountOnlyTicks(t *testing.T) {
	initialHash := hashFromBytes([]byte("genesis"))
	v := NewVerifier(initialHash)

	// Create entries that are all transaction entries (no ticks)
	currentHash := initialHash
	for i := 0; i < 5; i++ {
		var sig types.Signature
		sigHash := sha256.Sum256([]byte("sig_" + string(rune('0'+i))))
		copy(sig[:], sigHash[:])

		txs := []types.Transaction{{Signatures: []types.Signature{sig}}}
		nextHash := ComputeEntryHash(currentHash, 5, txs)

		entry := &types.Entry{
			NumHashes:    5,
			Hash:         nextHash,
			Transactions: txs,
		}

		_ = v.VerifyEntry(entry)
		currentHash = nextHash
	}

	// All transaction entries, no ticks
	if v.TickCount() != 0 {
		t.Errorf("expected tick count 0 for all transaction entries, got %d", v.TickCount())
	}
}

// Merkle tree tests
func TestComputeTransactionMerkleRoot_Single(t *testing.T) {
	var sig types.Signature
	sigHash := sha256.Sum256([]byte("test_signature"))
	copy(sig[:], sigHash[:])

	tx := types.Transaction{Signatures: []types.Signature{sig}}

	// For a single transaction, the merkle root should be the hash of its signature
	expected := types.Hash(sha256.Sum256(sig[:]))

	prevHash := hashFromBytes([]byte("prev"))
	hash := ComputeEntryHash(prevHash, 1, []types.Transaction{tx})

	// Manually compute what the hash should be
	h := sha256.New()
	h.Write(prevHash[:])
	h.Write(expected[:])
	var manualHash types.Hash
	copy(manualHash[:], h.Sum(nil))

	// With numHashes=1, result should be the mix hash
	if hash != manualHash {
		t.Error("single transaction merkle root is computed incorrectly")
	}
}

func TestComputeTransactionMerkleRoot_Multiple(t *testing.T) {
	prevHash := hashFromBytes([]byte("prev"))

	// Create 8 transactions
	txs := make([]types.Transaction, 8)
	for i := range txs {
		var sig types.Signature
		sigHash := sha256.Sum256([]byte("sig_" + string(rune('0'+i))))
		copy(sig[:], sigHash[:])
		txs[i] = types.Transaction{Signatures: []types.Signature{sig}}
	}

	hash1 := ComputeEntryHash(prevHash, 5, txs)
	hash2 := ComputeEntryHash(prevHash, 5, txs)

	// Should be deterministic
	if hash1 != hash2 {
		t.Error("merkle root computation should be deterministic")
	}

	// Changing one transaction should change the result
	var differentSig types.Signature
	sigHash := sha256.Sum256([]byte("different"))
	copy(differentSig[:], sigHash[:])
	txs[4] = types.Transaction{Signatures: []types.Signature{differentSig}}

	hash3 := ComputeEntryHash(prevHash, 5, txs)
	if hash1 == hash3 {
		t.Error("different transactions should produce different merkle root")
	}
}

// Benchmark tests
func BenchmarkComputeEntryHash_Tick(b *testing.B) {
	prevHash := hashFromBytes([]byte("prev"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeEntryHash(prevHash, 10, nil)
	}
}

func BenchmarkComputeEntryHash_Tick_LargeNumHashes(b *testing.B) {
	prevHash := hashFromBytes([]byte("prev"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeEntryHash(prevHash, 1000, nil)
	}
}

func BenchmarkComputeEntryHash_Transaction(b *testing.B) {
	prevHash := hashFromBytes([]byte("prev"))

	var sig types.Signature
	sigHash := sha256.Sum256([]byte("test_signature"))
	copy(sig[:], sigHash[:])
	txs := []types.Transaction{{Signatures: []types.Signature{sig}}}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeEntryHash(prevHash, 10, txs)
	}
}

func BenchmarkComputeEntryHash_ManyTransactions(b *testing.B) {
	prevHash := hashFromBytes([]byte("prev"))

	txs := make([]types.Transaction, 100)
	for i := range txs {
		var sig types.Signature
		sigHash := sha256.Sum256([]byte("sig_" + string(rune(i))))
		copy(sig[:], sigHash[:])
		txs[i] = types.Transaction{Signatures: []types.Signature{sig}}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeEntryHash(prevHash, 10, txs)
	}
}

func BenchmarkVerifyEntry(b *testing.B) {
	initialHash := hashFromBytes([]byte("genesis"))
	entry := &types.Entry{
		NumHashes: 100,
		Hash:      ComputeEntryHash(initialHash, 100, nil),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := NewVerifier(initialHash)
		_ = v.VerifyEntry(entry)
	}
}

func BenchmarkVerifyEntries_10(b *testing.B) {
	initialHash := hashFromBytes([]byte("genesis"))

	entries := make([]types.Entry, 10)
	currentHash := initialHash
	for i := range entries {
		nextHash := ComputeEntryHash(currentHash, 10, nil)
		entries[i] = types.Entry{
			NumHashes: 10,
			Hash:      nextHash,
		}
		currentHash = nextHash
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		v := NewVerifier(initialHash)
		_ = v.VerifyEntries(entries)
	}
}
