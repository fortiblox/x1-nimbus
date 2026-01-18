package accounts

import (
	"bytes"
	"crypto/sha256"
	"sync"
	"testing"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Helper function to create test pubkeys
func testPubkey(seed string) types.Pubkey {
	hash := sha256.Sum256([]byte(seed))
	var pk types.Pubkey
	copy(pk[:], hash[:])
	return pk
}

// Helper function to create test accounts
func testAccount(lamports types.Lamports, data []byte, owner types.Pubkey) *types.Account {
	return &types.Account{
		Lamports:   lamports,
		Data:       data,
		Owner:      owner,
		Executable: false,
		RentEpoch:  0,
	}
}

// Tests for MemoryDB
func TestMemoryDB_NewMemoryDB(t *testing.T) {
	db := NewMemoryDB()
	if db == nil {
		t.Fatal("NewMemoryDB returned nil")
	}

	if db.GetAccountsCount() != 0 {
		t.Errorf("new DB should have 0 accounts, got %d", db.GetAccountsCount())
	}
}

func TestMemoryDB_SetAndGetAccount(t *testing.T) {
	db := NewMemoryDB()
	pubkey := testPubkey("test_account")
	account := testAccount(1_000_000_000, []byte("test_data"), types.SystemProgramID)

	// Set account
	err := db.SetAccount(pubkey, account)
	if err != nil {
		t.Fatalf("SetAccount failed: %v", err)
	}

	// Get account
	retrieved, err := db.GetAccount(pubkey)
	if err != nil {
		t.Fatalf("GetAccount failed: %v", err)
	}

	if retrieved == nil {
		t.Fatal("GetAccount returned nil for existing account")
	}

	if retrieved.Lamports != account.Lamports {
		t.Errorf("expected lamports %d, got %d", account.Lamports, retrieved.Lamports)
	}

	if !bytes.Equal(retrieved.Data, account.Data) {
		t.Errorf("expected data %v, got %v", account.Data, retrieved.Data)
	}

	if retrieved.Owner != account.Owner {
		t.Errorf("expected owner %s, got %s", account.Owner.String(), retrieved.Owner.String())
	}
}

func TestMemoryDB_GetAccount_NotFound(t *testing.T) {
	db := NewMemoryDB()
	pubkey := testPubkey("nonexistent")

	account, err := db.GetAccount(pubkey)
	if err != nil {
		t.Fatalf("GetAccount should not error for nonexistent account: %v", err)
	}

	if account != nil {
		t.Error("GetAccount should return nil for nonexistent account")
	}
}

func TestMemoryDB_HasAccount(t *testing.T) {
	db := NewMemoryDB()
	pubkey := testPubkey("test_account")
	account := testAccount(1000, nil, types.SystemProgramID)

	// Before adding
	if db.HasAccount(pubkey) {
		t.Error("HasAccount should return false for nonexistent account")
	}

	// After adding
	_ = db.SetAccount(pubkey, account)
	if !db.HasAccount(pubkey) {
		t.Error("HasAccount should return true for existing account")
	}
}

func TestMemoryDB_DeleteAccount(t *testing.T) {
	db := NewMemoryDB()
	pubkey := testPubkey("test_account")
	account := testAccount(1000, nil, types.SystemProgramID)

	_ = db.SetAccount(pubkey, account)

	// Delete
	err := db.DeleteAccount(pubkey)
	if err != nil {
		t.Fatalf("DeleteAccount failed: %v", err)
	}

	// Verify deleted
	if db.HasAccount(pubkey) {
		t.Error("account should be deleted")
	}

	retrieved, _ := db.GetAccount(pubkey)
	if retrieved != nil {
		t.Error("GetAccount should return nil for deleted account")
	}
}

func TestMemoryDB_DeleteAccount_NotExist(t *testing.T) {
	db := NewMemoryDB()
	pubkey := testPubkey("nonexistent")

	// Should not error when deleting nonexistent account
	err := db.DeleteAccount(pubkey)
	if err != nil {
		t.Errorf("DeleteAccount should not error for nonexistent account: %v", err)
	}
}

func TestMemoryDB_GetAccountsCount(t *testing.T) {
	db := NewMemoryDB()

	for i := 0; i < 10; i++ {
		pubkey := testPubkey("account_" + string(rune('a'+i)))
		account := testAccount(types.Lamports(i*1000), nil, types.SystemProgramID)
		_ = db.SetAccount(pubkey, account)
	}

	if db.GetAccountsCount() != 10 {
		t.Errorf("expected 10 accounts, got %d", db.GetAccountsCount())
	}

	// Delete one
	pubkey := testPubkey("account_a")
	_ = db.DeleteAccount(pubkey)

	if db.GetAccountsCount() != 9 {
		t.Errorf("expected 9 accounts after delete, got %d", db.GetAccountsCount())
	}
}

func TestMemoryDB_Close(t *testing.T) {
	db := NewMemoryDB()

	pubkey := testPubkey("test_account")
	account := testAccount(1000, nil, types.SystemProgramID)
	_ = db.SetAccount(pubkey, account)

	err := db.Close()
	if err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	// After close, DB should be empty
	if db.GetAccountsCount() != 0 {
		t.Error("DB should be empty after close")
	}
}

func TestMemoryDB_DataIsolation(t *testing.T) {
	db := NewMemoryDB()
	pubkey := testPubkey("test_account")
	originalData := []byte("original_data")
	account := testAccount(1000, originalData, types.SystemProgramID)

	_ = db.SetAccount(pubkey, account)

	// Modify the original data
	originalData[0] = 'X'

	// Retrieved data should not be affected
	retrieved, _ := db.GetAccount(pubkey)
	if retrieved.Data[0] == 'X' {
		t.Error("modifying original data should not affect stored data")
	}

	// Modify retrieved data
	retrieved.Data[0] = 'Y'

	// Get again - should still have original data
	retrieved2, _ := db.GetAccount(pubkey)
	if retrieved2.Data[0] == 'Y' {
		t.Error("modifying retrieved data should not affect stored data")
	}
}

func TestMemoryDB_Concurrent(t *testing.T) {
	db := NewMemoryDB()
	var wg sync.WaitGroup

	// Concurrent writes
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pubkey := testPubkey("account_" + string(rune(i)))
			account := testAccount(types.Lamports(i*1000), nil, types.SystemProgramID)
			_ = db.SetAccount(pubkey, account)
		}(i)
	}

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pubkey := testPubkey("account_" + string(rune(i)))
			_, _ = db.GetAccount(pubkey)
		}(i)
	}

	wg.Wait()

	// Verify count (should be 100 unique accounts)
	count := db.GetAccountsCount()
	if count != 100 {
		t.Errorf("expected 100 accounts, got %d", count)
	}
}

func TestMemoryDB_UpdateAccount(t *testing.T) {
	db := NewMemoryDB()
	pubkey := testPubkey("test_account")

	// Initial account
	account1 := testAccount(1000, []byte("data1"), types.SystemProgramID)
	_ = db.SetAccount(pubkey, account1)

	// Update with new data
	account2 := testAccount(2000, []byte("data2"), types.TokenProgramID)
	_ = db.SetAccount(pubkey, account2)

	// Verify update
	retrieved, _ := db.GetAccount(pubkey)
	if retrieved.Lamports != 2000 {
		t.Errorf("expected lamports 2000, got %d", retrieved.Lamports)
	}

	if !bytes.Equal(retrieved.Data, []byte("data2")) {
		t.Errorf("expected data 'data2', got '%s'", string(retrieved.Data))
	}

	if retrieved.Owner != types.TokenProgramID {
		t.Error("owner should be updated")
	}

	// Count should still be 1
	if db.GetAccountsCount() != 1 {
		t.Errorf("account count should still be 1, got %d", db.GetAccountsCount())
	}
}

// Tests for ComputeAccountsDeltaHash (16-ary Merkle tree)
func TestComputeAccountsDeltaHash_Empty(t *testing.T) {
	hash := ComputeAccountsDeltaHash(nil)
	if hash != types.ZeroHash {
		t.Error("empty accounts should produce zero hash")
	}

	hash2 := ComputeAccountsDeltaHash([]types.AccountRef{})
	if hash2 != types.ZeroHash {
		t.Error("empty slice should produce zero hash")
	}
}

func TestComputeAccountsDeltaHash_SingleAccount(t *testing.T) {
	pubkey := testPubkey("account1")
	account := testAccount(1000, []byte("data"), types.SystemProgramID)

	accounts := []types.AccountRef{
		{Pubkey: pubkey, Account: account},
	}

	hash := ComputeAccountsDeltaHash(accounts)
	if hash == types.ZeroHash {
		t.Error("single account should not produce zero hash")
	}

	// Should equal the account's hash directly for single account
	expectedHash := account.Hash(pubkey)
	if hash != expectedHash {
		t.Error("single account hash should equal account.Hash(pubkey)")
	}
}

func TestComputeAccountsDeltaHash_TwoAccounts(t *testing.T) {
	pubkey1 := testPubkey("account1")
	pubkey2 := testPubkey("account2")
	account1 := testAccount(1000, []byte("data1"), types.SystemProgramID)
	account2 := testAccount(2000, []byte("data2"), types.TokenProgramID)

	accounts := []types.AccountRef{
		{Pubkey: pubkey1, Account: account1},
		{Pubkey: pubkey2, Account: account2},
	}

	hash := ComputeAccountsDeltaHash(accounts)
	if hash == types.ZeroHash {
		t.Error("two accounts should not produce zero hash")
	}

	// Verify determinism
	hash2 := ComputeAccountsDeltaHash(accounts)
	if hash != hash2 {
		t.Error("hash computation should be deterministic")
	}
}

func TestComputeAccountsDeltaHash_Ordering(t *testing.T) {
	pubkey1 := testPubkey("account_a")
	pubkey2 := testPubkey("account_b")
	account1 := testAccount(1000, []byte("data1"), types.SystemProgramID)
	account2 := testAccount(2000, []byte("data2"), types.TokenProgramID)

	// Order 1
	accounts1 := []types.AccountRef{
		{Pubkey: pubkey1, Account: account1},
		{Pubkey: pubkey2, Account: account2},
	}

	// Order 2 (reversed)
	accounts2 := []types.AccountRef{
		{Pubkey: pubkey2, Account: account2},
		{Pubkey: pubkey1, Account: account1},
	}

	hash1 := ComputeAccountsDeltaHash(accounts1)
	hash2 := ComputeAccountsDeltaHash(accounts2)

	// Should be the same because accounts are sorted by pubkey
	if hash1 != hash2 {
		t.Error("hash should be order-independent (sorted by pubkey)")
	}
}

func TestComputeAccountsDeltaHash_16AryTree(t *testing.T) {
	// Create 17 accounts to test 16-ary tree behavior
	// With 17 accounts, we should have:
	// - 2 parent nodes at level 1 (16 + 1 children)
	// - 1 root node

	var accounts []types.AccountRef
	for i := 0; i < 17; i++ {
		pubkey := testPubkey("account_" + string(rune('a'+i)))
		account := testAccount(types.Lamports(i*1000), nil, types.SystemProgramID)
		accounts = append(accounts, types.AccountRef{Pubkey: pubkey, Account: account})
	}

	hash := ComputeAccountsDeltaHash(accounts)
	if hash == types.ZeroHash {
		t.Error("17 accounts should not produce zero hash")
	}

	// Verify determinism
	hash2 := ComputeAccountsDeltaHash(accounts)
	if hash != hash2 {
		t.Error("hash computation should be deterministic")
	}
}

func TestComputeAccountsDeltaHash_LargeSet(t *testing.T) {
	// Test with 256 accounts (16^2 = 256)
	var accounts []types.AccountRef
	for i := 0; i < 256; i++ {
		hash := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		var pubkey types.Pubkey
		copy(pubkey[:], hash[:])
		account := testAccount(types.Lamports(i), nil, types.SystemProgramID)
		accounts = append(accounts, types.AccountRef{Pubkey: pubkey, Account: account})
	}

	hash := ComputeAccountsDeltaHash(accounts)
	if hash == types.ZeroHash {
		t.Error("256 accounts should not produce zero hash")
	}

	// Verify determinism
	hash2 := ComputeAccountsDeltaHash(accounts)
	if hash != hash2 {
		t.Error("hash computation should be deterministic")
	}
}

func TestComputeAccountsDeltaHash_DifferentData(t *testing.T) {
	pubkey := testPubkey("account1")

	account1 := testAccount(1000, []byte("data1"), types.SystemProgramID)
	account2 := testAccount(1000, []byte("data2"), types.SystemProgramID)

	hash1 := ComputeAccountsDeltaHash([]types.AccountRef{{Pubkey: pubkey, Account: account1}})
	hash2 := ComputeAccountsDeltaHash([]types.AccountRef{{Pubkey: pubkey, Account: account2}})

	if hash1 == hash2 {
		t.Error("different data should produce different hashes")
	}
}

func TestComputeAccountsDeltaHash_DifferentLamports(t *testing.T) {
	pubkey := testPubkey("account1")

	account1 := testAccount(1000, nil, types.SystemProgramID)
	account2 := testAccount(2000, nil, types.SystemProgramID)

	hash1 := ComputeAccountsDeltaHash([]types.AccountRef{{Pubkey: pubkey, Account: account1}})
	hash2 := ComputeAccountsDeltaHash([]types.AccountRef{{Pubkey: pubkey, Account: account2}})

	if hash1 == hash2 {
		t.Error("different lamports should produce different hashes")
	}
}

func TestComputeAccountsDeltaHash_DifferentOwner(t *testing.T) {
	pubkey := testPubkey("account1")

	account1 := testAccount(1000, nil, types.SystemProgramID)
	account2 := testAccount(1000, nil, types.TokenProgramID)

	hash1 := ComputeAccountsDeltaHash([]types.AccountRef{{Pubkey: pubkey, Account: account1}})
	hash2 := ComputeAccountsDeltaHash([]types.AccountRef{{Pubkey: pubkey, Account: account2}})

	if hash1 == hash2 {
		t.Error("different owner should produce different hashes")
	}
}

// Tests for Account.Hash
func TestAccount_Hash(t *testing.T) {
	pubkey := testPubkey("test_account")
	account := testAccount(1000, []byte("test_data"), types.SystemProgramID)

	hash1 := account.Hash(pubkey)
	if hash1 == types.ZeroHash {
		t.Error("account hash should not be zero")
	}

	// Same account, same pubkey should give same hash
	hash2 := account.Hash(pubkey)
	if hash1 != hash2 {
		t.Error("account hash should be deterministic")
	}

	// Same account, different pubkey should give different hash
	otherPubkey := testPubkey("other_account")
	hash3 := account.Hash(otherPubkey)
	if hash1 == hash3 {
		t.Error("different pubkey should give different hash")
	}
}

func TestAccount_Hash_ExecutableFlag(t *testing.T) {
	pubkey := testPubkey("test_account")

	account1 := &types.Account{
		Lamports:   1000,
		Data:       []byte("data"),
		Owner:      types.SystemProgramID,
		Executable: false,
	}

	account2 := &types.Account{
		Lamports:   1000,
		Data:       []byte("data"),
		Owner:      types.SystemProgramID,
		Executable: true,
	}

	hash1 := account1.Hash(pubkey)
	hash2 := account2.Hash(pubkey)

	if hash1 == hash2 {
		t.Error("different executable flag should give different hash")
	}
}

func TestAccount_Hash_RentEpoch(t *testing.T) {
	pubkey := testPubkey("test_account")

	account1 := &types.Account{
		Lamports:  1000,
		Data:      []byte("data"),
		Owner:     types.SystemProgramID,
		RentEpoch: 100,
	}

	account2 := &types.Account{
		Lamports:  1000,
		Data:      []byte("data"),
		Owner:     types.SystemProgramID,
		RentEpoch: 200,
	}

	hash1 := account1.Hash(pubkey)
	hash2 := account2.Hash(pubkey)

	if hash1 == hash2 {
		t.Error("different rent epoch should give different hash")
	}
}

// Tests for merkle tree internals
func TestComputeMerkleRoot_Empty(t *testing.T) {
	hash := computeMerkleRoot(nil)
	if hash != types.ZeroHash {
		t.Error("empty hashes should produce zero hash")
	}

	hash2 := computeMerkleRoot([]types.Hash{})
	if hash2 != types.ZeroHash {
		t.Error("empty slice should produce zero hash")
	}
}

func TestComputeMerkleRoot_Single(t *testing.T) {
	leaf := sha256.Sum256([]byte("leaf"))

	hash := computeMerkleRoot([]types.Hash{leaf})
	if hash != leaf {
		t.Error("single leaf should be the root")
	}
}

func TestComputeMerkleRoot_TwoLeaves(t *testing.T) {
	leaf1 := sha256.Sum256([]byte("leaf1"))
	leaf2 := sha256.Sum256([]byte("leaf2"))

	hash := computeMerkleRoot([]types.Hash{leaf1, leaf2})
	if hash == types.ZeroHash {
		t.Error("two leaves should not produce zero hash")
	}

	// Verify determinism
	hash2 := computeMerkleRoot([]types.Hash{leaf1, leaf2})
	if hash != hash2 {
		t.Error("merkle root should be deterministic")
	}
}

func TestComputeMerkleRoot_16Leaves(t *testing.T) {
	var leaves []types.Hash
	for i := 0; i < 16; i++ {
		leaf := sha256.Sum256([]byte{byte(i)})
		leaves = append(leaves, leaf)
	}

	hash := computeMerkleRoot(leaves)
	if hash == types.ZeroHash {
		t.Error("16 leaves should not produce zero hash")
	}

	// 16 leaves should produce 1 parent (16-ary tree)
	// So the root is the hash of all 16 leaves
	expectedRoot := hashChildren(leaves)
	if hash != expectedRoot {
		t.Error("16 leaves should produce expected root")
	}
}

func TestComputeMerkleRoot_17Leaves(t *testing.T) {
	var leaves []types.Hash
	for i := 0; i < 17; i++ {
		leaf := sha256.Sum256([]byte{byte(i)})
		leaves = append(leaves, leaf)
	}

	hash := computeMerkleRoot(leaves)
	if hash == types.ZeroHash {
		t.Error("17 leaves should not produce zero hash")
	}

	// Verify determinism
	hash2 := computeMerkleRoot(leaves)
	if hash != hash2 {
		t.Error("merkle root should be deterministic")
	}
}

func TestComputeNextLevel(t *testing.T) {
	var leaves []types.Hash
	for i := 0; i < 32; i++ {
		leaf := sha256.Sum256([]byte{byte(i)})
		leaves = append(leaves, leaf)
	}

	nextLevel := computeNextLevel(leaves)

	// With 32 leaves and arity 16, we should have 2 parents
	if len(nextLevel) != 2 {
		t.Errorf("expected 2 parents, got %d", len(nextLevel))
	}

	// Verify first parent is hash of first 16 leaves
	expectedFirst := hashChildren(leaves[:16])
	if nextLevel[0] != expectedFirst {
		t.Error("first parent should be hash of first 16 leaves")
	}

	// Verify second parent is hash of next 16 leaves
	expectedSecond := hashChildren(leaves[16:32])
	if nextLevel[1] != expectedSecond {
		t.Error("second parent should be hash of next 16 leaves")
	}
}

func TestHashChildren_Empty(t *testing.T) {
	hash := hashChildren(nil)
	if hash != types.ZeroHash {
		t.Error("empty children should produce zero hash")
	}
}

func TestHashChildren_Single(t *testing.T) {
	child := sha256.Sum256([]byte("child"))

	hash := hashChildren([]types.Hash{child})
	if hash != child {
		t.Error("single child should be returned as-is")
	}
}

func TestHashChildren_Multiple(t *testing.T) {
	child1 := sha256.Sum256([]byte("child1"))
	child2 := sha256.Sum256([]byte("child2"))

	hash := hashChildren([]types.Hash{child1, child2})
	if hash == types.ZeroHash {
		t.Error("multiple children should not produce zero hash")
	}

	// Verify it's SHA256 of concatenated children
	expected := types.SHA256(append(child1[:], child2[:]...))
	if hash != expected {
		t.Error("hash should be SHA256 of concatenated children")
	}
}

// Benchmark tests
func BenchmarkComputeAccountsDeltaHash_100(b *testing.B) {
	var accounts []types.AccountRef
	for i := 0; i < 100; i++ {
		pubkey := testPubkey("account_" + string(rune(i)))
		account := testAccount(types.Lamports(i*1000), make([]byte, 128), types.SystemProgramID)
		accounts = append(accounts, types.AccountRef{Pubkey: pubkey, Account: account})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeAccountsDeltaHash(accounts)
	}
}

func BenchmarkComputeAccountsDeltaHash_1000(b *testing.B) {
	var accounts []types.AccountRef
	for i := 0; i < 1000; i++ {
		hash := sha256.Sum256([]byte{byte(i), byte(i >> 8)})
		var pubkey types.Pubkey
		copy(pubkey[:], hash[:])
		account := testAccount(types.Lamports(i), make([]byte, 128), types.SystemProgramID)
		accounts = append(accounts, types.AccountRef{Pubkey: pubkey, Account: account})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeAccountsDeltaHash(accounts)
	}
}

func BenchmarkMemoryDB_SetAccount(b *testing.B) {
	db := NewMemoryDB()
	account := testAccount(1000, make([]byte, 128), types.SystemProgramID)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pubkey := testPubkey("account_" + string(rune(i)))
		_ = db.SetAccount(pubkey, account)
	}
}

func BenchmarkMemoryDB_GetAccount(b *testing.B) {
	db := NewMemoryDB()

	// Pre-populate with accounts
	for i := 0; i < 10000; i++ {
		pubkey := testPubkey("account_" + string(rune(i)))
		account := testAccount(types.Lamports(i), nil, types.SystemProgramID)
		_ = db.SetAccount(pubkey, account)
	}

	pubkey := testPubkey("account_" + string(rune(5000)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = db.GetAccount(pubkey)
	}
}
