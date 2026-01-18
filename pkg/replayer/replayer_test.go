package replayer

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/fortiblox/x1-nimbus/pkg/accounts"
	"github.com/fortiblox/x1-nimbus/pkg/poh"
	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// TestBlockProvider implements BlockProvider for testing
type TestBlockProvider struct {
	blocks map[types.Slot]*types.Block
}

func NewTestBlockProvider() *TestBlockProvider {
	return &TestBlockProvider{
		blocks: make(map[types.Slot]*types.Block),
	}
}

func (p *TestBlockProvider) AddBlock(block *types.Block) {
	p.blocks[block.Slot] = block
}

func (p *TestBlockProvider) GetBlock(slot types.Slot) (*types.Block, error) {
	block, ok := p.blocks[slot]
	if !ok {
		return nil, ErrBlockNotFound
	}
	return block, nil
}

func (p *TestBlockProvider) GetBlockRange(startSlot, endSlot types.Slot) ([]*types.Block, error) {
	var blocks []*types.Block
	for slot := startSlot; slot <= endSlot; slot++ {
		if block, ok := p.blocks[slot]; ok {
			blocks = append(blocks, block)
		}
	}
	if len(blocks) == 0 {
		return nil, ErrNoBlocks
	}
	return blocks, nil
}

// TestAccountLoader implements AccountLoader for testing
type TestAccountLoader struct {
	db accounts.AccountsDB
}

func NewTestAccountLoader(db accounts.AccountsDB) *TestAccountLoader {
	return &TestAccountLoader{db: db}
}

func (l *TestAccountLoader) LoadAccount(pubkey types.Pubkey) (*types.Account, error) {
	return l.db.GetAccount(pubkey)
}

// Helper functions for creating test data
func generateKeypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func pubkeyFromEd25519(pub ed25519.PublicKey) types.Pubkey {
	var pk types.Pubkey
	copy(pk[:], pub)
	return pk
}

func createSignedTransaction(
	fromPub ed25519.PublicKey,
	fromPriv ed25519.PrivateKey,
	toPub ed25519.PublicKey,
	lamports uint64,
	blockhash types.Hash,
) types.Transaction {
	fromPubkey := pubkeyFromEd25519(fromPub)
	toPubkey := pubkeyFromEd25519(toPub)

	// Create transfer instruction data
	// System Program Transfer: instruction discriminator (4 bytes) + lamports (8 bytes)
	ixData := make([]byte, 12)
	ixData[0] = 2 // Transfer instruction
	ixData[1] = 0
	ixData[2] = 0
	ixData[3] = 0
	// Lamports in little-endian
	ixData[4] = byte(lamports)
	ixData[5] = byte(lamports >> 8)
	ixData[6] = byte(lamports >> 16)
	ixData[7] = byte(lamports >> 24)
	ixData[8] = byte(lamports >> 32)
	ixData[9] = byte(lamports >> 40)
	ixData[10] = byte(lamports >> 48)
	ixData[11] = byte(lamports >> 56)

	msg := types.Message{
		Header: types.MessageHeader{
			NumRequiredSignatures:       1,
			NumReadonlySignedAccounts:   0,
			NumReadonlyUnsignedAccounts: 1, // System Program is readonly
		},
		AccountKeys: []types.Pubkey{
			fromPubkey,            // 0: fee payer, signer, writable
			toPubkey,              // 1: destination, writable
			types.SystemProgramID, // 2: System Program, readonly
		},
		RecentBlockhash: blockhash,
		Instructions: []types.CompiledInstruction{
			{
				ProgramIDIndex: 2, // System Program
				AccountIndices: []uint8{0, 1},
				Data:           ixData,
			},
		},
	}

	// Serialize and sign
	msgBytes, _ := msg.Serialize()
	sigBytes := ed25519.Sign(fromPriv, msgBytes)

	var sig types.Signature
	copy(sig[:], sigBytes)

	return types.Transaction{
		Signatures: []types.Signature{sig},
		Message:    msg,
	}
}

func createTickEntry(prevHash types.Hash, numHashes uint64) types.Entry {
	hash := poh.ComputeEntryHash(prevHash, numHashes, nil)
	return types.Entry{
		NumHashes:    numHashes,
		Hash:         hash,
		Transactions: nil,
	}
}

func createTransactionEntry(prevHash types.Hash, numHashes uint64, txs []types.Transaction) types.Entry {
	hash := poh.ComputeEntryHash(prevHash, numHashes, txs)
	return types.Entry{
		NumHashes:    numHashes,
		Hash:         hash,
		Transactions: txs,
	}
}

func createTestBlock(slot types.Slot, parentSlot types.Slot, prevBlockhash types.Hash, entries []types.Entry) *types.Block {
	// Block hash is the last entry's hash
	var blockhash types.Hash
	if len(entries) > 0 {
		blockhash = entries[len(entries)-1].Hash
	}

	return &types.Block{
		Slot:              slot,
		ParentSlot:        parentSlot,
		Blockhash:         blockhash,
		PreviousBlockhash: prevBlockhash,
		Entries:           entries,
	}
}

// Tests for Replayer
func TestNewReplayer(t *testing.T) {
	provider := NewTestBlockProvider()
	r := NewReplayer(provider)

	if r == nil {
		t.Fatal("NewReplayer returned nil")
	}

	if r.IsRunning() {
		t.Error("new replayer should not be running")
	}

	if r.LastReplayedSlot() != 0 {
		t.Error("new replayer should have last replayed slot of 0")
	}
}

func TestReplayBlock_TickOnly(t *testing.T) {
	provider := NewTestBlockProvider()
	r := NewReplayer(provider)

	// Create a block with only tick entries
	prevBlockhash := sha256.Sum256([]byte("genesis"))
	var entries []types.Entry
	currentHash := prevBlockhash

	for i := 0; i < 3; i++ {
		entry := createTickEntry(currentHash, 5)
		entries = append(entries, entry)
		currentHash = entry.Hash
	}

	block := createTestBlock(1, 0, prevBlockhash, entries)
	provider.AddBlock(block)

	// Configure replayer to skip signature verification (no transactions)
	opts := DefaultReplayOptions()
	opts.SkipSignatureVerification = true
	r.SetOptions(opts)

	result, err := r.ReplayBlock(block)
	if err != nil {
		t.Fatalf("ReplayBlock failed: %v", err)
	}

	if result == nil {
		t.Fatal("result should not be nil")
	}

	if result.Slot != 1 {
		t.Errorf("expected slot 1, got %d", result.Slot)
	}

	if result.TotalTransactions() != 0 {
		t.Errorf("expected 0 transactions, got %d", result.TotalTransactions())
	}

	if r.LastReplayedSlot() != 1 {
		t.Errorf("expected last replayed slot 1, got %d", r.LastReplayedSlot())
	}
}

func TestReplayBlock_WithTransactions(t *testing.T) {
	provider := NewTestBlockProvider()
	db := accounts.NewMemoryDB()
	r := NewReplayer(provider)
	r.SetAccountLoader(NewTestAccountLoader(db))

	// Create keypairs
	fromPub, fromPriv := generateKeypair()
	toPub, _ := generateKeypair()

	// Fund the sender account
	fromPubkey := pubkeyFromEd25519(fromPub)
	toPubkey := pubkeyFromEd25519(toPub)

	_ = db.SetAccount(fromPubkey, &types.Account{
		Lamports: 1_000_000_000, // 1 SOL
		Owner:    types.SystemProgramID,
	})
	_ = db.SetAccount(toPubkey, &types.Account{
		Lamports: 0,
		Owner:    types.SystemProgramID,
	})

	// Create a block with a transfer transaction
	prevBlockhash := sha256.Sum256([]byte("genesis"))
	tx := createSignedTransaction(fromPub, fromPriv, toPub, 100_000_000, prevBlockhash)

	// Create entries
	entry := createTransactionEntry(prevBlockhash, 5, []types.Transaction{tx})
	tickEntry := createTickEntry(entry.Hash, 5)

	block := createTestBlock(1, 0, prevBlockhash, []types.Entry{entry, tickEntry})
	provider.AddBlock(block)

	// Skip execution since we don't have full executor setup
	opts := DefaultReplayOptions()
	opts.SkipSignatureVerification = false
	r.SetOptions(opts)

	result, err := r.ReplayBlock(block)
	if err != nil {
		t.Fatalf("ReplayBlock failed: %v", err)
	}

	if result.Slot != 1 {
		t.Errorf("expected slot 1, got %d", result.Slot)
	}

	// Verify signature count
	if result.SignatureCount != 1 {
		t.Errorf("expected 1 signature, got %d", result.SignatureCount)
	}
}

// Tests for BankHasher
func TestBankHasher_NewBankHasher(t *testing.T) {
	parentHash := sha256.Sum256([]byte("parent"))
	hasher := NewBankHasher(parentHash)

	if hasher == nil {
		t.Fatal("NewBankHasher returned nil")
	}

	if hasher.GetSignatureCount() != 0 {
		t.Errorf("expected signature count 0, got %d", hasher.GetSignatureCount())
	}

	if hasher.GetDeltaCount() != 0 {
		t.Errorf("expected delta count 0, got %d", hasher.GetDeltaCount())
	}
}

func TestBankHasher_AddAccountDelta(t *testing.T) {
	parentHash := sha256.Sum256([]byte("parent"))
	hasher := NewBankHasher(parentHash)

	pubkey := types.MustPubkeyFromBase58("11111111111111111111111111111111")
	account := &types.Account{
		Lamports: 1000,
		Owner:    types.SystemProgramID,
	}

	hasher.AddAccountDelta(pubkey, account)

	if hasher.GetDeltaCount() != 1 {
		t.Errorf("expected delta count 1, got %d", hasher.GetDeltaCount())
	}
}

func TestBankHasher_SetSignatureCount(t *testing.T) {
	parentHash := sha256.Sum256([]byte("parent"))
	hasher := NewBankHasher(parentHash)

	hasher.SetSignatureCount(100)

	if hasher.GetSignatureCount() != 100 {
		t.Errorf("expected signature count 100, got %d", hasher.GetSignatureCount())
	}

	hasher.IncrementSignatureCount(50)

	if hasher.GetSignatureCount() != 150 {
		t.Errorf("expected signature count 150, got %d", hasher.GetSignatureCount())
	}
}

func TestBankHasher_Compute(t *testing.T) {
	parentHash := sha256.Sum256([]byte("parent"))
	blockhash := sha256.Sum256([]byte("blockhash"))

	hasher := NewBankHasher(parentHash)
	hasher.SetBlockhash(blockhash)
	hasher.SetSignatureCount(5)

	// Add some account deltas
	pubkey1 := types.MustPubkeyFromBase58("11111111111111111111111111111111")
	pubkey2 := types.MustPubkeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

	hasher.AddAccountDelta(pubkey1, &types.Account{
		Lamports: 1000,
		Owner:    types.SystemProgramID,
	})
	hasher.AddAccountDelta(pubkey2, &types.Account{
		Lamports: 2000,
		Owner:    types.TokenProgramID,
	})

	bankHash := hasher.Compute()

	// Verify it's not zero
	if bankHash == types.ZeroHash {
		t.Error("computed bank hash should not be zero")
	}

	// Verify determinism - same inputs should give same output
	hasher2 := NewBankHasher(parentHash)
	hasher2.SetBlockhash(blockhash)
	hasher2.SetSignatureCount(5)
	hasher2.AddAccountDelta(pubkey1, &types.Account{
		Lamports: 1000,
		Owner:    types.SystemProgramID,
	})
	hasher2.AddAccountDelta(pubkey2, &types.Account{
		Lamports: 2000,
		Owner:    types.TokenProgramID,
	})

	bankHash2 := hasher2.Compute()

	if bankHash != bankHash2 {
		t.Error("bank hash computation should be deterministic")
	}
}

func TestBankHasher_Reset(t *testing.T) {
	parentHash := sha256.Sum256([]byte("parent"))
	hasher := NewBankHasher(parentHash)

	hasher.SetSignatureCount(100)
	hasher.AddAccountDelta(types.SystemProgramID, &types.Account{Lamports: 1000})

	newParentHash := sha256.Sum256([]byte("new_parent"))
	hasher.Reset(newParentHash)

	if hasher.GetSignatureCount() != 0 {
		t.Errorf("expected signature count 0 after reset, got %d", hasher.GetSignatureCount())
	}

	if hasher.GetDeltaCount() != 0 {
		t.Errorf("expected delta count 0 after reset, got %d", hasher.GetDeltaCount())
	}
}

func TestBankHasher_Clone(t *testing.T) {
	parentHash := sha256.Sum256([]byte("parent"))
	hasher := NewBankHasher(parentHash)

	hasher.SetSignatureCount(100)
	hasher.AddAccountDelta(types.SystemProgramID, &types.Account{Lamports: 1000})

	clone := hasher.Clone()

	// Verify clone has same state
	if clone.GetSignatureCount() != hasher.GetSignatureCount() {
		t.Error("cloned signature count doesn't match")
	}

	if clone.GetDeltaCount() != hasher.GetDeltaCount() {
		t.Error("cloned delta count doesn't match")
	}

	// Modify clone and verify original is unchanged
	clone.SetSignatureCount(200)
	if hasher.GetSignatureCount() != 100 {
		t.Error("modifying clone should not affect original")
	}
}

// Tests for ComputeBankHash
func TestComputeBankHash(t *testing.T) {
	parentBankHash := sha256.Sum256([]byte("parent_bank"))
	accountsDeltaHash := sha256.Sum256([]byte("accounts_delta"))
	blockhash := sha256.Sum256([]byte("blockhash"))
	signatureCount := uint64(10)

	hash1 := ComputeBankHash(parentBankHash, accountsDeltaHash, signatureCount, blockhash)

	// Verify it's not zero
	if hash1 == types.ZeroHash {
		t.Error("computed bank hash should not be zero")
	}

	// Verify determinism
	hash2 := ComputeBankHash(parentBankHash, accountsDeltaHash, signatureCount, blockhash)
	if hash1 != hash2 {
		t.Error("ComputeBankHash should be deterministic")
	}

	// Verify different inputs give different outputs
	hash3 := ComputeBankHash(parentBankHash, accountsDeltaHash, signatureCount+1, blockhash)
	if hash1 == hash3 {
		t.Error("different signature count should give different hash")
	}
}

// Tests for ComputeAccountsDeltaHash
func TestComputeAccountsDeltaHash_Empty(t *testing.T) {
	hash := ComputeAccountsDeltaHash(nil)
	if hash != types.ZeroHash {
		t.Error("empty deltas should produce zero hash")
	}

	hash2 := ComputeAccountsDeltaHash([]AccountDeltaEntry{})
	if hash2 != types.ZeroHash {
		t.Error("empty deltas slice should produce zero hash")
	}
}

func TestComputeAccountsDeltaHash_SingleAccount(t *testing.T) {
	deltas := []AccountDeltaEntry{
		{
			Pubkey: types.SystemProgramID,
			Account: &types.Account{
				Lamports: 1000,
				Owner:    types.SystemProgramID,
			},
		},
	}

	hash := ComputeAccountsDeltaHash(deltas)
	if hash == types.ZeroHash {
		t.Error("single account delta should not produce zero hash")
	}
}

func TestComputeAccountsDeltaHash_Ordering(t *testing.T) {
	pubkey1 := types.MustPubkeyFromBase58("11111111111111111111111111111111")
	pubkey2 := types.MustPubkeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

	account1 := &types.Account{Lamports: 1000, Owner: types.SystemProgramID}
	account2 := &types.Account{Lamports: 2000, Owner: types.TokenProgramID}

	// Order 1: pubkey1 first
	deltas1 := []AccountDeltaEntry{
		{Pubkey: pubkey1, Account: account1},
		{Pubkey: pubkey2, Account: account2},
	}

	// Order 2: pubkey2 first
	deltas2 := []AccountDeltaEntry{
		{Pubkey: pubkey2, Account: account2},
		{Pubkey: pubkey1, Account: account1},
	}

	hash1 := ComputeAccountsDeltaHash(deltas1)
	hash2 := ComputeAccountsDeltaHash(deltas2)

	// Should be the same because deltas are sorted by pubkey
	if hash1 != hash2 {
		t.Error("accounts delta hash should be order-independent (sorted by pubkey)")
	}
}

// Tests for BlockVerifier
func TestBlockVerifier_NewBlockVerifier(t *testing.T) {
	verifier := NewBlockVerifier(nil)

	if verifier == nil {
		t.Fatal("NewBlockVerifier returned nil")
	}

	if !verifier.ParallelSignatureVerification {
		t.Error("ParallelSignatureVerification should be true by default")
	}
}

func TestBlockVerifier_VerifyPoHOnly(t *testing.T) {
	db := accounts.NewMemoryDB()
	verifier := NewBlockVerifier(NewTestAccountLoader(db))

	// Create a valid block with PoH chain
	prevBlockhash := sha256.Sum256([]byte("genesis"))
	var entries []types.Entry
	currentHash := prevBlockhash

	for i := 0; i < 5; i++ {
		entry := createTickEntry(currentHash, uint64(i+1))
		entries = append(entries, entry)
		currentHash = entry.Hash
	}

	block := createTestBlock(1, 0, prevBlockhash, entries)

	err := verifier.VerifyPoHOnly(block)
	if err != nil {
		t.Errorf("PoH verification should pass: %v", err)
	}
}

func TestBlockVerifier_VerifyPoHOnly_Invalid(t *testing.T) {
	verifier := NewBlockVerifier(nil)

	// Create a block with invalid PoH
	prevBlockhash := sha256.Sum256([]byte("genesis"))
	entries := []types.Entry{
		{
			NumHashes:    5,
			Hash:         types.ZeroHash, // Invalid hash
			Transactions: nil,
		},
	}

	block := createTestBlock(1, 0, prevBlockhash, entries)

	err := verifier.VerifyPoHOnly(block)
	if err == nil {
		t.Error("PoH verification should fail for invalid hash")
	}
}

func TestBlockVerifier_VerifySignaturesOnly(t *testing.T) {
	db := accounts.NewMemoryDB()
	verifier := NewBlockVerifier(NewTestAccountLoader(db))

	// Create keypairs and fund accounts
	fromPub, fromPriv := generateKeypair()
	toPub, _ := generateKeypair()

	fromPubkey := pubkeyFromEd25519(fromPub)
	toPubkey := pubkeyFromEd25519(toPub)

	_ = db.SetAccount(fromPubkey, &types.Account{Lamports: 1_000_000_000})
	_ = db.SetAccount(toPubkey, &types.Account{Lamports: 0})

	// Create a valid signed transaction
	prevBlockhash := sha256.Sum256([]byte("genesis"))
	tx := createSignedTransaction(fromPub, fromPriv, toPub, 100_000_000, prevBlockhash)

	entry := createTransactionEntry(prevBlockhash, 5, []types.Transaction{tx})
	block := createTestBlock(1, 0, prevBlockhash, []types.Entry{entry})

	err := verifier.VerifySignaturesOnly(block)
	if err != nil {
		t.Errorf("signature verification should pass: %v", err)
	}
}

func TestBlockVerifier_VerifySignaturesOnly_InvalidSignature(t *testing.T) {
	verifier := NewBlockVerifier(nil)

	// Create a transaction with an invalid signature
	fromPub, _ := generateKeypair()
	toPub, _ := generateKeypair()

	fromPubkey := pubkeyFromEd25519(fromPub)
	toPubkey := pubkeyFromEd25519(toPub)

	prevBlockhash := sha256.Sum256([]byte("genesis"))

	// Create transaction with zero signature (invalid)
	tx := types.Transaction{
		Signatures: []types.Signature{types.ZeroSignature},
		Message: types.Message{
			Header: types.MessageHeader{
				NumRequiredSignatures:       1,
				NumReadonlySignedAccounts:   0,
				NumReadonlyUnsignedAccounts: 1,
			},
			AccountKeys: []types.Pubkey{
				fromPubkey,
				toPubkey,
				types.SystemProgramID,
			},
			RecentBlockhash: prevBlockhash,
			Instructions: []types.CompiledInstruction{
				{
					ProgramIDIndex: 2,
					AccountIndices: []uint8{0, 1},
					Data:           []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
		},
	}

	entry := createTransactionEntry(prevBlockhash, 5, []types.Transaction{tx})
	block := createTestBlock(1, 0, prevBlockhash, []types.Entry{entry})

	err := verifier.VerifySignaturesOnly(block)
	if err == nil {
		t.Error("signature verification should fail for invalid signature")
	}
}

// Tests for ProgramRegistry
func TestProgramRegistry_NewProgramRegistry(t *testing.T) {
	registry := NewProgramRegistry()

	if registry == nil {
		t.Fatal("NewProgramRegistry returned nil")
	}

	if registry.Count() != 0 {
		t.Error("new registry should be empty")
	}
}

func TestProgramRegistry_RegisterProgram(t *testing.T) {
	registry := NewProgramRegistry()

	// Create a mock executor
	mockExecutor := ProgramExecutorFunc(func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
		return nil
	})

	registry.RegisterProgram(types.SystemProgramID, mockExecutor)

	if !registry.HasProgram(types.SystemProgramID) {
		t.Error("System Program should be registered")
	}

	if registry.Count() != 1 {
		t.Errorf("expected count 1, got %d", registry.Count())
	}
}

func TestProgramRegistry_RegisterProgramWithName(t *testing.T) {
	registry := NewProgramRegistry()

	mockExecutor := ProgramExecutorFunc(func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
		return nil
	})

	registry.RegisterProgramWithName(types.SystemProgramID, "System Program", mockExecutor)

	name, ok := registry.GetProgramName(types.SystemProgramID)
	if !ok {
		t.Error("should be able to get program name")
	}
	if name != "System Program" {
		t.Errorf("expected 'System Program', got '%s'", name)
	}
}

func TestProgramRegistry_GetProgram(t *testing.T) {
	registry := NewProgramRegistry()

	mockExecutor := ProgramExecutorFunc(func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
		return nil
	})

	registry.RegisterProgram(types.SystemProgramID, mockExecutor)

	executor, ok := registry.GetProgram(types.SystemProgramID)
	if !ok {
		t.Error("should find registered program")
	}
	if executor == nil {
		t.Error("executor should not be nil")
	}

	// Test unregistered program
	_, ok = registry.GetProgram(types.TokenProgramID)
	if ok {
		t.Error("should not find unregistered program")
	}
}

func TestProgramRegistry_UnregisterProgram(t *testing.T) {
	registry := NewProgramRegistry()

	mockExecutor := ProgramExecutorFunc(func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
		return nil
	})

	registry.RegisterProgramWithName(types.SystemProgramID, "System Program", mockExecutor)
	registry.UnregisterProgram(types.SystemProgramID)

	if registry.HasProgram(types.SystemProgramID) {
		t.Error("System Program should be unregistered")
	}

	_, ok := registry.GetProgramName(types.SystemProgramID)
	if ok {
		t.Error("program name should be removed")
	}
}

func TestProgramRegistry_ListPrograms(t *testing.T) {
	registry := NewProgramRegistry()

	mockExecutor := ProgramExecutorFunc(func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
		return nil
	})

	registry.RegisterProgram(types.SystemProgramID, mockExecutor)
	registry.RegisterProgram(types.TokenProgramID, mockExecutor)

	programs := registry.ListPrograms()
	if len(programs) != 2 {
		t.Errorf("expected 2 programs, got %d", len(programs))
	}
}

func TestProgramRegistry_Clear(t *testing.T) {
	registry := NewProgramRegistry()

	mockExecutor := ProgramExecutorFunc(func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
		return nil
	})

	registry.RegisterProgram(types.SystemProgramID, mockExecutor)
	registry.RegisterProgram(types.TokenProgramID, mockExecutor)

	registry.Clear()

	if registry.Count() != 0 {
		t.Error("registry should be empty after clear")
	}
}

func TestProgramRegistry_Clone(t *testing.T) {
	registry := NewProgramRegistry()

	mockExecutor := ProgramExecutorFunc(func(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
		return nil
	})

	registry.RegisterProgramWithName(types.SystemProgramID, "System Program", mockExecutor)

	clone := registry.Clone()

	// Verify clone has same content
	if clone.Count() != registry.Count() {
		t.Error("clone should have same count")
	}

	if !clone.HasProgram(types.SystemProgramID) {
		t.Error("clone should have System Program")
	}

	// Modify clone, verify original unchanged
	clone.Clear()
	if registry.Count() != 1 {
		t.Error("modifying clone should not affect original")
	}
}

// Tests for BlockResult
func TestBlockResult_NewBlockResult(t *testing.T) {
	result := NewBlockResult(123)

	if result.Slot != 123 {
		t.Errorf("expected slot 123, got %d", result.Slot)
	}

	if result.TotalTransactions() != 0 {
		t.Error("new result should have 0 transactions")
	}

	if result.SuccessCount != 0 || result.FailureCount != 0 {
		t.Error("new result should have 0 success and failure counts")
	}
}

func TestBlockResult_AddTransactionResult(t *testing.T) {
	result := NewBlockResult(1)

	result.AddTransactionResult(&types.TransactionResult{
		Success:      true,
		ComputeUnits: 1000,
	})

	result.AddTransactionResult(&types.TransactionResult{
		Success:      false,
		ComputeUnits: 500,
	})

	if result.SuccessCount != 1 {
		t.Errorf("expected success count 1, got %d", result.SuccessCount)
	}

	if result.FailureCount != 1 {
		t.Errorf("expected failure count 1, got %d", result.FailureCount)
	}

	if result.TotalTransactions() != 2 {
		t.Errorf("expected 2 total transactions, got %d", result.TotalTransactions())
	}

	if result.TotalComputeUnits != 1500 {
		t.Errorf("expected 1500 compute units, got %d", result.TotalComputeUnits)
	}
}

func TestBlockResult_SuccessRate(t *testing.T) {
	result := NewBlockResult(1)

	// Test empty
	if result.SuccessRate() != 0.0 {
		t.Error("empty result should have 0 success rate")
	}

	// Add transactions
	result.AddTransactionResult(&types.TransactionResult{Success: true})
	result.AddTransactionResult(&types.TransactionResult{Success: true})
	result.AddTransactionResult(&types.TransactionResult{Success: false})

	rate := result.SuccessRate()
	expected := 100.0 * 2.0 / 3.0
	if rate < expected-0.01 || rate > expected+0.01 {
		t.Errorf("expected success rate %.2f, got %.2f", expected, rate)
	}
}

func TestBlockResult_AllSuccessful(t *testing.T) {
	result := NewBlockResult(1)

	// Empty result has no failures
	if !result.AllSuccessful() {
		t.Error("empty result should be all successful")
	}

	result.AddTransactionResult(&types.TransactionResult{Success: true})
	if !result.AllSuccessful() {
		t.Error("result with only successful tx should be all successful")
	}

	result.AddTransactionResult(&types.TransactionResult{Success: false})
	if result.AllSuccessful() {
		t.Error("result with failed tx should not be all successful")
	}
}

func TestBlockResult_GetFailedResults(t *testing.T) {
	result := NewBlockResult(1)

	result.AddTransactionResult(&types.TransactionResult{Success: true, Logs: []string{"success1"}})
	result.AddTransactionResult(&types.TransactionResult{Success: false, Logs: []string{"failed1"}})
	result.AddTransactionResult(&types.TransactionResult{Success: false, Logs: []string{"failed2"}})

	failed := result.GetFailedResults()
	if len(failed) != 2 {
		t.Errorf("expected 2 failed results, got %d", len(failed))
	}
}

// Tests for CountSignatures and CountTransactions
func TestCountSignatures(t *testing.T) {
	fromPub, fromPriv := generateKeypair()
	toPub, _ := generateKeypair()

	prevBlockhash := sha256.Sum256([]byte("genesis"))
	tx1 := createSignedTransaction(fromPub, fromPriv, toPub, 100, prevBlockhash)
	tx2 := createSignedTransaction(fromPub, fromPriv, toPub, 200, prevBlockhash)

	entry := createTransactionEntry(prevBlockhash, 5, []types.Transaction{tx1, tx2})
	block := createTestBlock(1, 0, prevBlockhash, []types.Entry{entry})

	count := CountSignatures(block)
	if count != 2 {
		t.Errorf("expected 2 signatures, got %d", count)
	}
}

func TestCountTransactions(t *testing.T) {
	fromPub, fromPriv := generateKeypair()
	toPub, _ := generateKeypair()

	prevBlockhash := sha256.Sum256([]byte("genesis"))
	tx1 := createSignedTransaction(fromPub, fromPriv, toPub, 100, prevBlockhash)
	tx2 := createSignedTransaction(fromPub, fromPriv, toPub, 200, prevBlockhash)

	entry1 := createTransactionEntry(prevBlockhash, 5, []types.Transaction{tx1})
	entry2 := createTransactionEntry(entry1.Hash, 5, []types.Transaction{tx2})

	block := createTestBlock(1, 0, prevBlockhash, []types.Entry{entry1, entry2})

	count := CountTransactions(block)
	if count != 2 {
		t.Errorf("expected 2 transactions, got %d", count)
	}
}

// Tests for VerifyPoHChain
func TestVerifyPoHChain(t *testing.T) {
	// Create a chain of blocks with valid PoH
	var blocks []*types.Block
	currentHash := sha256.Sum256([]byte("genesis"))

	for slot := types.Slot(1); slot <= 3; slot++ {
		prevHash := currentHash
		var entries []types.Entry

		for i := 0; i < 3; i++ {
			entry := createTickEntry(currentHash, uint64(i+1))
			entries = append(entries, entry)
			currentHash = entry.Hash
		}

		var parentSlot types.Slot
		if slot > 1 {
			parentSlot = slot - 1
		}

		block := &types.Block{
			Slot:              slot,
			ParentSlot:        parentSlot,
			Blockhash:         currentHash,
			PreviousBlockhash: prevHash,
			Entries:           entries,
		}
		blocks = append(blocks, block)
	}

	err := VerifyPoHChain(blocks)
	if err != nil {
		t.Errorf("valid PoH chain should verify: %v", err)
	}
}

func TestVerifyPoHChain_Empty(t *testing.T) {
	err := VerifyPoHChain(nil)
	if err != nil {
		t.Error("empty chain should verify without error")
	}

	err = VerifyPoHChain([]*types.Block{})
	if err != nil {
		t.Error("empty slice should verify without error")
	}
}

func TestVerifyPoHChain_InvalidBlock(t *testing.T) {
	// Create a chain with an invalid block in the middle
	currentHash := sha256.Sum256([]byte("genesis"))

	block1 := &types.Block{
		Slot:              1,
		ParentSlot:        0,
		PreviousBlockhash: currentHash,
		Entries: []types.Entry{
			createTickEntry(currentHash, 5),
		},
	}
	block1.Blockhash = block1.Entries[len(block1.Entries)-1].Hash

	// Invalid block with wrong hash
	block2 := &types.Block{
		Slot:              2,
		ParentSlot:        1,
		PreviousBlockhash: block1.Blockhash,
		Entries: []types.Entry{
			{
				NumHashes:    5,
				Hash:         types.ZeroHash, // Invalid
				Transactions: nil,
			},
		},
	}

	blocks := []*types.Block{block1, block2}

	err := VerifyPoHChain(blocks)
	if err == nil {
		t.Error("chain with invalid block should fail verification")
	}
}

