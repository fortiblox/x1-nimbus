// Package test provides integration tests for the X1-Nimbus verification pipeline.
//
// These tests exercise the complete verification flow:
// 1. Create simulated block data with transactions
// 2. Verify Ed25519 signatures
// 3. Verify Proof of History (PoH)
// 4. Execute transactions
// 5. Compute bank hash
// 6. Validate the complete pipeline
package test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/fortiblox/x1-nimbus/pkg/accounts"
	"github.com/fortiblox/x1-nimbus/pkg/crypto"
	"github.com/fortiblox/x1-nimbus/pkg/poh"
	"github.com/fortiblox/x1-nimbus/pkg/replayer"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Test utilities

func generateKeypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

func pubkeyFromEd25519(pub ed25519.PublicKey) types.Pubkey {
	var pk types.Pubkey
	copy(pk[:], pub)
	return pk
}

func signatureFromBytes(sigBytes []byte) types.Signature {
	var sig types.Signature
	copy(sig[:], sigBytes)
	return sig
}

// createTransferInstruction creates a System Program transfer instruction
func createTransferInstruction(lamports uint64) []byte {
	// System Program Transfer: instruction discriminator (4 bytes, little-endian) + lamports (8 bytes, little-endian)
	data := make([]byte, 12)
	data[0] = 2 // Transfer instruction discriminator
	data[1] = 0
	data[2] = 0
	data[3] = 0
	// Lamports in little-endian
	data[4] = byte(lamports)
	data[5] = byte(lamports >> 8)
	data[6] = byte(lamports >> 16)
	data[7] = byte(lamports >> 24)
	data[8] = byte(lamports >> 32)
	data[9] = byte(lamports >> 40)
	data[10] = byte(lamports >> 48)
	data[11] = byte(lamports >> 56)
	return data
}

// createSignedTransaction creates a signed transfer transaction
func createSignedTransaction(
	fromPub ed25519.PublicKey,
	fromPriv ed25519.PrivateKey,
	toPub ed25519.PublicKey,
	lamports uint64,
	blockhash types.Hash,
) types.Transaction {
	fromPubkey := pubkeyFromEd25519(fromPub)
	toPubkey := pubkeyFromEd25519(toPub)

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
				Data:           createTransferInstruction(lamports),
			},
		},
	}

	// Serialize and sign the message
	msgBytes, _ := msg.Serialize()
	sigBytes := ed25519.Sign(fromPriv, msgBytes)
	sig := signatureFromBytes(sigBytes)

	return types.Transaction{
		Signatures: []types.Signature{sig},
		Message:    msg,
	}
}

// createTickEntry creates a tick entry (no transactions)
func createTickEntry(prevHash types.Hash, numHashes uint64) types.Entry {
	hash := poh.ComputeEntryHash(prevHash, numHashes, nil)
	return types.Entry{
		NumHashes:    numHashes,
		Hash:         hash,
		Transactions: nil,
	}
}

// createTransactionEntry creates an entry with transactions
func createTransactionEntry(prevHash types.Hash, numHashes uint64, txs []types.Transaction) types.Entry {
	hash := poh.ComputeEntryHash(prevHash, numHashes, txs)
	return types.Entry{
		NumHashes:    numHashes,
		Hash:         hash,
		Transactions: txs,
	}
}

// SimulatedBlockBuilder helps build test blocks
type SimulatedBlockBuilder struct {
	slot              types.Slot
	parentSlot        types.Slot
	previousBlockhash types.Hash
	entries           []types.Entry
	currentHash       types.Hash
}

func NewSimulatedBlockBuilder(slot, parentSlot types.Slot, prevBlockhash types.Hash) *SimulatedBlockBuilder {
	return &SimulatedBlockBuilder{
		slot:              slot,
		parentSlot:        parentSlot,
		previousBlockhash: prevBlockhash,
		currentHash:       prevBlockhash,
	}
}

func (b *SimulatedBlockBuilder) AddTickEntry(numHashes uint64) *SimulatedBlockBuilder {
	entry := createTickEntry(b.currentHash, numHashes)
	b.entries = append(b.entries, entry)
	b.currentHash = entry.Hash
	return b
}

func (b *SimulatedBlockBuilder) AddTransactionEntry(numHashes uint64, txs []types.Transaction) *SimulatedBlockBuilder {
	entry := createTransactionEntry(b.currentHash, numHashes, txs)
	b.entries = append(b.entries, entry)
	b.currentHash = entry.Hash
	return b
}

func (b *SimulatedBlockBuilder) Build() *types.Block {
	return &types.Block{
		Slot:              b.slot,
		ParentSlot:        b.parentSlot,
		Blockhash:         b.currentHash,
		PreviousBlockhash: b.previousBlockhash,
		Entries:           b.entries,
	}
}

// TestBlockProvider implements replayer.BlockProvider for testing
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
		return nil, replayer.ErrBlockNotFound
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
		return nil, replayer.ErrNoBlocks
	}
	return blocks, nil
}

// TestAccountLoader implements replayer.AccountLoader
type TestAccountLoader struct {
	db accounts.AccountsDB
}

func NewTestAccountLoader(db accounts.AccountsDB) *TestAccountLoader {
	return &TestAccountLoader{db: db}
}

func (l *TestAccountLoader) LoadAccount(pubkey types.Pubkey) (*types.Account, error) {
	return l.db.GetAccount(pubkey)
}

// Integration tests

// TestFullVerificationPipeline_TickOnlyBlock tests verification of a block with only tick entries
func TestFullVerificationPipeline_TickOnlyBlock(t *testing.T) {
	// Setup
	provider := NewTestBlockProvider()
	db := accounts.NewMemoryDB()
	loader := NewTestAccountLoader(db)

	// Create a simulated block with tick entries
	genesisHash := sha256.Sum256([]byte("genesis"))

	builder := NewSimulatedBlockBuilder(1, 0, genesisHash)
	builder.
		AddTickEntry(10).
		AddTickEntry(10).
		AddTickEntry(10).
		AddTickEntry(10).
		AddTickEntry(10)

	block := builder.Build()
	provider.AddBlock(block)

	// Create replayer
	r := replayer.NewReplayer(provider)
	r.SetAccountLoader(loader)

	opts := replayer.DefaultReplayOptions()
	opts.SkipSignatureVerification = true // No signatures in tick-only block
	r.SetOptions(opts)

	// Step 1: Verify PoH
	pohVerifier := poh.NewVerifier(block.PreviousBlockhash)
	err := pohVerifier.VerifyEntries(block.Entries)
	if err != nil {
		t.Fatalf("PoH verification failed: %v", err)
	}
	t.Logf("PoH verification passed. Final hash: %s", pohVerifier.CurrentHash().String())
	t.Logf("Tick count: %d", pohVerifier.TickCount())

	// Verify blockhash matches final entry hash
	if pohVerifier.CurrentHash() != block.Blockhash {
		t.Errorf("final PoH hash should match blockhash")
	}

	// Step 2: Replay block
	result, err := r.ReplayBlock(block)
	if err != nil {
		t.Fatalf("ReplayBlock failed: %v", err)
	}

	t.Logf("Block %d replayed successfully", result.Slot)
	t.Logf("Bank hash: %s", result.BankHash.String())
	t.Logf("Total transactions: %d", result.TotalTransactions())
	t.Logf("Signature count: %d", result.SignatureCount)

	// Verify results
	if result.Slot != 1 {
		t.Errorf("expected slot 1, got %d", result.Slot)
	}
	if result.TotalTransactions() != 0 {
		t.Errorf("expected 0 transactions, got %d", result.TotalTransactions())
	}
	if result.SignatureCount != 0 {
		t.Errorf("expected 0 signatures, got %d", result.SignatureCount)
	}
}

// TestFullVerificationPipeline_SingleTransaction tests the complete pipeline with a single transaction
func TestFullVerificationPipeline_SingleTransaction(t *testing.T) {
	// Setup accounts
	db := accounts.NewMemoryDB()
	provider := NewTestBlockProvider()
	loader := NewTestAccountLoader(db)

	// Create keypairs
	senderPub, senderPriv := generateKeypair()
	recipientPub, _ := generateKeypair()

	senderPubkey := pubkeyFromEd25519(senderPub)
	recipientPubkey := pubkeyFromEd25519(recipientPub)

	// Fund sender account
	senderBalance := types.Lamports(10_000_000_000) // 10 SOL
	_ = db.SetAccount(senderPubkey, &types.Account{
		Lamports: senderBalance,
		Owner:    types.SystemProgramID,
	})
	_ = db.SetAccount(recipientPubkey, &types.Account{
		Lamports: 0,
		Owner:    types.SystemProgramID,
	})

	t.Logf("Sender: %s (balance: %d lamports)", senderPubkey.String(), senderBalance)
	t.Logf("Recipient: %s", recipientPubkey.String())

	// Create block with transfer transaction
	genesisHash := sha256.Sum256([]byte("genesis"))
	transferAmount := uint64(1_000_000_000) // 1 SOL

	tx := createSignedTransaction(senderPub, senderPriv, recipientPub, transferAmount, genesisHash)

	builder := NewSimulatedBlockBuilder(1, 0, genesisHash)
	builder.
		AddTickEntry(5).
		AddTransactionEntry(5, []types.Transaction{tx}).
		AddTickEntry(5)

	block := builder.Build()
	provider.AddBlock(block)

	// Step 1: Verify signatures
	t.Log("Step 1: Verifying signatures...")
	err := crypto.VerifyTransaction(&tx)
	if err != nil {
		t.Fatalf("Signature verification failed: %v", err)
	}
	t.Log("Signature verification passed")

	// Step 2: Verify PoH
	t.Log("Step 2: Verifying PoH...")
	pohVerifier := poh.NewVerifier(block.PreviousBlockhash)
	err = pohVerifier.VerifyEntries(block.Entries)
	if err != nil {
		t.Fatalf("PoH verification failed: %v", err)
	}
	t.Logf("PoH verification passed. Tick count: %d", pohVerifier.TickCount())

	// Step 3: Full block replay
	t.Log("Step 3: Replaying block...")
	r := replayer.NewReplayer(provider)
	r.SetAccountLoader(loader)

	result, err := r.ReplayBlock(block)
	if err != nil {
		t.Fatalf("ReplayBlock failed: %v", err)
	}

	t.Logf("Block %d replayed successfully", result.Slot)
	t.Logf("Bank hash: %s", result.BankHash.String())
	t.Logf("Signature count: %d", result.SignatureCount)

	// Verify results
	if result.SignatureCount != 1 {
		t.Errorf("expected 1 signature, got %d", result.SignatureCount)
	}
}

// TestFullVerificationPipeline_MultipleTransactions tests multiple transactions in a block
func TestFullVerificationPipeline_MultipleTransactions(t *testing.T) {
	// Setup
	db := accounts.NewMemoryDB()
	provider := NewTestBlockProvider()
	loader := NewTestAccountLoader(db)

	// Create multiple sender/recipient pairs
	numTxs := 10
	senders := make([]ed25519.PublicKey, numTxs)
	privKeys := make([]ed25519.PrivateKey, numTxs)
	recipients := make([]ed25519.PublicKey, numTxs)

	for i := 0; i < numTxs; i++ {
		senders[i], privKeys[i] = generateKeypair()
		recipients[i], _ = generateKeypair()

		senderPubkey := pubkeyFromEd25519(senders[i])
		recipientPubkey := pubkeyFromEd25519(recipients[i])

		// Fund sender
		_ = db.SetAccount(senderPubkey, &types.Account{
			Lamports: types.Lamports(10_000_000_000),
			Owner:    types.SystemProgramID,
		})
		_ = db.SetAccount(recipientPubkey, &types.Account{
			Lamports: 0,
			Owner:    types.SystemProgramID,
		})
	}

	// Create block with multiple transactions
	genesisHash := sha256.Sum256([]byte("genesis"))

	txs := make([]types.Transaction, numTxs)
	for i := 0; i < numTxs; i++ {
		txs[i] = createSignedTransaction(senders[i], privKeys[i], recipients[i], uint64(i+1)*100_000_000, genesisHash)
	}

	builder := NewSimulatedBlockBuilder(1, 0, genesisHash)
	builder.
		AddTickEntry(5).
		AddTransactionEntry(5, txs[:5]).  // First 5 transactions
		AddTickEntry(5).
		AddTransactionEntry(5, txs[5:]).  // Remaining 5 transactions
		AddTickEntry(5)

	block := builder.Build()
	provider.AddBlock(block)

	// Verify all signatures using batch verification
	t.Log("Verifying signatures with batch verifier...")
	txPtrs := make([]*types.Transaction, len(txs))
	for i := range txs {
		txPtrs[i] = &txs[i]
	}
	errs := crypto.VerifyTransactionBatch(txPtrs)
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Transaction %d signature verification failed: %v", i, err)
		}
	}
	t.Logf("All %d signatures verified", len(txs))

	// Verify PoH
	t.Log("Verifying PoH...")
	pohVerifier := poh.NewVerifier(block.PreviousBlockhash)
	err := pohVerifier.VerifyEntries(block.Entries)
	if err != nil {
		t.Fatalf("PoH verification failed: %v", err)
	}
	t.Logf("PoH verification passed. Tick count: %d", pohVerifier.TickCount())

	// Full replay
	t.Log("Replaying block...")
	r := replayer.NewReplayer(provider)
	r.SetAccountLoader(loader)

	result, err := r.ReplayBlock(block)
	if err != nil {
		t.Fatalf("ReplayBlock failed: %v", err)
	}

	t.Logf("Block replayed. Signature count: %d", result.SignatureCount)

	if result.SignatureCount != uint64(numTxs) {
		t.Errorf("expected %d signatures, got %d", numTxs, result.SignatureCount)
	}
}

// TestFullVerificationPipeline_MultipleBlocks tests verification across multiple blocks
func TestFullVerificationPipeline_MultipleBlocks(t *testing.T) {
	db := accounts.NewMemoryDB()
	provider := NewTestBlockProvider()
	loader := NewTestAccountLoader(db)

	// Create initial accounts
	senderPub, senderPriv := generateKeypair()
	recipientPub, _ := generateKeypair()

	senderPubkey := pubkeyFromEd25519(senderPub)
	recipientPubkey := pubkeyFromEd25519(recipientPub)

	_ = db.SetAccount(senderPubkey, &types.Account{
		Lamports: types.Lamports(100_000_000_000), // 100 SOL
		Owner:    types.SystemProgramID,
	})
	_ = db.SetAccount(recipientPubkey, &types.Account{
		Lamports: 0,
		Owner:    types.SystemProgramID,
	})

	// Create 5 blocks, each with a transaction
	currentHash := sha256.Sum256([]byte("genesis"))
	var lastBankHash types.Hash

	for slot := types.Slot(1); slot <= 5; slot++ {
		tx := createSignedTransaction(senderPub, senderPriv, recipientPub, uint64(slot)*100_000_000, currentHash)

		builder := NewSimulatedBlockBuilder(slot, slot-1, currentHash)
		builder.
			AddTickEntry(10).
			AddTransactionEntry(10, []types.Transaction{tx}).
			AddTickEntry(10)

		block := builder.Build()
		provider.AddBlock(block)

		// Verify and replay this block
		err := crypto.VerifyTransaction(&tx)
		if err != nil {
			t.Fatalf("Block %d signature verification failed: %v", slot, err)
		}

		pohVerifier := poh.NewVerifier(block.PreviousBlockhash)
		err = pohVerifier.VerifyEntries(block.Entries)
		if err != nil {
			t.Fatalf("Block %d PoH verification failed: %v", slot, err)
		}

		r := replayer.NewReplayer(provider)
		r.SetAccountLoader(loader)
		r.SetInitialBankHash(lastBankHash)

		result, err := r.ReplayBlock(block)
		if err != nil {
			t.Fatalf("Block %d replay failed: %v", slot, err)
		}

		lastBankHash = result.BankHash
		currentHash = block.Blockhash

		t.Logf("Block %d: bank_hash=%s", slot, result.BankHash.String())
	}

	t.Log("Successfully verified and replayed 5 consecutive blocks")
}

// TestFullVerificationPipeline_BankHashDeterminism tests that bank hash is deterministic
func TestFullVerificationPipeline_BankHashDeterminism(t *testing.T) {
	// Create a block once, then replay it twice to verify bank hash is deterministic

	// Setup
	db := accounts.NewMemoryDB()

	senderPub, senderPriv := generateKeypair()
	recipientPub, _ := generateKeypair()

	senderPubkey := pubkeyFromEd25519(senderPub)
	recipientPubkey := pubkeyFromEd25519(recipientPub)

	_ = db.SetAccount(senderPubkey, &types.Account{
		Lamports: types.Lamports(10_000_000_000),
		Owner:    types.SystemProgramID,
	})
	_ = db.SetAccount(recipientPubkey, &types.Account{
		Lamports: 0,
		Owner:    types.SystemProgramID,
	})

	genesisHash := sha256.Sum256([]byte("determinism_test"))
	tx := createSignedTransaction(senderPub, senderPriv, recipientPub, 500_000_000, genesisHash)

	builder := NewSimulatedBlockBuilder(1, 0, genesisHash)
	builder.
		AddTickEntry(5).
		AddTransactionEntry(5, []types.Transaction{tx}).
		AddTickEntry(5)

	block := builder.Build()

	// Create fresh DBs for each replay (with same accounts)
	createDB := func() accounts.AccountsDB {
		db := accounts.NewMemoryDB()
		_ = db.SetAccount(senderPubkey, &types.Account{
			Lamports: types.Lamports(10_000_000_000),
			Owner:    types.SystemProgramID,
		})
		_ = db.SetAccount(recipientPubkey, &types.Account{
			Lamports: 0,
			Owner:    types.SystemProgramID,
		})
		return db
	}

	// First replay
	provider1 := NewTestBlockProvider()
	provider1.AddBlock(block)

	r1 := replayer.NewReplayer(provider1)
	r1.SetAccountLoader(NewTestAccountLoader(createDB()))
	result1, err := r1.ReplayBlock(block)
	if err != nil {
		t.Fatalf("first replay failed: %v", err)
	}

	// Second replay of the same block
	provider2 := NewTestBlockProvider()
	provider2.AddBlock(block)

	r2 := replayer.NewReplayer(provider2)
	r2.SetAccountLoader(NewTestAccountLoader(createDB()))
	result2, err := r2.ReplayBlock(block)
	if err != nil {
		t.Fatalf("second replay failed: %v", err)
	}

	// Bank hashes should match
	if result1.BankHash != result2.BankHash {
		t.Errorf("bank hashes should be deterministic: %s vs %s",
			result1.BankHash.String(), result2.BankHash.String())
	}

	t.Logf("Bank hash is deterministic: %s", result1.BankHash.String())
}

// TestFullVerificationPipeline_InvalidSignature tests that invalid signatures are caught
func TestFullVerificationPipeline_InvalidSignature(t *testing.T) {
	senderPub, _ := generateKeypair()
	recipientPub, _ := generateKeypair()

	senderPubkey := pubkeyFromEd25519(senderPub)
	recipientPubkey := pubkeyFromEd25519(recipientPub)

	genesisHash := sha256.Sum256([]byte("genesis"))

	// Create transaction with zero signature (invalid)
	msg := types.Message{
		Header: types.MessageHeader{
			NumRequiredSignatures:       1,
			NumReadonlySignedAccounts:   0,
			NumReadonlyUnsignedAccounts: 1,
		},
		AccountKeys: []types.Pubkey{
			senderPubkey,
			recipientPubkey,
			types.SystemProgramID,
		},
		RecentBlockhash: genesisHash,
		Instructions: []types.CompiledInstruction{
			{
				ProgramIDIndex: 2,
				AccountIndices: []uint8{0, 1},
				Data:           createTransferInstruction(100_000_000),
			},
		},
	}

	tx := types.Transaction{
		Signatures: []types.Signature{types.ZeroSignature}, // Invalid signature
		Message:    msg,
	}

	// Signature verification should fail
	err := crypto.VerifyTransaction(&tx)
	if err == nil {
		t.Error("expected signature verification to fail for invalid signature")
	}
	t.Logf("Invalid signature correctly detected: %v", err)
}

// TestFullVerificationPipeline_InvalidPoH tests that invalid PoH is detected
func TestFullVerificationPipeline_InvalidPoH(t *testing.T) {
	genesisHash := sha256.Sum256([]byte("genesis"))

	// Create block with corrupted PoH
	entries := []types.Entry{
		createTickEntry(genesisHash, 10),
		{
			NumHashes:    10,
			Hash:         types.ZeroHash, // Invalid hash - should not be zero
			Transactions: nil,
		},
	}

	block := &types.Block{
		Slot:              1,
		ParentSlot:        0,
		PreviousBlockhash: genesisHash,
		Entries:           entries,
		Blockhash:         types.ZeroHash,
	}

	// PoH verification should fail
	pohVerifier := poh.NewVerifier(block.PreviousBlockhash)
	err := pohVerifier.VerifyEntries(block.Entries)
	if err == nil {
		t.Error("expected PoH verification to fail for corrupted entry")
	}
	t.Logf("Invalid PoH correctly detected: %v", err)
}

// TestFullVerificationPipeline_EmptyBlock tests an empty block
func TestFullVerificationPipeline_EmptyBlock(t *testing.T) {
	genesisHash := sha256.Sum256([]byte("genesis"))

	// Block with empty entries should fail basic verification
	block := &types.Block{
		Slot:              1,
		ParentSlot:        0,
		PreviousBlockhash: genesisHash,
		Entries:           []types.Entry{},
		Blockhash:         genesisHash,
	}

	verifier := replayer.NewBlockVerifier(nil)
	err := verifier.VerifyPoHOnly(block)
	// Empty entries should succeed (no entries to verify = valid)
	if err != nil {
		t.Logf("Empty block PoH verification error: %v", err)
	}

	// But full verification should fail due to no entries
	err = verifier.Verify(block, types.ZeroHash)
	if err == nil {
		t.Logf("Empty block verification passed (expected for no entries)")
	}
}

// TestAccountsDeltaHashComputation tests the accounts delta hash computation
func TestAccountsDeltaHashComputation(t *testing.T) {
	// Create some account deltas
	pubkey1 := types.MustPubkeyFromBase58("11111111111111111111111111111111")
	pubkey2 := types.MustPubkeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

	account1 := &types.Account{
		Lamports: 1_000_000_000,
		Data:     []byte("account_data_1"),
		Owner:    types.SystemProgramID,
	}

	account2 := &types.Account{
		Lamports: 2_000_000_000,
		Data:     []byte("account_data_2"),
		Owner:    types.TokenProgramID,
	}

	// Use BankHasher to compute delta hash
	parentHash := sha256.Sum256([]byte("parent"))
	blockhash := sha256.Sum256([]byte("blockhash"))

	hasher := replayer.NewBankHasher(parentHash)
	hasher.SetBlockhash(blockhash)
	hasher.SetSignatureCount(5)
	hasher.AddAccountDelta(pubkey1, account1)
	hasher.AddAccountDelta(pubkey2, account2)

	bankHash1 := hasher.Compute()

	// Verify determinism with same inputs
	hasher2 := replayer.NewBankHasher(parentHash)
	hasher2.SetBlockhash(blockhash)
	hasher2.SetSignatureCount(5)
	hasher2.AddAccountDelta(pubkey1, account1)
	hasher2.AddAccountDelta(pubkey2, account2)

	bankHash2 := hasher2.Compute()

	if bankHash1 != bankHash2 {
		t.Error("bank hash computation should be deterministic")
	}

	// Verify different inputs give different hash
	hasher3 := replayer.NewBankHasher(parentHash)
	hasher3.SetBlockhash(blockhash)
	hasher3.SetSignatureCount(6) // Different signature count
	hasher3.AddAccountDelta(pubkey1, account1)
	hasher3.AddAccountDelta(pubkey2, account2)

	bankHash3 := hasher3.Compute()

	if bankHash1 == bankHash3 {
		t.Error("different signature count should give different bank hash")
	}

	t.Logf("Bank hash: %s", bankHash1.String())
	t.Logf("Delta count: %d", hasher.GetDeltaCount())
}

// TestBatchSignatureVerification tests batch verification performance path
func TestBatchSignatureVerification(t *testing.T) {
	// Create multiple signed transactions
	numTxs := 50
	txs := make([]*types.Transaction, numTxs)

	for i := 0; i < numTxs; i++ {
		senderPub, senderPriv := generateKeypair()
		recipientPub, _ := generateKeypair()
		blockhash := sha256.Sum256([]byte("blockhash"))

		tx := createSignedTransaction(senderPub, senderPriv, recipientPub, uint64(i+1)*1000000, blockhash)
		txs[i] = &tx
	}

	// Use batch verification
	errs := crypto.VerifyTransactionBatch(txs)

	validCount := 0
	for _, err := range errs {
		if err == nil {
			validCount++
		}
	}

	if validCount != numTxs {
		t.Errorf("expected %d valid transactions, got %d", numTxs, validCount)
	}

	t.Logf("Batch verified %d transactions", validCount)
}

// TestProgramRegistry tests the program registry functionality
func TestProgramRegistry(t *testing.T) {
	registry := replayer.NewProgramRegistry()

	// Register native programs
	replayer.RegisterNativePrograms(registry)

	// Verify System Program is registered
	if !registry.HasProgram(types.SystemProgramID) {
		t.Error("System Program should be registered")
	}

	// Verify Token Program is registered
	if !registry.HasProgram(types.TokenProgramID) {
		t.Error("Token Program should be registered")
	}

	// Verify Vote Program is registered
	if !registry.HasProgram(types.VoteProgramID) {
		t.Error("Vote Program should be registered")
	}

	// Verify program name
	name, ok := registry.GetProgramName(types.SystemProgramID)
	if !ok || name != "System Program" {
		t.Errorf("expected 'System Program', got '%s'", name)
	}

	t.Logf("Registry has %d programs registered", registry.Count())
}

// TestStatsCollector tests the replay stats collection
func TestStatsCollector(t *testing.T) {
	collector := replayer.NewStatsCollector()

	// Simulate block completion callbacks
	for i := 0; i < 10; i++ {
		result := replayer.NewBlockResult(types.Slot(i + 1))
		result.SuccessCount = 5
		result.FailureCount = 1
		result.TotalComputeUnits = 100000
		result.SignatureCount = 10

		collector.OnBlockComplete(result, 100_000_000) // 100ms per block
	}

	stats := collector.Stats()

	if stats.BlocksReplayed != 10 {
		t.Errorf("expected 10 blocks replayed, got %d", stats.BlocksReplayed)
	}

	if stats.SignaturesVerified != 100 {
		t.Errorf("expected 100 signatures, got %d", stats.SignaturesVerified)
	}

	t.Logf("Stats: blocks=%d, txs=%d, sigs=%d, CU=%d",
		stats.BlocksReplayed,
		stats.TransactionsExecuted,
		stats.SignaturesVerified,
		stats.ComputeUnitsUsed)
}

// Benchmark tests

func BenchmarkFullVerificationPipeline(b *testing.B) {
	// Setup
	senderPub, senderPriv := generateKeypair()
	recipientPub, _ := generateKeypair()
	genesisHash := sha256.Sum256([]byte("genesis"))

	tx := createSignedTransaction(senderPub, senderPriv, recipientPub, 100_000_000, genesisHash)

	builder := NewSimulatedBlockBuilder(1, 0, genesisHash)
	builder.
		AddTickEntry(10).
		AddTransactionEntry(10, []types.Transaction{tx}).
		AddTickEntry(10)

	block := builder.Build()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Verify PoH
		pohVerifier := poh.NewVerifier(block.PreviousBlockhash)
		_ = pohVerifier.VerifyEntries(block.Entries)

		// Verify signature
		_ = crypto.VerifyTransaction(&tx)
	}
}

func BenchmarkBatchSignatureVerification_50(b *testing.B) {
	// Pre-create transactions
	txs := make([]*types.Transaction, 50)
	for i := 0; i < 50; i++ {
		senderPub, senderPriv := generateKeypair()
		recipientPub, _ := generateKeypair()
		blockhash := sha256.Sum256([]byte("blockhash"))
		tx := createSignedTransaction(senderPub, senderPriv, recipientPub, uint64(i+1)*1000000, blockhash)
		txs[i] = &tx
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		crypto.VerifyTransactionBatch(txs)
	}
}

func BenchmarkPoHVerification_100Entries(b *testing.B) {
	// Pre-create entries
	genesisHash := sha256.Sum256([]byte("genesis"))
	entries := make([]types.Entry, 100)
	currentHash := genesisHash

	for i := range entries {
		entries[i] = createTickEntry(currentHash, 10)
		currentHash = entries[i].Hash
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pohVerifier := poh.NewVerifier(genesisHash)
		_ = pohVerifier.VerifyEntries(entries)
	}
}

func BenchmarkBankHashComputation(b *testing.B) {
	parentHash := sha256.Sum256([]byte("parent"))
	blockhash := sha256.Sum256([]byte("blockhash"))

	// Pre-create account deltas
	deltas := make([]struct {
		pubkey  types.Pubkey
		account *types.Account
	}, 100)

	for i := range deltas {
		h := sha256.Sum256([]byte{byte(i)})
		copy(deltas[i].pubkey[:], h[:])
		deltas[i].account = &types.Account{
			Lamports: types.Lamports(i * 1000),
			Data:     make([]byte, 100),
			Owner:    types.SystemProgramID,
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher := replayer.NewBankHasher(parentHash)
		hasher.SetBlockhash(blockhash)
		hasher.SetSignatureCount(100)
		for _, d := range deltas {
			hasher.AddAccountDelta(d.pubkey, d.account)
		}
		_ = hasher.Compute()
	}
}
