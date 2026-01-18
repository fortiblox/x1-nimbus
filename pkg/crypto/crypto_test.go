package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Helper function to generate keypairs
func generateKeypair() (ed25519.PublicKey, ed25519.PrivateKey) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return pub, priv
}

// Helper function to create pubkey from ed25519.PublicKey
func pubkeyFromEd25519(pub ed25519.PublicKey) types.Pubkey {
	var pk types.Pubkey
	copy(pk[:], pub)
	return pk
}

// Helper function to create signature from ed25519 signature bytes
func signatureFromBytes(sigBytes []byte) types.Signature {
	var sig types.Signature
	copy(sig[:], sigBytes)
	return sig
}

// Tests for VerifySignature
func TestVerifySignature_Valid(t *testing.T) {
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	valid := VerifySignature(pub, message, signature)
	if !valid {
		t.Error("valid signature should verify")
	}
}

func TestVerifySignature_InvalidSignature(t *testing.T) {
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	// Corrupt the signature
	signature[0] ^= 0xff

	valid := VerifySignature(pub, message, signature)
	if valid {
		t.Error("corrupted signature should not verify")
	}
}

func TestVerifySignature_WrongMessage(t *testing.T) {
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	wrongMessage := []byte("wrong message")
	valid := VerifySignature(pub, wrongMessage, signature)
	if valid {
		t.Error("signature for wrong message should not verify")
	}
}

func TestVerifySignature_WrongKey(t *testing.T) {
	_, priv := generateKeypair()
	otherPub, _ := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	valid := VerifySignature(otherPub, message, signature)
	if valid {
		t.Error("signature with wrong key should not verify")
	}
}

func TestVerifySignature_InvalidKeyLength(t *testing.T) {
	message := []byte("test message")
	signature := make([]byte, 64)

	// Too short key
	valid := VerifySignature([]byte{1, 2, 3}, message, signature)
	if valid {
		t.Error("too short key should fail")
	}

	// Too long key
	valid = VerifySignature(make([]byte, 64), message, signature)
	if valid {
		t.Error("too long key should fail")
	}
}

func TestVerifySignature_InvalidSignatureLength(t *testing.T) {
	pub, _ := generateKeypair()
	message := []byte("test message")

	// Too short signature
	valid := VerifySignature(pub, message, []byte{1, 2, 3})
	if valid {
		t.Error("too short signature should fail")
	}

	// Too long signature
	valid = VerifySignature(pub, message, make([]byte, 128))
	if valid {
		t.Error("too long signature should fail")
	}
}

// Tests for VerifySignatureStrict
func TestVerifySignatureStrict_Valid(t *testing.T) {
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	err := VerifySignatureStrict(pub, message, signature)
	if err != nil {
		t.Errorf("valid signature should verify: %v", err)
	}
}

func TestVerifySignatureStrict_InvalidKeyLength(t *testing.T) {
	message := []byte("test message")
	signature := make([]byte, 64)

	err := VerifySignatureStrict([]byte{1, 2, 3}, message, signature)
	if err == nil {
		t.Error("should error for invalid key length")
	}
}

func TestVerifySignatureStrict_InvalidSignatureLength(t *testing.T) {
	pub, _ := generateKeypair()
	message := []byte("test message")

	err := VerifySignatureStrict(pub, message, []byte{1, 2, 3})
	if err == nil {
		t.Error("should error for invalid signature length")
	}
}

func TestVerifySignatureStrict_VerificationFailed(t *testing.T) {
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)
	signature[0] ^= 0xff // Corrupt

	err := VerifySignatureStrict(pub, message, signature)
	if err == nil {
		t.Error("should error for failed verification")
	}
	if err != ErrVerificationFailed {
		t.Errorf("expected ErrVerificationFailed, got: %v", err)
	}
}

// Tests for BatchVerifier
func TestBatchVerifier_NewBatchVerifier(t *testing.T) {
	bv := NewBatchVerifier()
	if bv == nil {
		t.Fatal("NewBatchVerifier returned nil")
	}

	if bv.Len() != 0 {
		t.Error("new batch verifier should be empty")
	}
}

func TestBatchVerifier_NewBatchVerifierWithCapacity(t *testing.T) {
	bv := NewBatchVerifierWithCapacity(100)
	if bv == nil {
		t.Fatal("NewBatchVerifierWithCapacity returned nil")
	}

	if bv.Len() != 0 {
		t.Error("new batch verifier should be empty")
	}
}

func TestBatchVerifier_Add(t *testing.T) {
	bv := NewBatchVerifier()
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	err := bv.Add(pub, message, signature)
	if err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	if bv.Len() != 1 {
		t.Errorf("expected length 1, got %d", bv.Len())
	}
}

func TestBatchVerifier_Add_InvalidKey(t *testing.T) {
	bv := NewBatchVerifier()
	message := []byte("test message")
	signature := make([]byte, 64)

	err := bv.Add([]byte{1, 2, 3}, message, signature)
	if err == nil {
		t.Error("should error for invalid key")
	}
}

func TestBatchVerifier_Add_InvalidSignature(t *testing.T) {
	bv := NewBatchVerifier()
	pub, _ := generateKeypair()
	message := []byte("test message")

	err := bv.Add(pub, message, []byte{1, 2, 3})
	if err == nil {
		t.Error("should error for invalid signature")
	}
}

func TestBatchVerifier_AddUnchecked(t *testing.T) {
	bv := NewBatchVerifier()
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	bv.AddUnchecked(pub, message, signature)

	if bv.Len() != 1 {
		t.Errorf("expected length 1, got %d", bv.Len())
	}
}

func TestBatchVerifier_Verify_Empty(t *testing.T) {
	bv := NewBatchVerifier()

	result := bv.Verify()
	if !result.AllValid {
		t.Error("empty batch should be all valid")
	}
	if result.FirstInvalidIndex != -1 {
		t.Errorf("expected first invalid index -1, got %d", result.FirstInvalidIndex)
	}
}

func TestBatchVerifier_Verify_SingleValid(t *testing.T) {
	bv := NewBatchVerifier()
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	_ = bv.Add(pub, message, signature)

	result := bv.Verify()
	if !result.AllValid {
		t.Error("single valid signature should verify")
	}
	if len(result.Results) != 1 || !result.Results[0] {
		t.Error("result should show valid signature")
	}
}

func TestBatchVerifier_Verify_SingleInvalid(t *testing.T) {
	bv := NewBatchVerifier()
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)
	signature[0] ^= 0xff // Corrupt

	_ = bv.Add(pub, message, signature)

	result := bv.Verify()
	if result.AllValid {
		t.Error("corrupted signature should not verify")
	}
	if result.FirstInvalidIndex != 0 {
		t.Errorf("expected first invalid index 0, got %d", result.FirstInvalidIndex)
	}
}

func TestBatchVerifier_Verify_MultipleValid(t *testing.T) {
	bv := NewBatchVerifier()

	for i := 0; i < 10; i++ {
		pub, priv := generateKeypair()
		message := []byte("test message " + string(rune('0'+i)))
		signature := ed25519.Sign(priv, message)
		_ = bv.Add(pub, message, signature)
	}

	result := bv.Verify()
	if !result.AllValid {
		t.Error("all valid signatures should verify")
	}
	if len(result.Results) != 10 {
		t.Errorf("expected 10 results, got %d", len(result.Results))
	}
	for i, r := range result.Results {
		if !r {
			t.Errorf("signature %d should be valid", i)
		}
	}
}

func TestBatchVerifier_Verify_MixedValidity(t *testing.T) {
	bv := NewBatchVerifier()

	// Add valid signatures
	for i := 0; i < 5; i++ {
		pub, priv := generateKeypair()
		message := []byte("test message " + string(rune('0'+i)))
		signature := ed25519.Sign(priv, message)
		_ = bv.Add(pub, message, signature)
	}

	// Add invalid signature at index 5
	pub, priv := generateKeypair()
	message := []byte("invalid message")
	signature := ed25519.Sign(priv, message)
	signature[0] ^= 0xff // Corrupt
	_ = bv.Add(pub, message, signature)

	// Add more valid signatures
	for i := 0; i < 5; i++ {
		pub, priv := generateKeypair()
		message := []byte("test message " + string(rune('a'+i)))
		signature := ed25519.Sign(priv, message)
		_ = bv.Add(pub, message, signature)
	}

	result := bv.Verify()
	if result.AllValid {
		t.Error("batch with invalid signature should not be all valid")
	}
	if result.FirstInvalidIndex != 5 {
		t.Errorf("expected first invalid index 5, got %d", result.FirstInvalidIndex)
	}
}

func TestBatchVerifier_Verify_Parallel(t *testing.T) {
	// Force parallel verification by adding more than 4 signatures
	bv := NewBatchVerifier()

	for i := 0; i < 20; i++ {
		pub, priv := generateKeypair()
		message := []byte("test message " + string(rune(i)))
		signature := ed25519.Sign(priv, message)
		_ = bv.Add(pub, message, signature)
	}

	result := bv.Verify()
	if !result.AllValid {
		t.Error("all valid signatures should verify in parallel")
	}
}

func TestBatchVerifier_VerifyBool(t *testing.T) {
	bv := NewBatchVerifier()
	pub, priv := generateKeypair()
	message := []byte("test message")
	signature := ed25519.Sign(priv, message)

	_ = bv.Add(pub, message, signature)

	valid := bv.VerifyBool()
	if !valid {
		t.Error("valid signature should return true")
	}
}

func TestBatchVerifier_Reset(t *testing.T) {
	bv := NewBatchVerifier()

	for i := 0; i < 5; i++ {
		pub, priv := generateKeypair()
		message := []byte("test message " + string(rune('0'+i)))
		signature := ed25519.Sign(priv, message)
		_ = bv.Add(pub, message, signature)
	}

	bv.Reset()

	if bv.Len() != 0 {
		t.Errorf("expected length 0 after reset, got %d", bv.Len())
	}
}

// Tests for VerifyTransaction
func TestVerifyTransaction_Valid(t *testing.T) {
	pub, priv := generateKeypair()
	toPub, _ := generateKeypair()

	fromPubkey := pubkeyFromEd25519(pub)
	toPubkey := pubkeyFromEd25519(toPub)

	msg := types.Message{
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
		RecentBlockhash: sha256.Sum256([]byte("blockhash")),
		Instructions: []types.CompiledInstruction{
			{
				ProgramIDIndex: 2,
				AccountIndices: []uint8{0, 1},
				Data:           []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
	}

	msgBytes, _ := msg.Serialize()
	sigBytes := ed25519.Sign(priv, msgBytes)
	sig := signatureFromBytes(sigBytes)

	tx := &types.Transaction{
		Signatures: []types.Signature{sig},
		Message:    msg,
	}

	err := VerifyTransaction(tx)
	if err != nil {
		t.Errorf("valid transaction should verify: %v", err)
	}
}

func TestVerifyTransaction_Nil(t *testing.T) {
	err := VerifyTransaction(nil)
	if err == nil {
		t.Error("nil transaction should error")
	}
}

func TestVerifyTransaction_NoSignatures(t *testing.T) {
	tx := &types.Transaction{
		Signatures: nil,
		Message: types.Message{
			Header: types.MessageHeader{NumRequiredSignatures: 1},
		},
	}

	err := VerifyTransaction(tx)
	if err == nil {
		t.Error("transaction with no signatures should error")
	}
}

func TestVerifyTransaction_SignatureCountMismatch(t *testing.T) {
	pub, _ := generateKeypair()
	pubkey := pubkeyFromEd25519(pub)

	tx := &types.Transaction{
		Signatures: []types.Signature{types.ZeroSignature, types.ZeroSignature},
		Message: types.Message{
			Header: types.MessageHeader{
				NumRequiredSignatures: 1, // Only expects 1
			},
			AccountKeys: []types.Pubkey{pubkey},
		},
	}

	err := VerifyTransaction(tx)
	if err == nil {
		t.Error("signature count mismatch should error")
	}
}

func TestVerifyTransaction_InvalidSignature(t *testing.T) {
	pub, _ := generateKeypair()
	toPub, _ := generateKeypair()

	fromPubkey := pubkeyFromEd25519(pub)
	toPubkey := pubkeyFromEd25519(toPub)

	tx := &types.Transaction{
		Signatures: []types.Signature{types.ZeroSignature}, // Invalid signature
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
			RecentBlockhash: sha256.Sum256([]byte("blockhash")),
			Instructions: []types.CompiledInstruction{
				{
					ProgramIDIndex: 2,
					AccountIndices: []uint8{0, 1},
					Data:           []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
				},
			},
		},
	}

	err := VerifyTransaction(tx)
	if err == nil {
		t.Error("invalid signature should error")
	}
}

func TestVerifyTransaction_MultipleSigners(t *testing.T) {
	pub1, priv1 := generateKeypair()
	pub2, priv2 := generateKeypair()

	pubkey1 := pubkeyFromEd25519(pub1)
	pubkey2 := pubkeyFromEd25519(pub2)

	msg := types.Message{
		Header: types.MessageHeader{
			NumRequiredSignatures:       2,
			NumReadonlySignedAccounts:   0,
			NumReadonlyUnsignedAccounts: 1,
		},
		AccountKeys: []types.Pubkey{
			pubkey1,
			pubkey2,
			types.SystemProgramID,
		},
		RecentBlockhash: sha256.Sum256([]byte("blockhash")),
		Instructions: []types.CompiledInstruction{
			{
				ProgramIDIndex: 2,
				AccountIndices: []uint8{0, 1},
				Data:           []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			},
		},
	}

	msgBytes, _ := msg.Serialize()
	sig1 := signatureFromBytes(ed25519.Sign(priv1, msgBytes))
	sig2 := signatureFromBytes(ed25519.Sign(priv2, msgBytes))

	tx := &types.Transaction{
		Signatures: []types.Signature{sig1, sig2},
		Message:    msg,
	}

	err := VerifyTransaction(tx)
	if err != nil {
		t.Errorf("valid multi-signer transaction should verify: %v", err)
	}
}

// Tests for VerifyTransactionBatch
func TestVerifyTransactionBatch_Empty(t *testing.T) {
	errs := VerifyTransactionBatch(nil)
	if errs != nil {
		t.Error("empty batch should return nil")
	}

	errs = VerifyTransactionBatch([]*types.Transaction{})
	if errs != nil {
		t.Error("empty slice should return nil")
	}
}

func TestVerifyTransactionBatch_SingleValid(t *testing.T) {
	pub, priv := generateKeypair()
	toPub, _ := generateKeypair()

	fromPubkey := pubkeyFromEd25519(pub)
	toPubkey := pubkeyFromEd25519(toPub)

	msg := types.Message{
		Header: types.MessageHeader{
			NumRequiredSignatures:       1,
			NumReadonlySignedAccounts:   0,
			NumReadonlyUnsignedAccounts: 1,
		},
		AccountKeys:     []types.Pubkey{fromPubkey, toPubkey, types.SystemProgramID},
		RecentBlockhash: sha256.Sum256([]byte("blockhash")),
		Instructions: []types.CompiledInstruction{
			{ProgramIDIndex: 2, AccountIndices: []uint8{0, 1}, Data: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		},
	}

	msgBytes, _ := msg.Serialize()
	sig := signatureFromBytes(ed25519.Sign(priv, msgBytes))

	tx := &types.Transaction{
		Signatures: []types.Signature{sig},
		Message:    msg,
	}

	errs := VerifyTransactionBatch([]*types.Transaction{tx})
	if len(errs) != 1 {
		t.Fatalf("expected 1 result, got %d", len(errs))
	}
	if errs[0] != nil {
		t.Errorf("valid transaction should have nil error: %v", errs[0])
	}
}

func TestVerifyTransactionBatch_MixedValidity(t *testing.T) {
	// Create valid transaction
	pub, priv := generateKeypair()
	toPub, _ := generateKeypair()

	fromPubkey := pubkeyFromEd25519(pub)
	toPubkey := pubkeyFromEd25519(toPub)

	msg := types.Message{
		Header: types.MessageHeader{
			NumRequiredSignatures:       1,
			NumReadonlySignedAccounts:   0,
			NumReadonlyUnsignedAccounts: 1,
		},
		AccountKeys:     []types.Pubkey{fromPubkey, toPubkey, types.SystemProgramID},
		RecentBlockhash: sha256.Sum256([]byte("blockhash")),
		Instructions: []types.CompiledInstruction{
			{ProgramIDIndex: 2, AccountIndices: []uint8{0, 1}, Data: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		},
	}

	msgBytes, _ := msg.Serialize()
	validSig := signatureFromBytes(ed25519.Sign(priv, msgBytes))

	validTx := &types.Transaction{
		Signatures: []types.Signature{validSig},
		Message:    msg,
	}

	invalidTx := &types.Transaction{
		Signatures: []types.Signature{types.ZeroSignature},
		Message:    msg,
	}

	errs := VerifyTransactionBatch([]*types.Transaction{validTx, invalidTx, validTx})
	if len(errs) != 3 {
		t.Fatalf("expected 3 results, got %d", len(errs))
	}

	if errs[0] != nil {
		t.Errorf("first tx should be valid: %v", errs[0])
	}
	if errs[1] == nil {
		t.Error("second tx should be invalid")
	}
	if errs[2] != nil {
		t.Errorf("third tx should be valid: %v", errs[2])
	}
}

func TestVerifyTransactionBatch_NilTransaction(t *testing.T) {
	errs := VerifyTransactionBatch([]*types.Transaction{nil})
	if len(errs) != 1 {
		t.Fatalf("expected 1 result, got %d", len(errs))
	}
	if errs[0] == nil {
		t.Error("nil transaction should have error")
	}
}

func TestVerifyTransactionBatch_LargeBatch(t *testing.T) {
	// Create 20 valid transactions to force parallel processing
	txs := make([]*types.Transaction, 20)

	for i := 0; i < 20; i++ {
		pub, priv := generateKeypair()
		toPub, _ := generateKeypair()

		fromPubkey := pubkeyFromEd25519(pub)
		toPubkey := pubkeyFromEd25519(toPub)

		msg := types.Message{
			Header: types.MessageHeader{
				NumRequiredSignatures:       1,
				NumReadonlySignedAccounts:   0,
				NumReadonlyUnsignedAccounts: 1,
			},
			AccountKeys:     []types.Pubkey{fromPubkey, toPubkey, types.SystemProgramID},
			RecentBlockhash: sha256.Sum256([]byte("blockhash" + string(rune(i)))),
			Instructions: []types.CompiledInstruction{
				{ProgramIDIndex: 2, AccountIndices: []uint8{0, 1}, Data: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			},
		}

		msgBytes, _ := msg.Serialize()
		sig := signatureFromBytes(ed25519.Sign(priv, msgBytes))

		txs[i] = &types.Transaction{
			Signatures: []types.Signature{sig},
			Message:    msg,
		}
	}

	errs := VerifyTransactionBatch(txs)
	if len(errs) != 20 {
		t.Fatalf("expected 20 results, got %d", len(errs))
	}

	for i, err := range errs {
		if err != nil {
			t.Errorf("transaction %d should be valid: %v", i, err)
		}
	}
}

// Tests for SHA256 operations
func TestHash(t *testing.T) {
	data := []byte("test data")
	hash1 := Hash(data)

	if hash1 == [32]byte{} {
		t.Error("hash should not be zero")
	}

	// Verify determinism
	hash2 := Hash(data)
	if hash1 != hash2 {
		t.Error("hash should be deterministic")
	}

	// Different data should give different hash
	hash3 := Hash([]byte("other data"))
	if hash1 == hash3 {
		t.Error("different data should give different hash")
	}
}

func TestHash_Empty(t *testing.T) {
	hash := Hash(nil)
	// SHA256 of empty data is a specific value
	expected := sha256.Sum256(nil)
	if hash != expected {
		t.Error("empty data should give standard SHA256 empty hash")
	}
}

func TestHashMulti(t *testing.T) {
	part1 := []byte("hello")
	part2 := []byte(" ")
	part3 := []byte("world")

	hash1 := HashMulti(part1, part2, part3)

	// Should equal hash of concatenated data
	expected := sha256.Sum256([]byte("hello world"))
	if hash1 != expected {
		t.Error("HashMulti should equal hash of concatenated data")
	}
}

func TestHashMulti_Empty(t *testing.T) {
	hash := HashMulti()
	expected := sha256.Sum256(nil)
	if hash != expected {
		t.Error("empty HashMulti should give standard SHA256 empty hash")
	}
}

func TestHashv(t *testing.T) {
	slices := [][]byte{
		[]byte("hello"),
		[]byte(" "),
		[]byte("world"),
	}

	hash1 := Hashv(slices)

	// Should equal hash of concatenated data
	expected := sha256.Sum256([]byte("hello world"))
	if hash1 != expected {
		t.Error("Hashv should equal hash of concatenated data")
	}
}

func TestHashToBytes(t *testing.T) {
	data := []byte("test data")
	hashBytes := HashToBytes(data)

	if len(hashBytes) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(hashBytes))
	}

	expected := sha256.Sum256(data)
	if !bytes.Equal(hashBytes, expected[:]) {
		t.Error("HashToBytes should equal standard SHA256")
	}
}

// Tests for HashReader
func TestHashReader_NewHashReader(t *testing.T) {
	hr := NewHashReader()
	if hr == nil {
		t.Fatal("NewHashReader returned nil")
	}
}

func TestHashReader_Write(t *testing.T) {
	hr := NewHashReader()

	n, err := hr.Write([]byte("hello"))
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	if n != 5 {
		t.Errorf("expected 5 bytes written, got %d", n)
	}
}

func TestHashReader_Sum(t *testing.T) {
	hr := NewHashReader()
	_, _ = hr.Write([]byte("hello world"))

	hash1 := hr.Sum()

	expected := sha256.Sum256([]byte("hello world"))
	if hash1 != expected {
		t.Error("HashReader.Sum should equal standard SHA256")
	}

	// Sum should not reset the reader
	hash2 := hr.Sum()
	if hash1 != hash2 {
		t.Error("repeated Sum calls should give same result")
	}
}

func TestHashReader_Incremental(t *testing.T) {
	hr := NewHashReader()
	_, _ = hr.Write([]byte("hello"))
	_, _ = hr.Write([]byte(" "))
	_, _ = hr.Write([]byte("world"))

	hash := hr.Sum()

	expected := sha256.Sum256([]byte("hello world"))
	if hash != expected {
		t.Error("incremental writes should equal single write hash")
	}
}

func TestHashReader_Reset(t *testing.T) {
	hr := NewHashReader()
	_, _ = hr.Write([]byte("initial data"))
	hr.Reset()
	_, _ = hr.Write([]byte("new data"))

	hash := hr.Sum()

	expected := sha256.Sum256([]byte("new data"))
	if hash != expected {
		t.Error("Reset should clear previous writes")
	}
}

// Tests for error types
func TestVerificationError(t *testing.T) {
	err := &VerificationError{
		Index:  5,
		Pubkey: "TestPubkey123",
		Err:    ErrVerificationFailed,
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("error string should not be empty")
	}

	unwrapped := err.Unwrap()
	if unwrapped != ErrVerificationFailed {
		t.Error("Unwrap should return underlying error")
	}
}

func TestTransactionVerificationError(t *testing.T) {
	err := &TransactionVerificationError{
		SignatureIndex: 2,
		SignerPubkey:   "TestPubkey456",
		Err:            ErrVerificationFailed,
	}

	errStr := err.Error()
	if errStr == "" {
		t.Error("error string should not be empty")
	}

	unwrapped := err.Unwrap()
	if unwrapped != ErrVerificationFailed {
		t.Error("Unwrap should return underlying error")
	}
}

// Benchmark tests
func BenchmarkVerifySignature(b *testing.B) {
	pub, priv := generateKeypair()
	message := []byte("benchmark message for signature verification")
	signature := ed25519.Sign(priv, message)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifySignature(pub, message, signature)
	}
}

func BenchmarkBatchVerifier_10(b *testing.B) {
	// Pre-generate signatures
	type entry struct {
		pub ed25519.PublicKey
		msg []byte
		sig []byte
	}
	entries := make([]entry, 10)
	for i := 0; i < 10; i++ {
		pub, priv := generateKeypair()
		msg := []byte("message " + string(rune(i)))
		sig := ed25519.Sign(priv, msg)
		entries[i] = entry{pub, msg, sig}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bv := NewBatchVerifierWithCapacity(10)
		for _, e := range entries {
			bv.AddUnchecked(e.pub, e.msg, e.sig)
		}
		bv.Verify()
	}
}

func BenchmarkBatchVerifier_100(b *testing.B) {
	type entry struct {
		pub ed25519.PublicKey
		msg []byte
		sig []byte
	}
	entries := make([]entry, 100)
	for i := 0; i < 100; i++ {
		pub, priv := generateKeypair()
		msg := []byte("message " + string(rune(i)))
		sig := ed25519.Sign(priv, msg)
		entries[i] = entry{pub, msg, sig}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bv := NewBatchVerifierWithCapacity(100)
		for _, e := range entries {
			bv.AddUnchecked(e.pub, e.msg, e.sig)
		}
		bv.Verify()
	}
}

func BenchmarkHash(b *testing.B) {
	data := make([]byte, 1024)
	_, _ = rand.Read(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Hash(data)
	}
}

func BenchmarkHashReader_1KB(b *testing.B) {
	data := make([]byte, 1024)
	_, _ = rand.Read(data)
	hr := NewHashReader()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hr.Reset()
		_, _ = hr.Write(data)
		_ = hr.Sum()
	}
}

func BenchmarkVerifyTransaction(b *testing.B) {
	pub, priv := generateKeypair()
	toPub, _ := generateKeypair()

	fromPubkey := pubkeyFromEd25519(pub)
	toPubkey := pubkeyFromEd25519(toPub)

	msg := types.Message{
		Header: types.MessageHeader{
			NumRequiredSignatures:       1,
			NumReadonlySignedAccounts:   0,
			NumReadonlyUnsignedAccounts: 1,
		},
		AccountKeys:     []types.Pubkey{fromPubkey, toPubkey, types.SystemProgramID},
		RecentBlockhash: sha256.Sum256([]byte("blockhash")),
		Instructions: []types.CompiledInstruction{
			{ProgramIDIndex: 2, AccountIndices: []uint8{0, 1}, Data: []byte{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		},
	}

	msgBytes, _ := msg.Serialize()
	sig := signatureFromBytes(ed25519.Sign(priv, msgBytes))

	tx := &types.Transaction{
		Signatures: []types.Signature{sig},
		Message:    msg,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		VerifyTransaction(tx)
	}
}
