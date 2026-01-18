package crypto

import (
	"crypto/ed25519"
	"fmt"
	"sync"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// VerifySignature verifies a single Ed25519 signature.
// Returns true if the signature is valid, false otherwise.
//
// Parameters:
//   - pubkey: 32-byte Ed25519 public key
//   - message: the message that was signed
//   - signature: 64-byte Ed25519 signature
//
// Returns false if the public key or signature have invalid lengths.
func VerifySignature(pubkey, message, signature []byte) bool {
	if len(pubkey) != PublicKeySize {
		return false
	}
	if len(signature) != SignatureSize {
		return false
	}
	return ed25519.Verify(pubkey, message, signature)
}

// VerifySignatureStrict is like VerifySignature but returns an error
// with details about why verification failed.
func VerifySignatureStrict(pubkey, message, signature []byte) error {
	if len(pubkey) != PublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidPublicKey, PublicKeySize, len(pubkey))
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, SignatureSize, len(signature))
	}
	if !ed25519.Verify(pubkey, message, signature) {
		return ErrVerificationFailed
	}
	return nil
}

// BatchVerifier accumulates signature verification requests and verifies
// them in batch. This can be more efficient than verifying signatures
// one at a time, especially when hardware acceleration is available.
//
// The current implementation verifies signatures in parallel using
// goroutines. Future implementations may use more sophisticated batch
// verification algorithms.
type BatchVerifier struct {
	mu      sync.Mutex
	entries []batchEntry
}

// batchEntry holds a single verification request.
type batchEntry struct {
	pubkey    []byte
	message   []byte
	signature []byte
}

// NewBatchVerifier creates a new batch verifier.
func NewBatchVerifier() *BatchVerifier {
	return &BatchVerifier{
		entries: make([]batchEntry, 0, 64),
	}
}

// NewBatchVerifierWithCapacity creates a new batch verifier with a
// pre-allocated capacity for the expected number of signatures.
func NewBatchVerifierWithCapacity(capacity int) *BatchVerifier {
	return &BatchVerifier{
		entries: make([]batchEntry, 0, capacity),
	}
}

// Add adds a signature verification request to the batch.
// The pubkey, message, and signature slices are not copied, so they
// must not be modified until Verify() is called.
//
// Returns an error if the pubkey or signature have invalid lengths.
func (bv *BatchVerifier) Add(pubkey, message, signature []byte) error {
	if len(pubkey) != PublicKeySize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidPublicKey, PublicKeySize, len(pubkey))
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidSignature, SignatureSize, len(signature))
	}

	bv.mu.Lock()
	bv.entries = append(bv.entries, batchEntry{
		pubkey:    pubkey,
		message:   message,
		signature: signature,
	})
	bv.mu.Unlock()
	return nil
}

// AddUnchecked adds a signature verification request without checking
// the lengths of the inputs. Use this only when you have already validated
// the input lengths.
func (bv *BatchVerifier) AddUnchecked(pubkey, message, signature []byte) {
	bv.mu.Lock()
	bv.entries = append(bv.entries, batchEntry{
		pubkey:    pubkey,
		message:   message,
		signature: signature,
	})
	bv.mu.Unlock()
}

// Len returns the number of verification requests in the batch.
func (bv *BatchVerifier) Len() int {
	bv.mu.Lock()
	defer bv.mu.Unlock()
	return len(bv.entries)
}

// Reset clears the batch verifier for reuse.
func (bv *BatchVerifier) Reset() {
	bv.mu.Lock()
	bv.entries = bv.entries[:0]
	bv.mu.Unlock()
}

// BatchResult contains the results of a batch verification.
type BatchResult struct {
	// AllValid is true if all signatures in the batch are valid.
	AllValid bool

	// Results contains the verification result for each signature.
	// True means valid, false means invalid.
	Results []bool

	// FirstInvalidIndex is the index of the first invalid signature,
	// or -1 if all signatures are valid.
	FirstInvalidIndex int
}

// Verify verifies all signatures in the batch and returns the results.
// This method is safe to call concurrently with Add(), but the results
// will only include entries that were added before Verify() started.
//
// The current implementation verifies signatures in parallel using
// goroutines for batches larger than a threshold.
func (bv *BatchVerifier) Verify() BatchResult {
	bv.mu.Lock()
	entries := make([]batchEntry, len(bv.entries))
	copy(entries, bv.entries)
	bv.mu.Unlock()

	n := len(entries)
	if n == 0 {
		return BatchResult{
			AllValid:          true,
			Results:           nil,
			FirstInvalidIndex: -1,
		}
	}

	results := make([]bool, n)

	// For small batches, verify sequentially
	if n <= 4 {
		allValid := true
		firstInvalid := -1
		for i, e := range entries {
			valid := ed25519.Verify(e.pubkey, e.message, e.signature)
			results[i] = valid
			if !valid && allValid {
				allValid = false
				firstInvalid = i
			}
		}
		return BatchResult{
			AllValid:          allValid,
			Results:           results,
			FirstInvalidIndex: firstInvalid,
		}
	}

	// For larger batches, verify in parallel
	var wg sync.WaitGroup
	wg.Add(n)

	for i := range entries {
		go func(idx int) {
			defer wg.Done()
			e := entries[idx]
			results[idx] = ed25519.Verify(e.pubkey, e.message, e.signature)
		}(i)
	}

	wg.Wait()

	// Find results
	allValid := true
	firstInvalid := -1
	for i, valid := range results {
		if !valid {
			if allValid {
				allValid = false
				firstInvalid = i
			}
		}
	}

	return BatchResult{
		AllValid:          allValid,
		Results:           results,
		FirstInvalidIndex: firstInvalid,
	}
}

// VerifyBool is a convenience method that returns true if all signatures
// in the batch are valid, false otherwise.
func (bv *BatchVerifier) VerifyBool() bool {
	return bv.Verify().AllValid
}

// VerifyTransaction verifies all signatures on a transaction.
// It serializes the message and verifies each signature against the
// corresponding signer's public key.
//
// Returns nil if all signatures are valid, or an error describing
// which signature failed and why.
func VerifyTransaction(tx *types.Transaction) error {
	if tx == nil {
		return ErrMissingMessage
	}

	numSignatures := len(tx.Signatures)
	if numSignatures == 0 {
		return ErrNoSignatures
	}

	// Get the number of required signatures from the message header
	numRequired := int(tx.Message.Header.NumRequiredSignatures)
	if numSignatures != numRequired {
		return fmt.Errorf("%w: expected %d signatures, got %d",
			ErrSignatureCountMismatch, numRequired, numSignatures)
	}

	// Serialize the message for verification
	messageBytes, err := tx.Message.Serialize()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrMessageSerializationFailed, err)
	}

	// Get signer public keys (first numSignatures account keys)
	accountKeys := tx.Message.AccountKeys
	if len(accountKeys) < numSignatures {
		return fmt.Errorf("%w: not enough account keys for signatures",
			ErrInvalidSignerIndex)
	}

	// Verify each signature
	for i := 0; i < numSignatures; i++ {
		pubkey := accountKeys[i]
		signature := tx.Signatures[i]

		if !ed25519.Verify(pubkey[:], messageBytes, signature[:]) {
			return &TransactionVerificationError{
				SignatureIndex: i,
				SignerPubkey:   pubkey.String(),
				Err:            ErrVerificationFailed,
			}
		}
	}

	return nil
}

// VerifyTransactionBatch verifies signatures for multiple transactions
// using batch verification for improved throughput.
//
// Returns a slice of errors, one for each transaction. A nil error means
// the transaction's signatures are valid.
func VerifyTransactionBatch(txs []*types.Transaction) []error {
	if len(txs) == 0 {
		return nil
	}

	errors := make([]error, len(txs))

	// Count total signatures for capacity estimation
	totalSigs := 0
	for _, tx := range txs {
		if tx != nil {
			totalSigs += len(tx.Signatures)
		}
	}

	// For small batches, verify sequentially
	if totalSigs <= 8 {
		for i, tx := range txs {
			errors[i] = VerifyTransaction(tx)
		}
		return errors
	}

	// Prepare verification data
	type verifyItem struct {
		txIdx    int
		sigIdx   int
		pubkey   []byte
		message  []byte
		signature []byte
	}

	items := make([]verifyItem, 0, totalSigs)
	messages := make([][]byte, len(txs))

	// Serialize messages and prepare verification items
	for txIdx, tx := range txs {
		if tx == nil {
			errors[txIdx] = ErrMissingMessage
			continue
		}

		numSignatures := len(tx.Signatures)
		if numSignatures == 0 {
			errors[txIdx] = ErrNoSignatures
			continue
		}

		numRequired := int(tx.Message.Header.NumRequiredSignatures)
		if numSignatures != numRequired {
			errors[txIdx] = fmt.Errorf("%w: expected %d signatures, got %d",
				ErrSignatureCountMismatch, numRequired, numSignatures)
			continue
		}

		messageBytes, err := tx.Message.Serialize()
		if err != nil {
			errors[txIdx] = fmt.Errorf("%w: %v", ErrMessageSerializationFailed, err)
			continue
		}
		messages[txIdx] = messageBytes

		accountKeys := tx.Message.AccountKeys
		if len(accountKeys) < numSignatures {
			errors[txIdx] = fmt.Errorf("%w: not enough account keys for signatures",
				ErrInvalidSignerIndex)
			continue
		}

		for sigIdx := 0; sigIdx < numSignatures; sigIdx++ {
			items = append(items, verifyItem{
				txIdx:     txIdx,
				sigIdx:    sigIdx,
				pubkey:    accountKeys[sigIdx][:],
				message:   messageBytes,
				signature: tx.Signatures[sigIdx][:],
			})
		}
	}

	// Verify all signatures in parallel
	results := make([]bool, len(items))
	var wg sync.WaitGroup
	wg.Add(len(items))

	for i := range items {
		go func(idx int) {
			defer wg.Done()
			item := items[idx]
			results[idx] = ed25519.Verify(item.pubkey, item.message, item.signature)
		}(i)
	}

	wg.Wait()

	// Process results
	for i, item := range items {
		if !results[i] && errors[item.txIdx] == nil {
			tx := txs[item.txIdx]
			errors[item.txIdx] = &TransactionVerificationError{
				SignatureIndex: item.sigIdx,
				SignerPubkey:   tx.Message.AccountKeys[item.sigIdx].String(),
				Err:            ErrVerificationFailed,
			}
		}
	}

	return errors
}
