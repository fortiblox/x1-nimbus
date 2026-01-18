// Package crypto provides cryptographic utilities for X1-Nimbus.
//
// This package implements Ed25519 signature verification and SHA256 hashing
// functions used throughout the X1-Nimbus validator. It supports both single
// signature verification and batch verification for improved throughput.
//
// The package uses Go's standard library crypto/ed25519 for signature
// verification and crypto/sha256 for hashing. Future optimizations may
// include hardware acceleration and more efficient batch verification
// algorithms.
//
// Key features:
//   - Single Ed25519 signature verification
//   - Batch Ed25519 signature verification for transaction batches
//   - Transaction signature verification
//   - SHA256 hashing utilities compatible with Solana's hashv
//
// Example usage:
//
//	// Single signature verification
//	valid := crypto.VerifySignature(pubkey, message, signature)
//
//	// Batch verification
//	verifier := crypto.NewBatchVerifier()
//	verifier.Add(pubkey1, message1, sig1)
//	verifier.Add(pubkey2, message2, sig2)
//	valid, results := verifier.Verify()
//
//	// Transaction verification
//	err := crypto.VerifyTransaction(tx)
package crypto

import (
	"errors"
)

// Signature and key sizes for Ed25519.
const (
	// PublicKeySize is the size of an Ed25519 public key in bytes.
	PublicKeySize = 32

	// SignatureSize is the size of an Ed25519 signature in bytes.
	SignatureSize = 64

	// PrivateKeySize is the size of an Ed25519 private key in bytes.
	PrivateKeySize = 64

	// SeedSize is the size of an Ed25519 seed in bytes.
	SeedSize = 32
)

// Hash sizes.
const (
	// HashSize is the size of a SHA256 hash in bytes.
	HashSize = 32
)

// Common errors returned by the crypto package.
var (
	// ErrInvalidPublicKey is returned when a public key has an invalid format.
	ErrInvalidPublicKey = errors.New("crypto: invalid public key")

	// ErrInvalidSignature is returned when a signature has an invalid format.
	ErrInvalidSignature = errors.New("crypto: invalid signature")

	// ErrVerificationFailed is returned when signature verification fails.
	ErrVerificationFailed = errors.New("crypto: signature verification failed")

	// ErrNoSignatures is returned when a transaction has no signatures.
	ErrNoSignatures = errors.New("crypto: transaction has no signatures")

	// ErrSignatureCountMismatch is returned when the number of signatures
	// does not match the expected number of signers.
	ErrSignatureCountMismatch = errors.New("crypto: signature count mismatch")

	// ErrMissingMessage is returned when a transaction message is nil.
	ErrMissingMessage = errors.New("crypto: missing transaction message")

	// ErrInvalidSignerIndex is returned when a signer index is out of bounds.
	ErrInvalidSignerIndex = errors.New("crypto: invalid signer index")

	// ErrMessageSerializationFailed is returned when message serialization fails.
	ErrMessageSerializationFailed = errors.New("crypto: message serialization failed")
)

// VerificationError contains details about a signature verification failure.
type VerificationError struct {
	// Index is the index of the signature that failed (for batch verification).
	Index int

	// Pubkey is the base58 representation of the public key.
	Pubkey string

	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *VerificationError) Error() string {
	if e.Pubkey != "" {
		return "crypto: verification failed for pubkey " + e.Pubkey + ": " + e.Err.Error()
	}
	return "crypto: verification failed at index " + string(rune('0'+e.Index)) + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *VerificationError) Unwrap() error {
	return e.Err
}

// TransactionVerificationError contains details about a transaction verification failure.
type TransactionVerificationError struct {
	// SignatureIndex is the index of the signature that failed verification.
	SignatureIndex int

	// SignerPubkey is the base58 representation of the signer's public key.
	SignerPubkey string

	// Err is the underlying error.
	Err error
}

// Error implements the error interface.
func (e *TransactionVerificationError) Error() string {
	return "crypto: transaction verification failed for signer " + e.SignerPubkey +
		" (signature index " + itoa(e.SignatureIndex) + "): " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *TransactionVerificationError) Unwrap() error {
	return e.Err
}

// itoa is a simple integer to string conversion without fmt dependency.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
