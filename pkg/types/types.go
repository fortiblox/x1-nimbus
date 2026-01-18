// Package types provides core Solana/X1 data types for X1-Nimbus.
package types

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/mr-tron/base58"
)

// Hash represents a 32-byte SHA256 hash.
type Hash [32]byte

// ZeroHash is an all-zero hash.
var ZeroHash Hash

// HashFromBytes creates a Hash from a byte slice.
func HashFromBytes(b []byte) (Hash, error) {
	if len(b) != 32 {
		return Hash{}, fmt.Errorf("hash must be 32 bytes, got %d", len(b))
	}
	var h Hash
	copy(h[:], b)
	return h, nil
}

// HashFromBase58 decodes a base58 string into a Hash.
func HashFromBase58(s string) (Hash, error) {
	b, err := base58.Decode(s)
	if err != nil {
		return Hash{}, fmt.Errorf("invalid base58: %w", err)
	}
	return HashFromBytes(b)
}

// Bytes returns the hash as a byte slice.
func (h Hash) Bytes() []byte {
	return h[:]
}

// String returns the base58 representation.
func (h Hash) String() string {
	return base58.Encode(h[:])
}

// Hex returns the hex representation.
func (h Hash) Hex() string {
	return hex.EncodeToString(h[:])
}

// IsZero returns true if the hash is all zeros.
func (h Hash) IsZero() bool {
	return h == ZeroHash
}

// SHA256 computes SHA256 hash of data.
func SHA256(data []byte) Hash {
	return sha256.Sum256(data)
}

// SHA256Multi computes SHA256 hash of multiple byte slices.
func SHA256Multi(data ...[]byte) Hash {
	h := sha256.New()
	for _, d := range data {
		h.Write(d)
	}
	var result Hash
	copy(result[:], h.Sum(nil))
	return result
}

// Pubkey represents a 32-byte Ed25519 public key.
type Pubkey [32]byte

// ZeroPubkey is an all-zero pubkey.
var ZeroPubkey Pubkey

// Common program IDs
var (
	SystemProgramID            = MustPubkeyFromBase58("11111111111111111111111111111111")
	TokenProgramID             = MustPubkeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	Token2022ProgramID         = MustPubkeyFromBase58("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb")
	AssociatedTokenProgramID   = MustPubkeyFromBase58("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	VoteProgramID              = MustPubkeyFromBase58("Vote111111111111111111111111111111111111111")
	StakeProgramID             = MustPubkeyFromBase58("Stake11111111111111111111111111111111111111")
	ConfigProgramID            = MustPubkeyFromBase58("Config1111111111111111111111111111111111111")
	BPFLoaderProgramID         = MustPubkeyFromBase58("BPFLoader1111111111111111111111111111111111")
	BPFLoader2ProgramID        = MustPubkeyFromBase58("BPFLoader2111111111111111111111111111111111")
	BPFLoaderUpgradeableProgramID = MustPubkeyFromBase58("BPFLoaderUpgradeab1e11111111111111111111111")
	ComputeBudgetProgramID     = MustPubkeyFromBase58("ComputeBudget111111111111111111111111111111")
	AddressLookupTableProgramID = MustPubkeyFromBase58("AddressLookupTab1e1111111111111111111111111")
	Ed25519ProgramID           = MustPubkeyFromBase58("Ed25519SigVerify111111111111111111111111111")
	Secp256k1ProgramID         = MustPubkeyFromBase58("KeccakSecp256k11111111111111111111111111111")
	NativeLoaderID             = MustPubkeyFromBase58("NativeLoader1111111111111111111111111111111")
	SysvarClockID              = MustPubkeyFromBase58("SysvarC1ock11111111111111111111111111111111")
	SysvarRentID               = MustPubkeyFromBase58("SysvarRent111111111111111111111111111111111")
	SysvarSlotHashesID         = MustPubkeyFromBase58("SysvarS1otHashes111111111111111111111111111")
	SysvarRecentBlockhashesID  = MustPubkeyFromBase58("SysvarRecentB1ockHashes11111111111111111111")
	SysvarInstructionsID       = MustPubkeyFromBase58("Sysvar1nstructions1111111111111111111111111")
	SysvarStakeHistoryID       = MustPubkeyFromBase58("SysvarStakeHistory1111111111111111111111111")
	SysvarEpochScheduleID      = MustPubkeyFromBase58("SysvarEpochSchedu1e111111111111111111111111")
)

// PubkeyFromBytes creates a Pubkey from a byte slice.
func PubkeyFromBytes(b []byte) (Pubkey, error) {
	if len(b) != 32 {
		return Pubkey{}, fmt.Errorf("pubkey must be 32 bytes, got %d", len(b))
	}
	var pk Pubkey
	copy(pk[:], b)
	return pk, nil
}

// PubkeyFromBase58 decodes a base58 string into a Pubkey.
func PubkeyFromBase58(s string) (Pubkey, error) {
	b, err := base58.Decode(s)
	if err != nil {
		return Pubkey{}, fmt.Errorf("invalid base58: %w", err)
	}
	return PubkeyFromBytes(b)
}

// MustPubkeyFromBase58 decodes a base58 string or panics.
func MustPubkeyFromBase58(s string) Pubkey {
	pk, err := PubkeyFromBase58(s)
	if err != nil {
		panic(err)
	}
	return pk
}

// Bytes returns the pubkey as a byte slice.
func (pk Pubkey) Bytes() []byte {
	return pk[:]
}

// String returns the base58 representation.
func (pk Pubkey) String() string {
	return base58.Encode(pk[:])
}

// IsZero returns true if the pubkey is all zeros.
func (pk Pubkey) IsZero() bool {
	return pk == ZeroPubkey
}

// IsSystemProgram returns true if this is the System Program.
func (pk Pubkey) IsSystemProgram() bool {
	return pk == SystemProgramID
}

// IsNativeProgram returns true if this is a native program.
func (pk Pubkey) IsNativeProgram() bool {
	return pk == SystemProgramID ||
		pk == VoteProgramID ||
		pk == StakeProgramID ||
		pk == ConfigProgramID ||
		pk == TokenProgramID ||
		pk == Token2022ProgramID ||
		pk == AssociatedTokenProgramID ||
		pk == BPFLoaderProgramID ||
		pk == BPFLoader2ProgramID ||
		pk == BPFLoaderUpgradeableProgramID ||
		pk == ComputeBudgetProgramID ||
		pk == AddressLookupTableProgramID ||
		pk == Ed25519ProgramID ||
		pk == Secp256k1ProgramID
}

// Signature represents a 64-byte Ed25519 signature.
type Signature [64]byte

// ZeroSignature is an all-zero signature.
var ZeroSignature Signature

// SignatureFromBytes creates a Signature from a byte slice.
func SignatureFromBytes(b []byte) (Signature, error) {
	if len(b) != 64 {
		return Signature{}, fmt.Errorf("signature must be 64 bytes, got %d", len(b))
	}
	var sig Signature
	copy(sig[:], b)
	return sig, nil
}

// SignatureFromBase58 decodes a base58 string into a Signature.
func SignatureFromBase58(s string) (Signature, error) {
	b, err := base58.Decode(s)
	if err != nil {
		return Signature{}, fmt.Errorf("invalid base58: %w", err)
	}
	return SignatureFromBytes(b)
}

// Bytes returns the signature as a byte slice.
func (sig Signature) Bytes() []byte {
	return sig[:]
}

// String returns the base58 representation.
func (sig Signature) String() string {
	return base58.Encode(sig[:])
}

// IsZero returns true if the signature is all zeros.
func (sig Signature) IsZero() bool {
	return sig == ZeroSignature
}

// Slot represents a slot number.
type Slot uint64

// Epoch represents an epoch number.
type Epoch uint64

// Lamports represents a lamport amount (1 SOL = 1_000_000_000 lamports).
type Lamports uint64

// SOL converts lamports to SOL.
func (l Lamports) SOL() float64 {
	return float64(l) / 1_000_000_000
}

// LamportsFromSOL converts SOL to lamports.
func LamportsFromSOL(sol float64) Lamports {
	return Lamports(sol * 1_000_000_000)
}

// ComputeUnits represents compute units.
type ComputeUnits uint64

// Default compute limits
const (
	DefaultComputeUnitsPerInstruction ComputeUnits = 200_000
	MaxComputeUnitsPerTransaction     ComputeUnits = 1_400_000
	ComputeUnitsPerSignature          ComputeUnits = 720
	ComputeUnitsPerWritableAccount    ComputeUnits = 300
	ComputeUnitsPerCPI                ComputeUnits = 1_000
)
