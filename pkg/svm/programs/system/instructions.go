package system

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// System Program instruction discriminators (first 4 bytes of instruction data)
const (
	InstructionCreateAccount         uint32 = 0
	InstructionAssign                uint32 = 1
	InstructionTransfer              uint32 = 2
	InstructionCreateAccountWithSeed uint32 = 3
	InstructionAdvanceNonceAccount   uint32 = 4
	InstructionWithdrawNonceAccount  uint32 = 5
	InstructionInitializeNonceAccount uint32 = 6
	InstructionAuthorizeNonceAccount uint32 = 7
	InstructionAllocate              uint32 = 8
	InstructionAllocateWithSeed      uint32 = 9
	InstructionAssignWithSeed        uint32 = 10
	InstructionTransferWithSeed      uint32 = 11
)

// CreateAccountInstruction represents a CreateAccount instruction.
// Creates a new account with the specified lamports, space, and owner.
type CreateAccountInstruction struct {
	Lamports uint64       // Amount of lamports to transfer to the new account
	Space    uint64       // Amount of space in bytes to allocate
	Owner    types.Pubkey // Program that will own the new account
}

// Decode decodes a CreateAccount instruction from bytes.
func (inst *CreateAccountInstruction) Decode(data []byte) error {
	// Data layout: lamports (8 bytes) + space (8 bytes) + owner (32 bytes) = 48 bytes
	if len(data) < 48 {
		return fmt.Errorf("%w: CreateAccount requires 48 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.Lamports = binary.LittleEndian.Uint64(data[0:8])
	inst.Space = binary.LittleEndian.Uint64(data[8:16])
	copy(inst.Owner[:], data[16:48])
	return nil
}

// Encode encodes a CreateAccount instruction to bytes.
func (inst *CreateAccountInstruction) Encode() []byte {
	data := make([]byte, 4+48) // discriminator + instruction data
	binary.LittleEndian.PutUint32(data[0:4], InstructionCreateAccount)
	binary.LittleEndian.PutUint64(data[4:12], inst.Lamports)
	binary.LittleEndian.PutUint64(data[12:20], inst.Space)
	copy(data[20:52], inst.Owner[:])
	return data
}

// AssignInstruction represents an Assign instruction.
// Changes the owner of an account.
type AssignInstruction struct {
	Owner types.Pubkey // New owner program
}

// Decode decodes an Assign instruction from bytes.
func (inst *AssignInstruction) Decode(data []byte) error {
	// Data layout: owner (32 bytes)
	if len(data) < 32 {
		return fmt.Errorf("%w: Assign requires 32 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	copy(inst.Owner[:], data[0:32])
	return nil
}

// Encode encodes an Assign instruction to bytes.
func (inst *AssignInstruction) Encode() []byte {
	data := make([]byte, 4+32) // discriminator + instruction data
	binary.LittleEndian.PutUint32(data[0:4], InstructionAssign)
	copy(data[4:36], inst.Owner[:])
	return data
}

// TransferInstruction represents a Transfer instruction.
// Transfers lamports between accounts.
type TransferInstruction struct {
	Lamports uint64 // Amount of lamports to transfer
}

// Decode decodes a Transfer instruction from bytes.
func (inst *TransferInstruction) Decode(data []byte) error {
	// Data layout: lamports (8 bytes)
	if len(data) < 8 {
		return fmt.Errorf("%w: Transfer requires 8 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.Lamports = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a Transfer instruction to bytes.
func (inst *TransferInstruction) Encode() []byte {
	data := make([]byte, 4+8) // discriminator + instruction data
	binary.LittleEndian.PutUint32(data[0:4], InstructionTransfer)
	binary.LittleEndian.PutUint64(data[4:12], inst.Lamports)
	return data
}

// CreateAccountWithSeedInstruction represents a CreateAccountWithSeed instruction.
// Creates a new account at an address derived from a base pubkey and seed.
type CreateAccountWithSeedInstruction struct {
	Base     types.Pubkey // Base public key
	Seed     string       // Seed string (max 32 bytes)
	Lamports uint64       // Amount of lamports to transfer
	Space    uint64       // Amount of space in bytes
	Owner    types.Pubkey // Program that will own the new account
}

// Decode decodes a CreateAccountWithSeed instruction from bytes.
func (inst *CreateAccountWithSeedInstruction) Decode(data []byte) error {
	// Data layout: base (32) + seed_len (8) + seed (variable) + lamports (8) + space (8) + owner (32)
	if len(data) < 32+8 {
		return fmt.Errorf("%w: CreateAccountWithSeed too short", ErrInvalidInstructionData)
	}
	copy(inst.Base[:], data[0:32])
	seedLen := binary.LittleEndian.Uint64(data[32:40])
	if seedLen > 32 {
		return fmt.Errorf("%w: seed too long", ErrInvalidSeed)
	}
	expectedLen := 32 + 8 + int(seedLen) + 8 + 8 + 32
	if len(data) < expectedLen {
		return fmt.Errorf("%w: CreateAccountWithSeed requires %d bytes, got %d", ErrInvalidInstructionData, expectedLen, len(data))
	}
	inst.Seed = string(data[40 : 40+seedLen])
	offset := 40 + int(seedLen)
	inst.Lamports = binary.LittleEndian.Uint64(data[offset : offset+8])
	inst.Space = binary.LittleEndian.Uint64(data[offset+8 : offset+16])
	copy(inst.Owner[:], data[offset+16:offset+48])
	return nil
}

// Encode encodes a CreateAccountWithSeed instruction to bytes.
func (inst *CreateAccountWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.Seed)
	data := make([]byte, 4+32+8+len(seedBytes)+8+8+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionCreateAccountWithSeed)
	copy(data[4:36], inst.Base[:])
	binary.LittleEndian.PutUint64(data[36:44], uint64(len(seedBytes)))
	copy(data[44:44+len(seedBytes)], seedBytes)
	offset := 44 + len(seedBytes)
	binary.LittleEndian.PutUint64(data[offset:offset+8], inst.Lamports)
	binary.LittleEndian.PutUint64(data[offset+8:offset+16], inst.Space)
	copy(data[offset+16:offset+48], inst.Owner[:])
	return data
}

// AdvanceNonceAccountInstruction represents an AdvanceNonceAccount instruction.
// Advances the nonce account to a new blockhash.
type AdvanceNonceAccountInstruction struct {
	// No additional data required
}

// Decode decodes an AdvanceNonceAccount instruction from bytes.
func (inst *AdvanceNonceAccountInstruction) Decode(data []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes an AdvanceNonceAccount instruction to bytes.
func (inst *AdvanceNonceAccountInstruction) Encode() []byte {
	data := make([]byte, 4)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAdvanceNonceAccount)
	return data
}

// WithdrawNonceAccountInstruction represents a WithdrawNonceAccount instruction.
// Withdraws lamports from a nonce account.
type WithdrawNonceAccountInstruction struct {
	Lamports uint64 // Amount of lamports to withdraw
}

// Decode decodes a WithdrawNonceAccount instruction from bytes.
func (inst *WithdrawNonceAccountInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: WithdrawNonceAccount requires 8 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.Lamports = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a WithdrawNonceAccount instruction to bytes.
func (inst *WithdrawNonceAccountInstruction) Encode() []byte {
	data := make([]byte, 4+8)
	binary.LittleEndian.PutUint32(data[0:4], InstructionWithdrawNonceAccount)
	binary.LittleEndian.PutUint64(data[4:12], inst.Lamports)
	return data
}

// InitializeNonceAccountInstruction represents an InitializeNonceAccount instruction.
// Initializes a nonce account with the given authority.
type InitializeNonceAccountInstruction struct {
	Authority types.Pubkey // Nonce authority
}

// Decode decodes an InitializeNonceAccount instruction from bytes.
func (inst *InitializeNonceAccountInstruction) Decode(data []byte) error {
	if len(data) < 32 {
		return fmt.Errorf("%w: InitializeNonceAccount requires 32 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	copy(inst.Authority[:], data[0:32])
	return nil
}

// Encode encodes an InitializeNonceAccount instruction to bytes.
func (inst *InitializeNonceAccountInstruction) Encode() []byte {
	data := make([]byte, 4+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionInitializeNonceAccount)
	copy(data[4:36], inst.Authority[:])
	return data
}

// AuthorizeNonceAccountInstruction represents an AuthorizeNonceAccount instruction.
// Changes the authority of a nonce account.
type AuthorizeNonceAccountInstruction struct {
	Authority types.Pubkey // New nonce authority
}

// Decode decodes an AuthorizeNonceAccount instruction from bytes.
func (inst *AuthorizeNonceAccountInstruction) Decode(data []byte) error {
	if len(data) < 32 {
		return fmt.Errorf("%w: AuthorizeNonceAccount requires 32 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	copy(inst.Authority[:], data[0:32])
	return nil
}

// Encode encodes an AuthorizeNonceAccount instruction to bytes.
func (inst *AuthorizeNonceAccountInstruction) Encode() []byte {
	data := make([]byte, 4+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAuthorizeNonceAccount)
	copy(data[4:36], inst.Authority[:])
	return data
}

// AllocateInstruction represents an Allocate instruction.
// Allocates space in an account's data.
type AllocateInstruction struct {
	Space uint64 // Amount of space in bytes to allocate
}

// Decode decodes an Allocate instruction from bytes.
func (inst *AllocateInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: Allocate requires 8 bytes, got %d", ErrInvalidInstructionData, len(data))
	}
	inst.Space = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes an Allocate instruction to bytes.
func (inst *AllocateInstruction) Encode() []byte {
	data := make([]byte, 4+8)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAllocate)
	binary.LittleEndian.PutUint64(data[4:12], inst.Space)
	return data
}

// AllocateWithSeedInstruction represents an AllocateWithSeed instruction.
// Allocates space in an account derived from a base pubkey and seed.
type AllocateWithSeedInstruction struct {
	Base  types.Pubkey // Base public key
	Seed  string       // Seed string (max 32 bytes)
	Space uint64       // Amount of space in bytes
	Owner types.Pubkey // Program that will own the account
}

// Decode decodes an AllocateWithSeed instruction from bytes.
func (inst *AllocateWithSeedInstruction) Decode(data []byte) error {
	// Data layout: base (32) + seed_len (8) + seed (variable) + space (8) + owner (32)
	if len(data) < 32+8 {
		return fmt.Errorf("%w: AllocateWithSeed too short", ErrInvalidInstructionData)
	}
	copy(inst.Base[:], data[0:32])
	seedLen := binary.LittleEndian.Uint64(data[32:40])
	if seedLen > 32 {
		return fmt.Errorf("%w: seed too long", ErrInvalidSeed)
	}
	expectedLen := 32 + 8 + int(seedLen) + 8 + 32
	if len(data) < expectedLen {
		return fmt.Errorf("%w: AllocateWithSeed requires %d bytes, got %d", ErrInvalidInstructionData, expectedLen, len(data))
	}
	inst.Seed = string(data[40 : 40+seedLen])
	offset := 40 + int(seedLen)
	inst.Space = binary.LittleEndian.Uint64(data[offset : offset+8])
	copy(inst.Owner[:], data[offset+8:offset+40])
	return nil
}

// Encode encodes an AllocateWithSeed instruction to bytes.
func (inst *AllocateWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.Seed)
	data := make([]byte, 4+32+8+len(seedBytes)+8+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAllocateWithSeed)
	copy(data[4:36], inst.Base[:])
	binary.LittleEndian.PutUint64(data[36:44], uint64(len(seedBytes)))
	copy(data[44:44+len(seedBytes)], seedBytes)
	offset := 44 + len(seedBytes)
	binary.LittleEndian.PutUint64(data[offset:offset+8], inst.Space)
	copy(data[offset+8:offset+40], inst.Owner[:])
	return data
}

// AssignWithSeedInstruction represents an AssignWithSeed instruction.
// Assigns an owner to an account derived from a base pubkey and seed.
type AssignWithSeedInstruction struct {
	Base  types.Pubkey // Base public key
	Seed  string       // Seed string (max 32 bytes)
	Owner types.Pubkey // Program that will own the account
}

// Decode decodes an AssignWithSeed instruction from bytes.
func (inst *AssignWithSeedInstruction) Decode(data []byte) error {
	// Data layout: base (32) + seed_len (8) + seed (variable) + owner (32)
	if len(data) < 32+8 {
		return fmt.Errorf("%w: AssignWithSeed too short", ErrInvalidInstructionData)
	}
	copy(inst.Base[:], data[0:32])
	seedLen := binary.LittleEndian.Uint64(data[32:40])
	if seedLen > 32 {
		return fmt.Errorf("%w: seed too long", ErrInvalidSeed)
	}
	expectedLen := 32 + 8 + int(seedLen) + 32
	if len(data) < expectedLen {
		return fmt.Errorf("%w: AssignWithSeed requires %d bytes, got %d", ErrInvalidInstructionData, expectedLen, len(data))
	}
	inst.Seed = string(data[40 : 40+seedLen])
	offset := 40 + int(seedLen)
	copy(inst.Owner[:], data[offset:offset+32])
	return nil
}

// Encode encodes an AssignWithSeed instruction to bytes.
func (inst *AssignWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.Seed)
	data := make([]byte, 4+32+8+len(seedBytes)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionAssignWithSeed)
	copy(data[4:36], inst.Base[:])
	binary.LittleEndian.PutUint64(data[36:44], uint64(len(seedBytes)))
	copy(data[44:44+len(seedBytes)], seedBytes)
	offset := 44 + len(seedBytes)
	copy(data[offset:offset+32], inst.Owner[:])
	return data
}

// TransferWithSeedInstruction represents a TransferWithSeed instruction.
// Transfers lamports from an account derived from a base pubkey and seed.
type TransferWithSeedInstruction struct {
	Lamports  uint64       // Amount of lamports to transfer
	FromSeed  string       // Seed string for the source account
	FromOwner types.Pubkey // Owner program of the source account
}

// Decode decodes a TransferWithSeed instruction from bytes.
func (inst *TransferWithSeedInstruction) Decode(data []byte) error {
	// Data layout: lamports (8) + seed_len (8) + seed (variable) + from_owner (32)
	if len(data) < 8+8 {
		return fmt.Errorf("%w: TransferWithSeed too short", ErrInvalidInstructionData)
	}
	inst.Lamports = binary.LittleEndian.Uint64(data[0:8])
	seedLen := binary.LittleEndian.Uint64(data[8:16])
	if seedLen > 32 {
		return fmt.Errorf("%w: seed too long", ErrInvalidSeed)
	}
	expectedLen := 8 + 8 + int(seedLen) + 32
	if len(data) < expectedLen {
		return fmt.Errorf("%w: TransferWithSeed requires %d bytes, got %d", ErrInvalidInstructionData, expectedLen, len(data))
	}
	inst.FromSeed = string(data[16 : 16+seedLen])
	offset := 16 + int(seedLen)
	copy(inst.FromOwner[:], data[offset:offset+32])
	return nil
}

// Encode encodes a TransferWithSeed instruction to bytes.
func (inst *TransferWithSeedInstruction) Encode() []byte {
	seedBytes := []byte(inst.FromSeed)
	data := make([]byte, 4+8+8+len(seedBytes)+32)
	binary.LittleEndian.PutUint32(data[0:4], InstructionTransferWithSeed)
	binary.LittleEndian.PutUint64(data[4:12], inst.Lamports)
	binary.LittleEndian.PutUint64(data[12:20], uint64(len(seedBytes)))
	copy(data[20:20+len(seedBytes)], seedBytes)
	offset := 20 + len(seedBytes)
	copy(data[offset:offset+32], inst.FromOwner[:])
	return data
}

// ParseInstructionDiscriminator extracts the instruction discriminator from instruction data.
func ParseInstructionDiscriminator(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}
	return binary.LittleEndian.Uint32(data[0:4]), nil
}
