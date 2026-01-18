package token

import (
	"encoding/binary"
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Token Program instruction discriminators (first byte of instruction data)
const (
	InstructionInitializeMint     uint8 = 0
	InstructionInitializeAccount  uint8 = 1
	InstructionInitializeMultisig uint8 = 2
	InstructionTransfer           uint8 = 3
	InstructionApprove            uint8 = 4
	InstructionRevoke             uint8 = 5
	InstructionSetAuthority       uint8 = 6
	InstructionMintTo             uint8 = 7
	InstructionBurn               uint8 = 8
	InstructionCloseAccount       uint8 = 9
	InstructionFreezeAccount      uint8 = 10
	InstructionThawAccount        uint8 = 11
	InstructionTransferChecked    uint8 = 12
	InstructionApproveChecked     uint8 = 13
	InstructionMintToChecked      uint8 = 14
	InstructionBurnChecked        uint8 = 15
	InstructionInitializeAccount2 uint8 = 16
	InstructionSyncNative         uint8 = 17
	InstructionInitializeAccount3 uint8 = 18
	InstructionInitializeMint2    uint8 = 20
)

// Authority types for SetAuthority instruction
const (
	AuthorityTypeMintTokens      uint8 = 0
	AuthorityTypeFreezeAccount   uint8 = 1
	AuthorityTypeAccountOwner    uint8 = 2
	AuthorityTypeCloseAccount    uint8 = 3
)

// InitializeMintInstruction represents an InitializeMint instruction.
// Accounts:
//   [0] mint (writable) - The mint to initialize
//   [1] rent sysvar
type InitializeMintInstruction struct {
	Decimals        uint8         // Number of decimal places
	MintAuthority   types.Pubkey  // Authority to mint tokens
	FreezeAuthority *types.Pubkey // Optional authority to freeze accounts
}

// Decode decodes an InitializeMint instruction from bytes.
func (inst *InitializeMintInstruction) Decode(data []byte) error {
	// Layout: decimals (1) + mint_authority (32) + freeze_authority_option (1) + freeze_authority (32)
	// Total: 66 bytes minimum (without freeze authority) or 67 bytes (with freeze authority flag)
	if len(data) < 34 {
		return fmt.Errorf("%w: InitializeMint requires at least 34 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}

	inst.Decimals = data[0]
	copy(inst.MintAuthority[:], data[1:33])

	// Check for optional freeze authority
	if len(data) >= 34 && data[33] == 1 {
		if len(data) < 66 {
			return fmt.Errorf("%w: InitializeMint with freeze authority requires 66 bytes",
				ErrInvalidInstructionData)
		}
		freezeAuth := types.Pubkey{}
		copy(freezeAuth[:], data[34:66])
		inst.FreezeAuthority = &freezeAuth
	}

	return nil
}

// Encode encodes an InitializeMint instruction to bytes.
func (inst *InitializeMintInstruction) Encode() []byte {
	var data []byte
	if inst.FreezeAuthority != nil {
		data = make([]byte, 1+66) // discriminator + instruction data
		data[0] = InstructionInitializeMint
		data[1] = inst.Decimals
		copy(data[2:34], inst.MintAuthority[:])
		data[34] = 1
		copy(data[35:67], inst.FreezeAuthority[:])
	} else {
		data = make([]byte, 1+34)
		data[0] = InstructionInitializeMint
		data[1] = inst.Decimals
		copy(data[2:34], inst.MintAuthority[:])
		data[34] = 0
	}
	return data
}

// InitializeAccountInstruction represents an InitializeAccount instruction.
// Accounts:
//   [0] account (writable) - The account to initialize
//   [1] mint - The mint for this account
//   [2] owner - The owner of the new account
//   [3] rent sysvar
type InitializeAccountInstruction struct {
	// No additional data required - accounts provide all info
}

// Decode decodes an InitializeAccount instruction from bytes.
func (inst *InitializeAccountInstruction) Decode(_ []byte) error {
	// No additional data to decode
	return nil
}

// Encode encodes an InitializeAccount instruction to bytes.
func (inst *InitializeAccountInstruction) Encode() []byte {
	return []byte{InstructionInitializeAccount}
}

// InitializeMultisigInstruction represents an InitializeMultisig instruction.
// Accounts:
//   [0] multisig (writable) - The multisig to initialize
//   [1] rent sysvar
//   [2..n] signer accounts
type InitializeMultisigInstruction struct {
	M uint8 // Number of signers required (threshold)
}

// Decode decodes an InitializeMultisig instruction from bytes.
func (inst *InitializeMultisigInstruction) Decode(data []byte) error {
	if len(data) < 1 {
		return fmt.Errorf("%w: InitializeMultisig requires 1 byte, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.M = data[0]
	return nil
}

// Encode encodes an InitializeMultisig instruction to bytes.
func (inst *InitializeMultisigInstruction) Encode() []byte {
	return []byte{InstructionInitializeMultisig, inst.M}
}

// TransferInstruction represents a Transfer instruction.
// Accounts:
//   [0] source (writable) - The source token account
//   [1] destination (writable) - The destination token account
//   [2] authority (signer) - The source account owner or delegate
type TransferInstruction struct {
	Amount uint64 // Amount of tokens to transfer
}

// Decode decodes a Transfer instruction from bytes.
func (inst *TransferInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: Transfer requires 8 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a Transfer instruction to bytes.
func (inst *TransferInstruction) Encode() []byte {
	data := make([]byte, 9)
	data[0] = InstructionTransfer
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	return data
}

// ApproveInstruction represents an Approve instruction.
// Accounts:
//   [0] source (writable) - The token account to delegate
//   [1] delegate - The delegate account
//   [2] owner (signer) - The source account owner
type ApproveInstruction struct {
	Amount uint64 // Maximum amount the delegate may transfer
}

// Decode decodes an Approve instruction from bytes.
func (inst *ApproveInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: Approve requires 8 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes an Approve instruction to bytes.
func (inst *ApproveInstruction) Encode() []byte {
	data := make([]byte, 9)
	data[0] = InstructionApprove
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	return data
}

// RevokeInstruction represents a Revoke instruction.
// Accounts:
//   [0] source (writable) - The token account
//   [1] owner (signer) - The source account owner
type RevokeInstruction struct {
	// No additional data required
}

// Decode decodes a Revoke instruction from bytes.
func (inst *RevokeInstruction) Decode(_ []byte) error {
	return nil
}

// Encode encodes a Revoke instruction to bytes.
func (inst *RevokeInstruction) Encode() []byte {
	return []byte{InstructionRevoke}
}

// SetAuthorityInstruction represents a SetAuthority instruction.
// Accounts:
//   [0] account (writable) - The mint or token account
//   [1] current_authority (signer) - The current authority
type SetAuthorityInstruction struct {
	AuthorityType uint8         // Type of authority to change
	NewAuthority  *types.Pubkey // New authority (None to remove)
}

// Decode decodes a SetAuthority instruction from bytes.
func (inst *SetAuthorityInstruction) Decode(data []byte) error {
	if len(data) < 2 {
		return fmt.Errorf("%w: SetAuthority requires at least 2 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.AuthorityType = data[0]

	// Check for optional new authority
	if data[1] == 1 {
		if len(data) < 34 {
			return fmt.Errorf("%w: SetAuthority with new authority requires 34 bytes",
				ErrInvalidInstructionData)
		}
		newAuth := types.Pubkey{}
		copy(newAuth[:], data[2:34])
		inst.NewAuthority = &newAuth
	}

	return nil
}

// Encode encodes a SetAuthority instruction to bytes.
func (inst *SetAuthorityInstruction) Encode() []byte {
	if inst.NewAuthority != nil {
		data := make([]byte, 35)
		data[0] = InstructionSetAuthority
		data[1] = inst.AuthorityType
		data[2] = 1
		copy(data[3:35], inst.NewAuthority[:])
		return data
	}
	return []byte{InstructionSetAuthority, inst.AuthorityType, 0}
}

// MintToInstruction represents a MintTo instruction.
// Accounts:
//   [0] mint (writable) - The mint
//   [1] destination (writable) - The account to mint to
//   [2] mint_authority (signer) - The mint authority
type MintToInstruction struct {
	Amount uint64 // Amount of tokens to mint
}

// Decode decodes a MintTo instruction from bytes.
func (inst *MintToInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: MintTo requires 8 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a MintTo instruction to bytes.
func (inst *MintToInstruction) Encode() []byte {
	data := make([]byte, 9)
	data[0] = InstructionMintTo
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	return data
}

// BurnInstruction represents a Burn instruction.
// Accounts:
//   [0] source (writable) - The token account to burn from
//   [1] mint (writable) - The mint
//   [2] authority (signer) - The account owner or delegate
type BurnInstruction struct {
	Amount uint64 // Amount of tokens to burn
}

// Decode decodes a Burn instruction from bytes.
func (inst *BurnInstruction) Decode(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("%w: Burn requires 8 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	return nil
}

// Encode encodes a Burn instruction to bytes.
func (inst *BurnInstruction) Encode() []byte {
	data := make([]byte, 9)
	data[0] = InstructionBurn
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	return data
}

// CloseAccountInstruction represents a CloseAccount instruction.
// Accounts:
//   [0] account (writable) - The account to close
//   [1] destination (writable) - The account to receive remaining lamports
//   [2] authority (signer) - The account owner or close authority
type CloseAccountInstruction struct {
	// No additional data required
}

// Decode decodes a CloseAccount instruction from bytes.
func (inst *CloseAccountInstruction) Decode(_ []byte) error {
	return nil
}

// Encode encodes a CloseAccount instruction to bytes.
func (inst *CloseAccountInstruction) Encode() []byte {
	return []byte{InstructionCloseAccount}
}

// FreezeAccountInstruction represents a FreezeAccount instruction.
// Accounts:
//   [0] account (writable) - The token account to freeze
//   [1] mint - The mint
//   [2] freeze_authority (signer) - The freeze authority
type FreezeAccountInstruction struct {
	// No additional data required
}

// Decode decodes a FreezeAccount instruction from bytes.
func (inst *FreezeAccountInstruction) Decode(_ []byte) error {
	return nil
}

// Encode encodes a FreezeAccount instruction to bytes.
func (inst *FreezeAccountInstruction) Encode() []byte {
	return []byte{InstructionFreezeAccount}
}

// ThawAccountInstruction represents a ThawAccount instruction.
// Accounts:
//   [0] account (writable) - The token account to thaw
//   [1] mint - The mint
//   [2] freeze_authority (signer) - The freeze authority
type ThawAccountInstruction struct {
	// No additional data required
}

// Decode decodes a ThawAccount instruction from bytes.
func (inst *ThawAccountInstruction) Decode(_ []byte) error {
	return nil
}

// Encode encodes a ThawAccount instruction to bytes.
func (inst *ThawAccountInstruction) Encode() []byte {
	return []byte{InstructionThawAccount}
}

// TransferCheckedInstruction represents a TransferChecked instruction.
// Accounts:
//   [0] source (writable) - The source token account
//   [1] mint - The mint
//   [2] destination (writable) - The destination token account
//   [3] authority (signer) - The source account owner or delegate
type TransferCheckedInstruction struct {
	Amount   uint64 // Amount of tokens to transfer
	Decimals uint8  // Expected decimals of the mint
}

// Decode decodes a TransferChecked instruction from bytes.
func (inst *TransferCheckedInstruction) Decode(data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("%w: TransferChecked requires 9 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	inst.Decimals = data[8]
	return nil
}

// Encode encodes a TransferChecked instruction to bytes.
func (inst *TransferCheckedInstruction) Encode() []byte {
	data := make([]byte, 10)
	data[0] = InstructionTransferChecked
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	data[9] = inst.Decimals
	return data
}

// ApproveCheckedInstruction represents an ApproveChecked instruction.
// Accounts:
//   [0] source (writable) - The token account
//   [1] mint - The mint
//   [2] delegate - The delegate account
//   [3] owner (signer) - The source account owner
type ApproveCheckedInstruction struct {
	Amount   uint64 // Maximum amount the delegate may transfer
	Decimals uint8  // Expected decimals of the mint
}

// Decode decodes an ApproveChecked instruction from bytes.
func (inst *ApproveCheckedInstruction) Decode(data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("%w: ApproveChecked requires 9 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	inst.Decimals = data[8]
	return nil
}

// Encode encodes an ApproveChecked instruction to bytes.
func (inst *ApproveCheckedInstruction) Encode() []byte {
	data := make([]byte, 10)
	data[0] = InstructionApproveChecked
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	data[9] = inst.Decimals
	return data
}

// MintToCheckedInstruction represents a MintToChecked instruction.
// Accounts:
//   [0] mint (writable) - The mint
//   [1] destination (writable) - The account to mint to
//   [2] mint_authority (signer) - The mint authority
type MintToCheckedInstruction struct {
	Amount   uint64 // Amount of tokens to mint
	Decimals uint8  // Expected decimals of the mint
}

// Decode decodes a MintToChecked instruction from bytes.
func (inst *MintToCheckedInstruction) Decode(data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("%w: MintToChecked requires 9 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	inst.Decimals = data[8]
	return nil
}

// Encode encodes a MintToChecked instruction to bytes.
func (inst *MintToCheckedInstruction) Encode() []byte {
	data := make([]byte, 10)
	data[0] = InstructionMintToChecked
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	data[9] = inst.Decimals
	return data
}

// BurnCheckedInstruction represents a BurnChecked instruction.
// Accounts:
//   [0] source (writable) - The token account to burn from
//   [1] mint (writable) - The mint
//   [2] authority (signer) - The account owner or delegate
type BurnCheckedInstruction struct {
	Amount   uint64 // Amount of tokens to burn
	Decimals uint8  // Expected decimals of the mint
}

// Decode decodes a BurnChecked instruction from bytes.
func (inst *BurnCheckedInstruction) Decode(data []byte) error {
	if len(data) < 9 {
		return fmt.Errorf("%w: BurnChecked requires 9 bytes, got %d",
			ErrInvalidInstructionData, len(data))
	}
	inst.Amount = binary.LittleEndian.Uint64(data[0:8])
	inst.Decimals = data[8]
	return nil
}

// Encode encodes a BurnChecked instruction to bytes.
func (inst *BurnCheckedInstruction) Encode() []byte {
	data := make([]byte, 10)
	data[0] = InstructionBurnChecked
	binary.LittleEndian.PutUint64(data[1:9], inst.Amount)
	data[9] = inst.Decimals
	return data
}

// ParseInstructionDiscriminator extracts the instruction discriminator from instruction data.
func ParseInstructionDiscriminator(data []byte) (uint8, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}
	return data[0], nil
}
