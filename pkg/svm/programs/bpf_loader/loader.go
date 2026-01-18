// Package bpf_loader implements the BPF Loader Upgradeable program for X1-Nimbus.
//
// The BPF Loader Upgradeable program is responsible for:
//   - Deploying new programs to the network
//   - Upgrading existing programs with new bytecode
//   - Managing program upgrade authorities
//   - Handling program data accounts
//
// Programs deployed via this loader can be upgraded by their upgrade authority,
// or made immutable by removing the upgrade authority.
package bpf_loader

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// BPFLoaderUpgradeable implements the BPF Loader Upgradeable program.
type BPFLoaderUpgradeable struct {
	// ProgramID is the BPF Loader Upgradeable program's public key
	ProgramID types.Pubkey
}

// New creates a new BPFLoaderUpgradeable instance.
func New() *BPFLoaderUpgradeable {
	return &BPFLoaderUpgradeable{
		ProgramID: types.BPFLoaderUpgradeableProgramID,
	}
}

// Execute executes a BPF Loader Upgradeable instruction.
// The instruction format is:
//   - First 4 bytes: instruction discriminator (little-endian uint32)
//   - Remaining bytes: instruction-specific data
func (p *BPFLoaderUpgradeable) Execute(ctx *syscall.ExecutionContext, instruction *types.Instruction) error {
	// Extract instruction data
	data := instruction.Data
	if len(data) < 4 {
		return fmt.Errorf("%w: instruction data too short", ErrInvalidInstructionData)
	}

	// Parse the instruction discriminator
	discriminator, err := ParseInstructionDiscriminator(data)
	if err != nil {
		return err
	}

	// Get instruction data (everything after the discriminator)
	var instructionData []byte
	if len(data) > 4 {
		instructionData = data[4:]
	}

	// Route to the appropriate handler
	switch discriminator {
	case InstructionInitializeBuffer:
		var inst InitializeBufferInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleInitializeBuffer(ctx, &inst)

	case InstructionWrite:
		var inst WriteInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleWrite(ctx, &inst)

	case InstructionDeployWithMaxDataLen:
		var inst DeployWithMaxDataLenInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleDeployWithMaxDataLen(ctx, &inst)

	case InstructionUpgrade:
		var inst UpgradeInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleUpgrade(ctx, &inst)

	case InstructionSetAuthority:
		var inst SetAuthorityInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetAuthority(ctx, &inst)

	case InstructionClose:
		var inst CloseInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleClose(ctx, &inst)

	case InstructionExtendProgram:
		var inst ExtendProgramInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleExtendProgram(ctx, &inst)

	case InstructionSetAuthorityChecked:
		var inst SetAuthorityCheckedInstruction
		if err := inst.Decode(instructionData); err != nil {
			return err
		}
		return handleSetAuthorityChecked(ctx, &inst)

	default:
		return fmt.Errorf("%w: unknown instruction %d", ErrInvalidInstructionData, discriminator)
	}
}

// GetProgramID returns the BPF Loader Upgradeable program's public key.
func (p *BPFLoaderUpgradeable) GetProgramID() types.Pubkey {
	return p.ProgramID
}

// IsBPFLoaderUpgradeable checks if a pubkey is the BPF Loader Upgradeable program.
func IsBPFLoaderUpgradeable(pubkey types.Pubkey) bool {
	return pubkey == types.BPFLoaderUpgradeableProgramID
}

// IsProgramAccount checks if an account is a deployed program.
func IsProgramAccount(acc *syscall.AccountInfo) bool {
	if acc.Owner != types.BPFLoaderUpgradeableProgramID {
		return false
	}
	if len(acc.Data) < 4 {
		return false
	}
	state, err := DeserializeUpgradeableLoaderState(acc.Data)
	if err != nil {
		return false
	}
	return state.IsProgram()
}

// IsBufferAccount checks if an account is a buffer.
func IsBufferAccount(acc *syscall.AccountInfo) bool {
	if acc.Owner != types.BPFLoaderUpgradeableProgramID {
		return false
	}
	if len(acc.Data) < 4 {
		return false
	}
	state, err := DeserializeUpgradeableLoaderState(acc.Data)
	if err != nil {
		return false
	}
	return state.IsBuffer()
}

// IsProgramDataAccount checks if an account is program data.
func IsProgramDataAccount(acc *syscall.AccountInfo) bool {
	if acc.Owner != types.BPFLoaderUpgradeableProgramID {
		return false
	}
	if len(acc.Data) < 4 {
		return false
	}
	state, err := DeserializeUpgradeableLoaderState(acc.Data)
	if err != nil {
		return false
	}
	return state.IsProgramData()
}

// GetProgramDataFromProgram retrieves the program data address from a program account.
func GetProgramDataFromProgram(programData []byte) (types.Pubkey, error) {
	state, err := DeserializeUpgradeableLoaderState(programData)
	if err != nil {
		return types.ZeroPubkey, err
	}
	if !state.IsProgram() {
		return types.ZeroPubkey, fmt.Errorf("%w: account is not a program", ErrInvalidProgramAccount)
	}
	return state.ProgramDataAddress, nil
}

// GetUpgradeAuthority retrieves the upgrade authority from a program data account.
func GetUpgradeAuthority(programData []byte) (*types.Pubkey, error) {
	state, err := DeserializeUpgradeableLoaderState(programData)
	if err != nil {
		return nil, err
	}
	if !state.IsProgramData() {
		return nil, fmt.Errorf("%w: account is not program data", ErrInvalidProgramDataAccount)
	}
	return state.UpgradeAuthorityAddress, nil
}

// GetDeploymentSlot retrieves the deployment slot from a program data account.
func GetDeploymentSlot(programData []byte) (uint64, error) {
	state, err := DeserializeUpgradeableLoaderState(programData)
	if err != nil {
		return 0, err
	}
	if !state.IsProgramData() {
		return 0, fmt.Errorf("%w: account is not program data", ErrInvalidProgramDataAccount)
	}
	return state.Slot, nil
}

// GetProgramBytecode retrieves the program bytecode from a program data account.
func GetProgramBytecode(programDataData []byte) ([]byte, error) {
	if len(programDataData) < PROGRAMDATA_METADATA_SIZE {
		return nil, fmt.Errorf("%w: program data too short", ErrInvalidAccountData)
	}
	state, err := DeserializeUpgradeableLoaderState(programDataData)
	if err != nil {
		return nil, err
	}
	if !state.IsProgramData() {
		return nil, fmt.Errorf("%w: account is not program data", ErrInvalidProgramDataAccount)
	}
	return programDataData[PROGRAMDATA_METADATA_SIZE:], nil
}

// GetBufferData retrieves the buffer data from a buffer account.
func GetBufferData(bufferData []byte) ([]byte, error) {
	if len(bufferData) < BUFFER_METADATA_SIZE {
		return nil, fmt.Errorf("%w: buffer data too short", ErrInvalidAccountData)
	}
	state, err := DeserializeUpgradeableLoaderState(bufferData)
	if err != nil {
		return nil, err
	}
	if !state.IsBuffer() {
		return nil, fmt.Errorf("%w: account is not a buffer", ErrInvalidBufferAccount)
	}
	return bufferData[BUFFER_METADATA_SIZE:], nil
}
