package bpf_loader

import (
	"fmt"

	"github.com/fortiblox/x1-nimbus/pkg/svm/syscall"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Maximum account data size for programs
const MaxProgramDataSize = 10 * 1024 * 1024 // 10 MB

// handleInitializeBuffer handles the InitializeBuffer instruction.
// Creates a buffer for program deployment.
// Account layout:
//
//	[0] buffer account (writable)
//	[1] authority (optional, signer)
func handleInitializeBuffer(ctx *syscall.ExecutionContext, _ *InitializeBufferInstruction) error {
	// Validate we have at least 1 account
	if ctx.AccountCount() < 1 {
		return fmt.Errorf("%w: InitializeBuffer requires at least 1 account", ErrInvalidInstructionData)
	}

	// Get the buffer account
	bufferAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !bufferAcc.IsWritable {
		return fmt.Errorf("%w: buffer account", ErrAccountNotWritable)
	}

	// Verify the account is owned by BPF Loader Upgradeable
	if bufferAcc.Owner != types.BPFLoaderUpgradeableProgramID {
		return fmt.Errorf("%w: buffer must be owned by BPF Loader Upgradeable", ErrAccountOwnerMismatch)
	}

	// Check if buffer is already initialized
	if len(bufferAcc.Data) >= 4 {
		existingState, err := DeserializeUpgradeableLoaderState(bufferAcc.Data)
		if err == nil && !existingState.IsUninitialized() {
			return ErrAccountAlreadyInitialized
		}
	}

	// Get authority if provided
	var authority *types.Pubkey
	if ctx.AccountCount() > 1 {
		authorityAcc, err := ctx.GetAccountByIndex(1)
		if err != nil {
			return err
		}
		authority = &authorityAcc.Pubkey
	}

	// Create buffer state
	state := NewBufferState(authority)

	// Ensure buffer has enough space for metadata
	if len(bufferAcc.Data) < BUFFER_METADATA_SIZE {
		return fmt.Errorf("%w: buffer too small for metadata", ErrInvalidAccountData)
	}

	// Write state to buffer
	if err := WriteStateToAccountData(bufferAcc.Data, state); err != nil {
		return err
	}

	return nil
}

// handleWrite handles the Write instruction.
// Writes bytes to a buffer at the specified offset.
// Account layout:
//
//	[0] buffer account (writable)
//	[1] authority (signer)
func handleWrite(ctx *syscall.ExecutionContext, inst *WriteInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: Write requires 2 accounts", ErrInvalidInstructionData)
	}

	// Get the buffer account
	bufferAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !bufferAcc.IsWritable {
		return fmt.Errorf("%w: buffer account", ErrAccountNotWritable)
	}

	// Get the authority
	authorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Verify the account is owned by BPF Loader Upgradeable
	if bufferAcc.Owner != types.BPFLoaderUpgradeableProgramID {
		return fmt.Errorf("%w: buffer must be owned by BPF Loader Upgradeable", ErrAccountOwnerMismatch)
	}

	// Parse buffer state
	state, err := DeserializeUpgradeableLoaderState(bufferAcc.Data)
	if err != nil {
		return err
	}

	// Verify it's a buffer
	if !state.IsBuffer() {
		return fmt.Errorf("%w: account is not a buffer", ErrInvalidBufferAccount)
	}

	// Verify authority
	if state.BufferAuthority == nil {
		return ErrMissingAuthority
	}
	if *state.BufferAuthority != authorityAcc.Pubkey {
		return ErrAuthorityMismatch
	}

	// Calculate the write position
	dataOffset := GetBufferDataOffset()
	writeStart := dataOffset + int(inst.Offset)
	writeEnd := writeStart + len(inst.Bytes)

	// Validate write bounds
	if writeEnd > len(bufferAcc.Data) {
		return fmt.Errorf("%w: write would exceed buffer size", ErrWriteOffsetOutOfBounds)
	}

	// Write the bytes
	copy(bufferAcc.Data[writeStart:writeEnd], inst.Bytes)

	return nil
}

// handleDeployWithMaxDataLen handles the DeployWithMaxDataLen instruction.
// Deploys a program from a buffer.
// Account layout:
//
//	[0] payer account (signer, writable)
//	[1] program data account (writable)
//	[2] program account (writable)
//	[3] buffer account (writable)
//	[4] rent sysvar
//	[5] clock sysvar
//	[6] system program
//	[7] authority (signer)
func handleDeployWithMaxDataLen(ctx *syscall.ExecutionContext, inst *DeployWithMaxDataLenInstruction) error {
	// Validate we have enough accounts
	if ctx.AccountCount() < 8 {
		return fmt.Errorf("%w: DeployWithMaxDataLen requires 8 accounts", ErrInvalidInstructionData)
	}

	// Get accounts
	payerAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !payerAcc.IsSigner || !payerAcc.IsWritable {
		return fmt.Errorf("%w: payer must be signer and writable", ErrAccountNotSigner)
	}

	programDataAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !programDataAcc.IsWritable {
		return fmt.Errorf("%w: program data account", ErrAccountNotWritable)
	}

	programAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !programAcc.IsWritable {
		return fmt.Errorf("%w: program account", ErrAccountNotWritable)
	}

	bufferAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !bufferAcc.IsWritable {
		return fmt.Errorf("%w: buffer account", ErrAccountNotWritable)
	}

	authorityAcc, err := ctx.GetAccountByIndex(7)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Verify buffer is owned by BPF Loader Upgradeable
	if bufferAcc.Owner != types.BPFLoaderUpgradeableProgramID {
		return fmt.Errorf("%w: buffer must be owned by BPF Loader Upgradeable", ErrAccountOwnerMismatch)
	}

	// Parse buffer state
	bufferState, err := DeserializeUpgradeableLoaderState(bufferAcc.Data)
	if err != nil {
		return err
	}

	if !bufferState.IsBuffer() {
		return fmt.Errorf("%w: source account is not a buffer", ErrInvalidBufferAccount)
	}

	// Verify buffer authority
	if bufferState.BufferAuthority == nil {
		return ErrMissingAuthority
	}
	if *bufferState.BufferAuthority != authorityAcc.Pubkey {
		return ErrAuthorityMismatch
	}

	// Get the program data from buffer
	programData := bufferAcc.Data[GetBufferDataOffset():]
	if len(programData) == 0 {
		return fmt.Errorf("%w: buffer contains no program data", ErrInvalidBufferAccount)
	}

	// Validate the ELF
	if err := ValidateELF(programData); err != nil {
		return err
	}

	// Verify max data len is sufficient
	if inst.MaxDataLen < uint64(len(programData)) {
		return fmt.Errorf("%w: max_data_len %d is smaller than program size %d",
			ErrDataLenTooSmall, inst.MaxDataLen, len(programData))
	}

	if inst.MaxDataLen > MaxProgramDataSize {
		return fmt.Errorf("%w: max_data_len exceeds maximum", ErrMaxDataLenExceeded)
	}

	// Calculate required program data account size
	requiredSize := PROGRAMDATA_METADATA_SIZE + int(inst.MaxDataLen)

	// Verify program data account has enough space
	if len(programDataAcc.Data) < requiredSize {
		return fmt.Errorf("%w: program data account too small", ErrInvalidProgramDataAccount)
	}

	// Initialize program data state
	programDataState := NewProgramDataState(ctx.Slot, &authorityAcc.Pubkey)
	if err := WriteStateToAccountData(programDataAcc.Data, programDataState); err != nil {
		return err
	}

	// Copy program data to program data account
	copy(programDataAcc.Data[PROGRAMDATA_METADATA_SIZE:], programData)

	// Initialize program account state
	programState := NewProgramState(programDataAcc.Pubkey)
	if len(programAcc.Data) < PROGRAM_ACCOUNT_SIZE {
		return fmt.Errorf("%w: program account too small", ErrInvalidProgramAccount)
	}
	if err := WriteStateToAccountData(programAcc.Data, programState); err != nil {
		return err
	}

	// Mark program account as executable
	programAcc.Executable = true

	// Set program data account owner to BPF Loader Upgradeable
	programDataAcc.Owner = types.BPFLoaderUpgradeableProgramID

	// Clear the buffer (transfer lamports to payer)
	bufferLamports := *bufferAcc.Lamports
	*bufferAcc.Lamports = 0
	*payerAcc.Lamports += bufferLamports

	// Zero out buffer data
	for i := range bufferAcc.Data {
		bufferAcc.Data[i] = 0
	}

	return nil
}

// handleUpgrade handles the Upgrade instruction.
// Upgrades an existing program with new bytecode from a buffer.
// Account layout:
//
//	[0] program data account (writable)
//	[1] program account
//	[2] buffer account (writable)
//	[3] spill account (writable) - receives lamports from buffer
//	[4] rent sysvar
//	[5] clock sysvar
//	[6] authority (signer)
func handleUpgrade(ctx *syscall.ExecutionContext, _ *UpgradeInstruction) error {
	// Validate we have enough accounts
	if ctx.AccountCount() < 7 {
		return fmt.Errorf("%w: Upgrade requires 7 accounts", ErrInvalidInstructionData)
	}

	// Get accounts
	programDataAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !programDataAcc.IsWritable {
		return fmt.Errorf("%w: program data account", ErrAccountNotWritable)
	}

	programAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	bufferAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !bufferAcc.IsWritable {
		return fmt.Errorf("%w: buffer account", ErrAccountNotWritable)
	}

	spillAcc, err := ctx.GetAccountByIndex(3)
	if err != nil {
		return err
	}
	if !spillAcc.IsWritable {
		return fmt.Errorf("%w: spill account", ErrAccountNotWritable)
	}

	authorityAcc, err := ctx.GetAccountByIndex(6)
	if err != nil {
		return err
	}
	if !authorityAcc.IsSigner {
		return fmt.Errorf("%w: authority", ErrAccountNotSigner)
	}

	// Verify program is executable
	if !programAcc.Executable {
		return ErrAccountNotExecutable
	}

	// Parse program state
	programState, err := DeserializeUpgradeableLoaderState(programAcc.Data)
	if err != nil {
		return err
	}

	if !programState.IsProgram() {
		return fmt.Errorf("%w: account is not a program", ErrInvalidProgramAccount)
	}

	// Verify program data account matches
	if programState.ProgramDataAddress != programDataAcc.Pubkey {
		return fmt.Errorf("%w: program data address mismatch", ErrInvalidProgramDataAccount)
	}

	// Parse program data state
	programDataState, err := DeserializeUpgradeableLoaderState(programDataAcc.Data)
	if err != nil {
		return err
	}

	if !programDataState.IsProgramData() {
		return fmt.Errorf("%w: account is not program data", ErrInvalidProgramDataAccount)
	}

	// Check if program is upgradeable
	if programDataState.UpgradeAuthorityAddress == nil {
		return ErrImmutable
	}

	// Verify authority
	if *programDataState.UpgradeAuthorityAddress != authorityAcc.Pubkey {
		return ErrAuthorityMismatch
	}

	// Parse buffer state
	bufferState, err := DeserializeUpgradeableLoaderState(bufferAcc.Data)
	if err != nil {
		return err
	}

	if !bufferState.IsBuffer() {
		return fmt.Errorf("%w: source account is not a buffer", ErrInvalidBufferAccount)
	}

	// Get the new program data
	newProgramData := bufferAcc.Data[GetBufferDataOffset():]
	if len(newProgramData) == 0 {
		return fmt.Errorf("%w: buffer contains no program data", ErrInvalidBufferAccount)
	}

	// Validate the new ELF
	if err := ValidateELF(newProgramData); err != nil {
		return err
	}

	// Calculate available space in program data account
	availableSpace := len(programDataAcc.Data) - PROGRAMDATA_METADATA_SIZE
	if len(newProgramData) > availableSpace {
		return fmt.Errorf("%w: new program too large for program data account", ErrMaxDataLenExceeded)
	}

	// Update program data state with new slot
	programDataState.Slot = ctx.Slot
	if err := WriteStateToAccountData(programDataAcc.Data, programDataState); err != nil {
		return err
	}

	// Copy new program data
	copy(programDataAcc.Data[PROGRAMDATA_METADATA_SIZE:], newProgramData)

	// Zero out remaining space
	for i := PROGRAMDATA_METADATA_SIZE + len(newProgramData); i < len(programDataAcc.Data); i++ {
		programDataAcc.Data[i] = 0
	}

	// Transfer buffer lamports to spill account
	bufferLamports := *bufferAcc.Lamports
	*bufferAcc.Lamports = 0
	*spillAcc.Lamports += bufferLamports

	// Zero out buffer
	for i := range bufferAcc.Data {
		bufferAcc.Data[i] = 0
	}

	return nil
}

// handleSetAuthority handles the SetAuthority instruction.
// Changes the upgrade authority of a program or buffer.
// Account layout:
//
//	[0] buffer or program data account (writable)
//	[1] current authority (signer)
//	[2] new authority (optional)
func handleSetAuthority(ctx *syscall.ExecutionContext, _ *SetAuthorityInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: SetAuthority requires at least 2 accounts", ErrInvalidInstructionData)
	}

	// Get the account to modify
	accountAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !accountAcc.IsWritable {
		return fmt.Errorf("%w: account", ErrAccountNotWritable)
	}

	// Get current authority
	currentAuthorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !currentAuthorityAcc.IsSigner {
		return fmt.Errorf("%w: current authority", ErrAccountNotSigner)
	}

	// Get new authority if provided
	var newAuthority *types.Pubkey
	if ctx.AccountCount() > 2 {
		newAuthorityAcc, err := ctx.GetAccountByIndex(2)
		if err != nil {
			return err
		}
		newAuthority = &newAuthorityAcc.Pubkey
	}

	// Parse account state
	state, err := DeserializeUpgradeableLoaderState(accountAcc.Data)
	if err != nil {
		return err
	}

	switch state.Type {
	case StateBuffer:
		// Verify current authority
		if state.BufferAuthority == nil {
			return ErrMissingAuthority
		}
		if *state.BufferAuthority != currentAuthorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}

		// Update authority
		state.BufferAuthority = newAuthority
		if err := WriteStateToAccountData(accountAcc.Data, state); err != nil {
			return err
		}

	case StateProgramData:
		// Verify current authority
		if state.UpgradeAuthorityAddress == nil {
			return ErrImmutable
		}
		if *state.UpgradeAuthorityAddress != currentAuthorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}

		// Update authority (nil makes it immutable)
		state.UpgradeAuthorityAddress = newAuthority
		if err := WriteStateToAccountData(accountAcc.Data, state); err != nil {
			return err
		}

	default:
		return fmt.Errorf("%w: account is not a buffer or program data", ErrInvalidAccountData)
	}

	return nil
}

// handleClose handles the Close instruction.
// Closes a buffer or program account and transfers lamports.
// Account layout:
//
//	[0] account to close (writable)
//	[1] recipient (writable)
//	[2] authority (signer, optional for buffer)
//	[3] program account (optional, for closing program data)
func handleClose(ctx *syscall.ExecutionContext, _ *CloseInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: Close requires at least 2 accounts", ErrInvalidInstructionData)
	}

	// Get the account to close
	closeAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !closeAcc.IsWritable {
		return fmt.Errorf("%w: account to close", ErrAccountNotWritable)
	}

	// Get the recipient
	recipientAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !recipientAcc.IsWritable {
		return fmt.Errorf("%w: recipient", ErrAccountNotWritable)
	}

	// Cannot close to self
	if closeAcc.Pubkey == recipientAcc.Pubkey {
		return fmt.Errorf("%w: cannot close to self", ErrInvalidRecipient)
	}

	// Parse account state
	state, err := DeserializeUpgradeableLoaderState(closeAcc.Data)
	if err != nil {
		return err
	}

	switch state.Type {
	case StateUninitialized:
		// Can close uninitialized accounts without authority check
		// Just transfer lamports

	case StateBuffer:
		// Need authority to close buffer
		if ctx.AccountCount() < 3 {
			return fmt.Errorf("%w: Close buffer requires authority", ErrMissingAuthority)
		}
		authorityAcc, err := ctx.GetAccountByIndex(2)
		if err != nil {
			return err
		}
		if !authorityAcc.IsSigner {
			return fmt.Errorf("%w: authority", ErrAccountNotSigner)
		}

		// Verify authority if set
		if state.BufferAuthority != nil && *state.BufferAuthority != authorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}

	case StateProgramData:
		// Need authority and program account to close program data
		if ctx.AccountCount() < 4 {
			return fmt.Errorf("%w: Close program data requires authority and program account", ErrInvalidInstructionData)
		}

		authorityAcc, err := ctx.GetAccountByIndex(2)
		if err != nil {
			return err
		}
		if !authorityAcc.IsSigner {
			return fmt.Errorf("%w: authority", ErrAccountNotSigner)
		}

		// Verify authority
		if state.UpgradeAuthorityAddress == nil {
			return ErrImmutable
		}
		if *state.UpgradeAuthorityAddress != authorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}

		// Get and verify program account
		programAcc, err := ctx.GetAccountByIndex(3)
		if err != nil {
			return err
		}

		// Parse program state to verify it points to this program data
		programState, err := DeserializeUpgradeableLoaderState(programAcc.Data)
		if err != nil {
			return err
		}
		if !programState.IsProgram() {
			return fmt.Errorf("%w: account is not a program", ErrInvalidProgramAccount)
		}
		if programState.ProgramDataAddress != closeAcc.Pubkey {
			return fmt.Errorf("%w: program data address mismatch", ErrInvalidProgramDataAccount)
		}

	case StateProgram:
		// Cannot close program accounts directly
		return fmt.Errorf("%w: cannot close program account directly, close program data instead",
			ErrInvalidAccountData)

	default:
		return fmt.Errorf("%w: unknown account state", ErrInvalidAccountData)
	}

	// Transfer lamports to recipient
	lamports := *closeAcc.Lamports
	*closeAcc.Lamports = 0
	*recipientAcc.Lamports += lamports

	// Zero out the account data
	for i := range closeAcc.Data {
		closeAcc.Data[i] = 0
	}

	return nil
}

// handleExtendProgram handles the ExtendProgram instruction.
// Extends the program data account size.
// Account layout:
//
//	[0] program data account (writable)
//	[1] program account
//	[2] system program (optional, for additional lamports)
//	[3] payer (optional, signer, writable)
func handleExtendProgram(ctx *syscall.ExecutionContext, inst *ExtendProgramInstruction) error {
	// Validate we have at least 2 accounts
	if ctx.AccountCount() < 2 {
		return fmt.Errorf("%w: ExtendProgram requires at least 2 accounts", ErrInvalidInstructionData)
	}

	// Get the program data account
	programDataAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !programDataAcc.IsWritable {
		return fmt.Errorf("%w: program data account", ErrAccountNotWritable)
	}

	// Get the program account
	programAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}

	// Verify program is executable
	if !programAcc.Executable {
		return ErrAccountNotExecutable
	}

	// Parse program state
	programState, err := DeserializeUpgradeableLoaderState(programAcc.Data)
	if err != nil {
		return err
	}

	if !programState.IsProgram() {
		return fmt.Errorf("%w: account is not a program", ErrInvalidProgramAccount)
	}

	// Verify program data account matches
	if programState.ProgramDataAddress != programDataAcc.Pubkey {
		return fmt.Errorf("%w: program data address mismatch", ErrInvalidProgramDataAccount)
	}

	// Parse program data state
	programDataState, err := DeserializeUpgradeableLoaderState(programDataAcc.Data)
	if err != nil {
		return err
	}

	if !programDataState.IsProgramData() {
		return fmt.Errorf("%w: account is not program data", ErrInvalidProgramDataAccount)
	}

	// Calculate new size
	currentSize := len(programDataAcc.Data)
	newSize := currentSize + int(inst.AdditionalBytes)

	if newSize > MaxProgramDataSize+PROGRAMDATA_METADATA_SIZE {
		return fmt.Errorf("%w: new size exceeds maximum", ErrMaxDataLenExceeded)
	}

	// Calculate additional rent needed
	currentRent := types.RentExemptMinimum(uint64(currentSize))
	newRent := types.RentExemptMinimum(uint64(newSize))
	additionalRent := uint64(newRent - currentRent)

	// If additional rent is needed, require a payer
	if additionalRent > 0 && ctx.AccountCount() >= 4 {
		payerAcc, err := ctx.GetAccountByIndex(3)
		if err != nil {
			return err
		}
		if !payerAcc.IsSigner {
			return fmt.Errorf("%w: payer", ErrAccountNotSigner)
		}
		if !payerAcc.IsWritable {
			return fmt.Errorf("%w: payer", ErrAccountNotWritable)
		}

		if *payerAcc.Lamports < additionalRent {
			return fmt.Errorf("%w: payer has insufficient funds for rent", ErrInsufficientFunds)
		}

		// Transfer rent from payer
		*payerAcc.Lamports -= additionalRent
		*programDataAcc.Lamports += additionalRent
	}

	// Extend the data (in a real implementation, this would need to reallocate)
	// For this implementation, we assume the account data can be resized
	newData := make([]byte, newSize)
	copy(newData, programDataAcc.Data)
	programDataAcc.Data = newData

	return nil
}

// handleSetAuthorityChecked handles the SetAuthorityChecked instruction.
// Changes the upgrade authority with verification that the new authority signs.
// Account layout:
//
//	[0] buffer or program data account (writable)
//	[1] current authority (signer)
//	[2] new authority (signer)
func handleSetAuthorityChecked(ctx *syscall.ExecutionContext, _ *SetAuthorityCheckedInstruction) error {
	// Validate we have at least 3 accounts
	if ctx.AccountCount() < 3 {
		return fmt.Errorf("%w: SetAuthorityChecked requires 3 accounts", ErrInvalidInstructionData)
	}

	// Get the account to modify
	accountAcc, err := ctx.GetAccountByIndex(0)
	if err != nil {
		return err
	}
	if !accountAcc.IsWritable {
		return fmt.Errorf("%w: account", ErrAccountNotWritable)
	}

	// Get current authority
	currentAuthorityAcc, err := ctx.GetAccountByIndex(1)
	if err != nil {
		return err
	}
	if !currentAuthorityAcc.IsSigner {
		return fmt.Errorf("%w: current authority", ErrAccountNotSigner)
	}

	// Get new authority (must be signer in checked version)
	newAuthorityAcc, err := ctx.GetAccountByIndex(2)
	if err != nil {
		return err
	}
	if !newAuthorityAcc.IsSigner {
		return fmt.Errorf("%w: new authority must be a signer", ErrAccountNotSigner)
	}

	// Parse account state
	state, err := DeserializeUpgradeableLoaderState(accountAcc.Data)
	if err != nil {
		return err
	}

	switch state.Type {
	case StateBuffer:
		// Verify current authority
		if state.BufferAuthority == nil {
			return ErrMissingAuthority
		}
		if *state.BufferAuthority != currentAuthorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}

		// Update authority
		state.BufferAuthority = &newAuthorityAcc.Pubkey
		if err := WriteStateToAccountData(accountAcc.Data, state); err != nil {
			return err
		}

	case StateProgramData:
		// Verify current authority
		if state.UpgradeAuthorityAddress == nil {
			return ErrImmutable
		}
		if *state.UpgradeAuthorityAddress != currentAuthorityAcc.Pubkey {
			return ErrAuthorityMismatch
		}

		// Update authority
		state.UpgradeAuthorityAddress = &newAuthorityAcc.Pubkey
		if err := WriteStateToAccountData(accountAcc.Data, state); err != nil {
			return err
		}

	default:
		return fmt.Errorf("%w: account is not a buffer or program data", ErrInvalidAccountData)
	}

	return nil
}
