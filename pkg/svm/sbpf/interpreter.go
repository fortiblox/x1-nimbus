package sbpf

// execute runs the main interpreter loop.
func (vm *VM) execute() error {
	for {
		// Check compute budget
		if vm.computeUnits == 0 {
			return NewVMError(ErrComputeExhausted, vm.pc, 0, 0)
		}

		// Fetch instruction
		pc := vm.pc
		if pc >= uint64(len(vm.instructions)) {
			return NewVMError(ErrInvalidInstruction, pc, 0, 0)
		}

		inst := vm.instructions[pc]

		// Consume compute unit for this instruction
		vm.computeUnits--

		// Execute instruction
		err := vm.step(inst)
		if err != nil {
			return err
		}

		// Check for exit condition
		if vm.exited {
			return nil
		}
	}
}

// step executes a single instruction.
func (vm *VM) step(inst Instruction) error {
	switch inst.Opcode {
	// ==================== ALU64 Immediate ====================
	case ADD64_IMM:
		vm.reg[inst.Dst] += uint64(int64(inst.Imm))
		vm.pc++

	case SUB64_IMM:
		vm.reg[inst.Dst] -= uint64(int64(inst.Imm))
		vm.pc++

	case MUL64_IMM:
		vm.reg[inst.Dst] *= uint64(int64(inst.Imm))
		vm.pc++

	case DIV64_IMM:
		if inst.Imm == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] /= uint64(int64(inst.Imm))
		vm.pc++

	case OR64_IMM:
		vm.reg[inst.Dst] |= uint64(int64(inst.Imm))
		vm.pc++

	case AND64_IMM:
		vm.reg[inst.Dst] &= uint64(int64(inst.Imm))
		vm.pc++

	case LSH64_IMM:
		vm.reg[inst.Dst] <<= uint64(inst.Imm) & 63
		vm.pc++

	case RSH64_IMM:
		vm.reg[inst.Dst] >>= uint64(inst.Imm) & 63
		vm.pc++

	case NEG64:
		vm.reg[inst.Dst] = uint64(-int64(vm.reg[inst.Dst]))
		vm.pc++

	case MOD64_IMM:
		if inst.Imm == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] %= uint64(int64(inst.Imm))
		vm.pc++

	case XOR64_IMM:
		vm.reg[inst.Dst] ^= uint64(int64(inst.Imm))
		vm.pc++

	case MOV64_IMM:
		vm.reg[inst.Dst] = uint64(int64(inst.Imm))
		vm.pc++

	case ARSH64_IMM:
		vm.reg[inst.Dst] = uint64(int64(vm.reg[inst.Dst]) >> (uint64(inst.Imm) & 63))
		vm.pc++

	// ==================== ALU64 Register ====================
	case ADD64_REG:
		vm.reg[inst.Dst] += vm.reg[inst.Src]
		vm.pc++

	case SUB64_REG:
		vm.reg[inst.Dst] -= vm.reg[inst.Src]
		vm.pc++

	case MUL64_REG:
		vm.reg[inst.Dst] *= vm.reg[inst.Src]
		vm.pc++

	case DIV64_REG:
		if vm.reg[inst.Src] == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] /= vm.reg[inst.Src]
		vm.pc++

	case OR64_REG:
		vm.reg[inst.Dst] |= vm.reg[inst.Src]
		vm.pc++

	case AND64_REG:
		vm.reg[inst.Dst] &= vm.reg[inst.Src]
		vm.pc++

	case LSH64_REG:
		vm.reg[inst.Dst] <<= vm.reg[inst.Src] & 63
		vm.pc++

	case RSH64_REG:
		vm.reg[inst.Dst] >>= vm.reg[inst.Src] & 63
		vm.pc++

	case MOD64_REG:
		if vm.reg[inst.Src] == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] %= vm.reg[inst.Src]
		vm.pc++

	case XOR64_REG:
		vm.reg[inst.Dst] ^= vm.reg[inst.Src]
		vm.pc++

	case MOV64_REG:
		vm.reg[inst.Dst] = vm.reg[inst.Src]
		vm.pc++

	case ARSH64_REG:
		vm.reg[inst.Dst] = uint64(int64(vm.reg[inst.Dst]) >> (vm.reg[inst.Src] & 63))
		vm.pc++

	// ==================== ALU32 Immediate ====================
	case ADD32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) + uint32(inst.Imm))
		vm.pc++

	case SUB32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) - uint32(inst.Imm))
		vm.pc++

	case MUL32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) * uint32(inst.Imm))
		vm.pc++

	case DIV32_IMM:
		if inst.Imm == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) / uint32(inst.Imm))
		vm.pc++

	case OR32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) | uint32(inst.Imm))
		vm.pc++

	case AND32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) & uint32(inst.Imm))
		vm.pc++

	case LSH32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) << (uint32(inst.Imm) & 31))
		vm.pc++

	case RSH32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) >> (uint32(inst.Imm) & 31))
		vm.pc++

	case NEG32:
		vm.reg[inst.Dst] = uint64(uint32(-int32(vm.reg[inst.Dst])))
		vm.pc++

	case MOD32_IMM:
		if inst.Imm == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) % uint32(inst.Imm))
		vm.pc++

	case XOR32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) ^ uint32(inst.Imm))
		vm.pc++

	case MOV32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(inst.Imm))
		vm.pc++

	case ARSH32_IMM:
		vm.reg[inst.Dst] = uint64(uint32(int32(vm.reg[inst.Dst]) >> (uint32(inst.Imm) & 31)))
		vm.pc++

	// ==================== ALU32 Register ====================
	case ADD32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) + uint32(vm.reg[inst.Src]))
		vm.pc++

	case SUB32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) - uint32(vm.reg[inst.Src]))
		vm.pc++

	case MUL32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) * uint32(vm.reg[inst.Src]))
		vm.pc++

	case DIV32_REG:
		if uint32(vm.reg[inst.Src]) == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) / uint32(vm.reg[inst.Src]))
		vm.pc++

	case OR32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) | uint32(vm.reg[inst.Src]))
		vm.pc++

	case AND32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) & uint32(vm.reg[inst.Src]))
		vm.pc++

	case LSH32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) << (uint32(vm.reg[inst.Src]) & 31))
		vm.pc++

	case RSH32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) >> (uint32(vm.reg[inst.Src]) & 31))
		vm.pc++

	case MOD32_REG:
		if uint32(vm.reg[inst.Src]) == 0 {
			return NewVMError(ErrDivisionByZero, vm.pc, inst.Opcode, 0)
		}
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) % uint32(vm.reg[inst.Src]))
		vm.pc++

	case XOR32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Dst]) ^ uint32(vm.reg[inst.Src]))
		vm.pc++

	case MOV32_REG:
		vm.reg[inst.Dst] = uint64(uint32(vm.reg[inst.Src]))
		vm.pc++

	case ARSH32_REG:
		vm.reg[inst.Dst] = uint64(uint32(int32(vm.reg[inst.Dst]) >> (uint32(vm.reg[inst.Src]) & 31)))
		vm.pc++

	// ==================== Endianness ====================
	case LE:
		// Little endian (no-op on little-endian systems, but we handle explicitly)
		vm.reg[inst.Dst] = vm.endianConvert(vm.reg[inst.Dst], inst.Imm, false)
		vm.pc++

	case BE:
		// Big endian conversion
		vm.reg[inst.Dst] = vm.endianConvert(vm.reg[inst.Dst], inst.Imm, true)
		vm.pc++

	// ==================== Memory Load ====================
	case LDXB:
		addr := vm.reg[inst.Src] + uint64(int64(inst.Offset))
		val, err := vm.memory.ReadByte(addr)
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.reg[inst.Dst] = uint64(val)
		vm.pc++

	case LDXH:
		addr := vm.reg[inst.Src] + uint64(int64(inst.Offset))
		val, err := vm.memory.ReadUint16(addr)
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.reg[inst.Dst] = uint64(val)
		vm.pc++

	case LDXW:
		addr := vm.reg[inst.Src] + uint64(int64(inst.Offset))
		val, err := vm.memory.ReadUint32(addr)
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.reg[inst.Dst] = uint64(val)
		vm.pc++

	case LDXDW:
		addr := vm.reg[inst.Src] + uint64(int64(inst.Offset))
		val, err := vm.memory.ReadUint64(addr)
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.reg[inst.Dst] = val
		vm.pc++

	case LDDW:
		// Load 64-bit immediate (uses two instruction slots)
		if vm.pc+1 >= uint64(len(vm.instructions)) {
			return NewVMError(ErrInvalidInstruction, vm.pc, inst.Opcode, 0)
		}
		next := vm.instructions[vm.pc+1]
		imm64 := uint64(uint32(inst.Imm)) | (uint64(uint32(next.Imm)) << 32)
		vm.reg[inst.Dst] = imm64
		vm.pc += 2

	// ==================== Memory Store Immediate ====================
	case STB:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteByte(addr, byte(inst.Imm))
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	case STH:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteUint16(addr, uint16(inst.Imm))
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	case STW:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteUint32(addr, uint32(inst.Imm))
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	case STDW:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteUint64(addr, uint64(int64(inst.Imm)))
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	// ==================== Memory Store Register ====================
	case STXB:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteByte(addr, byte(vm.reg[inst.Src]))
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	case STXH:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteUint16(addr, uint16(vm.reg[inst.Src]))
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	case STXW:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteUint32(addr, uint32(vm.reg[inst.Src]))
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	case STXDW:
		addr := vm.reg[inst.Dst] + uint64(int64(inst.Offset))
		err := vm.memory.WriteUint64(addr, vm.reg[inst.Src])
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, addr)
		}
		vm.pc++

	// ==================== Jump Always ====================
	case JA:
		vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)

	// ==================== Jump Immediate ====================
	case JEQ_IMM:
		if vm.reg[inst.Dst] == uint64(int64(inst.Imm)) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JGT_IMM:
		if vm.reg[inst.Dst] > uint64(int64(inst.Imm)) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JGE_IMM:
		if vm.reg[inst.Dst] >= uint64(int64(inst.Imm)) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSET_IMM:
		if vm.reg[inst.Dst]&uint64(int64(inst.Imm)) != 0 {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JNE_IMM:
		if vm.reg[inst.Dst] != uint64(int64(inst.Imm)) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSGT_IMM:
		if int64(vm.reg[inst.Dst]) > int64(inst.Imm) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSGE_IMM:
		if int64(vm.reg[inst.Dst]) >= int64(inst.Imm) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JLT_IMM:
		if vm.reg[inst.Dst] < uint64(int64(inst.Imm)) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JLE_IMM:
		if vm.reg[inst.Dst] <= uint64(int64(inst.Imm)) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSLT_IMM:
		if int64(vm.reg[inst.Dst]) < int64(inst.Imm) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSLE_IMM:
		if int64(vm.reg[inst.Dst]) <= int64(inst.Imm) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	// ==================== Jump Register ====================
	case JEQ_REG:
		if vm.reg[inst.Dst] == vm.reg[inst.Src] {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JGT_REG:
		if vm.reg[inst.Dst] > vm.reg[inst.Src] {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JGE_REG:
		if vm.reg[inst.Dst] >= vm.reg[inst.Src] {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSET_REG:
		if vm.reg[inst.Dst]&vm.reg[inst.Src] != 0 {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JNE_REG:
		if vm.reg[inst.Dst] != vm.reg[inst.Src] {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSGT_REG:
		if int64(vm.reg[inst.Dst]) > int64(vm.reg[inst.Src]) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSGE_REG:
		if int64(vm.reg[inst.Dst]) >= int64(vm.reg[inst.Src]) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JLT_REG:
		if vm.reg[inst.Dst] < vm.reg[inst.Src] {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JLE_REG:
		if vm.reg[inst.Dst] <= vm.reg[inst.Src] {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSLT_REG:
		if int64(vm.reg[inst.Dst]) < int64(vm.reg[inst.Src]) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	case JSLE_REG:
		if int64(vm.reg[inst.Dst]) <= int64(vm.reg[inst.Src]) {
			vm.pc = uint64(int64(vm.pc) + int64(inst.Offset) + 1)
		} else {
			vm.pc++
		}

	// ==================== Call and Exit ====================
	case CALL:
		return vm.handleCall(inst)

	case EXIT:
		if vm.callDepth == 0 {
			vm.exited = true
			return nil
		}
		// Return from function call
		return vm.handleReturn()

	default:
		return NewVMError(ErrInvalidOpcode, vm.pc, inst.Opcode, 0)
	}

	return nil
}

// handleCall handles the CALL instruction.
func (vm *VM) handleCall(inst Instruction) error {
	syscallNum := uint32(inst.Imm)

	// Check if this is a syscall (high bit set or known syscall number)
	if vm.syscallHandler != nil {
		result, err := vm.syscallHandler.HandleSyscall(vm, syscallNum)
		if err != nil {
			return NewVMError(err, vm.pc, inst.Opcode, 0)
		}
		vm.reg[R0] = result
		vm.pc++
		return nil
	}

	// Internal function call
	if vm.callDepth >= MaxStackFrames-1 {
		return NewVMError(ErrCallDepthExceeded, vm.pc, inst.Opcode, 0)
	}

	// Save return address and caller-saved state
	vm.callStack[vm.callDepth] = CallFrame{
		ReturnPC: vm.pc + 1,
		FramePtr: vm.reg[R10],
		// Callee-saved registers would be saved here if needed
	}
	vm.callDepth++

	// Update frame pointer
	vm.reg[R10] = vm.memory.GetFramePointer(vm.callDepth)

	// Jump to function (relative to current PC)
	vm.pc = uint64(int64(vm.pc) + int64(inst.Imm) + 1)

	return nil
}

// handleReturn handles returning from a function call.
func (vm *VM) handleReturn() error {
	if vm.callDepth == 0 {
		return NewVMError(ErrStackUnderflow, vm.pc, EXIT, 0)
	}

	vm.callDepth--
	frame := vm.callStack[vm.callDepth]

	// Restore frame pointer
	vm.reg[R10] = frame.FramePtr

	// Return to caller
	vm.pc = frame.ReturnPC

	return nil
}

// endianConvert performs endianness conversion.
func (vm *VM) endianConvert(val uint64, size int32, toBigEndian bool) uint64 {
	switch size {
	case 16:
		v := uint16(val)
		if toBigEndian {
			return uint64(((v & 0x00ff) << 8) | ((v & 0xff00) >> 8))
		}
		return uint64(v)
	case 32:
		v := uint32(val)
		if toBigEndian {
			return uint64(((v & 0x000000ff) << 24) |
				((v & 0x0000ff00) << 8) |
				((v & 0x00ff0000) >> 8) |
				((v & 0xff000000) >> 24))
		}
		return uint64(v)
	case 64:
		if toBigEndian {
			return ((val & 0x00000000000000ff) << 56) |
				((val & 0x000000000000ff00) << 40) |
				((val & 0x0000000000ff0000) << 24) |
				((val & 0x00000000ff000000) << 8) |
				((val & 0x000000ff00000000) >> 8) |
				((val & 0x0000ff0000000000) >> 24) |
				((val & 0x00ff000000000000) >> 40) |
				((val & 0xff00000000000000) >> 56)
		}
		return val
	default:
		return val
	}
}
