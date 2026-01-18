package snapshot

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/fortiblox/x1-nimbus/pkg/types"
)

func TestComputeAccountHash(t *testing.T) {
	// Create a test account
	pubkey := types.MustPubkeyFromBase58("11111111111111111111111111111111")
	owner := types.MustPubkeyFromBase58("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")

	account := &types.Account{
		Lamports:   1000000000,
		Data:       []byte{1, 2, 3, 4, 5},
		Owner:      owner,
		Executable: false,
		RentEpoch:  0,
	}

	// Compute hash using our function
	hash := ComputeAccountHash(account, pubkey)

	// Manually compute expected hash
	h := sha256.New()
	var lamportsBuf [8]byte
	binary.LittleEndian.PutUint64(lamportsBuf[:], 1000000000)
	h.Write(lamportsBuf[:])

	var rentEpochBuf [8]byte
	binary.LittleEndian.PutUint64(rentEpochBuf[:], 0)
	h.Write(rentEpochBuf[:])

	h.Write([]byte{1, 2, 3, 4, 5})
	h.Write([]byte{0}) // executable = false

	h.Write(owner[:])
	h.Write(pubkey[:])

	var expectedHash types.Hash
	copy(expectedHash[:], h.Sum(nil))

	if hash != expectedHash {
		t.Errorf("ComputeAccountHash() = %s, want %s", hash.String(), expectedHash.String())
	}
}

func TestComputeAccountHashExecutable(t *testing.T) {
	pubkey := types.MustPubkeyFromBase58("BPFLoader1111111111111111111111111111111111")
	owner := types.MustPubkeyFromBase58("NativeLoader1111111111111111111111111111111")

	account := &types.Account{
		Lamports:   5000000000,
		Data:       []byte{0xBF, 0x00, 0x00, 0x00}, // BPF program header
		Owner:      owner,
		Executable: true,
		RentEpoch:  100,
	}

	hash := ComputeAccountHash(account, pubkey)

	// Verify it's not zero
	if hash == types.ZeroHash {
		t.Error("ComputeAccountHash() returned zero hash for executable account")
	}

	// Verify changing executable flag changes hash
	account.Executable = false
	hash2 := ComputeAccountHash(account, pubkey)

	if hash == hash2 {
		t.Error("Executable flag should affect account hash")
	}
}

func TestVerifyAccountHash(t *testing.T) {
	pubkey := types.MustPubkeyFromBase58("11111111111111111111111111111111")
	owner := types.SystemProgramID

	account := &types.Account{
		Lamports:   500000000,
		Data:       nil,
		Owner:      owner,
		Executable: false,
		RentEpoch:  0,
	}

	expectedHash := ComputeAccountHash(account, pubkey)

	// Should pass with correct hash
	err := VerifyAccountHash(account, pubkey, expectedHash)
	if err != nil {
		t.Errorf("VerifyAccountHash() error = %v, want nil", err)
	}

	// Should fail with wrong hash
	wrongHash := types.SHA256([]byte("wrong"))
	err = VerifyAccountHash(account, pubkey, wrongHash)
	if err == nil {
		t.Error("VerifyAccountHash() should fail with wrong hash")
	}
}

func TestComputeMerkle16Root(t *testing.T) {
	tests := []struct {
		name   string
		hashes []types.Hash
		want   types.Hash
	}{
		{
			name:   "empty",
			hashes: []types.Hash{},
			want:   types.ZeroHash,
		},
		{
			name:   "single hash",
			hashes: []types.Hash{types.SHA256([]byte("test"))},
			want:   types.SHA256([]byte("test")),
		},
		{
			name: "two hashes",
			hashes: []types.Hash{
				types.SHA256([]byte("a")),
				types.SHA256([]byte("b")),
			},
			want: func() types.Hash {
				h1 := types.SHA256([]byte("a"))
				h2 := types.SHA256([]byte("b"))
				data := make([]byte, 64)
				copy(data[0:32], h1[:])
				copy(data[32:64], h2[:])
				return types.SHA256(data)
			}(),
		},
		{
			name: "16 hashes - single level",
			hashes: func() []types.Hash {
				hashes := make([]types.Hash, 16)
				for i := 0; i < 16; i++ {
					hashes[i] = types.SHA256([]byte{byte(i)})
				}
				return hashes
			}(),
			want: func() types.Hash {
				hashes := make([]types.Hash, 16)
				for i := 0; i < 16; i++ {
					hashes[i] = types.SHA256([]byte{byte(i)})
				}
				data := make([]byte, 16*32)
				for i, h := range hashes {
					copy(data[i*32:(i+1)*32], h[:])
				}
				return types.SHA256(data)
			}(),
		},
		{
			name: "17 hashes - two levels",
			hashes: func() []types.Hash {
				hashes := make([]types.Hash, 17)
				for i := 0; i < 17; i++ {
					hashes[i] = types.SHA256([]byte{byte(i)})
				}
				return hashes
			}(),
			want: func() types.Hash {
				hashes := make([]types.Hash, 17)
				for i := 0; i < 17; i++ {
					hashes[i] = types.SHA256([]byte{byte(i)})
				}
				// First group of 16
				data1 := make([]byte, 16*32)
				for i := 0; i < 16; i++ {
					copy(data1[i*32:(i+1)*32], hashes[i][:])
				}
				parent1 := types.SHA256(data1)
				// Second group of 1
				parent2 := hashes[16]
				// Root
				rootData := make([]byte, 64)
				copy(rootData[0:32], parent1[:])
				copy(rootData[32:64], parent2[:])
				return types.SHA256(rootData)
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := computeMerkle16Root(tt.hashes)
			if got != tt.want {
				t.Errorf("computeMerkle16Root() = %s, want %s", got.String(), tt.want.String())
			}
		})
	}
}

func TestComputeAccountsHashMerkle16(t *testing.T) {
	// Create test accounts with known pubkeys (will be sorted)
	var pubkey1, pubkey2, pubkey3 types.Pubkey
	for i := 0; i < 32; i++ {
		pubkey1[i] = byte(1)
		pubkey2[i] = byte(2)
		pubkey3[i] = byte(3)
	}

	account := &types.Account{
		Lamports: 1000,
		Owner:    types.SystemProgramID,
	}

	refs := []accountHashRef{
		{pubkey: pubkey3, hash: ComputeAccountHash(account, pubkey3)},
		{pubkey: pubkey1, hash: ComputeAccountHash(account, pubkey1)},
		{pubkey: pubkey2, hash: ComputeAccountHash(account, pubkey2)},
	}

	hash := computeAccountsHashMerkle16(refs)

	// Verify result is deterministic
	hash2 := computeAccountsHashMerkle16(refs)
	if hash != hash2 {
		t.Error("computeAccountsHashMerkle16() should be deterministic")
	}

	// Verify ordering is by pubkey
	// After sorting: pubkey1 < pubkey2 < pubkey3
	sortedRefs := []accountHashRef{
		{pubkey: pubkey1, hash: ComputeAccountHash(account, pubkey1)},
		{pubkey: pubkey2, hash: ComputeAccountHash(account, pubkey2)},
		{pubkey: pubkey3, hash: ComputeAccountHash(account, pubkey3)},
	}

	// Manually compute expected hash
	hashes := make([]types.Hash, 3)
	for i, ref := range sortedRefs {
		hashes[i] = ref.hash
	}
	expected := computeMerkle16Root(hashes)

	if hash != expected {
		t.Errorf("computeAccountsHashMerkle16() = %s, want %s", hash.String(), expected.String())
	}
}

func TestVerifyBankHash(t *testing.T) {
	// Create test accounts - using valid 32-byte pubkeys
	var pubkey1, pubkey2 types.Pubkey
	for i := 0; i < 32; i++ {
		pubkey1[i] = byte(i + 1)
		pubkey2[i] = byte(i + 33)
	}

	accounts := []types.AccountRef{
		{
			Pubkey: pubkey1,
			Account: &types.Account{
				Lamports: 1000,
				Owner:    types.SystemProgramID,
			},
		},
		{
			Pubkey: pubkey2,
			Account: &types.Account{
				Lamports: 2000,
				Owner:    types.SystemProgramID,
			},
		},
	}

	// Compute the expected bank hash
	refs := make([]accountHashRef, len(accounts))
	for i, acc := range accounts {
		refs[i] = accountHashRef{
			pubkey: acc.Pubkey,
			hash:   ComputeAccountHash(acc.Account, acc.Pubkey),
		}
	}
	expectedHash := computeAccountsHashMerkle16(refs)

	// Should pass with correct hash
	err := VerifyBankHash(accounts, expectedHash)
	if err != nil {
		t.Errorf("VerifyBankHash() error = %v, want nil", err)
	}

	// Should fail with wrong hash
	wrongHash := types.SHA256([]byte("wrong"))
	err = VerifyBankHash(accounts, wrongHash)
	if err == nil {
		t.Error("VerifyBankHash() should fail with wrong hash")
	}
}

func TestVerifyManifestHash(t *testing.T) {
	manifest := &SnapshotManifest{
		Slot:          12345,
		AccountsCount: 100,
		LamportsTotal: 1000000000000,
		Version:       1,
		SnapshotType:  SnapshotTypeFull,
	}

	// Compute expected hash
	data, err := manifest.SerializeBinary()
	if err != nil {
		t.Fatalf("SerializeBinary() error = %v", err)
	}
	expectedHash := types.SHA256(data)

	// Should pass with correct hash
	err = VerifyManifestHash(manifest, expectedHash)
	if err != nil {
		t.Errorf("VerifyManifestHash() error = %v, want nil", err)
	}

	// Should fail with wrong hash
	wrongHash := types.SHA256([]byte("wrong"))
	err = VerifyManifestHash(manifest, wrongHash)
	if err == nil {
		t.Error("VerifyManifestHash() should fail with wrong hash")
	}
}

func TestComputeSnapshotHash(t *testing.T) {
	manifest := &SnapshotManifest{
		Slot:          99999,
		AccountsCount: 500,
		LamportsTotal: 5000000000000,
		Version:       1,
		SnapshotType:  SnapshotTypeFull,
	}

	hash := ComputeSnapshotHash(manifest)

	// Should not be zero
	if hash == types.ZeroHash {
		t.Error("ComputeSnapshotHash() returned zero hash")
	}

	// Should be deterministic
	hash2 := ComputeSnapshotHash(manifest)
	if hash != hash2 {
		t.Error("ComputeSnapshotHash() should be deterministic")
	}

	// Changing manifest should change hash
	manifest.Slot = 100000
	hash3 := ComputeSnapshotHash(manifest)
	if hash == hash3 {
		t.Error("ComputeSnapshotHash() should produce different hash for different manifest")
	}
}

func TestHashMerkle16Children(t *testing.T) {
	tests := []struct {
		name     string
		children []types.Hash
	}{
		{"empty", []types.Hash{}},
		{"one", []types.Hash{types.SHA256([]byte("a"))}},
		{"two", []types.Hash{types.SHA256([]byte("a")), types.SHA256([]byte("b"))}},
		{"sixteen", func() []types.Hash {
			h := make([]types.Hash, 16)
			for i := range h {
				h[i] = types.SHA256([]byte{byte(i)})
			}
			return h
		}()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash := hashMerkle16Children(tt.children)

			// Should be deterministic
			hash2 := hashMerkle16Children(tt.children)
			if hash != hash2 {
				t.Error("hashMerkle16Children() should be deterministic")
			}

			// Special cases
			if len(tt.children) == 0 && hash != types.ZeroHash {
				t.Error("hashMerkle16Children() should return zero hash for empty input")
			}
			if len(tt.children) == 1 && hash != tt.children[0] {
				t.Error("hashMerkle16Children() should return the same hash for single input")
			}
		})
	}
}

func TestAccountHashConsistency(t *testing.T) {
	// Test that ComputeAccountHash matches Account.Hash from types package
	pubkey := types.MustPubkeyFromBase58("Vote111111111111111111111111111111111111111")
	owner := types.VoteProgramID

	account := &types.Account{
		Lamports:   10000000000,
		Data:       bytes.Repeat([]byte{0xAB}, 100),
		Owner:      owner,
		Executable: false,
		RentEpoch:  500,
	}

	// Our implementation
	ourHash := ComputeAccountHash(account, pubkey)

	// Types package implementation
	typesHash := account.Hash(pubkey)

	if ourHash != typesHash {
		t.Errorf("Hash mismatch: ComputeAccountHash() = %s, Account.Hash() = %s",
			ourHash.String(), typesHash.String())
	}
}

func TestVerifyAccountEntry(t *testing.T) {
	pubkey := types.MustPubkeyFromBase58("Stake11111111111111111111111111111111111111")

	entry := &AccountEntry{
		StoredMeta: StoredMeta{
			WriteVersion: 1,
			DataLen:      10,
			Pubkey:       pubkey,
		},
		Account: &types.Account{
			Lamports:   50000000000,
			Data:       bytes.Repeat([]byte{0x01}, 10),
			Owner:      types.StakeProgramID,
			Executable: false,
			RentEpoch:  200,
		},
		Offset: 0,
	}

	// Should pass verification
	err := VerifyAccountEntry(entry)
	if err != nil {
		t.Errorf("VerifyAccountEntry() error = %v, want nil", err)
	}
}

func TestComputeAccountsHash(t *testing.T) {
	// Test the exported ComputeAccountsHash function
	var pubkey1, pubkey2 types.Pubkey
	for i := 0; i < 32; i++ {
		pubkey1[i] = byte(i + 1)
		pubkey2[i] = byte(i + 33)
	}

	accounts := []types.AccountRef{
		{
			Pubkey: pubkey1,
			Account: &types.Account{
				Lamports: 1000,
				Owner:    types.SystemProgramID,
			},
		},
		{
			Pubkey: pubkey2,
			Account: &types.Account{
				Lamports: 2000,
				Owner:    types.SystemProgramID,
			},
		},
	}

	hash := ComputeAccountsHash(accounts)

	// Should not be zero
	if hash == types.ZeroHash {
		t.Error("ComputeAccountsHash() returned zero hash")
	}

	// Should be deterministic
	hash2 := ComputeAccountsHash(accounts)
	if hash != hash2 {
		t.Error("ComputeAccountsHash() should be deterministic")
	}

	// Empty accounts should return zero hash
	emptyHash := ComputeAccountsHash([]types.AccountRef{})
	if emptyHash != types.ZeroHash {
		t.Error("ComputeAccountsHash() should return zero hash for empty input")
	}
}

func TestDefaultVerifyConfig(t *testing.T) {
	config := DefaultVerifyConfig()

	if !config.VerifyAccountsHash {
		t.Error("DefaultVerifyConfig() should enable VerifyAccountsHash")
	}
	if !config.VerifyBankHash {
		t.Error("DefaultVerifyConfig() should enable VerifyBankHash")
	}
	if config.VerifyIndividualAccounts {
		t.Error("DefaultVerifyConfig() should disable VerifyIndividualAccounts")
	}
}

func TestVerifyResultFields(t *testing.T) {
	result := &VerifyResult{
		ManifestValid:        true,
		AccountsHashValid:    true,
		BankHashValid:        true,
		AccountsCount:        100,
		LamportsTotal:        1000000000000,
		ComputedAccountsHash: types.SHA256([]byte("accounts")),
		ComputedBankHash:     types.SHA256([]byte("bank")),
		FailedAccounts:       []types.Pubkey{types.MustPubkeyFromBase58("11111111111111111111111111111111")},
	}

	if result.AccountsCount != 100 {
		t.Error("VerifyResult.AccountsCount not set correctly")
	}
	if result.LamportsTotal != 1000000000000 {
		t.Error("VerifyResult.LamportsTotal not set correctly")
	}
	if len(result.FailedAccounts) != 1 {
		t.Error("VerifyResult.FailedAccounts not set correctly")
	}
}

func BenchmarkComputeAccountHash(b *testing.B) {
	pubkey := types.MustPubkeyFromBase58("11111111111111111111111111111111")
	account := &types.Account{
		Lamports:   1000000000,
		Data:       bytes.Repeat([]byte{0xAB}, 1024),
		Owner:      types.SystemProgramID,
		Executable: false,
		RentEpoch:  0,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ComputeAccountHash(account, pubkey)
	}
}

func BenchmarkComputeMerkle16Root(b *testing.B) {
	// Create 10000 random hashes
	hashes := make([]types.Hash, 10000)
	for i := range hashes {
		hashes[i] = types.SHA256([]byte{byte(i), byte(i >> 8)})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Make a copy since the function modifies the slice
		hashCopy := make([]types.Hash, len(hashes))
		copy(hashCopy, hashes)
		computeMerkle16Root(hashCopy)
	}
}

func BenchmarkComputeAccountsHashMerkle16(b *testing.B) {
	// Create 10000 account refs
	refs := make([]accountHashRef, 10000)
	for i := range refs {
		var pubkey types.Pubkey
		binary.BigEndian.PutUint64(pubkey[:8], uint64(i))
		refs[i] = accountHashRef{
			pubkey: pubkey,
			hash:   types.SHA256([]byte{byte(i), byte(i >> 8)}),
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Make a copy since the function sorts the slice
		refsCopy := make([]accountHashRef, len(refs))
		copy(refsCopy, refs)
		computeAccountsHashMerkle16(refsCopy)
	}
}
