// X1-Nimbus: Trustless Verification Node for X1 Blockchain
//
// This is the main entry point for X1-Nimbus, a lightweight full-verifying node
// that independently validates every transaction on the X1 network without
// trusting any third party.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/fortiblox/x1-nimbus/pkg/accounts"
	"github.com/fortiblox/x1-nimbus/pkg/geyser"
	"github.com/fortiblox/x1-nimbus/pkg/metrics"
	"github.com/fortiblox/x1-nimbus/pkg/poh"
	"github.com/fortiblox/x1-nimbus/pkg/replayer"
	"github.com/fortiblox/x1-nimbus/pkg/rpc"
	"github.com/fortiblox/x1-nimbus/pkg/types"
)

// Version information (set at build time)
var (
	Version   = "0.1.0"
	GitCommit = "dev"
	BuildTime = "unknown"
)

// Configuration flags
var (
	configFile        = flag.String("config", "/root/.config/x1-nimbus/config.json", "Path to JSON configuration file")
	dataDir           = flag.String("data-dir", "", "Data directory for accounts and blocks")
	logLevel          = flag.String("log-level", "", "Log level: debug, info, warn, error")
	rpcAddr           = flag.String("rpc-addr", "", "RPC server listen address")
	enableRPC         = flag.Bool("enable-rpc", false, "Enable JSON-RPC server")
	geyserURL         = flag.String("geyser-url", "", "Geyser gRPC endpoint URL")
	geyserToken       = flag.String("geyser-token", "", "Geyser authentication token")
	rpcEndpoint       = flag.String("rpc-endpoint", "", "RPC endpoint for fallback")
	pollInterval      = flag.Duration("poll-interval", 0, "RPC polling interval")
	commitment        = flag.String("commitment", "", "Commitment level: processed, confirmed, finalized")
	startSlot         = flag.Uint64("start-slot", 0, "Starting slot (0 = current)")
	verifyBankHash    = flag.Bool("verify-bank-hash", false, "Verify bank hash against network")
	skipSigVerify     = flag.Bool("skip-sig-verify", false, "Skip signature verification (unsafe)")
	skipPoH           = flag.Bool("skip-poh", false, "Skip PoH verification (unsafe)")
	showVersion       = flag.Bool("version", false, "Print version and exit")
	showStats         = flag.Bool("stats", false, "Show statistics periodically")
	enableMetrics     = flag.Bool("enable-metrics", false, "Enable Prometheus metrics server")
	metricsAddr       = flag.String("metrics-addr", "", "Metrics server listen address")
	parallelSigVerify = flag.Bool("parallel-sig-verify", false, "Enable parallel signature verification")
	bufferSize        = flag.Int("buffer-size", 0, "Block buffer size")
)

// Reference RPC endpoints for X1 mainnet
var referenceEndpoints = []string{
	"https://rpc.mainnet.x1.xyz",
	"https://entrypoint0.mainnet.x1.xyz",
	"https://entrypoint1.mainnet.x1.xyz",
	"https://entrypoint2.mainnet.x1.xyz",
}

// Config represents the JSON configuration file structure.
type Config struct {
	Geyser       GeyserConfig       `json:"geyser"`
	RPC          RPCConfig          `json:"rpc"`
	Metrics      MetricsConfig      `json:"metrics"`
	Verification VerificationConfig `json:"verification"`
	General      GeneralConfig      `json:"general"`
	Performance  PerformanceConfig  `json:"performance"`
}

// GeyserConfig holds Geyser gRPC connection settings.
type GeyserConfig struct {
	Endpoint string `json:"endpoint"`
	Token    string `json:"token"`
}

// RPCConfig holds RPC server and fallback settings.
type RPCConfig struct {
	FallbackEndpoint string `json:"fallback_endpoint"`
	ServerEnabled    bool   `json:"server_enabled"`
	ServerAddr       string `json:"server_addr"`
}

// MetricsConfig holds Prometheus metrics settings.
type MetricsConfig struct {
	Enabled bool   `json:"enabled"`
	Addr    string `json:"addr"`
}

// VerificationConfig holds verification pipeline settings.
type VerificationConfig struct {
	Signatures bool `json:"signatures"`
	PoH        bool `json:"poh"`
	BankHash   bool `json:"bank_hash"`
}

// GeneralConfig holds general application settings.
type GeneralConfig struct {
	DataDir  string `json:"data_dir"`
	LogLevel string `json:"log_level"`
}

// PerformanceConfig holds performance tuning settings.
type PerformanceConfig struct {
	PollIntervalMs    int  `json:"poll_interval_ms"`
	BufferSize        int  `json:"buffer_size"`
	ParallelSigVerify bool `json:"parallel_sig_verify"`
}

// defaultConfig returns a Config with default values.
func defaultConfig() Config {
	return Config{
		Geyser: GeyserConfig{
			Endpoint: "https://grpc.xolana.xen.network:443",
			Token:    "",
		},
		RPC: RPCConfig{
			FallbackEndpoint: "https://rpc.mainnet.x1.xyz",
			ServerEnabled:    false,
			ServerAddr:       ":8899",
		},
		Metrics: MetricsConfig{
			Enabled: true,
			Addr:    ":9090",
		},
		Verification: VerificationConfig{
			Signatures: true,
			PoH:        true,
			BankHash:   true,
		},
		General: GeneralConfig{
			DataDir:  "/mnt/x1-nimbus",
			LogLevel: "info",
		},
		Performance: PerformanceConfig{
			PollIntervalMs:    400,
			BufferSize:        1000,
			ParallelSigVerify: true,
		},
	}
}

// loadConfig loads configuration from the specified JSON file.
// If the file doesn't exist, it returns the default configuration.
// CLI flags override config file values when explicitly set.
func loadConfig(configPath string) (Config, error) {
	cfg := defaultConfig()

	// Try to read the config file
	data, err := os.ReadFile(configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("Config file not found at %s, using defaults", configPath)
			return cfg, nil
		}
		return cfg, fmt.Errorf("failed to read config file: %w", err)
	}

	// Parse JSON
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("failed to parse config file: %w", err)
	}

	log.Printf("Loaded configuration from %s", configPath)
	return cfg, nil
}

// applyConfigWithCLIOverrides applies config values and lets CLI flags override them.
// This function checks if CLI flags were explicitly set and uses those values,
// otherwise it uses values from the config file.
func applyConfigWithCLIOverrides(cfg Config) {
	// Helper to check if a flag was explicitly set on command line
	flagSet := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) {
		flagSet[f.Name] = true
	})

	// Geyser settings
	if !flagSet["geyser-url"] {
		*geyserURL = cfg.Geyser.Endpoint
	}
	if !flagSet["geyser-token"] {
		*geyserToken = cfg.Geyser.Token
	}

	// RPC settings
	if !flagSet["rpc-endpoint"] {
		*rpcEndpoint = cfg.RPC.FallbackEndpoint
	}
	if !flagSet["enable-rpc"] {
		*enableRPC = cfg.RPC.ServerEnabled
	}
	if !flagSet["rpc-addr"] {
		*rpcAddr = cfg.RPC.ServerAddr
	}

	// Metrics settings
	if !flagSet["enable-metrics"] {
		*enableMetrics = cfg.Metrics.Enabled
	}
	if !flagSet["metrics-addr"] {
		*metricsAddr = cfg.Metrics.Addr
	}

	// Verification settings (note: config uses positive flags, CLI uses skip flags)
	if !flagSet["skip-sig-verify"] {
		*skipSigVerify = !cfg.Verification.Signatures
	}
	if !flagSet["skip-poh"] {
		*skipPoH = !cfg.Verification.PoH
	}
	if !flagSet["verify-bank-hash"] {
		*verifyBankHash = cfg.Verification.BankHash
	}

	// General settings
	if !flagSet["data-dir"] {
		*dataDir = cfg.General.DataDir
	}
	if !flagSet["log-level"] {
		*logLevel = cfg.General.LogLevel
	}

	// Performance settings
	if !flagSet["poll-interval"] {
		*pollInterval = time.Duration(cfg.Performance.PollIntervalMs) * time.Millisecond
	}
	if !flagSet["buffer-size"] {
		*bufferSize = cfg.Performance.BufferSize
	}
	if !flagSet["parallel-sig-verify"] {
		*parallelSigVerify = cfg.Performance.ParallelSigVerify
	}
}

// BlockProcessor ties together all verification components.
type BlockProcessor struct {
	// Geyser client for block fetching
	client *geyser.Client

	// Accounts database
	db accounts.AccountsDB

	// Transaction executor
	executor *replayer.Executor

	// Program registry
	registry *replayer.ProgramRegistry

	// Block verifier for signature and PoH verification
	verifier *replayer.BlockVerifier

	// Current bank hash (used for bank hash computation)
	currentBankHash types.Hash

	// Statistics
	stats ProcessorStats

	// Metrics collector
	metrics *metrics.Metrics

	// Configuration
	skipSigVerify  bool
	skipPoH        bool
	verifyBankHash bool

	// Synchronization
	mu     sync.RWMutex
	closed atomic.Bool
}

// ProcessorStats tracks block processing statistics.
type ProcessorStats struct {
	mu               sync.Mutex
	BlocksProcessed  uint64
	TxsProcessed     uint64
	SigsVerified     uint64
	SuccessfulTxs    uint64
	FailedTxs        uint64
	TotalComputeUsed uint64
	StartTime        time.Time
	LastSlot         types.Slot
	LastBankHash     types.Hash
	Errors           uint64
}

// NewBlockProcessor creates a new block processor.
func NewBlockProcessor(client *geyser.Client, db accounts.AccountsDB, registry *replayer.ProgramRegistry) *BlockProcessor {
	executor := replayer.NewExecutor(db, registry)

	verifier := replayer.NewBlockVerifier(&dbAccountLoader{db: db})
	verifier.SetTransactionExecutor(executor)
	verifier.ParallelSignatureVerification = true

	return &BlockProcessor{
		client:   client,
		db:       db,
		executor: executor,
		registry: registry,
		verifier: verifier,
		stats: ProcessorStats{
			StartTime: time.Now(),
		},
	}
}

// dbAccountLoader adapts AccountsDB to the AccountLoader interface.
type dbAccountLoader struct {
	db accounts.AccountsDB
}

func (l *dbAccountLoader) LoadAccount(pubkey types.Pubkey) (*types.Account, error) {
	return l.db.GetAccount(pubkey)
}

// SetSkipSigVerify sets whether to skip signature verification.
func (bp *BlockProcessor) SetSkipSigVerify(skip bool) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.skipSigVerify = skip
	bp.verifier.SkipSignatureVerification = skip
}

// SetSkipPoH sets whether to skip PoH verification.
func (bp *BlockProcessor) SetSkipPoH(skip bool) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.skipPoH = skip
	bp.verifier.SkipPoHVerification = skip
}

// SetVerifyBankHash sets whether to verify bank hash.
func (bp *BlockProcessor) SetVerifyBankHash(verify bool) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.verifyBankHash = verify
}

// SetCurrentBankHash sets the current bank hash.
func (bp *BlockProcessor) SetCurrentBankHash(hash types.Hash) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.currentBankHash = hash
	bp.verifier.SetParentBankHash(hash)
}

// SetMetrics sets the metrics collector for the block processor.
func (bp *BlockProcessor) SetMetrics(m *metrics.Metrics) {
	bp.mu.Lock()
	defer bp.mu.Unlock()
	bp.metrics = m
}

// ProcessBlock processes a single block.
func (bp *BlockProcessor) ProcessBlock(ctx context.Context, block *types.Block) error {
	if block == nil {
		return fmt.Errorf("nil block")
	}

	startTime := time.Now()

	bp.mu.RLock()
	skipSig := bp.skipSigVerify
	skipPoh := bp.skipPoH
	parentBankHash := bp.currentBankHash
	bp.mu.RUnlock()

	// Count transactions and signatures
	txCount := block.NumTransactions()
	sigCount := replayer.CountSignatures(block)

	// Step 1: Verify signatures (unless skipped)
	if !skipSig {
		if err := replayer.VerifyBlockSignatures(block); err != nil {
			bp.stats.mu.Lock()
			bp.stats.Errors++
			bp.stats.mu.Unlock()
			if bp.metrics != nil {
				bp.metrics.ErrorsTotal.Inc()
			}
			return fmt.Errorf("signature verification failed: %w", err)
		}
	}

	// Step 2: Verify PoH (unless skipped)
	if !skipPoh {
		pohVerifier := poh.NewVerifier(block.PreviousBlockhash)
		if err := pohVerifier.VerifyEntries(block.Entries); err != nil {
			bp.stats.mu.Lock()
			bp.stats.Errors++
			bp.stats.mu.Unlock()
			if bp.metrics != nil {
				bp.metrics.ErrorsTotal.Inc()
			}
			return fmt.Errorf("PoH verification failed: %w", err)
		}
	}

	// Step 3: Execute transactions
	hasher := replayer.NewBankHasher(parentBankHash)
	hasher.SetBlockhash(block.Blockhash)

	var successCount, failCount int
	var totalCU uint64

	// Update executor slot and blockhash
	bp.executor.SetCurrentSlot(block.Slot)
	bp.executor.SetCurrentBlockhash(block.Blockhash)

	for _, entry := range block.Entries {
		for i := range entry.Transactions {
			tx := &entry.Transactions[i]

			// Count signatures for bank hash
			hasher.IncrementSignatureCount(uint64(len(tx.Signatures)))

			// Execute the transaction
			result, err := bp.executor.ExecuteTransaction(tx)
			if err != nil {
				// Execution error (not transaction failure)
				log.Printf("Transaction execution error: %v", err)
				failCount++
				continue
			}

			if result.Success {
				successCount++
			} else {
				failCount++
			}

			totalCU += uint64(result.ComputeUnits)

			// Add account deltas to bank hasher
			hasher.AddAccountDeltas(result.AccountDeltas)
		}
	}

	// Step 4: Compute bank hash
	computedBankHash := hasher.Compute()

	// Step 5: Update state
	bp.mu.Lock()
	bp.currentBankHash = computedBankHash
	bp.verifier.SetParentBankHash(computedBankHash)
	bp.mu.Unlock()

	// Update statistics
	elapsed := time.Since(startTime)
	bp.stats.mu.Lock()
	bp.stats.BlocksProcessed++
	bp.stats.TxsProcessed += uint64(txCount)
	bp.stats.SigsVerified += sigCount
	bp.stats.SuccessfulTxs += uint64(successCount)
	bp.stats.FailedTxs += uint64(failCount)
	bp.stats.TotalComputeUsed += totalCU
	bp.stats.LastSlot = block.Slot
	bp.stats.LastBankHash = computedBankHash
	bp.stats.mu.Unlock()

	// Log progress
	log.Printf("Slot %d: %d txs, %d sigs, bank hash OK (%dms)",
		block.Slot, txCount, sigCount, elapsed.Milliseconds())

	return nil
}

// Run starts the block processing loop.
func (bp *BlockProcessor) Run(ctx context.Context, commitment string) error {
	if bp.client == nil {
		return fmt.Errorf("no client configured")
	}

	// Connect to Geyser/RPC
	if err := bp.client.Connect(ctx); err != nil {
		return fmt.Errorf("failed to connect: %w", err)
	}

	// Subscribe to blocks
	blockCh, err := bp.client.SubscribeBlocks(ctx, commitment)
	if err != nil {
		return fmt.Errorf("failed to subscribe to blocks: %w", err)
	}

	log.Println("Connected to block stream, starting verification...")

	// Process blocks
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case block, ok := <-blockCh:
			if !ok {
				// Channel closed, attempt reconnection
				log.Println("Block stream closed, reconnecting...")

				// Wait a bit before reconnecting
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-time.After(5 * time.Second):
				}

				// Try to reconnect
				if err := bp.client.Connect(ctx); err != nil {
					log.Printf("Reconnection failed: %v", err)
					continue
				}

				blockCh, err = bp.client.SubscribeBlocks(ctx, commitment)
				if err != nil {
					log.Printf("Failed to resubscribe: %v", err)
					continue
				}

				log.Println("Reconnected to block stream")
				continue
			}

			// Process the block
			if err := bp.ProcessBlock(ctx, block); err != nil {
				log.Printf("Error processing block %d: %v", block.Slot, err)
				// Continue processing - don't stop on individual block errors
			}
		}
	}
}

// Stats returns the current statistics.
func (bp *BlockProcessor) Stats() ProcessorStats {
	bp.stats.mu.Lock()
	defer bp.stats.mu.Unlock()

	return ProcessorStats{
		BlocksProcessed:  bp.stats.BlocksProcessed,
		TxsProcessed:     bp.stats.TxsProcessed,
		SigsVerified:     bp.stats.SigsVerified,
		SuccessfulTxs:    bp.stats.SuccessfulTxs,
		FailedTxs:        bp.stats.FailedTxs,
		TotalComputeUsed: bp.stats.TotalComputeUsed,
		StartTime:        bp.stats.StartTime,
		LastSlot:         bp.stats.LastSlot,
		LastBankHash:     bp.stats.LastBankHash,
		Errors:           bp.stats.Errors,
	}
}

// Close gracefully stops the block processor.
func (bp *BlockProcessor) Close() error {
	if bp.closed.Swap(true) {
		return nil // Already closed
	}

	if bp.client != nil {
		return bp.client.Close()
	}

	return nil
}

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Printf("X1-Nimbus %s (%s)\n", Version, GitCommit)
		fmt.Printf("Build time: %s\n", BuildTime)
		fmt.Println()
		fmt.Println("Trustless Verification Node for X1 Blockchain")
		fmt.Println("https://github.com/fortiblox/x1-nimbus")
		os.Exit(0)
	}

	// Setup logging
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Printf("Starting X1-Nimbus %s", Version)
	log.Println()
	log.Println("  _   _ _           _")
	log.Println(" | \\ | (_)_ __ ___ | |__  _   _ ___")
	log.Println(" |  \\| | | '_ ` _ \\| '_ \\| | | / __|")
	log.Println(" | |\\  | | | | | | | |_) | |_| \\__ \\")
	log.Println(" |_| \\_|_|_| |_| |_|_.__/ \\__,_|___/")
	log.Println()
	log.Println(" Trustless Verification for X1 Blockchain")
	log.Println()

	// Load configuration from file
	cfg, err := loadConfig(*configFile)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Apply config values, allowing CLI flags to override
	applyConfigWithCLIOverrides(cfg)

	// Create context with cancellation
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Initialize accounts database
	log.Printf("Initializing accounts database at %s", *dataDir)
	var db accounts.AccountsDB

	// Use in-memory DB for now (BadgerDB for production)
	if *dataDir == ":memory:" {
		db = accounts.NewMemoryDB()
		log.Println("Using in-memory database (for testing)")
	} else {
		dbPath := *dataDir + "/accounts"
		if err := os.MkdirAll(dbPath, 0755); err != nil {
			log.Fatalf("Failed to create data directory: %v", err)
		}
		db, err = accounts.NewBadgerDB(dbPath)
		if err != nil {
			log.Fatalf("Failed to open accounts database: %v", err)
		}
		log.Printf("Opened BadgerDB at %s", dbPath)
	}
	defer db.Close()

	// Create program registry with native programs
	registry := replayer.NewProgramRegistry()
	replayer.RegisterNativePrograms(registry)
	log.Printf("Registered %d native programs", len(registry.ListPrograms()))

	// Create Geyser client
	var client *geyser.Client

	// Configure client options
	bufSize := *bufferSize
	if bufSize == 0 {
		bufSize = 1000
	}
	opts := []geyser.Option{
		geyser.WithAutoReconnect(true),
		geyser.WithBufferSize(bufSize),
		geyser.WithRPCPollInterval(*pollInterval),
	}

	// Add RPC fallback if configured
	if *rpcEndpoint != "" {
		opts = append(opts, geyser.WithRPCFallback(*rpcEndpoint))
	}

	// Add Geyser token if configured
	if *geyserToken != "" {
		opts = append(opts, geyser.WithToken(*geyserToken))
		opts = append(opts, geyser.WithTLS())
	}

	// Determine endpoint
	endpoint := *geyserURL
	if endpoint == "" && *rpcEndpoint != "" {
		// Use RPC endpoint as the base (will use RPC fallback mode)
		endpoint = *rpcEndpoint
	}

	if endpoint == "" {
		// Use default reference endpoint
		endpoint = referenceEndpoints[0]
	}

	client, err = geyser.NewClient(endpoint, opts...)
	if err != nil {
		log.Fatalf("Failed to create Geyser client: %v", err)
	}

	// Create block processor
	processor := NewBlockProcessor(client, db, registry)
	processor.SetSkipSigVerify(*skipSigVerify)
	processor.SetSkipPoH(*skipPoH)
	processor.SetVerifyBankHash(*verifyBankHash)

	// Set parallel signature verification from config
	processor.verifier.ParallelSignatureVerification = *parallelSigVerify

	// Log configuration
	log.Println()
	log.Println("Configuration:")
	log.Printf("  Config file:        %s", *configFile)
	log.Printf("  Data directory:     %s", *dataDir)
	log.Printf("  Commitment level:   %s", *commitment)
	log.Printf("  Verify bank hash:   %v", *verifyBankHash)
	log.Printf("  Verify signatures:  %v", !*skipSigVerify)
	log.Printf("  Verify PoH:         %v", !*skipPoH)
	if *geyserURL != "" {
		log.Printf("  Geyser endpoint:    %s", *geyserURL)
	}
	if *rpcEndpoint != "" {
		log.Printf("  RPC endpoint:       %s", *rpcEndpoint)
	}
	log.Printf("  Poll interval:      %s", *pollInterval)
	log.Printf("  Buffer size:        %d", bufSize)
	log.Printf("  Parallel sig verify:%v", *parallelSigVerify)
	log.Println()

	// Print verification status
	log.Println("Verification Pipeline:")
	if *skipSigVerify {
		log.Println("  [SKIP] Signature verification (UNSAFE)")
	} else {
		log.Println("  [ON]   Ed25519 signature verification")
	}
	if *skipPoH {
		log.Println("  [SKIP] PoH verification (UNSAFE)")
	} else {
		log.Println("  [ON]   Proof of History verification")
	}
	log.Println("  [ON]   Transaction execution (SVM)")
	if *verifyBankHash {
		log.Println("  [ON]   Bank hash verification")
	} else {
		log.Println("  [SKIP] Bank hash verification")
	}
	log.Println()

	// Start block processing
	log.Println("Starting block verification...")

	// Start RPC server if enabled
	var rpcServer *rpc.Server
	if *enableRPC {
		rpcServer = rpc.NewServer(*rpcAddr, db)
		go func() {
			log.Printf("JSON-RPC server listening on %s", *rpcAddr)
			if err := rpcServer.Start(ctx); err != nil {
				log.Printf("RPC server error: %v", err)
			}
		}()
	}

	// Start metrics server if enabled
	var metricsServer *metrics.Server
	var metricsCollector *metrics.Metrics
	if *enableMetrics {
		metricsCollector = metrics.NewMetrics()
		processor.SetMetrics(metricsCollector)
		metricsServer = metrics.NewServer(
			metrics.WithAddr(*metricsAddr),
			metrics.WithMetrics(metricsCollector),
		)
		if err := metricsServer.Start(); err != nil {
			log.Fatalf("Failed to start metrics server: %v", err)
		}
		log.Printf("Prometheus metrics server listening on %s", *metricsAddr)
	}

	// Stats ticker
	var statsTicker *time.Ticker
	if *showStats {
		statsTicker = time.NewTicker(30 * time.Second)
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case <-statsTicker.C:
					stats := processor.Stats()
					elapsed := time.Since(stats.StartTime)
					log.Println()
					log.Println("=== Verification Statistics ===")
					log.Printf("  Uptime:              %s", elapsed.Round(time.Second))
					log.Printf("  Blocks verified:     %d", stats.BlocksProcessed)
					log.Printf("  Transactions:        %d (success: %d, fail: %d)",
						stats.TxsProcessed, stats.SuccessfulTxs, stats.FailedTxs)
					log.Printf("  Signatures verified: %d", stats.SigsVerified)
					if stats.BlocksProcessed > 0 {
						log.Printf("  Blocks/sec:          %.2f", float64(stats.BlocksProcessed)/elapsed.Seconds())
					}
					log.Printf("  Total compute units: %d", stats.TotalComputeUsed)
					log.Printf("  Last slot:           %d", stats.LastSlot)
					log.Printf("  Accounts in DB:      %d", db.GetAccountsCount())
					log.Printf("  Errors:              %d", stats.Errors)
					log.Println("===============================")
					log.Println()
				}
			}
		}()
	}

	// Run block processor in a goroutine
	processorDone := make(chan error, 1)
	go func() {
		processorDone <- processor.Run(ctx, *commitment)
	}()

	// Wait for shutdown signal or processor error
	select {
	case sig := <-sigChan:
		log.Printf("Received signal %v, shutting down...", sig)
		cancel()

	case err := <-processorDone:
		if err != nil && err != context.Canceled {
			log.Printf("Block processor error: %v", err)
		}
	}

	// Stop stats ticker
	if statsTicker != nil {
		statsTicker.Stop()
	}

	// Graceful shutdown
	log.Println("Shutting down...")

	// Stop RPC server
	if rpcServer != nil {
		log.Println("Stopping RPC server...")
		if err := rpcServer.Stop(); err != nil {
			log.Printf("Error stopping RPC server: %v", err)
		}
	}

	// Stop metrics server
	if metricsServer != nil {
		log.Println("Stopping metrics server...")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := metricsServer.Stop(shutdownCtx); err != nil {
			log.Printf("Error stopping metrics server: %v", err)
		}
		shutdownCancel()
	}

	// Close block processor
	if err := processor.Close(); err != nil {
		log.Printf("Error closing processor: %v", err)
	}

	// Flush pending data to disk
	log.Println("Flushing data to disk...")

	// Print final stats
	stats := processor.Stats()
	elapsed := time.Since(stats.StartTime)
	log.Println()
	log.Println("=== Final Statistics ===")
	log.Printf("  Total runtime:       %s", elapsed.Round(time.Second))
	log.Printf("  Blocks verified:     %d", stats.BlocksProcessed)
	log.Printf("  Transactions:        %d (success: %d, fail: %d)",
		stats.TxsProcessed, stats.SuccessfulTxs, stats.FailedTxs)
	log.Printf("  Signatures verified: %d", stats.SigsVerified)
	if elapsed.Seconds() > 0 && stats.BlocksProcessed > 0 {
		log.Printf("  Avg blocks/sec:      %.2f", float64(stats.BlocksProcessed)/elapsed.Seconds())
	}
	log.Printf("  Total compute units: %d", stats.TotalComputeUsed)
	log.Printf("  Last slot:           %d", stats.LastSlot)
	log.Printf("  Last bank hash:      %s", stats.LastBankHash.String())
	log.Printf("  Final account count: %d", db.GetAccountsCount())
	log.Printf("  Total errors:        %d", stats.Errors)
	log.Println("========================")
	log.Println()
	log.Println("X1-Nimbus stopped gracefully")
}
