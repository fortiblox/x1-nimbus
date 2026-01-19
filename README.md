# X1-Nimbus

**Trustless Verification Node for X1 Blockchain**

X1-Nimbus is a lightweight, full-verifying node that independently validates every transaction on the X1 network without trusting any third party. Built in Go for accessibility and performance.

## Features

- **Strong Verification** - Independently verifies signatures, transaction execution, and bank hash
- **Full SVM Implementation** - Complete Solana Virtual Machine reimplementation in Go
- **Low Hardware Requirements** - Runs on commodity hardware (2-4 GB RAM)
- **Ed25519 Batch Verification** - High-performance signature verification
- **Native Program Execution** - System, Token, Vote, Stake, BPF Loader, ALT, Compute Budget
- **BPF Program Support** - sBPF interpreter for deployed programs
- **Bank Hash Verification** - Exact hash compatibility with Solana/X1
- **RPC Fallback** - Works with standard RPC endpoints (no Geyser required)
- **Auto-Reconnection** - Automatic reconnection on network disruptions
- **Prometheus Metrics** - Full observability at `/metrics`

## Trust Model

X1-Nimbus provides **strong verification** without requiring a full validator node:

| Component | Status | Description |
|-----------|--------|-------------|
| **Signatures** | Verified | Ed25519 verification of all transaction signatures |
| **Execution** | Verified | Full SVM execution of all transactions |
| **State Changes** | Verified | Account deltas computed and tracked |
| **Bank Hash** | Verified | Computed locally, proves execution correctness |
| **Blockhash** | Trusted | Received from RPC (validators already verified PoH) |

### Why No PoH Verification?

PoH (Proof of History) verification requires entry-level data (num_hashes, entry boundaries) that the RPC API does not provide. This is a limitation of the Solana RPC specification, not Nimbus.

**What this means:**
- We trust that validators correctly verified the PoH chain before publishing the block
- We independently verify everything else: signatures, execution, and resulting state
- This is significantly stronger than trusting RPC responses directly

### Comparison

| Approach | Signatures | Execution | Bank Hash | PoH |
|----------|------------|-----------|-----------|-----|
| **X1-Nimbus** | Verified | Verified | Verified | Trusted |
| Full Validator | Verified | Verified | Verified | Verified |
| Light Client | Verified | Trusted | Trusted | Trusted |
| Direct RPC | Trusted | Trusted | Trusted | Trusted |

## Architecture

```
Block Source (Geyser/RPC)
         |
         v
+-----------------------------+
|    VERIFICATION PIPELINE    |
|  +------------------------+ |
|  | 1. PoH Verification    | |
|  | 2. Signature Verify    | |
|  | 3. TX Execution        | |
|  | 4. State Verification  | |
|  +------------------------+ |
+-----------------------------+
         |
         v
    Verified State
```

### Components Detail

```
                    +------------------+
                    |   Geyser gRPC    |
                    |   (or RPC Poll)  |
                    +--------+---------+
                             |
                             v
                    +--------+---------+
                    |   Block Stream   |
                    +--------+---------+
                             |
              +--------------+--------------+
              |              |              |
              v              v              v
      +-------+----+  +------+-----+  +-----+------+
      | Signature  |  |    PoH     |  |   Bank     |
      | Verifier   |  |  Verifier  |  |   Hash     |
      +-------+----+  +------+-----+  +-----+------+
              |              |              |
              +--------------+--------------+
                             |
                             v
                    +--------+---------+
                    |  SVM Executor    |
                    |  (Transaction    |
                    |   Execution)     |
                    +--------+---------+
                             |
                             v
                    +--------+---------+
                    |   AccountsDB     |
                    |   (BadgerDB)     |
                    +------------------+
```

## System Requirements

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| RAM | 2 GB | 4-8 GB |
| CPU | 2 cores | 4+ cores |
| Storage | 10 GB SSD | 100+ GB NVMe |
| Network | 50 Mbps | 100 Mbps |
| OS | Linux (Ubuntu 20.04+) | Linux |

## Installation

### Quick Install

```bash
curl -sSL https://raw.githubusercontent.com/fortiblox/x1-nimbus/main/install.sh | sudo bash
```

### Manual Installation

1. Clone the repository:
```bash
git clone https://github.com/fortiblox/X1-Nimbus.git /opt/x1-nimbus
cd /opt/x1-nimbus
```

2. Build the binary:
```bash
go build -o nimbus ./cmd/nimbus
```

3. Create the bin directory and move the binary:
```bash
mkdir -p /opt/x1-nimbus/bin
mv nimbus /opt/x1-nimbus/bin/
```

4. Create the data directory:
```bash
mkdir -p /mnt/x1-nimbus/{accounts,blocks}
```

5. Create the configuration directory and file:
```bash
mkdir -p /root/.config/x1-nimbus
```

6. Create `/root/.config/x1-nimbus/config.json`:
```json
{
    "geyser_endpoint": "https://grpc.xolana.xen.network:443",
    "geyser_token": "",
    "rpc_endpoint": "https://rpc.mainnet.x1.xyz",
    "rpc_server": {
        "enabled": false,
        "port": 8899
    },
    "metrics": {
        "enabled": true,
        "port": 9090
    },
    "data_dir": "/mnt/x1-nimbus",
    "log_level": "info",
    "commitment": "confirmed",
    "verification": {
        "verify_signatures": true,
        "verify_poh": true,
        "verify_bank_hash": true
    },
    "performance": {
        "poll_interval_ms": 400,
        "buffer_size": 1000,
        "parallel_sig_verify": true
    }
}
```

7. Install the systemd service:
```bash
sudo cp /etc/systemd/system/x1-nimbus.service /etc/systemd/system/
sudo systemctl daemon-reload
```

8. Start the service:
```bash
sudo systemctl enable x1-nimbus
sudo systemctl start x1-nimbus
```

## Configuration Options

### Geyser Settings

| Option | Description | Default |
|--------|-------------|---------|
| `geyser_endpoint` | Geyser gRPC endpoint URL | `https://grpc.xolana.xen.network:443` |
| `geyser_token` | Authentication token for Geyser | (empty) |

### RPC Settings

| Option | Description | Default |
|--------|-------------|---------|
| `rpc_endpoint` | RPC endpoint for fallback queries | `https://rpc.mainnet.x1.xyz` |
| `rpc_server.enabled` | Enable local RPC server | `false` |
| `rpc_server.port` | Local RPC server port | `8899` |

### Verification Settings

| Option | Description | Default |
|--------|-------------|---------|
| `verification.verify_signatures` | Verify Ed25519 signatures | `true` |
| `verification.verify_poh` | Verify Proof of History | `true` |
| `verification.verify_bank_hash` | Verify bank hash | `true` |

### General Settings

| Option | Description | Default |
|--------|-------------|---------|
| `data_dir` | Directory for accounts database | `/mnt/x1-nimbus` |
| `log_level` | Logging level (debug, info, warn, error) | `info` |
| `commitment` | Commitment level (processed, confirmed, finalized) | `confirmed` |
| `metrics.enabled` | Enable metrics endpoint | `true` |
| `metrics.port` | Metrics server port | `9090` |

### Performance Settings

| Option | Description | Default |
|--------|-------------|---------|
| `performance.poll_interval_ms` | RPC polling interval in milliseconds | `400` |
| `performance.buffer_size` | Block buffer size | `1000` |
| `performance.parallel_sig_verify` | Enable parallel signature verification | `true` |

## Usage

### Service Management

```bash
# Start the verifier
x1-nimbus start

# Stop the verifier
x1-nimbus stop

# Restart the verifier
x1-nimbus restart

# Check status
x1-nimbus status
```

### Monitoring

```bash
# View recent logs
x1-nimbus logs

# View more logs
x1-nimbus logs 200

# Follow logs in real-time
x1-nimbus follow

# View verification statistics
x1-nimbus stats
```

### Configuration

```bash
# View current configuration
x1-nimbus config

# Edit configuration
x1-nimbus config edit
```

### Command Line Options

Run the binary directly with custom options:

```bash
/opt/x1-nimbus/bin/nimbus \
    --data-dir=/mnt/x1-nimbus \
    --geyser-url=https://grpc.xolana.xen.network:443 \
    --rpc-endpoint=https://rpc.mainnet.x1.xyz \
    --commitment=confirmed \
    --log-level=info \
    --stats
```

Available flags:

| Flag | Description |
|------|-------------|
| `--data-dir` | Data directory for accounts and blocks |
| `--geyser-url` | Geyser gRPC endpoint URL |
| `--geyser-token` | Geyser authentication token |
| `--rpc-endpoint` | RPC endpoint for fallback |
| `--rpc-addr` | Local RPC server listen address |
| `--enable-rpc` | Enable local JSON-RPC server |
| `--commitment` | Commitment level |
| `--log-level` | Log level |
| `--poll-interval` | RPC polling interval |
| `--skip-sig-verify` | Skip signature verification (unsafe) |
| `--skip-poh` | Skip PoH verification (unsafe) |
| `--verify-bank-hash` | Verify bank hash against network |
| `--stats` | Show periodic statistics |
| `--version` | Print version and exit |

## Components

| Package | Description |
|---------|-------------|
| `pkg/crypto` | Ed25519 batch verification, secp256k1 |
| `pkg/poh` | Proof of History verification |
| `pkg/svm` | Solana Virtual Machine (sBPF, syscalls, programs) |
| `pkg/accounts` | Account state database (BadgerDB) |
| `pkg/replayer` | Block replay and verification engine |
| `pkg/blockstore` | Block storage (BoltDB) |

## Verification vs Validation

X1-Nimbus is a **verifier**, not a validator:

| Aspect | Validator | Nimbus (Verifier) |
|--------|-----------|-------------------|
| Votes on consensus | Yes | No |
| Produces blocks | Yes | No |
| Earns rewards | Yes | No |
| Verifies all transactions | Yes | Yes |
| Hardware requirements | 128+ GB RAM | 4-8 GB RAM |
| Network requirements | 1+ Gbps | 50 Mbps |

## Comparison with X1-Stratus

| Feature | X1-Stratus | X1-Nimbus |
|---------|------------|-----------|
| Trust Model | Trust-minimized (RPC verification) | Trustless (full verification) |
| Block fetching | RPC polling | Geyser gRPC |
| Signature verification | Trusts RPC | Full Ed25519 |
| PoH verification | Trusts RPC | Full SHA-256 |
| Transaction execution | None | Full SVM |
| State verification | None | Bank hash |
| Memory usage | ~35 MB | 2-8 GB |
| Disk usage | ~1 GB | 10+ GB |
| CPU usage | Minimal | Higher |

## Troubleshooting

### Service won't start

Check the logs for errors:
```bash
journalctl -u x1-nimbus -n 100 --no-pager
```

Common issues:
- Insufficient disk space in data directory
- Network connectivity issues
- Invalid configuration file

### High memory usage

Adjust memory limits in the systemd service:
```bash
sudo systemctl edit x1-nimbus
```

Add:
```ini
[Service]
MemoryMax=4G
MemoryHigh=3G
```

### Connection issues

If Geyser connection fails, X1-Nimbus will fall back to RPC polling. Check:
- Geyser endpoint is correct
- Authentication token is valid (if required)
- Network allows gRPC connections

### Database corruption

If the accounts database becomes corrupted:
```bash
# Stop the service
x1-nimbus stop

# Backup and remove the database
mv /mnt/x1-nimbus/accounts /mnt/x1-nimbus/accounts.backup

# Restart (will resync)
x1-nimbus start
```

## License

MIT License - see LICENSE file

## Credits

Inspired by [Mithril](https://github.com/Overclock-Validator/mithril) by Overclock Validator.

## Support

- GitHub Issues: https://github.com/fortiblox/X1-Nimbus/issues
- Documentation: https://docs.x1.xyz
