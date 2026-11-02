# Wallet Scanner 🔐

**Async cryptocurrency address scanner** for Bitcoin, TRON, Solana, TON, and Ethereum with multi-API/RPC support, rate limiting, and optional caching.

> ⚠️ **Educational Purpose Only**: This project is designed for learning and research. Ensure compliance with applicable laws and terms of service of blockchain APIs.

> ⚠️ **Bitcoin key security and feasibility:** `bit_scanner.py` generates random private keys and checks their derived addresses against public APIs. If it finds a nonzero balance, it writes the private key in plaintext to `found_wallets.txt`. Treat that file as highly sensitive. A uniformly random 256-bit key is astronomically unlikely to match a funded wallet; this is not a practical way to find or recover wallets. For monitoring, use addresses you own and a purpose-built public-address checker.

---

## Features

### Bitcoin Scanner (`bit_scanner.py`)
- 🚀 **Async I/O** with `curl_cffi` and per-session browser impersonation
- 🌐 **Multi-provider fallback** across nine public Bitcoin APIs
- 📦 **Optional in-memory LRU cache** with disk persistence (disabled by default)
- 🔄 **Optional proxy rotation** via `proxies.txt`
- ⚡ **Worker Pool** (8 concurrent workers) with graceful shutdown
- 🎯 **Per-provider token bucket rate limiting**, backoff, and Retry-After handling
- 💾 **Statistics tracking** and result logging
- 🔐 Checks Native SegWit (P2WPKH) addresses by default; Legacy and Nested SegWit are also supported

### TRON Scanner (`tron_scanner.py`)
- 🚀 **Async I/O** with `curl_cffi` for concurrent address checking
- 💰 **Dual balance checking**: TRX + USDT (TRC-20)
- 🌐 **Multi-API support** (TronGrid, TronScan, P2P) with fallback and health checks
- 🔑 **TronGrid API Key support** (optional, for higher rate limits)
- ⏭️ **Skip USDT** for accounts that do not exist on-chain (native mode)
- 🔀 **Optional JSON-RPC batch mode** (`eth_getBalance` + `eth_call`) for monitoring workloads
- 🔒 **Connection pool cap** via `asyncio.Semaphore`
- 📦 **Result caching** to prevent duplicate requests
- 🔄 **Proxy rotation** support
- ⚡ **Worker Pool** (6 concurrent workers)
- 🎯 **Token Bucket Rate Limiter** per provider
- 📊 **Performance statistics** and logging

### Solana Scanner (`solana_scanner.py`)
- 🚀 **Async I/O** with `curl_cffi` for TLS/JA3 fingerprint spoofing
- 💰 **Dual balance checking**: SOL + USDC (SPL)
- 🌐 **Multi-RPC** with fallback and health checks
- 🔀 **Batch JSON-RPC mode** (`getBalance` + `getTokenAccountsByOwner` in one round-trip)
- 🔒 **Connection pool cap** via `asyncio.Semaphore`
- 📦 **LRU cache** with disk persistence
- 🔄 **Proxy rotation** and User-Agent rotation
- ⚡ **Worker Pool** (6 concurrent workers)
- 🎯 **Token Bucket Rate Limiter** per RPC provider
- 📊 **Performance statistics** and logging

### TON Scanner (`ton_scanner.py`)
- 🚀 **Async I/O** with `curl_cffi` for TLS/JA3 fingerprint spoofing
- 💰 **Dual balance checking**: TON + USDT (Jetton)
- 🌐 **Multi-API support**: TON Center API v2 + TONAPI.io with fallback and health checks
- 🔑 **TON Center API Key support** (optional, raises rate limit from 0.8 to 8.0 req/s)
- ⏭️ **Smart Jetton check skip**: Skips Jetton query if account contract is not deployed (prevents false USDT balances & 429 rate limits)
- 🔒 **Connection pool cap** via `asyncio.Semaphore` (`MAX_CONCURRENT_REQUESTS = 16`)
- 📦 **LRU cache** with disk persistence
- 🔄 **Proxy rotation** and User-Agent rotation
- ⚡ **Worker Pool** (4 concurrent workers)
- 🎯 **Token Bucket Rate Limiter** (AIMD) per provider
- 📊 **Performance statistics** and logging

### Ethereum Scanner (`ethereum_scanner.py`)
- 🚀 **Async I/O** with `curl_cffi` for TLS/JA3 fingerprint spoofing
- 💰 **Dual balance checking**: ETH + USDT (ERC-20)
- 🌐 **Multi-Provider support**: PublicNode, LlamaRPC, 1RPC, Ankr, and Etherscan V2 with fallback and health checks
- 🔑 **Etherscan API Key support** (optional, enables Etherscan V2 provider at 4.0 req/s)
- ⏭️ **Skip USDT** for empty native ETH accounts in native mode
- 🔀 **Optional JSON-RPC batch mode** (`eth_getBalance` + `eth_call` in one round-trip)
- 🔒 **Connection pool cap** via `asyncio.Semaphore` (`MAX_CONCURRENT_REQUESTS = 32`)
- 📦 **LRU cache** with disk persistence
- 🔄 **Proxy rotation** and User-Agent rotation
- ⚡ **Worker Pool** (6 concurrent workers)
- 🎯 **Token Bucket Rate Limiter** (AIMD) per provider
- 📊 **Performance statistics** and logging

---

## Requirements

- Python 3.10+
- pip (Python package manager)

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/greenware63/wallet_scanner.git
cd wallet_scanner
```

### 2. Create Virtual Environment
```bash
# Windows
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux/Mac
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

**Dependencies:**
- `bit>=0.8.0` — Bitcoin address utilities
- `tronpy>=0.6.2` — TRON key/address helpers
- `curl_cffi>=0.16.0` — Async HTTP with TLS spoofing
- `base58>=2.1.1` — Base58 encoding/decoding (Solana keys)
- `coincurve>=21.0.0` — Elliptic curve cryptography
- `solders>=0.21.0` — Solana keypair generation
- `eth-account>=0.13.0` — Ethereum key/address generation and checksumming
- `tonsdk>=1.0.14` — TON mnemonic generation, BoC/cell serialization, and address utils
- `python-dotenv>=1.0.0` — *(optional)* loads API keys from a local `.env` file; falls back to OS environment variables if not installed

### 4. Configure API Keys (Optional)
The TRON, Solana, TON, and Ethereum scanners can use private API keys/RPCs for higher rate limits. Keys are **never** hardcoded in the source — they are read from environment variables, optionally via a local `.env` file.

```bash
# Copy the example file and fill in the values you need
cp .env.example .env
```

```ini
# .env
TRONGRID_API_KEY=your-trongrid-key-here
HELIUS_API_KEY=your-helius-key-here
QUICKNODE_SOLANA_URL=
TRITON_RPC_URL=
TONCENTER_API_KEY=your-toncenter-key-here
ETHERSCAN_API_KEY=your-etherscan-key-here
```

> ⚠️ `.env` is git-ignored and must **never** be committed. Only `.env.example` (with empty placeholder values) is tracked in the repository.

---

## Configuration

### Bitcoin Scanner Configuration
Edit the configuration section in `bit_scanner.py`:

```python
NUM_WORKERS = 8                # Number of concurrent workers
REQUEST_TIMEOUT = 6            # Request timeout in seconds
MAX_ATTEMPTS_PER_PROVIDER = 2  # Attempts per provider before fallback
ENABLE_CACHE = False           # Optional cache; most useful for repeated addresses
MAX_CONCURRENT_REQUESTS = 32   # Cap on concurrent outbound HTTP requests
MAX_SESSIONS = 64              # Maximum cached HTTP sessions
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
CHECK_ADDRESS_TYPES = (
    "Native SegWit (P2WPKH)",
    # Also supported: "Legacy (P2PKH)" and "Nested SegWit (P2SH-P2WPKH)"
)
```

**Output Files:**
- `found_wallets.txt` — Found addresses with balances
- `scan_stats.txt` — Scan statistics
- `btc_cache.json` — Cache data
- `proxies.txt` — Optional proxy URLs, one per line

Browser impersonation targets and request headers are selected internally; the scanner does not load a `user_agents.txt` file.

### TRON Scanner Configuration
Edit the configuration section in `tron_scanner.py`:

```python
NUM_WORKERS = 6                # Number of concurrent workers
REQUEST_TIMEOUT = 15           # Request timeout in seconds
MAX_RETRIES_PER_PROVIDER = 2   # Max retries per API
USE_JSONRPC_BATCH = False      # False = native + skip-empty; True = batch JSON-RPC
MAX_CONCURRENT_REQUESTS = 32   # Cap on concurrent outbound HTTP requests
ENABLE_CACHE = False           # False for random scanning, True for monitoring fixed addresses
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_DECIMALS = 6
```

`TRONGRID_API_KEY` is **not** a hardcoded constant — it is read at runtime from the `TRONGRID_API_KEY` environment variable (or `.env` file). Get a free key from https://www.trongrid.io/.

**Output Files:**
- `found_tron_wallets.txt` — Found addresses with balances
- `scan_tron_stats.txt` — Scan statistics
- `tron_cache.json` — Cache data

### Solana Scanner Configuration
Edit the configuration section in `solana_scanner.py`:

```python
NUM_WORKERS = 6                # Number of concurrent workers
REQUEST_TIMEOUT = 12           # Request timeout in seconds
MAX_RETRIES_PER_PROVIDER = 1   # Max retries per RPC (fail-fast)
USE_BATCH_RPC = True           # One JSON-RPC batch per address (recommended)
MAX_CONCURRENT_REQUESTS = 32   # Cap on concurrent outbound HTTP requests
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDC_DECIMALS = 6
```

**Output Files:**
- `found_solana_wallets.txt` — Found addresses with balances
- `scan_solana_stats.txt` — Scan statistics
- `solana_cache.json` — Cache data

### TON Scanner Configuration
Edit the configuration section in `ton_scanner.py`:

```python
NUM_WORKERS = 4                # Number of concurrent workers
REQUEST_TIMEOUT = 20           # Request timeout in seconds
USE_JSONRPC_BATCH = False      # False = REST; True = batch JSON-RPC
MAX_CONCURRENT_REQUESTS = 16   # Cap on concurrent outbound HTTP requests
ENABLE_CACHE = False           # False for random scanning, True for monitoring fixed addresses
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
USDT_JETTON_MASTER = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
USDT_DECIMALS = 6
```

`TONCENTER_API_KEY` is read from `TONCENTER_API_KEY` in environment variables or `.env`.

**Output Files:**
- `found_ton_wallets.txt` — Found addresses with balances
- `scan_ton_stats.txt` — Scan statistics
- `ton_cache.json` — Cache data

### Ethereum Scanner Configuration
Edit the configuration section in `ethereum_scanner.py`:

```python
NUM_WORKERS = 6                # Number of concurrent workers
REQUEST_TIMEOUT = 15           # Request timeout in seconds
MAX_RETRIES_PER_PROVIDER = 2   # Max retries per API
USE_JSONRPC_BATCH = False      # False = native + skip-empty; True = batch JSON-RPC
MAX_CONCURRENT_REQUESTS = 32   # Cap on concurrent outbound HTTP requests
ENABLE_CACHE = False           # False for random scanning, True for monitoring fixed addresses
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDT_DECIMALS = 6
```

`ETHERSCAN_API_KEY` is read from `ETHERSCAN_API_KEY` in environment variables or `.env`. Get a free key at https://etherscan.io/myapikey.

**Output Files:**
- `found_eth_wallets.txt` — Found addresses with balances
- `scan_eth_stats.txt` — Scan statistics
- `eth_cache.json` — Cache data

---

## Usage

### Run Bitcoin Scanner
```bash
# Activate virtual environment first
# Windows
.\venv\Scripts\Activate.ps1
# Linux/Mac
source venv/bin/activate

python bit_scanner.py
```

### Run TRON Scanner
```bash
python tron_scanner.py
```

### Run Solana Scanner
```bash
python solana_scanner.py
```

### Run TON Scanner
```bash
python ton_scanner.py
```

### Run Ethereum Scanner
```bash
python ethereum_scanner.py
```

### Stop Gracefully
Press `Ctrl+C` to stop any scanner. The application will:
1. Signal all workers to stop
2. Cancel pending tasks
3. Save cache to disk
4. Save statistics
5. Clean shutdown

---

## Advanced Features

### Proxy Support
Create a `proxies.txt` file with one proxy per line:
```
http://proxy1:port
http://proxy2:port
socks5://proxy3:port
```

The scanner will automatically rotate through available proxies.

### Custom User-Agents
Create a `user_agents.txt` file with one User-Agent per line. The scanner will cycle through this list.

### TLS Fingerprinting
The Bitcoin scanner uses `curl_cffi` browser impersonation with a target pinned per session:
- Chrome versions: 124, 123, 120, 116, 110
- Edge: 101
- Safari: 17.0, 15.5

### Caching
- **LRU Cache**: In-memory cache with configurable size limit
- **Disk Persistence**: Cache is saved to disk on shutdown and loaded on startup
- **TTL (Time-To-Live)**: Cached entries expire after the configured TTL

### Rate Limiting
Each API/RPC provider has its own Token Bucket rate limiter (AIMD) to:
- Avoid overwhelming APIs
- Respect rate limit quotas
- Distribute load evenly

### Connection Pool Control
Scanners use `asyncio.Semaphore` (`MAX_CONCURRENT_REQUESTS`) to cap concurrent outbound HTTP requests independently of worker count.

### Batch JSON-RPC
- **TRON**: set `USE_JSONRPC_BATCH = True` for one batch request per address (better for monitoring known addresses). Keep `False` for random scanning so empty accounts can skip the USDT call.
- **Solana**: `USE_BATCH_RPC = True` by default; public RPCs are heavily rate-limited, so batching halves round-trips.
- **Ethereum**: set `USE_JSONRPC_BATCH = True` to combine `eth_getBalance` and `eth_call` in one payload, or `False` to skip the USDT call when ETH balance is 0.
- **TON**: supports batch JSON-RPC or REST via TON Center and TONAPI.

---

## Output Format

### Bitcoin Scanner Output
```
Found wallet: 1A1z7agoat6Ft8ukX6LWLcSh3r0JJxvJ2n
  Balance: 0.00542018 BTC
  Received: 0.00542018 BTC
  Sent: 0 BTC
```

### TRON Scanner Output
```
Found wallet: TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t
  TRX Balance: 1000.50
  USDT Balance: 5000.123456
```

### Solana Scanner Output
```
Found wallet: 7EqQdEULxWcraVx3mXKFjc84LhQk8BNAR...
  SOL Balance: 1.250000000 SOL
  USDC Balance: 100.500000 USDC
```

### TON Scanner Output
```
======================================================================
[2026-10-11 12:00:00] کیف پول TON با موجودی پیدا شد!
Private Key (HEX): 1a2b3c...
Mnemonic:         word1 word2 word3 ... word24
Address (Friendly): EQCGb8x...
موجودی TON:        2.500000000 TON
موجودی USDT:       150.000000 USDT
Deployed:          True
Provider:          toncenter
======================================================================
```

### Ethereum Scanner Output
```
======================================================================
[2026-10-11 12:00:00] کیف پول اتریوم با موجودی پیدا شد!
Private Key (HEX): 4d5e6f...
Address (EIP-55):  0x71C...
موجودی ETH:        0.052000000000000000 ETH
موجودی USDT:       250.000000 USDT
Provider:          publicnode
======================================================================
```

---

## File Structure
```
wallet_scanner/
├── bit_scanner.py              # Bitcoin address scanner
├── tron_scanner.py             # TRON address scanner
├── solana_scanner.py           # Solana address scanner
├── ton_scanner.py              # TON address scanner
├── ethereum_scanner.py         # Ethereum address scanner
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
├── .gitignore                  # Git ignore rules
├── .env.example                # Template for API key configuration (safe to commit)
├── .env                        # Local API keys (git-ignored, never committed)
├── venv/                       # Virtual environment (created on install)
├── proxies.txt                 # Proxy list (optional)
├── user_agents.txt             # User-Agent list (optional)
├── found_wallets.txt           # Found BTC addresses (generated)
├── found_tron_wallets.txt      # Found TRON addresses (generated)
├── found_solana_wallets.txt    # Found Solana addresses (generated)
├── found_ton_wallets.txt       # Found TON addresses (generated)
├── found_eth_wallets.txt       # Found Ethereum addresses (generated)
├── scan_stats.txt              # Bitcoin scan statistics (generated)
├── scan_tron_stats.txt         # TRON scan statistics (generated)
├── scan_solana_stats.txt       # Solana scan statistics (generated)
├── scan_ton_stats.txt          # TON scan statistics (generated)
├── scan_eth_stats.txt          # Ethereum scan statistics (generated)
├── btc_cache.json              # Bitcoin cache (generated)
├── tron_cache.json             # TRON cache (generated)
├── solana_cache.json           # Solana cache (generated)
├── ton_cache.json              # TON cache (generated)
└── eth_cache.json              # Ethereum cache (generated)
```

---

## Performance Considerations

- **Worker Count**: Increase `NUM_WORKERS` for faster scanning (requires more system resources)
- **Concurrent Requests**: Tune `MAX_CONCURRENT_REQUESTS` to match your network bandwidth and RPC rate limits
- **Request Timeout**: Lower timeout for faster failure detection, higher for slower networks
- **Cache Size**: Larger cache reduces API calls but uses more memory
- **Proxy Rotation**: Can slow scanning but reduces detection and IP ban risk
- **Rate Limiting**: Strict rate limits prevent bans but reduce throughput
- **RPC Providers**: Public endpoints have aggressive rate limits; private keys/RPCs significantly increase throughput

---

## Troubleshooting

### `ModuleNotFoundError`
Ensure the virtual environment is activated and dependencies are installed:
```bash
pip install -r requirements.txt
```

### API Rate Limiting
- Reduce `NUM_WORKERS` to lower request rate
- Add proxies via `proxies.txt`
- For TRON: Set `TRONGRID_API_KEY` in `.env`
- For Solana: Set `HELIUS_API_KEY`, `QUICKNODE_SOLANA_URL`, or `TRITON_RPC_URL` in `.env`
- For TON: Set `TONCENTER_API_KEY` in `.env`
- For Ethereum: Set `ETHERSCAN_API_KEY` in `.env`

### Proxy Errors
- Verify proxy list format (one per line)
- Test proxies with `curl` before adding
- Use `http://` or `socks5://` prefix correctly

### Slow Performance
- Check network connection
- Increase `NUM_WORKERS`
- Reduce `REQUEST_TIMEOUT`
- Verify proxy quality
- On Solana and Ethereum, tune batch mode according to your use case

---

## Legal Disclaimer

This project is provided for **educational purposes only**. Users are responsible for:
- ✅ Complying with all applicable laws and regulations
- ✅ Obtaining necessary permissions
- ✅ Respecting API terms of service
- ✅ Not abusing blockchain API services

The authors assume no liability for misuse. Always use responsibly and ethically.

---

## Security Notes

- ⚠️ **Never hardcode API keys** in the source code — all scanners read keys exclusively from environment variables / `.env`
- ⚠️ Use environment variables or `.env` files for sensitive data; copy `.env.example` to `.env` and never commit the real `.env` (it is already listed in `.gitignore`)
- ⚠️ Keep `proxies.txt` and results private
- ⚠️ Be cautious with rate limiting to avoid IP bans
- ⚠️ Respect blockchain network resources
- ⚠️ If a secret is ever committed by mistake, rotate/revoke it immediately and remove it from git history before pushing

---

## Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

This project is licensed under the MIT License - see LICENSE file for details.

---

## Author

Created for educational blockchain research and development.

---

## Support

For issues, questions, or suggestions:
- Open a GitHub Issue
- Check existing documentation
- Review code comments (scanners include documentation)

---

## Changelog

### Version 1.3.0
- Added TON scanner ([`ton_scanner.py`](file:///C:/Users/Sajad%20nemati/PycharmProjects/wallet_scanner/ton_scanner.py)) with TON + USDT (Jetton) balance checking, TonCenter & TONAPI support, and smart deployment checks
- Added Ethereum scanner ([`ethereum_scanner.py`](file:///C:/Users/Sajad%20nemati/PycharmProjects/wallet_scanner/ethereum_scanner.py)) with ETH + USDT (ERC-20) checking, multi-RPC fallback (PublicNode, LlamaRPC, 1RPC, Ankr), and optional Etherscan V2 support
- Updated dependencies in [`requirements.txt`](file:///C:/Users/Sajad%20nemati/PycharmProjects/wallet_scanner/requirements.txt) with `eth-account` and `tonsdk`
- Updated [`.env.example`](file:///C:/Users/Sajad%20nemati/PycharmProjects/wallet_scanner/.env.example) template with `TONCENTER_API_KEY` and `ETHERSCAN_API_KEY`

### Version 1.2.0
- Hardened secret handling: API keys are read exclusively from environment variables / `.env` (never hardcoded or committed)
- Added `.env.example` template and `python-dotenv` as an optional dependency
- Expanded `.gitignore` to exclude `.env` and local secret files
- Performance/reliability tuning across scanners (AIMD rate limiting, fail-fast retries, connection semaphores)

### Version 1.1.0
- Added Solana scanner (`solana_scanner.py`) with SOL + USDC support
- TRON: skip USDT for non-existent accounts, optional JSON-RPC batch mode, connection semaphore
- Updated dependencies (`solders`)

### Version 1.0.0
- Initial release
- Bitcoin and TRON scanners
- Async I/O with proxy support
- Multi-API with fallback
- Intelligent caching system
- Graceful shutdown support

---

## Roadmap

- [x] Ethereum scanner support
- [x] TON scanner support
- [ ] Database backend for results
- [ ] Web UI dashboard
- [ ] Batch processing from files
- [ ] WebSocket support for real-time updates
- [ ] Docker containerization

---

**Happy Scanning! 🚀**
