# Wallet Scanner 🔐

**High-performance async cryptocurrency address scanner** for Bitcoin, TRON, and Solana with proxy rotation, TLS fingerprinting, multi-API/RPC support, and intelligent caching.

> ⚠️ **Educational Purpose Only**: This project is designed for learning and research. Ensure compliance with applicable laws and terms of service of blockchain APIs.

---

## Features

### Bitcoin Scanner (`bit_scanner.py`)
- 🚀 **Async I/O** with `curl_cffi` for TLS/JA3 fingerprint spoofing
- 🌐 **Multiple reliable APIs**: mempool.space, blockstream.info, mempool.ninja, mempool.emzy.de, bitaps
- 📦 **Two-tier LRU cache** with disk persistence
- 🔄 **Proxy rotation** and User-Agent rotation
- ⚡ **Worker Pool** (8 concurrent workers) with graceful shutdown
- 🎯 **Token Bucket Rate Limiter** per provider
- 💾 **Statistics tracking** and result logging

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

---

## Requirements

- Python 3.10+
- pip (Python package manager)

---

## Installation

### 1. Clone the Repository
```bash
git clone https://github.com/yourusername/wallet_scanner.git
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

---

## Configuration

### Bitcoin Scanner Configuration
Edit the configuration section in `bit_scanner.py`:

```python
NUM_WORKERS = 8                # Number of concurrent workers
REQUEST_TIMEOUT = 12           # Request timeout in seconds
MAX_RETRIES_PER_PROVIDER = 2   # Max retries per API
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
```

**Output Files:**
- `found_wallets.txt` — Found addresses with balances
- `scan_stats.txt` — Scan statistics
- `btc_cache.json` — Cache data

**Input Files (Optional):**
- `proxies.txt` — Proxy list (one per line)
- `user_agents.txt` — Custom User-Agent list (one per line)

### TRON Scanner Configuration
Edit the configuration section in `tron_scanner.py`:

```python
NUM_WORKERS = 6                # Number of concurrent workers
REQUEST_TIMEOUT = 15           # Request timeout in seconds
MAX_RETRIES_PER_PROVIDER = 2   # Max retries per API
USE_JSONRPC_BATCH = False      # False = native + skip-empty; True = batch JSON-RPC
MAX_CONCURRENT_REQUESTS = 32   # Cap on concurrent outbound HTTP requests
TRONGRID_API_KEY = ""          # Get from https://www.trongrid.io/
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_DECIMALS = 6
```

**Output Files:**
- `found_tron_wallets.txt` — Found addresses with balances
- `scan_tron_stats.txt` — Scan statistics
- `tron_cache.json` — Cache data

**Input Files (Optional):**
- `proxies.txt` — Proxy list (one per line)
- `user_agents.txt` — Custom User-Agent list (one per line)

### Solana Scanner Configuration
Edit the configuration section in `solana_scanner.py`:

```python
NUM_WORKERS = 6                # Number of concurrent workers
REQUEST_TIMEOUT = 15           # Request timeout in seconds
MAX_RETRIES_PER_PROVIDER = 2   # Max retries per RPC
USE_BATCH_RPC = True           # One JSON-RPC batch per address (recommended)
MAX_CONCURRENT_REQUESTS = 32   # Cap on concurrent outbound HTTP requests
CACHE_MAX_SIZE = 50_000        # Maximum cache entries
CACHE_TTL = 3600               # Cache TTL in seconds (1 hour)
USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDC_DECIMALS = 6

# Prefer your own Helius / QuickNode / Triton endpoint for real use
SOLANA_RPC_ENDPOINTS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-api.projectserum.com",
    "https://rpc.ankr.com/solana",
    "https://solana.public-rpc.com",
]
```

**Output Files:**
- `found_solana_wallets.txt` — Found addresses with balances
- `scan_solana_stats.txt` — Scan statistics
- `solana_cache.json` — Cache data

**Input Files (Optional):**
- `proxies.txt` — Proxy list (one per line)
- `user_agents.txt` — Custom User-Agent list (one per line)

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
All scanners use `curl_cffi` with `impersonate` mode to spoof browser TLS fingerprints:
- Chrome versions: 124, 123, 120, 116, 110
- Edge: 101
- Safari: 17.0, 15.5

### Caching
- **LRU Cache**: In-memory cache with configurable size limit
- **Disk Persistence**: Cache is saved to disk on shutdown and loaded on startup
- **TTL (Time-To-Live)**: Cached entries expire after the configured TTL

### Rate Limiting
Each API/RPC provider has its own Token Bucket rate limiter to:
- Avoid overwhelming APIs
- Respect rate limit quotas
- Distribute load evenly

### Connection Pool Control
TRON and Solana scanners use `asyncio.Semaphore` (`MAX_CONCURRENT_REQUESTS`) to cap concurrent outbound HTTP requests independently of worker count.

### Batch JSON-RPC
- **TRON**: set `USE_JSONRPC_BATCH = True` for one batch request per address (better for monitoring known addresses). Keep `False` for random scanning so empty accounts can skip the USDT call.
- **Solana**: `USE_BATCH_RPC = True` by default; public RPCs are heavily rate-limited, so batching halves round-trips.

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

---

## File Structure
```
wallet_scanner/
├── bit_scanner.py              # Bitcoin address scanner
├── tron_scanner.py             # TRON address scanner
├── solana_scanner.py           # Solana address scanner
├── requirements.txt            # Python dependencies
├── README.md                   # This file
├── .gitignore                  # Git ignore rules
├── venv/                       # Virtual environment (created on install)
├── proxies.txt                 # Proxy list (optional)
├── user_agents.txt             # User-Agent list (optional)
├── found_wallets.txt           # Found BTC addresses (generated)
├── found_tron_wallets.txt      # Found TRON addresses (generated)
├── found_solana_wallets.txt    # Found Solana addresses (generated)
├── scan_stats.txt              # Bitcoin scan statistics (generated)
├── scan_tron_stats.txt         # TRON scan statistics (generated)
├── scan_solana_stats.txt       # Solana scan statistics (generated)
├── btc_cache.json              # Bitcoin cache (generated)
├── tron_cache.json             # TRON cache (generated)
└── solana_cache.json           # Solana cache (generated)
```

---

## Performance Considerations

- **Worker Count**: Increase `NUM_WORKERS` for faster scanning (requires more system resources)
- **Concurrent Requests**: Tune `MAX_CONCURRENT_REQUESTS` on TRON/Solana to match your network and RPC limits
- **Request Timeout**: Lower timeout for faster failure detection, higher for unreliable networks
- **Cache Size**: Larger cache reduces API calls but uses more memory
- **Proxy Rotation**: Can slow scanning but reduces detection risk
- **Rate Limiting**: Strict rate limits prevent bans but reduce throughput
- **Solana RPCs**: Public endpoints are aggressively rate-limited; use a private RPC for serious use

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
- For TRON: Add `TRONGRID_API_KEY` for higher limits
- For Solana: Replace public RPCs with a private endpoint (Helius, QuickNode, Triton, etc.)

### Proxy Errors
- Verify proxy list format (one per line)
- Test proxies with `curl` before adding
- Use `http://` or `socks5://` prefix correctly

### Slow Performance
- Check network connection
- Increase `NUM_WORKERS`
- Reduce `REQUEST_TIMEOUT`
- Verify proxy quality
- On Solana, ensure batch mode is enabled and RPCs are healthy

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

- ⚠️ **Never hardcode API keys** in the source code
- ⚠️ Use environment variables or `.env` files for sensitive data
- ⚠️ Keep `proxies.txt` and results private
- ⚠️ Be cautious with rate limiting to avoid IP bans
- ⚠️ Respect blockchain network resources

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
- Review code comments (TRON scanner includes Farsi documentation)

---

## Changelog

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

- [ ] Ethereum scanner support
- [ ] Database backend for results
- [ ] Web UI dashboard
- [ ] Batch processing from files
- [ ] WebSocket support for real-time updates
- [ ] Docker containerization

---

**Happy Scanning! 🚀**
