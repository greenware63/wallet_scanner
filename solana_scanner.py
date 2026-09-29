"""
Solana Address Scanner (Educational)
- Concurrently checks SOL and USDC (SPL) balances
- Async I/O with curl_cffi (browser TLS/JA3 impersonation)
- Multi-RPC with fallback and health-check
- Batch JSON-RPC mode (one round-trip per address)
- Cache results to avoid duplicate requests
- Proxy rotation
- Worker pool with asyncio
- Token bucket rate limiter per provider
- asyncio.Semaphore for connection pool control
"""
import asyncio
import sys
import time
import signal
import random
import json
from datetime import datetime
from pathlib import Path
from itertools import cycle
from collections import OrderedDict

import base58
from curl_cffi.requests import AsyncSession
from solders.keypair import Keypair
from solders.pubkey import Pubkey

# ==================== CONFIG ====================
NUM_WORKERS = 6
REQUEST_TIMEOUT = 15
MAX_RETRIES_PER_PROVIDER = 2

# Batch mode: single JSON-RPC array containing both getBalance and
# getTokenAccountsByOwner. Recommended for Solana because public RPCs
# are heavily rate-limited and batch halves the round-trips.
USE_BATCH_RPC = True

# Concurrency cap for outbound HTTP requests (independent of NUM_WORKERS)
MAX_CONCURRENT_REQUESTS = 32

# Solana RPC endpoints. Public ones are aggressively rate-limited.
# Replace with your own Helius / QuickNode / Triton endpoint for real use.
SOLANA_RPC_ENDPOINTS = [
    "https://api.mainnet-beta.solana.com",
    "https://solana-api.projectserum.com",
    "https://rpc.ankr.com/solana",
    "https://solana.public-rpc.com",
]

USDC_MINT = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
USDC_DECIMALS = 6
LAMPORTS_PER_SOL = 1_000_000_000

FOUND_FILE = Path("found_solana_wallets.txt")
STATS_FILE = Path("scan_solana_stats.txt")
CACHE_FILE = Path("solana_cache.json")
PROXY_FILE = Path("proxies.txt")
UA_FILE = Path("user_agents.txt")

CACHE_MAX_SIZE = 50_000
CACHE_TTL = 3600

IMPERSONATE_TARGETS = [
    "chrome124", "chrome123", "chrome120",
    "chrome116", "chrome110",
    "edge101", "safari17_0", "safari15_5",
]

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ==================== Rate Limiter ====================
class RateLimiter:
    def __init__(self, rate_per_sec: float, burst: int = 3):
        self.rate = rate_per_sec
        self.capacity = burst
        self.tokens = float(burst)
        self.last = time.monotonic()
        self.lock = asyncio.Lock()

    async def acquire(self):
        while True:
            async with self.lock:
                now = time.monotonic()
                self.tokens = min(
                    self.capacity,
                    self.tokens + (now - self.last) * self.rate
                )
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            await asyncio.sleep(wait)


# ==================== Cache ====================
class BalanceCache:
    """LRU cache with TTL for balance results."""

    def __init__(self, max_size=50_000, ttl=3600):
        self.max_size = max_size
        self.ttl = ttl
        self.store = OrderedDict()
        self.lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0

    async def get(self, address: str):
        async with self.lock:
            if address not in self.store:
                self.misses += 1
                return None
            ts, result = self.store[address]
            if time.time() - ts > self.ttl:
                del self.store[address]
                self.misses += 1
                return None
            self.store.move_to_end(address)
            self.hits += 1
            return result

    async def set(self, address: str, result: dict):
        async with self.lock:
            self.store[address] = (time.time(), result)
            self.store.move_to_end(address)
            while len(self.store) > self.max_size:
                self.store.popitem(last=False)

    async def load_from_disk(self):
        if not CACHE_FILE.exists():
            return
        try:
            with open(CACHE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            now = time.time()
            for addr, entry in data.items():
                ts, result = entry
                if now - ts <= self.ttl:
                    self.store[addr] = (ts, result)
            print(f"📦 Loaded {len(self.store)} addresses from disk cache.")
        except Exception as e:
            print(f"⚠ Cache load error: {e}")

    async def save_to_disk(self):
        try:
            async with self.lock:
                data = {
                    addr: entry
                    for addr, entry in self.store.items()
                    if entry[1].get("sol_lamports", 0) > 0
                    or entry[1].get("usdc_raw", 0) > 0
                }
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            print(f"💾 Saved {len(data)} funded addresses to disk cache.")
        except Exception as e:
            print(f"⚠ Cache save error: {e}")


# ==================== Provider ====================
class SolanaProvider:
    def __init__(self, name, endpoint, rate=3.0):
        self.name = name
        self.endpoint = endpoint
        self.rate_limiter = RateLimiter(rate_per_sec=rate, burst=3)
        self.fail_count = 0
        self.disabled_until = 0.0
        self.success_count = 0

    def is_available(self) -> bool:
        return time.monotonic() >= self.disabled_until

    def mark_failure(self):
        self.fail_count += 1
        if self.fail_count >= 3:
            self.disabled_until = time.monotonic() + 60.0
            self.fail_count = 0

    def mark_success(self):
        self.fail_count = 0
        self.success_count += 1

    def headers(self) -> dict:
        return {"Content-Type": "application/json"}

    # ---------- Request builders ----------

    def build_requests(self, address: str):
        if USE_BATCH_RPC:
            return self._build_batch(address)
        return self._build_native(address)

    def _build_batch(self, address: str):
        """One POST containing a JSON-RPC 2.0 array with two methods."""
        payload = [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "getBalance",
                "params": [address],
            },
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "getTokenAccountsByOwner",
                "params": [
                    address,
                    {"mint": USDC_MINT},
                    {"encoding": "jsonParsed"},
                ],
            },
        ]
        return [(self.endpoint, "POST", payload, "batch")]

    def _build_native(self, address: str):
        """Two separate POST requests."""
        sol_body = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "getBalance",
            "params": [address],
        }
        usdc_body = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "getTokenAccountsByOwner",
            "params": [
                address,
                {"mint": USDC_MINT},
                {"encoding": "jsonParsed"},
            ],
        }
        return [
            (self.endpoint, "POST", sol_body, "sol"),
            (self.endpoint, "POST", usdc_body, "usdc"),
        ]

    # ---------- Parsers ----------

    @staticmethod
    def parse_sol(result, address, provider_name):
        if result is None:
            return None
        try:
            lamports = int(result.get("value", 0))
        except Exception:
            return None
        return {
            "address": address,
            "sol_lamports": lamports,
            "sol": lamports / LAMPORTS_PER_SOL,
            "provider": provider_name,
            "active": lamports > 0,
        }

    @staticmethod
    def parse_usdc(result, address, provider_name):
        if result is None:
            return {"usdc_raw": 0, "usdc": 0.0}
        try:
            accounts = result.get("value", [])
            total_raw = 0
            for acc in accounts:
                parsed = (
                    acc.get("account", {})
                    .get("data", {})
                    .get("parsed", {})
                )
                info = parsed.get("info", {})
                token_amount = info.get("tokenAmount", {})
                raw = token_amount.get("amount", "0")
                total_raw += int(raw)
            return {
                "usdc_raw": total_raw,
                "usdc": total_raw / (10 ** USDC_DECIMALS),
            }
        except Exception:
            return {"usdc_raw": 0, "usdc": 0.0}

    @classmethod
    def parse_batch(cls, data, address, provider_name):
        """Parse a JSON-RPC batch array → (sol_result, usdc_result)."""
        if not isinstance(data, list):
            return None, None
        sol_result = None
        usdc_result = None
        for item in data:
            if not isinstance(item, dict):
                continue
            rid = item.get("id")
            result = item.get("result")
            if rid == 1:
                sol_result = cls.parse_sol(result, address, provider_name)
            elif rid == 2:
                usdc_result = cls.parse_usdc(result, address, provider_name)
        return sol_result, usdc_result


def build_providers():
    return [
        SolanaProvider(f"rpc-{i+1}", endpoint, rate=2.0)
        for i, endpoint in enumerate(SOLANA_RPC_ENDPOINTS)
    ]


# ==================== Proxy Pool ====================
class ProxyPool:
    def __init__(self, proxy_file: Path):
        self.proxies = []
        self.idx = 0
        self.lock = asyncio.Lock()
        self._load(proxy_file)

    def _load(self, path: Path):
        if not path.exists():
            print(f"⚠ Proxy file not found: {path} — running without proxies.")
            return
        with open(path, "r", encoding="utf-8") as f:
            raw = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        self.proxies = []
        for p in raw:
            if "://" not in p:
                p = f"http://{p}"
            self.proxies.append(p)
        print(f"✅ Loaded {len(self.proxies)} proxies.")

    async def get(self):
        if not self.proxies:
            return None
        async with self.lock:
            p = self.proxies[self.idx % len(self.proxies)]
            self.idx += 1
        return {"http": p, "https": p}

    def __len__(self):
        return len(self.proxies)


# ==================== User-Agent Manager ====================
DEFAULT_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]


class UAManager:
    def __init__(self, path: Path):
        self.ua_list = list(DEFAULT_UAS)
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                extra = [l.strip() for l in f if l.strip()]
            if extra:
                self.ua_list.extend(extra)
        self._cycle = cycle(self.ua_list)

    def next(self):
        return next(self._cycle)


REFERERS = [
    "https://solana.com/",
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://docs.solana.com/",
    "https://explorer.solana.com/",
]


def build_headers(ua: str, extra: dict | None = None) -> dict:
    h = {
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": random.choice([
            "en-US,en;q=0.9",
            "en-GB,en;q=0.8",
        ]),
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": random.choice(REFERERS),
        "Origin": "https://solana.com",
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
    }
    if extra:
        h.update(extra)
    return h


# ==================== Balance Checker ====================
class SolanaBalanceChecker:
    def __init__(self, providers, proxy_pool: ProxyPool, ua_mgr: UAManager,
                 cache: BalanceCache, max_concurrent: int = MAX_CONCURRENT_REQUESTS):
        self.providers = providers
        self.proxy_pool = proxy_pool
        self.ua_mgr = ua_mgr
        self.cache = cache
        self.session: AsyncSession | None = None
        self._sem = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        self.session = AsyncSession()
        return self

    async def __aexit__(self, *exc):
        if self.session:
            await self.session.close()

    async def _request(self, provider, url, method, body):
        """One outbound HTTP request with semaphore + rate limit + proxy + impersonate."""
        async with self._sem:
            await provider.rate_limiter.acquire()
            headers = build_headers(self.ua_mgr.next(), provider.headers())
            proxies = await self.proxy_pool.get()
            impersonate = random.choice(IMPERSONATE_TARGETS)

            kwargs = {
                "headers": headers,
                "proxies": proxies,
                "timeout": REQUEST_TIMEOUT,
                "impersonate": impersonate,
            }
            if method == "POST" and body is not None:
                kwargs["json"] = body

            return await self.session.request(method, url, **kwargs)

    async def check(self, address: str):
        """
        Check SOL and USDC balances.
        Returns: (result | None, api_call_made: bool)
        """
        cached = await self.cache.get(address)
        if cached is not None:
            return cached, False

        start = random.randrange(len(self.providers))
        ordered = self.providers[start:] + self.providers[:start]

        api_call_made = False

        for provider in ordered:
            if not provider.is_available():
                continue

            try:
                requests_list = provider.build_requests(address)
            except Exception:
                continue

            sol_result = None
            usdc_result = None

            for url, method, body, kind in requests_list:
                if kind == "sol" and sol_result is not None:
                    continue
                if kind == "usdc" and usdc_result is not None:
                    continue

                try:
                    api_call_made = True
                    r = await self._request(provider, url, method, body)

                    if r.status_code == 429:
                        await asyncio.sleep(2.0)
                        break
                    if r.status_code in (401, 403, 451):
                        provider.mark_failure()
                        break
                    if r.status_code >= 400:
                        break

                    try:
                        data = r.json()
                    except Exception:
                        data = None

                    if kind == "batch":
                        b_sol, b_usdc = provider.parse_batch(
                            data, address, provider.name
                        )
                        if b_sol is not None:
                            sol_result = b_sol
                        if b_usdc is not None:
                            usdc_result = b_usdc
                        continue

                    if kind in ("sol", "both"):
                        sol_result = provider.parse_sol(data, address, provider.name)
                    if kind in ("usdc", "both"):
                        usdc_result = provider.parse_usdc(data, address, provider.name)

                except Exception:
                    break

            # Fallback: if we have SOL but not USDC, try another provider for USDC
            if sol_result is not None and usdc_result is None:
                for p2 in ordered:
                    if p2 is provider or not p2.is_available():
                        continue
                    try:
                        reqs = p2.build_requests(address)
                    except Exception:
                        continue
                    for url, method, body, kind in reqs:
                        if kind not in ("usdc", "both"):
                            continue
                        try:
                            api_call_made = True
                            r = await self._request(p2, url, method, body)
                            if r.status_code == 200:
                                try:
                                    data = r.json()
                                    usdc_result = p2.parse_usdc(data, address, p2.name)
                                except Exception:
                                    pass
                        except Exception:
                            continue
                        if usdc_result is not None:
                            break
                    if usdc_result is not None:
                        break

            if sol_result is not None:
                provider.mark_success()
                final = {
                    **sol_result,
                    "usdc_raw": (usdc_result or {}).get("usdc_raw", 0),
                    "usdc": (usdc_result or {}).get("usdc", 0.0),
                }
                await self.cache.set(address, final)
                return final, True

        return None, api_call_made


# ==================== Key Utils ====================
def generate_keypair() -> Keypair:
    """Generate a random Solana keypair."""
    return Keypair()


def keypair_to_private_key_b58(kp: Keypair) -> str:
    """64-byte secret key (seed + pubkey) as Base58 — Phantom-compatible."""
    return base58.b58encode(bytes(kp)).decode()


def keypair_to_address(kp: Keypair) -> str:
    """Base58 public address."""
    return str(kp.pubkey())


# ==================== State / Stats ====================
class Stats:
    def __init__(self, providers):
        self.lock = asyncio.Lock()
        self.total_keys = 0
        self.total_requests = 0
        self.start_time = time.monotonic()
        self.provider_stats = {p.name: {"success": 0, "fail": 0} for p in providers}
        self.found = False

    async def incr_keys(self):
        async with self.lock:
            self.total_keys += 1
            return self.total_keys

    async def incr_requests(self, provider_name: str | None, ok: bool):
        async with self.lock:
            self.total_requests += 1
            if provider_name and provider_name in self.provider_stats:
                key = "success" if ok else "fail"
                self.provider_stats[provider_name][key] += 1

    @property
    def elapsed(self):
        return time.monotonic() - self.start_time


def save_found(private_key_b58, address, balance):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        f"[{ts}] Funded Solana wallet found!",
        f"Private Key (Base58): {private_key_b58}",
        f"Address (Base58):     {address}",
        f"SOL balance:          {balance['sol']:.9f} SOL",
        f"USDC balance:         {balance.get('usdc', 0.0):.6f} USDC",
        f"Provider:             {balance.get('provider', '?')}",
        "=" * 70,
    ]
    text = "\n".join(lines)
    print("\n" + text + "\n")
    with open(FOUND_FILE, "a", encoding="utf-8") as f:
        f.write(text + "\n\n")


def save_stats(stats: Stats, cache: BalanceCache):
    elapsed = stats.elapsed
    rate = stats.total_requests / elapsed if elapsed > 0 else 0
    total_cache = cache.hits + cache.misses
    hit_rate = (cache.hits / total_cache * 100) if total_cache > 0 else 0
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        f.write(f"Keys generated:  {stats.total_keys}\n")
        f.write(f"Network requests: {stats.total_requests}\n")
        f.write(f"Elapsed:          {elapsed:.2f}s\n")
        f.write(f"Rate:             {rate:.2f} req/s\n")
        f.write(f"Cache hits:       {cache.hits}\n")
        f.write(f"Cache misses:     {cache.misses}\n")
        f.write(f"Cache hit rate:   {hit_rate:.1f}%\n\n")
        f.write("Provider stats:\n")
        for name, s in stats.provider_stats.items():
            f.write(f"  {name}: ok={s['success']} | fail={s['fail']}\n")


# ==================== Worker ====================
async def worker(
    worker_id: int,
    checker: SolanaBalanceChecker,
    stats: Stats,
    stop_event: asyncio.Event,
    print_lock: asyncio.Lock,
):
    while not stop_event.is_set():
        kp = generate_keypair()
        pk_b58 = keypair_to_private_key_b58(kp)
        address = keypair_to_address(kp)

        n = await stats.incr_keys()

        if n % 50 == 0:
            async with print_lock:
                elapsed = stats.elapsed
                rate = stats.total_requests / elapsed if elapsed > 0 else 0
                active = sum(1 for p in checker.providers if p.is_available())
                cache_total = checker.cache.hits + checker.cache.misses
                hit_rate = (checker.cache.hits / cache_total * 100) if cache_total > 0 else 0
                print(
                    f"📊 Key #{n} | "
                    f"{stats.total_requests} req | "
                    f"{elapsed:.1f}s | {rate:.2f} req/s | "
                    f"RPC active: {active}/{len(checker.providers)} | "
                    f"cache: {hit_rate:.0f}%"
                )

        info, api_call_made = await checker.check(address)

        if api_call_made:
            if info is None:
                await stats.incr_requests(None, ok=False)
            else:
                await stats.incr_requests(info.get("provider"), ok=True)

        if info is None:
            continue

        has_sol = info.get("sol_lamports", 0) > 0
        has_usdc = info.get("usdc_raw", 0) > 0

        if has_sol or has_usdc:
            async with print_lock:
                save_found(pk_b58, address, info)
            stats.found = True
            stop_event.set()
            return


# ==================== Main ====================
def _install_signal_handlers(loop, stop_event):
    def _stop():
        if not stop_event.is_set():
            print("\n⏹ Stop requested...")
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except (NotImplementedError, AttributeError):
            try:
                signal.signal(sig, lambda *_: loop.call_soon_threadsafe(_stop))
            except (ValueError, OSError, RuntimeError):
                pass
    return _stop


async def main():
    print("=" * 70)
    print("  Solana Scanner — async + curl_cffi + USDC + Cache")
    print("  Features: SOL + USDC | TLS Fingerprint | Multi-RPC | Proxy | Cache")
    print(f"  RPC endpoints: {len(SOLANA_RPC_ENDPOINTS)} | Workers: {NUM_WORKERS}")
    if USE_BATCH_RPC:
        print("  🔀 Batch JSON-RPC mode active (one round-trip per address)")
    else:
        print("  ⚡ Native mode active (two requests per address)")
    print(f"  Max concurrent requests: {MAX_CONCURRENT_REQUESTS}")
    print("  Press Ctrl+C to stop")
    print("=" * 70)

    providers = build_providers()
    proxy_pool = ProxyPool(PROXY_FILE)
    ua_mgr = UAManager(UA_FILE)
    cache = BalanceCache(max_size=CACHE_MAX_SIZE, ttl=CACHE_TTL)
    await cache.load_from_disk()

    stats = Stats(providers)
    stop_event = asyncio.Event()
    print_lock = asyncio.Lock()

    loop = asyncio.get_running_loop()
    _install_signal_handlers(loop, stop_event)

    try:
        async with SolanaBalanceChecker(
            providers, proxy_pool, ua_mgr, cache,
            max_concurrent=MAX_CONCURRENT_REQUESTS,
        ) as checker:
            tasks = [
                asyncio.create_task(
                    worker(i, checker, stats, stop_event, print_lock),
                    name=f"worker-{i}",
                )
                for i in range(NUM_WORKERS)
            ]

            try:
                while not stop_event.is_set():
                    done, pending = await asyncio.wait(
                        tasks,
                        timeout=0.5,
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if not pending:
                        break
            finally:
                for t in tasks:
                    t.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    except (KeyboardInterrupt, asyncio.CancelledError):
        stop_event.set()

    await cache.save_to_disk()
    save_stats(stats, cache)
    print(f"\n📁 Stats saved to {STATS_FILE}.")
    print(f"⏱  Total: {stats.elapsed:.1f}s | Keys: {stats.total_keys}")
    print(f"📦 Cache: {cache.hits} hit / {cache.misses} miss")
    print("👋 Done.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass