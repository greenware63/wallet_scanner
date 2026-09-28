"""
Bitcoin Address Scanner (Educational)
- Async I/O با curl_cffi (جعل TLS/JA3 fingerprint مرورگر)
- چند API سالم و پرسرعت (mempool.space, blockstream.info, mempool.ninja, mempool.emzy.de, bitaps)
- سیستم کش دو سطحی LRU با قابلیت ذخیره روی دیسک
- چرخش پروکسی و User-Agent
- Worker Pool با asyncio و خاموشی امن (Graceful Shutdown) در ویندوز و لینوکس
- Rate limiter Token Bucket برای هر Provider
"""
import asyncio
import sys
import time
import signal
import secrets
import random
import json
from datetime import datetime
from pathlib import Path
from itertools import cycle
from collections import OrderedDict

from curl_cffi.requests import AsyncSession
from bit import Key
from bit.base32 import bech32_encode, convertbits
from bit.format import ripemd160_sha256

# ==================== تنظیمات ====================
HRP = "bc"
NUM_WORKERS = 8
REQUEST_TIMEOUT = 12
MAX_RETRIES_PER_PROVIDER = 2

FOUND_FILE = Path("found_wallets.txt")
STATS_FILE = Path("scan_stats.txt")
CACHE_FILE = Path("btc_cache.json")
PROXY_FILE = Path("proxies.txt")
UA_FILE = Path("user_agents.txt")

CACHE_MAX_SIZE = 50_000
CACHE_TTL = 3600

IMPERSONATE_TARGETS = [
    "chrome124", "chrome123", "chrome120",
    "chrome116", "chrome110",
    "edge101", "safari17_0", "safari15_5",
]

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ==================== Rate Limiter (Token Bucket) ====================
class RateLimiter:
    """محدودکننده‌ی نرخ async با الگوریتم token bucket"""
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
                    self.tokens + (now - self.last) * self.rate,
                )
                self.last = now
                if self.tokens >= 1.0:
                    self.tokens -= 1.0
                    return
                wait = (1.0 - self.tokens) / self.rate
            await asyncio.sleep(wait)


# ==================== Cache ====================
class BalanceCache:
    """
    کش LRU با TTL برای نتایج موجودی آدرس‌های بیت‌کوین.
    کلید: address | مقدار: (timestamp, result_dict)
    از time.time() استفاده می‌شود تا بین ری‌استارت‌ها هم معتبر باشد.
    """
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
            print(f"📦 {len(self.store)} آدرس بیت‌کوین از کش دیسک بارگذاری شد.")
        except Exception as e:
            print(f"⚠ خطا در بارگذاری کش: {e}")

    async def save_to_disk(self):
        try:
            async with self.lock:
                data = {
                    addr: (ts, res)
                    for addr, (ts, res) in self.store.items()
                    if res.get("total_sats", 0) > 0 or res.get("tx_count", 0) > 0
                }
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception as e:
            print(f"⚠ خطا در ذخیره کش: {e}")


# ==================== Provider ====================
class BitcoinAPIProvider:
    def __init__(self, name, base_url, parser=None, rate=3.0, impersonate=True):
        self.name = name
        self.base_url = base_url
        self.parser = parser or self._default_mempool_parser
        self.rate_limiter = RateLimiter(rate_per_sec=rate, burst=3)
        self.impersonate = impersonate
        self.fail_count = 0
        self.disabled_until = 0.0
        self.success_count = 0

    def is_available(self) -> bool:
        return time.monotonic() >= self.disabled_until

    def mark_failure(self):
        self.fail_count += 1
        if self.fail_count >= 3:
            self.disabled_until = time.monotonic() + 45.0
            self.fail_count = 0

    def mark_success(self):
        self.fail_count = 0
        self.success_count += 1

    def build_url(self, address: str) -> str:
        return self.base_url.format(address=address)

    @staticmethod
    def _default_mempool_parser(data, address, provider_name):
        chain = data.get("chain_stats", {})
        mempool = data.get("mempool_stats", {})
        confirmed = int(chain.get("funded_txo_sum", 0)) - int(chain.get("spent_txo_sum", 0))
        unconfirmed = int(mempool.get("funded_txo_sum", 0)) - int(mempool.get("spent_txo_sum", 0))
        total = confirmed + unconfirmed
        tx_count = int(chain.get("tx_count", 0)) + int(mempool.get("tx_count", 0))
        return {
            "address": address,
            "confirmed_sats": confirmed,
            "unconfirmed_sats": unconfirmed,
            "total_sats": total,
            "confirmed_btc": confirmed / 100_000_000,
            "total_btc": total / 100_000_000,
            "tx_count": tx_count,
            "provider": provider_name,
        }


def _bitaps_parser(data, address, name):
    # bitaps ممکن است پاسخ را داخل کلید "data" بدهد یا مستقیم — هر دو حالت را پشتیبانی می‌کنیم
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        b_data = data["data"]
    elif isinstance(data, dict):
        b_data = data
    else:
        b_data = {}

    confirmed = int(b_data.get("balance", 0) or 0)
    pending_rec = int(b_data.get("pendingReceivedAmount", 0) or 0)
    pending_sent = int(b_data.get("pendingSentAmount", 0) or 0)
    unconfirmed = pending_rec - pending_sent
    total = confirmed + unconfirmed
    tx_count = int(b_data.get("receivedTxCount", 0) or 0) + int(b_data.get("sentTxCount", 0) or 0)
    return {
        "address": address,
        "confirmed_sats": confirmed,
        "unconfirmed_sats": unconfirmed,
        "total_sats": total,
        "confirmed_btc": confirmed / 100_000_000,
        "total_btc": total / 100_000_000,
        "tx_count": tx_count,
        "provider": name,
    }


def build_providers():
    return [
        BitcoinAPIProvider(
            "mempool.space",
            "https://mempool.space/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser,
            rate=4.0,
            impersonate=True,
        ),
        BitcoinAPIProvider(
            "blockstream.info",
            "https://blockstream.info/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser,
            rate=4.0,
            impersonate=True,
        ),
        BitcoinAPIProvider(
            "mempool.ninja",
            "https://mempool.ninja/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser,
            rate=4.0,
            impersonate=True,
        ),
        BitcoinAPIProvider(
            "mempool.emzy.de",
            "https://mempool.emzy.de/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser,
            rate=3.0,
            impersonate=True,
        ),
        BitcoinAPIProvider(
            "bitaps",
            "https://api.bitaps.com/btc/v1/blockchain/address/state/{address}",
            _bitaps_parser,
            rate=2.0,
            impersonate=True,
        ),
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
            print(f"⚠ فایل پروکسی یافت نشد: {path} — بدون پروکسی اجرا می‌شود.")
            return
        with open(path, "r", encoding="utf-8") as f:
            raw = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        self.proxies = []
        for p in raw:
            # اطمینان از داشتن اسکیم (http:// یا socks5://)
            if "://" not in p:
                p = f"http://{p}"
            self.proxies.append(p)
        print(f"✅ {len(self.proxies)} پروکسی بارگذاری شد.")

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
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
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
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://www.bing.com/",
    "https://mempool.space/",
    "https://blockstream.info/",
    "https://bitcoin.org/",
]


def build_headers(ua: str) -> dict:
    return {
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": random.choice(REFERERS),
        "DNT": "1",
        "Connection": "keep-alive",
        "Sec-Fetch-Dest": "empty",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Site": "cross-site",
    }


# ==================== Balance Checker ====================
class BalanceChecker:
    def __init__(self, providers, proxy_pool: ProxyPool, ua_mgr: UAManager, cache: BalanceCache):
        self.providers = providers
        self.proxy_pool = proxy_pool
        self.ua_mgr = ua_mgr
        self.cache = cache
        self.session: AsyncSession | None = None

    async def __aenter__(self):
        self.session = AsyncSession()
        return self

    async def __aexit__(self, *exc):
        if self.session:
            await self.session.close()

    async def check(self, address: str):
        """
        چند API رو با fallback امتحان می‌کنه؛ ابتدا کش بررسی می‌شه.
        خروجی: (result | None, api_call_made: bool)
        - اگر از کش برگردد: api_call_made = False
        - اگر درخواست واقعی به API زده شود (حتی در صورت شکست): api_call_made = True
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

            for attempt in range(MAX_RETRIES_PER_PROVIDER):
                try:
                    await provider.rate_limiter.acquire()
                    url = provider.build_url(address)
                    headers = build_headers(self.ua_mgr.next())
                    proxies = await self.proxy_pool.get()
                    impersonate = random.choice(IMPERSONATE_TARGETS) if provider.impersonate else None

                    api_call_made = True
                    r = await self.session.get(
                        url,
                        headers=headers,
                        proxies=proxies,
                        timeout=REQUEST_TIMEOUT,
                        impersonate=impersonate,
                    )

                    if r.status_code == 429:
                        await asyncio.sleep(1.5 * (attempt + 1))
                        continue

                    if r.status_code == 404:
                        provider.mark_success()
                        res = {
                            "address": address, "confirmed_sats": 0,
                            "unconfirmed_sats": 0, "total_sats": 0,
                            "confirmed_btc": 0.0, "total_btc": 0.0,
                            "tx_count": 0, "provider": provider.name,
                        }
                        await self.cache.set(address, res)
                        return res, True

                    if r.status_code in (401, 403, 451):
                        provider.mark_failure()
                        break

                    if r.status_code >= 400:
                        if attempt < MAX_RETRIES_PER_PROVIDER - 1:
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                        provider.mark_failure()
                        break

                    data = r.json()
                    result = provider.parser(data, address, provider.name)
                    provider.mark_success()
                    await self.cache.set(address, result)
                    return result, True

                except Exception:
                    if attempt < MAX_RETRIES_PER_PROVIDER - 1:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    provider.mark_failure()
                    break

        return None, api_call_made


# ==================== Key Utils ====================
def generate_private_key() -> str:
    while True:
        k = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= k < CURVE_ORDER:
            return f"{k:064x}"


def public_key_to_native_segwit(pub_bytes: bytes, hrp=HRP) -> str:
    wp = ripemd160_sha256(pub_bytes)
    data = [0] + convertbits(wp, 8, 5)
    return bech32_encode(hrp, data)


def private_key_to_addresses(pk_hex: str):
    try:
        key = Key.from_hex(pk_hex)
        return {
            "Legacy (P2PKH)": key.address,
            "Nested SegWit (P2SH-P2WPKH)": key.segwit_address,
            "Native SegWit (P2WPKH)": public_key_to_native_segwit(key.public_key),
        }, key
    except Exception as e:
        print(f"⚠ خطا در تبدیل کلید: {e}")
        return None, None


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


def save_found(private_key, addresses, balance, found_address):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        f"[{ts}] کیف پول با موجودی پیدا شد!",
        f"Private Key (HEX): {private_key}",
    ]
    for kind, addr in addresses.items():
        marker = "  ← یافت‌شده" if addr == found_address else ""
        lines.append(f"  {kind}: {addr}{marker}")
    lines.append(f"  موجودی تأییدشده: {balance['confirmed_btc']:.8f} BTC")
    lines.append(f"  موجودی کل:      {balance['total_btc']:.8f} BTC")
    lines.append(f"  تعداد تراکنش:   {balance['tx_count']}")
    lines.append(f"  Provider:       {balance.get('provider', '?')}")
    lines.append("=" * 70)
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
        f.write(f"کلیدهای تولیدشده: {stats.total_keys}\n")
        f.write(f"درخواست‌های API:   {stats.total_requests}\n")
        f.write(f"زمان اجرا:         {elapsed:.2f} ثانیه\n")
        f.write(f"نرخ درخواست:       {rate:.2f} req/s\n")
        f.write(f"کش hit rate:       {hit_rate:.1f}%\n\n")
        f.write("آمار Providerها:\n")
        for name, s in stats.provider_stats.items():
            f.write(f"  {name}: موفق={s['success']} | خطا={s['fail']}\n")


# ==================== Worker ====================
async def worker(
    worker_id: int,
    checker: BalanceChecker,
    stats: Stats,
    stop_event: asyncio.Event,
    print_lock: asyncio.Lock,
):
    while not stop_event.is_set():
        pk_hex = generate_private_key()
        addresses, _ = private_key_to_addresses(pk_hex)
        if not addresses:
            continue

        n = await stats.incr_keys()

        if n % 50 == 0:
            async with print_lock:
                elapsed = stats.elapsed
                rate = stats.total_requests / elapsed if elapsed > 0 else 0
                active = sum(1 for p in checker.providers if p.is_available())
                cache_total = checker.cache.hits + checker.cache.misses
                hit_rate = (checker.cache.hits / cache_total * 100) if cache_total > 0 else 0
                print(
                    f"📊 کلید #{n} | "
                    f"{stats.total_requests} req | "
                    f"{elapsed:.1f}s | {rate:.2f} req/s | "
                    f"API فعال: {active}/{len(checker.providers)} | "
                    f"کش: {hit_rate:.0f}%"
                )

        for kind, addr in addresses.items():
            if stop_event.is_set():
                return

            info, api_call_made = await checker.check(addr)

            # فقط درخواست‌های واقعی API را می‌شماریم، نه hitهای کش
            if api_call_made:
                if info is None:
                    await stats.incr_requests(None, ok=False)
                else:
                    await stats.incr_requests(info.get("provider"), ok=True)

            if info is not None and info.get("total_sats", 0) > 0:
                async with print_lock:
                    save_found(pk_hex, addresses, info, addr)
                stats.found = True
                stop_event.set()
                return


# ==================== Main ====================
async def main():
    # ابتدا providers ساخته می‌شود چون در print و Stats استفاده می‌شود
    providers = build_providers()

    print("=" * 70)
    print("  اسکنر بیت‌کوین — نسخه async + curl_cffi + Cache")
    print("  ویژگی‌ها: TLS Fingerprint مرورگر | Multi-API سالم | LRU Cache | Proxy Rotation")
    print(f"  تعداد APIها: {len(providers)} | Workerها: {NUM_WORKERS}")
    print("  برای توقف: Ctrl+C")
    print("=" * 70)

    proxy_pool = ProxyPool(PROXY_FILE)
    ua_mgr = UAManager(UA_FILE)
    cache = BalanceCache(max_size=CACHE_MAX_SIZE, ttl=CACHE_TTL)
    await cache.load_from_disk()

    stats = Stats(providers)
    stop_event = asyncio.Event()
    print_lock = asyncio.Lock()

    loop = asyncio.get_running_loop()

    def _stop():
        if not stop_event.is_set():
            print("\n⏹ درخواست توقف دریافت شد...")
            stop_event.set()

    # ثبت سیگنال‌ها: در لینوکس/مک از add_signal_handler، در ویندوز fallback به signal.signal
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except (NotImplementedError, AttributeError):
            try:
                signal.signal(
                    sig,
                    lambda *_: loop.call_soon_threadsafe(_stop),
                )
            except (ValueError, OSError, RuntimeError):
                pass

    try:
        async with BalanceChecker(providers, proxy_pool, ua_mgr, cache) as checker:
            tasks = [
                asyncio.create_task(
                    worker(i, checker, stats, stop_event, print_lock),
                    name=f"worker-{i}",
                )
                for i in range(NUM_WORKERS)
            ]

            while not stop_event.is_set():
                done, pending = await asyncio.wait(
                    tasks,
                    timeout=0.5,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if stop_event.is_set():
                    break
                if not pending:
                    break

            for t in tasks:
                t.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    except (KeyboardInterrupt, asyncio.CancelledError):
        _stop()

    await cache.save_to_disk()
    save_stats(stats, cache)
    print(f"\n📁 آمار در {STATS_FILE} ذخیره شد.")
    print(f"⏱  زمان کل: {stats.elapsed:.1f}s | کلیدها: {stats.total_keys}")
    print(f"📦 کش: {cache.hits} hit / {cache.misses} miss")
    print("👋 پایان.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass