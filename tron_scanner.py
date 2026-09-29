"""
TRON Address Scanner (Educational)
- بررسی همزمان موجودی TRX و USDT (TRC-20)
- Async I/O با curl_cffi (جعل TLS/JA3 مرورگر)
- Multi-API با fallback و health-check
- پشتیبانی از TronGrid API Key
- کش نتایج برای جلوگیری از درخواست تکراری
- چرخش پروکسی
- Worker Pool با asyncio
- Rate limiter Token Bucket برای هر Provider

بهینه‌سازی‌های اعمال‌شده:
  1) Skip درخواست USDT برای اکانت‌های ناموجود روی زنجیره
  2) حالت batch JSON-RPC (eth_getBalance + eth_call) برای مانیتورینگ
  3) asyncio.Semaphore برای کنترل سقف اتصال‌های همزمان curl_cffi
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
from tronpy.keys import PrivateKey, to_hex_address

# ==================== تنظیمات ====================
NUM_WORKERS = 6
REQUEST_TIMEOUT = 15
MAX_RETRIES_PER_PROVIDER = 2

# بهینه‌سازی ۲ — حالت batch JSON-RPC:
#   False → API نیتیو ترون + skip-empty (بهترین برای اسکن تصادفی)
#   True  → یک درخواست batch دو متدی per address (بهترین برای مانیتورینگ)
USE_JSONRPC_BATCH = False

# بهینه‌سازی ۳ — سقف اتصال‌های همزمان curl_cffi
MAX_CONCURRENT_REQUESTS = 32

TRONGRID_API_KEY = ""   # از https://www.trongrid.io/ بگیر

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_DECIMALS = 6

# eth_getBalance روی TronGrid مقدار را بر حسب SUN برمی‌گرداند.
# اگر provider شما wei (۱۸ رقم اعشار) برگرداند، به 10**18 تغییر دهید.
ETH_BALANCE_UNIT = 1_000_000

FOUND_FILE = Path("found_tron_wallets.txt")
STATS_FILE = Path("scan_tron_stats.txt")
CACHE_FILE = Path("tron_cache.json")
PROXY_FILE = Path("proxies.txt")
UA_FILE = Path("user_agents.txt")

CACHE_MAX_SIZE = 50_000
CACHE_TTL = 3600

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

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
    """
    کش LRU با TTL برای نتایج موجودی.
    از time.time() استفاده می‌شود تا بین ری‌استارت/ریبوت هم TTL معتبر بماند.
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
            print(f"📦 {len(self.store)} آدرس از کش دیسک بارگذاری شد.")
        except Exception as e:
            print(f"⚠ خطا در بارگذاری کش: {e}")

    async def save_to_disk(self):
        try:
            async with self.lock:
                data = {
                    addr: entry
                    for addr, entry in self.store.items()
                    if entry[1].get("total_sun", 0) > 0
                    or entry[1].get("usdt_sun", 0) > 0
                }
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            print(f"💾 {len(data)} آدرس دارای موجودی در کش ذخیره شد.")
        except Exception as e:
            print(f"⚠ خطا در ذخیره کش: {e}")


# ==================== Provider ====================
class TronAPIProvider:
    def __init__(self, name, rate=3.0):
        self.name = name
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

    def build_requests(self, address: str):
        raise NotImplementedError

    def headers(self) -> dict:
        return {}

    @staticmethod
    def parse_trx(data, address, provider_name):
        raise NotImplementedError

    @staticmethod
    def parse_usdt(data, address, provider_name):
        raise NotImplementedError


# ---- Provider 1: TronGrid ----
_USDT_CONTRACT_HEX_CACHE = None


def _usdt_contract_hex() -> str:
    """0x + 40 hex بدون پیشوند 41"""
    global _USDT_CONTRACT_HEX_CACHE
    if _USDT_CONTRACT_HEX_CACHE is None:
        _USDT_CONTRACT_HEX_CACHE = "0x" + to_hex_address(USDT_CONTRACT)[2:]
    return _USDT_CONTRACT_HEX_CACHE


def _tron_to_evm_hex(address: str) -> str:
    """Base58 TRON → 0x-prefixed 20-byte hex"""
    return "0x" + to_hex_address(address)[2:]


class TronGridProvider(TronAPIProvider):
    BALANCE_OF_SELECTOR = "70a08231"  # keccak256("balanceOf(address)")[:4]

    def __init__(self):
        super().__init__("trongrid", rate=6.0)
        self.base_url = "https://api.trongrid.io"
        self.jsonrpc_url = f"{self.base_url}/jsonrpc"
        self.use_batch = USE_JSONRPC_BATCH
        self._extra_headers = {"Content-Type": "application/json"}
        if TRONGRID_API_KEY:
            self._extra_headers["TRON-PRO-API-KEY"] = TRONGRID_API_KEY

    # ---------- Request builders ----------

    def build_requests(self, address):
        if self.use_batch:
            return self._build_batch(address)
        return self._build_native(address)

    def _build_native(self, address):
        """حالت پیش‌فرض: دو درخواست جدا، با قابلیت skip."""
        trx_url = f"{self.base_url}/wallet/getaccount"
        trx_body = {"address": address, "visible": True}

        addr_hex = to_hex_address(address)[2:]
        param = addr_hex.rjust(64, "0")
        usdt_url = f"{self.base_url}/wallet/triggerconstantcontract"
        usdt_body = {
            "owner_address": address,
            "contract_address": USDT_CONTRACT,
            "function_selector": "balanceOf(address)",
            "parameter": param,
            "visible": True,
        }
        return [
            (trx_url, "POST", trx_body, "trx"),
            (usdt_url, "POST", usdt_body, "usdt"),
        ]

    def _build_batch(self, address):
        """حالت batch: یک POST با آرایه‌ی دو متد JSON-RPC 2.0."""
        evm = _tron_to_evm_hex(address)
        trx_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_getBalance",
            "params": [evm, "latest"],
        }
        call_data = "0x" + self.BALANCE_OF_SELECTOR + evm[2:].rjust(64, "0")
        usdt_req = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "eth_call",
            "params": [
                {"to": _usdt_contract_hex(), "data": call_data},
                "latest",
            ],
        }
        return [(self.jsonrpc_url, "POST", [trx_req, usdt_req], "batch")]

    def headers(self):
        return self._extra_headers

    # ---------- Native parsers ----------

    @staticmethod
    def parse_trx(data, address, provider_name):
        # wallet/getaccount برای اکانت ناموجود {} برمی‌گرداند
        if not data:
            return {
                "address": address, "total_sun": 0, "total_trx": 0.0,
                "tx_count": 0, "provider": provider_name, "active": False,
            }
        balance_sun = data.get("balance", 0) or 0
        return {
            "address": address, "total_sun": balance_sun,
            "total_trx": balance_sun / 1_000_000,
            "tx_count": data.get("transactions", 0) or 0,
            "provider": provider_name,
            "active": True,  # اکانت روی زنجیره وجود دارد
        }

    @staticmethod
    def parse_usdt(data, address, provider_name):
        if not data:
            return {"usdt_sun": 0, "usdt": 0.0}
        constant = data.get("constant_result")
        if not constant or not isinstance(constant, list) or not constant:
            return {"usdt_sun": 0, "usdt": 0.0}
        try:
            raw = int(constant[0], 16)
            return {"usdt_sun": raw, "usdt": raw / (10 ** USDT_DECIMALS)}
        except Exception:
            return {"usdt_sun": 0, "usdt": 0.0}

    # ---------- JSON-RPC parsers ----------

    @staticmethod
    def parse_eth_balance(hex_result, address, provider_name):
        if hex_result is None:
            return None
        try:
            sun = int(hex_result, 16) if isinstance(hex_result, str) else int(hex_result)
        except Exception:
            return None
        return {
            "address": address, "total_sun": sun,
            "total_trx": sun / ETH_BALANCE_UNIT,
            "tx_count": 0,
            "provider": provider_name,
            # eth_getBalance وجود اکانت را نشان نمی‌دهد؛ فقط موجودی.
            "active": sun > 0,
        }

    @staticmethod
    def parse_eth_call(hex_result, address, provider_name):
        if hex_result is None:
            return {"usdt_sun": 0, "usdt": 0.0}
        try:
            raw = int(hex_result, 16) if isinstance(hex_result, str) else int(hex_result)
            return {"usdt_sun": raw, "usdt": raw / (10 ** USDT_DECIMALS)}
        except Exception:
            return {"usdt_sun": 0, "usdt": 0.0}

    @classmethod
    def parse_batch(cls, data, address, provider_name):
        """پاسخ آرایه‌ای JSON-RPC batch → (trx_result, usdt_result)"""
        if not isinstance(data, list):
            return None, None
        trx_result = None
        usdt_result = None
        for item in data:
            if not isinstance(item, dict):
                continue
            rid = item.get("id")
            result = item.get("result")
            if rid == 1:
                trx_result = cls.parse_eth_balance(result, address, provider_name)
            elif rid == 2:
                usdt_result = cls.parse_eth_call(result, address, provider_name)
        return trx_result, usdt_result


# ---- Provider 2: TronScan ----
class TronScanProvider(TronAPIProvider):
    def __init__(self):
        super().__init__("tronscan", rate=3.0)
        self.base_url = "https://apilist.tronscanapi.com/api/accountv2"

    def build_requests(self, address):
        url = f"{self.base_url}?address={address}"
        return [(url, "GET", None, "both")]

    @staticmethod
    def parse_trx(data, address, provider_name):
        if not data or "balance" not in data:
            return {
                "address": address, "total_sun": 0, "total_trx": 0.0,
                "tx_count": 0, "provider": provider_name, "active": False,
            }
        balance_sun = int(data.get("balance", 0) or 0)
        return {
            "address": address, "total_sun": balance_sun,
            "total_trx": balance_sun / 1_000_000,
            "tx_count": data.get("transactions", 0) or 0,
            "provider": provider_name, "active": True,
        }

    @staticmethod
    def parse_usdt(data, address, provider_name):
        if not data:
            return {"usdt_sun": 0, "usdt": 0.0}
        balances = data.get("trc20token_balances", []) or []
        for token in balances:
            if token.get("tokenId") == USDT_CONTRACT:
                raw = int(token.get("balance", 0) or 0)
                return {"usdt_sun": raw, "usdt": raw / (10 ** USDT_DECIMALS)}
        return {"usdt_sun": 0, "usdt": 0.0}


# ---- Provider 3: P2P.org (فقط TRX) ----
class P2PProvider(TronAPIProvider):
    def __init__(self):
        super().__init__("p2p", rate=2.0)
        self.base_url = "https://api.p2p.org/api/v1/tron/mainnet/account"

    def build_requests(self, address):
        url = f"{self.base_url}/{address}"
        return [(url, "GET", None, "trx")]

    @staticmethod
    def parse_trx(data, address, provider_name):
        if not data:
            return None
        balance_sun = 0
        tx_count = 0
        if isinstance(data, dict):
            balance_sun = int(data.get("balance", 0) or 0)
            tx_count = int(data.get("transactions", 0) or 0)
            if "result" in data and isinstance(data["result"], dict):
                balance_sun = int(data["result"].get("balance", balance_sun) or 0)
        return {
            "address": address, "total_sun": balance_sun,
            "total_trx": balance_sun / 1_000_000,
            "tx_count": tx_count, "provider": provider_name,
            "active": balance_sun > 0,
        }

    @staticmethod
    def parse_usdt(data, address, provider_name):
        return {"usdt_sun": 0, "usdt": 0.0}


def build_providers():
    return [
        TronGridProvider(),
        TronScanProvider(),
        P2PProvider(),
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
    "https://tronscan.org/",
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://developers.tron.network/",
    "https://tron.network/",
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
        "Origin": "https://tronscan.org",
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
class BalanceChecker:
    def __init__(self, providers, proxy_pool: ProxyPool, ua_mgr: UAManager,
                 cache: BalanceCache, max_concurrent: int = MAX_CONCURRENT_REQUESTS):
        self.providers = providers
        self.proxy_pool = proxy_pool
        self.ua_mgr = ua_mgr
        self.cache = cache
        self.session: AsyncSession | None = None
        # بهینه‌سازی ۳: سقف اتصال‌های همزمان
        self._sem = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        self.session = AsyncSession()
        return self

    async def __aexit__(self, *exc):
        if self.session:
            await self.session.close()

    async def _request(self, provider, url, method, body):
        """یک درخواست شبکه‌ای با Semaphore + rate limiting + proxies + impersonate"""
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
        بررسی موجودی TRX و USDT.
        خروجی: (result | None, api_call_made: bool)
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

            trx_result = None
            usdt_result = None

            for url, method, body, kind in requests_list:
                if kind == "trx" and trx_result is not None:
                    continue
                if kind == "usdt" and usdt_result is not None:
                    continue

                # بهینه‌سازی ۱: اگر اکانت روی زنجیره وجود ندارد،
                # درخواست USDT را کاملاً حذف کن.
                if (kind == "usdt"
                        and trx_result is not None
                        and not trx_result.get("active")):
                    usdt_result = {"usdt_sun": 0, "usdt": 0.0}
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

                    # بهینه‌سازی ۲: پاسخ batch را جدا پارس کن
                    if kind == "batch":
                        b_trx, b_usdt = provider.parse_batch(
                            data, address, provider.name
                        )
                        if b_trx is not None:
                            trx_result = b_trx
                        if b_usdt is not None:
                            usdt_result = b_usdt
                        continue

                    if kind in ("trx", "both"):
                        trx_result = provider.parse_trx(data, address, provider.name)
                    if kind in ("usdt", "both"):
                        usdt_result = provider.parse_usdt(data, address, provider.name)

                except Exception:
                    break

            # اگر TRX داریم ولی USDT نداریم، از provider بعدی USDT را بگیر
            if trx_result is not None and usdt_result is None:
                for p2 in ordered:
                    if p2 is provider or not p2.is_available():
                        continue
                    try:
                        reqs = p2.build_requests(address)
                    except Exception:
                        continue
                    for url, method, body, kind in reqs:
                        if kind not in ("usdt", "both"):
                            continue
                        try:
                            api_call_made = True
                            r = await self._request(p2, url, method, body)
                            if r.status_code == 200:
                                try:
                                    data = r.json()
                                    usdt_result = p2.parse_usdt(data, address, p2.name)
                                except Exception:
                                    pass
                        except Exception:
                            continue
                        if usdt_result is not None:
                            break
                    if usdt_result is not None:
                        break

            if trx_result is not None:
                provider.mark_success()
                final = {
                    **trx_result,
                    "usdt_sun": (usdt_result or {}).get("usdt_sun", 0),
                    "usdt": (usdt_result or {}).get("usdt", 0.0),
                }
                await self.cache.set(address, final)
                return final, True

        return None, api_call_made


# ==================== Key Utils ====================
def generate_private_key_bytes() -> bytes:
    while True:
        k = secrets.token_bytes(32)
        if 1 <= int.from_bytes(k, "big") < CURVE_ORDER:
            return k


def private_key_to_address(pk_bytes: bytes) -> str | None:
    try:
        return PrivateKey(pk_bytes).public_key.to_base58check_address()
    except Exception as e:
        print(f"⚠ خطا در تبدیل کلید: {e}")
        return None


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


def save_found(private_key_hex, address, balance):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        f"[{ts}] کیف پول ترون با موجودی پیدا شد!",
        f"Private Key (HEX): {private_key_hex}",
        f"Address (Base58):  {address}",
        f"موجودی TRX:       {balance['total_trx']:.6f} TRX",
        f"موجودی USDT:      {balance.get('usdt', 0.0):.6f} USDT",
        f"تعداد تراکنش:     {balance.get('tx_count', 0)}",
        f"Provider:         {balance.get('provider', '?')}",
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
        f.write(f"کلیدهای تولیدشده: {stats.total_keys}\n")
        f.write(f"درخواست‌های شبکه:  {stats.total_requests}\n")
        f.write(f"زمان اجرا:         {elapsed:.2f} ثانیه\n")
        f.write(f"نرخ:               {rate:.2f} req/s\n")
        f.write(f"کش hits:           {cache.hits}\n")
        f.write(f"کش misses:         {cache.misses}\n")
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
        pk_bytes = generate_private_key_bytes()
        pk_hex = pk_bytes.hex()
        address = private_key_to_address(pk_bytes)
        if not address:
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

        info, api_call_made = await checker.check(address)

        # فقط درخواست‌های واقعی API شمرده می‌شوند، نه hitهای کش
        if api_call_made:
            if info is None:
                await stats.incr_requests(None, ok=False)
            else:
                await stats.incr_requests(info.get("provider"), ok=True)

        if info is None:
            continue

        has_trx = info.get("total_sun", 0) > 0
        has_usdt = info.get("usdt_sun", 0) > 0

        if has_trx or has_usdt:
            async with print_lock:
                save_found(pk_hex, address, info)
            stats.found = True
            stop_event.set()
            return


# ==================== Main ====================
def _install_signal_handlers(loop, stop_event):
    """نصب signal handler سازگار با لینوکس + ویندوز"""
    def _stop():
        if not stop_event.is_set():
            print("\n⏹ درخواست توقف دریافت شد...")
            stop_event.set()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _stop)
        except (NotImplementedError, AttributeError):
            # ویندوز: fallback به signal.signal + call_soon_threadsafe
            try:
                signal.signal(sig, lambda *_: loop.call_soon_threadsafe(_stop))
            except (ValueError, OSError, RuntimeError):
                pass
    return _stop


async def main():
    print("=" * 70)
    print("  اسکنر ترون — async + curl_cffi + USDT + Cache")
    print("  ویژگی‌ها: TRX + USDT | TLS Fingerprint | Multi-API | Proxy | Cache")
    print(f"  تعداد APIها: 3 | Workerها: {NUM_WORKERS}")
    if USE_JSONRPC_BATCH:
        print("  🔀 حالت batch JSON-RPC فعال (مناسب مانیتورینگ)")
    else:
        print("  ⚡ حالت native + skip-empty فعال (مناسب اسکن)")
    print(f"  سقف اتصال همزمان: {MAX_CONCURRENT_REQUESTS}")
    if TRONGRID_API_KEY:
        print("  ✅ TronGrid API Key فعال")
    else:
        print("  ⚠ TronGrid API Key تنظیم نشده — محدودیت نرخ شدیدتر")
    print("  برای توقف: Ctrl+C")
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
        async with BalanceChecker(
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
                # منتظر بمان تا یا stop_event روشن شود یا همه‌ی taskها تمام شوند
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

    # cleanup در finally اصلی اجرا می‌شود
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