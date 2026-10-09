"""
TRON Address Scanner (Educational)
- بررسی همزمان موجودی TRX و USDT (TRC-20)
- Async I/O با curl_cffi (جعل TLS/JA3 مرورگر)
- Multi-API با fallback و health-check
- پشتیبانی از TronGrid API Key (فقط از متغیر محیطی)
- کش نتایج برای جلوگیری از درخواست تکراری (قابل خاموش کردن)
- چرخش پروکسی
- Worker Pool با asyncio
- Rate limiter Token Bucket تطبیقی (AIMD) برای هر Provider

اصلاحات نسخه‌ی جدید:
  - RateLimiter با back_off / speed_up (AIMD)
  - TronAPIProvider با mark_rate_limited جدا از mark_failure
  - 429 دیگر provider را disable نمی‌کند؛ فقط rate را کم می‌کند
  - mark_success اکنون rate را به آرامی برمی‌گرداند
  - DoH غیرفعال شد (از ایران بلاک است و proxies.txt هم IP محلی است)
  - ProxyPool فقط یک بار ساخته می‌شود
  - نرخ اولیه TronGrid از 6.0 به 2.0 کاهش یافت (IP اشتراکی تونل)

اصلاحات این نسخه:
  ۱) TRONGRID_API_KEY حالا فقط از متغیر محیطی خوانده می‌شود
     (متغیر TRONGRID_API_KEY یا فایل .env در کنار اسکریپت)
  ۲) ENABLE_CACHE به‌عنوان سوئیچ اضافه شد — برای اسکن تصادفی خاموش کنید
  ۳) بررسی کلید "error" در پاسخ‌های JSON-RPC batch و علامت‌گذاری provider
"""
import asyncio
import os
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

# بارگذاری اختیاری از فایل .env (در صورت نصب python-dotenv)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from curl_cffi.requests import AsyncSession
from tronpy.keys import PrivateKey, to_hex_address, public_key_to_addr

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

# سوئیچ کش:
#   False → برای اسکن تصادفی کلید (احتمال برخورد تقریباً صفر است)
#   True  → برای مانیتورینگ لیست ثابتی از آدرس‌ها
ENABLE_CACHE = False

# ---- کلید API فقط از متغیر محیطی خوانده می‌شود ----
#   export TRONGRID_API_KEY="your-key-here"
# یا یک فایل .env در کنار اسکریپت با محتوای زیر:
#   TRONGRID_API_KEY=your-key-here
# از https://www.trongrid.io/ بگیرید.
TRONGRID_API_KEY = os.environ.get("TRONGRID_API_KEY", "").strip()

USDT_CONTRACT = "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t"
USDT_DECIMALS = 6

# eth_getBalance روی TronGrid مقدار را بر حسب SUN برمی‌گرداند.
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


# ==================== Rate Limiter (AIMD) ====================
class RateLimiter:
    """
    Token bucket با AIMD:
      - back_off() : کاهش ضربی روی 429
      - speed_up() : افزایش تدریجی روی موفقیت
    """

    def __init__(self, rate_per_sec: float, burst: int = 3,
                 min_rate: float | None = None):
        self.initial_rate = rate_per_sec
        self.rate = rate_per_sec
        self.min_rate = (
            min_rate if min_rate is not None
            else max(0.05, rate_per_sec * 0.05)
        )
        self.initial_capacity = burst
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

    async def back_off(self, label: str = ""):
        async with self.lock:
            old_rate = self.rate
            old_burst = self.capacity
            self.rate = max(self.min_rate, self.rate * 0.5)
            self.capacity = max(1, self.capacity // 2)
            self.tokens = 0.0
            if old_rate != self.rate or old_burst != self.capacity:
                tag = f"[{label}] " if label else ""
                print(
                    f"    ↳ {tag}rate {old_rate:.2f}→{self.rate:.2f} req/s, "
                    f"burst {old_burst}→{self.capacity}"
                )

    async def speed_up(self):
        async with self.lock:
            if self.rate < self.initial_rate:
                self.rate = min(self.initial_rate, self.rate * 1.05)
            if self.capacity < self.initial_capacity:
                self.capacity = min(self.initial_capacity, self.capacity + 1)


# ==================== Cache ====================
class BalanceCache:
    """
    کش LRU با TTL برای نتایج موجودی.
    از time.time() استفاده می‌شود تا بین ری‌استارت/ریبوت هم TTL معتبر بماند.

    نکته: برای اسکن تصادفی کلید، این کش تقریباً هیچ‌وقت hit نمی‌شود و
    صرفاً سربار حافظه و CPU است. با ENABLE_CACHE=False خاموش می‌شود.
    """

    def __init__(self, max_size=50_000, ttl=3600, enabled: bool = True):
        self.enabled = enabled
        self.max_size = max_size
        self.ttl = ttl
        self.store = OrderedDict()
        self.lock = asyncio.Lock()
        self.hits = 0
        self.misses = 0

    async def get(self, address: str):
        if not self.enabled:
            return None
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
        if not self.enabled:
            return
        async with self.lock:
            self.store[address] = (time.time(), result)
            self.store.move_to_end(address)
            while len(self.store) > self.max_size:
                self.store.popitem(last=False)

    async def load_from_disk(self):
        if not self.enabled:
            return
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
        if not self.enabled:
            return
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
    BASE_BACKOFF = 60.0
    MAX_BACKOFF = 900.0  # 15 min cap

    def __init__(self, name, rate=3.0):
        self.name = name
        self.rate_limiter = RateLimiter(rate_per_sec=rate, burst=3)
        self.fail_count = 0
        self.disabled_until = 0.0
        self.success_count = 0
        self.backoff = self.BASE_BACKOFF
        self.last_disable_reason = ""
        self.consecutive_rate_limits = 0

    def is_available(self) -> bool:
        return time.monotonic() >= self.disabled_until

    def mark_failure(self, reason: str = ""):
        """خطاهای واقعی: timeout، SSL error، 5xx، مسدودسازی."""
        self.fail_count += 1
        if self.fail_count >= 3:
            self.disabled_until = time.monotonic() + self.backoff
            self.last_disable_reason = reason or "unknown"
            print(
                f"⛔ [{self.name}] disabled for {self.backoff:.0f}s "
                f"(reason: {self.last_disable_reason})"
            )
            self.fail_count = 0
            self.backoff = min(self.backoff * 2, self.MAX_BACKOFF)

    def mark_rate_limited(self, reason: str = "429"):
        """429 فشار معکوس است؛ provider را زنده نگه می‌دارد."""
        self.consecutive_rate_limits += 1
        if self.consecutive_rate_limits >= 30:
            self.disabled_until = time.monotonic() + self.backoff
            self.last_disable_reason = f"persistent {reason}"
            print(
                f"⛔ [{self.name}] disabled for {self.backoff:.0f}s "
                f"(reason: persistent {reason} × {self.consecutive_rate_limits})"
            )
            self.consecutive_rate_limits = 0
            self.backoff = min(self.backoff * 2, self.MAX_BACKOFF)

    def mark_success(self):
        self.fail_count = 0
        self.success_count += 1
        self.consecutive_rate_limits = 0
        if self.backoff != self.BASE_BACKOFF:
            print(f"✅ [{self.name}] recovered — backoff reset")
            self.backoff = self.BASE_BACKOFF
            self.last_disable_reason = ""

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
    BALANCE_OF_SELECTOR = "70a08231"

    def __init__(self):
        # rate اولیه پایین — تونل اشتراکی است و TronGrid per-IP rate-limit می‌کند
        super().__init__("trongrid", rate=2.0)
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
            "active": True,
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

    @staticmethod
    def extract_batch_errors(data) -> list:
        """
        اگر پاسخ JSON-RPC شامل آیتمی با کلید "error" باشد، فهرست خطاها را برمی‌گرداند.
        ساختار خطای ممکن: {"code": -32602, "message": "..."}
        """
        errors = []
        if not isinstance(data, list):
            return errors
        for item in data:
            if not isinstance(item, dict):
                continue
            if "error" in item and item["error"]:
                errors.append(item.get("error"))
        return errors

    @classmethod
    def parse_batch(cls, data, address, provider_name):
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
        self._sem = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        self.session = AsyncSession()
        return self

    async def __aexit__(self, *exc):
        if self.session:
            await self.session.close()

    async def _request(self, provider, url, method, body):
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
            except Exception as e:
                print(f"⚠ [{provider.name}] build_requests failed: {e}")
                continue

            trx_result = None
            usdt_result = None

            for url, method, body, kind in requests_list:
                if kind == "trx" and trx_result is not None:
                    continue
                if kind == "usdt" and usdt_result is not None:
                    continue

                # بهینه‌سازی ۱: skip USDT برای اکانت‌های ناموجود
                if (kind == "usdt"
                        and trx_result is not None
                        and not trx_result.get("active")):
                    usdt_result = {"usdt_sun": 0, "usdt": 0.0}
                    continue

                try:
                    api_call_made = True
                    r = await self._request(provider, url, method, body)

                    if r.status_code == 429:
                        print(f"⚠ [{provider.name}] 429 rate-limited")
                        await provider.rate_limiter.back_off(provider.name)
                        provider.mark_rate_limited("429")
                        await asyncio.sleep(1.0)
                        break

                    if r.status_code in (401, 403, 451):
                        print(f"⚠ [{provider.name}] HTTP {r.status_code} (blocked)")
                        provider.mark_failure(f"HTTP {r.status_code}")
                        break
                    if r.status_code >= 400:
                        print(f"⚠ [{provider.name}] HTTP {r.status_code}")
                        provider.mark_failure(f"HTTP {r.status_code}")
                        break

                    try:
                        data = r.json()
                    except Exception as e:
                        print(f"⚠ [{provider.name}] JSON parse failed: {e}")
                        data = None

                    if kind == "batch":
                        # بررسی خطاهای JSON-RPC قبل از پارس نتیجه
                        errors = TronGridProvider.extract_batch_errors(data)
                        if errors:
                            first = errors[0]
                            # اگر دیکشنری باشد، فقط پیام را نمایش بده
                            if isinstance(first, dict):
                                msg = first.get("message", str(first))
                                code = first.get("code", "?")
                                print(
                                    f"⚠ [{provider.name}] JSON-RPC error "
                                    f"(code={code}): {msg}"
                                )
                            else:
                                print(f"⚠ [{provider.name}] JSON-RPC error: {first}")
                            provider.mark_failure("jsonrpc-error")
                            break

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

                except Exception as e:
                    print(
                        f"⚠ [{provider.name}] request error: "
                        f"{type(e).__name__}: {e}"
                    )
                    provider.mark_failure(type(e).__name__)
                    break

            # اگر TRX داریم ولی USDT نداریم، از provider بعدی USDT بگیر
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
                await provider.rate_limiter.speed_up()
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
        self.last_all_down_warn = 0.0

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
        f.write(f"کش فعال:           {'بله' if cache.enabled else 'خیر'}\n")
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
        # اگر همه‌ی providerها disabled هستند، نچرخ — منتظر بازیابی بمان.
        if not any(p.is_available() for p in checker.providers):
            async with print_lock:
                now = time.monotonic()
                if now - stats.last_all_down_warn >= 30.0:
                    stats.last_all_down_warn = now
                    reasons = ", ".join(
                        f"{p.name}→{p.last_disable_reason or '?'}"
                        for p in checker.providers
                    )
                    print(f"⏸ همه‌ی APIها غیرفعال — 5s صبر. دلایل: {reasons}")
            await asyncio.sleep(5.0)
            continue

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
                cache_label = f"{hit_rate:.0f}%" if checker.cache.enabled else "off"
                print(
                    f"📊 کلید #{n} | "
                    f"{stats.total_requests} req | "
                    f"{elapsed:.1f}s | {rate:.2f} req/s | "
                    f"API فعال: {active}/{len(checker.providers)} | "
                    f"کش: {cache_label}"
                )

        info, api_call_made = await checker.check(address)

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
    def _stop():
        if not stop_event.is_set():
            print("\n⏹ درخواست توقف دریافت شد...")
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
    print("  اسکنر ترون — async + curl_cffi + USDT + Cache")
    print("  ویژگی‌ها: TRX + USDT | TLS Fingerprint | Multi-API | Proxy | Cache")
    print(f"  تعداد APIها: 3 | Workerها: {NUM_WORKERS}")
    if USE_JSONRPC_BATCH:
        print("  🔀 حالت batch JSON-RPC فعال (مناسب مانیتورینگ)")
    else:
        print("  ⚡ حالت native + skip-empty فعال (مناسب اسکن)")
    print(f"  سقف اتصال همزمان: {MAX_CONCURRENT_REQUESTS}")
    print(f"  کش: {'فعال' if ENABLE_CACHE else 'غیرفعال'}")
    if TRONGRID_API_KEY:
        print(f"  ✅ TronGrid API Key فعال (طول={len(TRONGRID_API_KEY)})")
    else:
        print("  ⚠ TronGrid API Key تنظیم نشده — محدودیت نرخ شدیدتر")
        print("     برای تنظیم: export TRONGRID_API_KEY=\"your-key-here\"")
    print("  برای توقف: Ctrl+C")
    print("=" * 70)

    # DoH غیرفعال — از ایران بلاک است و proxies.txt هم IP محلی است.
    providers = build_providers()
    proxy_pool = ProxyPool(PROXY_FILE)
    ua_mgr = UAManager(UA_FILE)
    cache = BalanceCache(
        max_size=CACHE_MAX_SIZE,
        ttl=CACHE_TTL,
        enabled=ENABLE_CACHE,
    )
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
    print(f"\n📁 آمار در {STATS_FILE} ذخیره شد.")
    print(f"⏱  زمان کل: {stats.elapsed:.1f}s | کلیدها: {stats.total_keys}")
    if cache.enabled:
        print(f"📦 کش: {cache.hits} hit / {cache.misses} miss")
    else:
        print("📦 کش: غیرفعال بود")
    print("👋 پایان.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass