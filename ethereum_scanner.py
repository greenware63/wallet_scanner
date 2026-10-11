"""
Ethereum Address Scanner (Educational)
- بررسی همزمان موجودی ETH و USDT (ERC-20)
- Async I/O با curl_cffi (جعل TLS/JA3 مرورگر)
- Multi-API با fallback و health-check
- پشتیبانی از Etherscan API Key (فقط از متغیر محیطی)
- کش نتایج (قابل خاموش کردن)
- چرخش پروکسی
- Worker Pool با asyncio
- Rate limiter Token Bucket تطبیقی (AIMD) برای هر Provider

⚠️ هشدار: استفاده از این اسکریپت برای یافتن و برداشت دارایی
   کیف پول‌های دیگران در بسیاری از کشورها جرم است.
   این کد صرفاً برای یادگیری مفاهیم شبکه‌ای/امنیتی ارائه شده.
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

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from curl_cffi.requests import AsyncSession
from eth_account import Account


# ==================== تنظیمات ====================
NUM_WORKERS = 6
REQUEST_TIMEOUT = 15
MAX_RETRIES_PER_PROVIDER = 2

# True → یک درخواست batch دو متدی per address (eth_getBalance + eth_call)
# False → دو درخواست جدا با امکان skip-empty (بهینه برای اسکن)
USE_JSONRPC_BATCH = False

MAX_CONCURRENT_REQUESTS = 32

# برای اسکن تصادفی کلید، تقریباً هیچ‌وقت cache hit نمی‌شود.
ENABLE_CACHE = False

# ---- کلید Etherscan فقط از متغیر محیطی ----
#   export ETHERSCAN_API_KEY="your-key-here"
# یا فایل .env کنار اسکریپت:
#   ETHERSCAN_API_KEY=your-key-here
# از https://etherscan.io/myapikey بگیرید (رایگان).
ETHERSCAN_API_KEY = os.environ.get("ETHERSCAN_API_KEY", "").strip()

# USDT ERC-20 روی Ethereum Mainnet
USDT_CONTRACT = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
USDT_DECIMALS = 6

# eth_getBalance مقدار را بر حسب wei برمی‌گرداند.
WEI_PER_ETH = 10 ** 18

# selector برای balanceOf(address)
BALANCE_OF_SELECTOR = "70a08231"

FOUND_FILE = Path("found_eth_wallets.txt")
STATS_FILE = Path("scan_eth_stats.txt")
CACHE_FILE = Path("eth_cache.json")
PROXY_FILE = Path("proxies.txt")
UA_FILE = Path("user_agents.txt")

CACHE_MAX_SIZE = 50_000
CACHE_TTL = 3600

# secp256k1 curve order (همان secp256k1 ترون و بیت‌کوین)
CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

IMPERSONATE_TARGETS = [
    "chrome124", "chrome123", "chrome120",
    "chrome116", "chrome110",
    "edge101", "safari17_0", "safari15_5",
]

if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ==================== Rate Limiter (AIMD) ====================
class RateLimiter:
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
        if not self.enabled or not CACHE_FILE.exists():
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
                    if entry[1].get("total_wei", 0) > 0
                    or entry[1].get("usdt_raw", 0) > 0
                }
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            print(f"💾 {len(data)} آدرس دارای موجودی در کش ذخیره شد.")
        except Exception as e:
            print(f"⚠ خطا در ذخیره کش: {e}")


# ==================== Provider ====================
class EthAPIProvider:
    BASE_BACKOFF = 60.0
    MAX_BACKOFF = 900.0

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


# ---- Provider 1: PublicNode (JSON-RPC، بدون کلید) ----
class PublicNodeProvider(EthAPIProvider):
    def __init__(self):
        super().__init__("publicnode", rate=4.0)
        self.url = "https://ethereum-rpc.publicnode.com"
        self._headers = {"Content-Type": "application/json"}

    def headers(self):
        return self._headers

    def build_requests(self, address):
        if USE_JSONRPC_BATCH:
            return [(self.url, "POST", self._batch_body(address), "batch")]
        return [
            (self.url, "POST", self._balance_body(address), "eth"),
            (self.url, "POST", self._usdt_body(address), "usdt"),
        ]

    @staticmethod
    def _balance_body(address):
        return {
            "jsonrpc": "2.0", "id": 1,
            "method": "eth_getBalance",
            "params": [address, "latest"],
        }

    @staticmethod
    def _usdt_body(address):
        return {
            "jsonrpc": "2.0", "id": 2,
            "method": "eth_call",
            "params": [
                {"to": USDT_CONTRACT, "data": _usdt_call_data(address)},
                "latest",
            ],
        }

    def _batch_body(self, address):
        return [self._balance_body(address), self._usdt_body(address)]


# ---- Provider 2: LlamaRPC ----
class LlamaRPCProvider(PublicNodeProvider):
    def __init__(self):
        super().__init__()
        self.name = "llamarpc"
        self.url = "https://eth.llamarpc.com"


# ---- Provider 3: 1RPC ----
class OneRPCProvider(PublicNodeProvider):
    def __init__(self):
        super().__init__()
        self.name = "1rpc"
        self.url = "https://1rpc.io/eth"


# ---- Provider 4: Ankr (ممکن است rate-limit کند) ----
class AnkrProvider(PublicNodeProvider):
    def __init__(self):
        super().__init__()
        self.name = "ankr"
        self.url = "https://rpc.ankr.com/eth"


# ---- Provider 5: Etherscan V2 (نیاز به API Key) ----
class EtherscanProvider(EthAPIProvider):
    def __init__(self):
        # Etherscan رایگان 5 req/s می‌دهد
        super().__init__("etherscan", rate=4.0)
        self.base = "https://api.etherscan.io/v2/api"
        self._headers = {}

    def headers(self):
        return self._headers

    def is_available(self) -> bool:
        # اگر کلید نداریم، این provider هیچ‌وقت در دسترس نیست
        if not ETHERSCAN_API_KEY:
            return False
        return super().is_available()

    def build_requests(self, address):
        if not ETHERSCAN_API_KEY:
            return []
        eth_url = (
            f"{self.base}?chainid=1&module=account&action=balance"
            f"&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
        )
        usdt_url = (
            f"{self.base}?chainid=1&module=account&action=tokenbalance"
            f"&contractaddress={USDT_CONTRACT}&address={address}"
            f"&tag=latest&apikey={ETHERSCAN_API_KEY}"
        )
        return [
            (eth_url, "GET", None, "eth"),
            (usdt_url, "GET", None, "usdt"),
        ]


# ---- helper: USDT ERC-20 call data ----
def _usdt_call_data(address: str) -> str:
    """0x70a08231 + address (left-padded to 64 hex chars)"""
    addr_hex = address.lower().replace("0x", "")
    return "0x" + BALANCE_OF_SELECTOR + addr_hex.rjust(64, "0")


# ---- helpers: parse JSON-RPC hex ----
def _hex_to_int(value):
    if value is None:
        return None
    try:
        if isinstance(value, str):
            if value == "0x" or value == "":
                return 0
            return int(value, 16)
        return int(value)
    except Exception:
        return None


def parse_eth_balance_rpc(data, address, provider_name):
    """پاسخ eth_getBalance"""
    if not isinstance(data, dict):
        return None
    if "error" in data and data["error"]:
        return None
    result = data.get("result")
    wei = _hex_to_int(result)
    if wei is None:
        return None
    return {
        "address": address,
        "total_wei": wei,
        "total_eth": wei / WEI_PER_ETH,
        "tx_count": 0,       # eth_getBalance تعداد tx را نمی‌دهد
        "provider": provider_name,
        "active": wei > 0,
    }


def parse_usdt_rpc(data, address, provider_name):
    if not isinstance(data, dict):
        return {"usdt_raw": 0, "usdt": 0.0}
    if "error" in data and data["error"]:
        return {"usdt_raw": 0, "usdt": 0.0}
    raw = _hex_to_int(data.get("result"))
    if raw is None:
        return {"usdt_raw": 0, "usdt": 0.0}
    return {"usdt_raw": raw, "usdt": raw / (10 ** USDT_DECIMALS)}


def extract_batch_errors(data) -> list:
    errors = []
    if not isinstance(data, list):
        return errors
    for item in data:
        if isinstance(item, dict) and item.get("error"):
            errors.append(item["error"])
    return errors


def parse_batch(data, address, provider_name):
    if not isinstance(data, list):
        return None, None
    eth_result = None
    usdt_result = None
    for item in data:
        if not isinstance(item, dict):
            continue
        rid = item.get("id")
        if rid == 1:
            eth_result = parse_eth_balance_rpc(item, address, provider_name)
        elif rid == 2:
            usdt_result = parse_usdt_rpc(item, address, provider_name)
    return eth_result, usdt_result


def parse_etherscan(data, address, provider_name, kind):
    """kind: 'eth' | 'usdt'"""
    if not isinstance(data, dict):
        return None
    if data.get("status") != "1":
        # status 0 = empty / error
        if kind == "eth":
            return {
                "address": address, "total_wei": 0, "total_eth": 0.0,
                "tx_count": 0, "provider": provider_name, "active": False,
            }
        return {"usdt_raw": 0, "usdt": 0.0}
    try:
        raw = int(data.get("result", 0))
    except Exception:
        raw = 0
    if kind == "eth":
        return {
            "address": address, "total_wei": raw,
            "total_eth": raw / WEI_PER_ETH,
            "tx_count": 0, "provider": provider_name,
            "active": raw > 0,
        }
    return {"usdt_raw": raw, "usdt": raw / (10 ** USDT_DECIMALS)}


def build_providers():
    return [
        PublicNodeProvider(),
        LlamaRPCProvider(),
        OneRPCProvider(),
        AnkrProvider(),
        EtherscanProvider(),
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
    "https://etherscan.io/",
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://ethereum.org/",
    "https://metamask.io/",
]


def build_headers(ua: str, extra: dict | None = None) -> dict:
    h = {
        "User-Agent": ua,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8"]),
        "Accept-Encoding": "gzip, deflate, br",
        "Referer": random.choice(REFERERS),
        "Origin": "https://etherscan.io",
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
        بررسی موجودی ETH و USDT.
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

            if not requests_list:
                continue

            eth_result = None
            usdt_result = None

            for url, method, body, kind in requests_list:
                if kind == "eth" and eth_result is not None:
                    continue
                if kind == "usdt" and usdt_result is not None:
                    continue

                # skip USDT برای اکانت‌های خالی (فقط در حالت native)
                if (kind == "usdt"
                        and eth_result is not None
                        and not eth_result.get("active")):
                    usdt_result = {"usdt_raw": 0, "usdt": 0.0}
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

                    # --- batch JSON-RPC ---
                    if kind == "batch":
                        errors = extract_batch_errors(data)
                        if errors:
                            first = errors[0]
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
                        b_eth, b_usdt = parse_batch(data, address, provider.name)
                        if b_eth is not None:
                            eth_result = b_eth
                        if b_usdt is not None:
                            usdt_result = b_usdt
                        continue

                    # --- Etherscan (ساختار متفاوت) ---
                    if isinstance(provider, EtherscanProvider):
                        if kind == "eth":
                            eth_result = parse_etherscan(data, address, provider.name, "eth")
                        elif kind == "usdt":
                            usdt_result = parse_etherscan(data, address, provider.name, "usdt")
                        continue

                    # --- JSON-RPC نیتیو ---
                    if kind == "eth":
                        eth_result = parse_eth_balance_rpc(data, address, provider.name)
                    elif kind == "usdt":
                        usdt_result = parse_usdt_rpc(data, address, provider.name)

                except Exception as e:
                    print(
                        f"⚠ [{provider.name}] request error: "
                        f"{type(e).__name__}: {e}"
                    )
                    provider.mark_failure(type(e).__name__)
                    break

            # اگر ETH داریم ولی USDT نداریم، از provider بعدی USDT بگیر
            if eth_result is not None and usdt_result is None:
                for p2 in ordered:
                    if p2 is provider or not p2.is_available():
                        continue
                    try:
                        reqs = p2.build_requests(address)
                    except Exception:
                        continue
                    for url, method, body, kind in reqs:
                        if kind not in ("usdt", "batch"):
                            continue
                        try:
                            api_call_made = True
                            r = await self._request(p2, url, method, body)
                            if r.status_code == 200:
                                try:
                                    data = r.json()
                                    if kind == "batch":
                                        _, usdt_result = parse_batch(
                                            data, address, p2.name
                                        )
                                    elif isinstance(p2, EtherscanProvider):
                                        usdt_result = parse_etherscan(
                                            data, address, p2.name, "usdt"
                                        )
                                    else:
                                        usdt_result = parse_usdt_rpc(
                                            data, address, p2.name
                                        )
                                except Exception:
                                    pass
                        except Exception:
                            continue
                        if usdt_result is not None:
                            break
                    if usdt_result is not None:
                        break

            if eth_result is not None:
                provider.mark_success()
                await provider.rate_limiter.speed_up()
                final = {
                    **eth_result,
                    "usdt_raw": (usdt_result or {}).get("usdt_raw", 0),
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
        return Account.from_key(pk_bytes).address  # EIP-55 checksummed
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
        f"[{ts}] کیف پول اتریوم با موجودی پیدا شد!",
        f"Private Key (HEX): {private_key_hex}",
        f"Address (EIP-55):  {address}",
        f"موجودی ETH:        {balance['total_eth']:.18f} ETH",
        f"موجودی USDT:       {balance.get('usdt', 0.0):.6f} USDT",
        f"Provider:          {balance.get('provider', '?')}",
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

        has_eth = info.get("total_wei", 0) > 0
        has_usdt = info.get("usdt_raw", 0) > 0

        if has_eth or has_usdt:
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
    print("  اسکنر اتریوم — async + curl_cffi + USDT ERC-20 + Cache")
    print("  ویژگی‌ها: ETH + USDT | TLS Fingerprint | Multi-RPC | Proxy | Cache")
    print(f"  تعداد Providerها: 5 | Workerها: {NUM_WORKERS}")
    if USE_JSONRPC_BATCH:
        print("  🔀 حالت batch JSON-RPC فعال (مناسب مانیتورینگ)")
    else:
        print("  ⚡ حالت native + skip-empty فعال (مناسب اسکن)")
    print(f"  سقف اتصال همزمان: {MAX_CONCURRENT_REQUESTS}")
    print(f"  کش: {'فعال' if ENABLE_CACHE else 'غیرفعال'}")
    if ETHERSCAN_API_KEY:
        print(f"  ✅ Etherscan API Key فعال (طول={len(ETHERSCAN_API_KEY)})")
    else:
        print("  ⚠ Etherscan API Key تنظیم نشده — فقط از RPCهای عمومی استفاده می‌شود")
        print("     برای تنظیم: export ETHERSCAN_API_KEY=\"your-key-here\"")
    print("  ⚠️  توجه: این ابزار صرفاً آموزشی است. برداشت دارایی دیگران جرم است.")
    print("  برای توقف: Ctrl+C")
    print("=" * 70)

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