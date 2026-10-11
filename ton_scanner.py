"""
TON Address Scanner (Educational)
- بررسی همزمان موجودی TON و USDT (Jetton)
- Async I/O با curl_cffi (جعل TLS/JA3 مرورگر)
- Multi-API با fallback و health-check
- پشتیبانی از TON Center API Key (فقط از متغیر محیطی)
- کش نتایج (قابل خاموش کردن)
- چرخش پروکسی
- Worker Pool با asyncio
- Rate limiter Token Bucket تطبیقی (AIMD) برای هر Provider

⚠️ هشدار: استفاده از این اسکریپت برای یافتن و برداشت دارایی
   کیف پول‌های دیگران در بسیاری از کشورها جرم است.
   این کد صرفاً برای یادگیری مفاهیم شبکه‌ای/امنیتی ارائه شده.

اصلاحات این نسخه (تاریخچه):
  [1] rename کلاس tonapi.io به TonAPIIOProvider (رفع NameError)
  [2] "tvm.Slice" جای "slice" در runGetMethod (رفع 422)
  [3] base64 استاندارد به‌جای URL-safe (رفع 422)
  [4] پاسخ runGetMethod در stack[0][1] یک dict است نه str
  [5] read_msg_addr به‌جای load_address (tonsdk API صحیح)
  [6] پارس عدد hex (0x...) در stack (رفع ValueError)
  [7] مدیریت HTTP 422 بدون disable کردن provider
  [8] حذف TonKeeperProvider (endpoint 404)
  [9] _parse_ton_balance_from_rest حالا is_deployed برمی‌گرداند
  [10] skip کردن Jetton check وقتی قرارداد دیپلوی نشده (رفع 429 و USDT کاذب)
  [11] _parse_jetton_balance_from_stack حالا exit_code و ok را چک می‌کند
  [12] worker شرط سخت‌گیرانه‌تر برای "پیدا شدن" اعمال می‌کند
"""
import asyncio
import os
import sys
import time
import signal
import secrets
import random
import json
import base64
from datetime import datetime
from pathlib import Path
from itertools import cycle
from collections import OrderedDict

# بارگذاری اختیاری از فایل .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from curl_cffi.requests import AsyncSession

# tonsdk
from tonsdk.crypto import mnemonic_new
from tonsdk.contract.wallet import Wallets, WalletVersionEnum
from tonsdk.utils import Address


# ==================== تنظیمات ====================
NUM_WORKERS = 4
REQUEST_TIMEOUT = 20

USE_JSONRPC_BATCH = False

MAX_CONCURRENT_REQUESTS = 16

ENABLE_CACHE = False

# ---- کلید TON Center فقط از متغیر محیطی ----
#   export TONCENTER_API_KEY="your-key-here"
# یا فایل .env کنار اسکریپت
TONCENTER_API_KEY = os.environ.get("TONCENTER_API_KEY", "").strip()

# USDT Jetton Master روی TON Mainnet
USDT_JETTON_MASTER = "EQCxE6mUtQJKFnGfaROTKOt1lZbDiiX1kCixRv7Nw2Id_sDs"
USDT_DECIMALS = 6

NANO_PER_TON = 10 ** 9

FOUND_FILE = Path("found_ton_wallets.txt")
STATS_FILE = Path("scan_ton_stats.txt")
CACHE_FILE = Path("ton_cache.json")
PROXY_FILE = Path("proxies.txt")
UA_FILE = Path("user_agents.txt")

CACHE_MAX_SIZE = 50_000
CACHE_TTL = 3600

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
    """
    Token bucket با AIMD:
      - back_off() : کاهش ضربی روی 429
      - speed_up() : افزایش تدریجی روی موفقیت
    """

    def __init__(self, rate_per_sec: float, burst: int = 2,
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
    برای اسکن تصادفی کلید، تقریباً هیچ‌وقت hit نمی‌شود.
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
                    if entry[1].get("total_nano", 0) > 0
                    or entry[1].get("usdt_raw", 0) > 0
                }
            with open(CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False)
            print(f"💾 {len(data)} آدرس دارای موجودی در کش ذخیره شد.")
        except Exception as e:
            print(f"⚠ خطا در ذخیره کش: {e}")


# ==================== Helpers ====================
def _address_to_slice(address: str) -> str | None:
    """
    تبدیل آدرس TON به base64 استاندارد BoC برای stack در runGetMethod.
    """
    try:
        addr = Address(address)
        from tonsdk.boc import begin_cell
        cell = begin_cell().store_address(addr).end_cell()
        boc_bytes = cell.to_boc(False)
        return base64.b64encode(boc_bytes).decode("ascii")
    except Exception as e:
        print(f"⚠ _address_to_slice failed for {address!r}: {e}")
        return None


def _safe_int_from_stack_value(value) -> int:
    """
    TON Center اعداد را هم به‌صورت decimal و هم hex برمی‌گرداند.
    """
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        v = value.strip()
        try:
            if v.startswith(("0x", "0X")):
                return int(v, 16)
            if v.startswith(("-0x", "-0X")):
                return -int(v[1:], 16)
            return int(v, 10)
        except ValueError:
            return 0
    return 0


def _parse_ton_balance_from_rest(data) -> dict | None:
    """
    [پچ ۱] استخراج balance + وضعیت deployment از getAddressInformation.

    خروجی: {"balance_sun": int, "is_deployed": bool} یا None

    is_deployed بر اساس وجود code و data در پاسخ تعیین می‌شود.
    اگر هر دو خالی باشند، یعنی قرارداد کیف پول هنوز دیپلوی نشده
    و بنابراین حتی یک Jetton Wallet هم برای آن وجود ندارد.
    """
    if not isinstance(data, dict):
        return None
    result = data.get("result")
    if not isinstance(result, dict):
        return None
    try:
        balance_sun = int(result.get("balance", 0) or 0)
    except Exception:
        balance_sun = 0

    code = result.get("code", "") or ""
    data_field = result.get("data", "") or ""
    is_deployed = bool(code.strip()) and bool(data_field.strip())

    return {
        "balance_sun": balance_sun,
        "is_deployed": is_deployed,
    }


def _parse_jetton_wallet_address_from_stack(data) -> str | None:
    """
    استخراج آدرس Jetton Wallet از stack پاسخ runGetMethod.

    فرمت پاسخ TON Center v2:
        {"result": {"stack": [["cell", {"bytes": "te6cc..."}]]}}
    """
    if not isinstance(data, dict):
        return None
    if not data.get("ok"):
        return None
    result = data.get("result")
    if not isinstance(result, dict):
        return None

    exit_code = result.get("exit_code", 0)
    if exit_code != 0:
        return None

    stack = result.get("stack")
    if not isinstance(stack, list) or not stack:
        return None
    first = stack[0]
    if not isinstance(first, list) or len(first) < 2:
        return None

    value = first[1]
    b64_str = None
    if isinstance(value, dict):
        b64_str = value.get("bytes")
    elif isinstance(value, str):
        b64_str = value

    if not b64_str:
        return None

    try:
        from tonsdk.boc import Cell
        cell = Cell.one_from_boc(base64.b64decode(b64_str))
        return cell.begin_parse().read_msg_addr().to_string(True, True, True)
    except Exception as e:
        print(f"⚠ jetton wallet address parse failed: {e}")
        return None


def _parse_jetton_balance_from_stack(data) -> int | None:
    """
    [پچ ۴] استخراج balance از پاسخ get_wallet_data.

    چک‌های امنیتی:
      - ok باید true باشد (نه 429/500)
      - exit_code باید صفر باشد (وگرنه متد اجرا نشده)
    """
    if not isinstance(data, dict):
        return None
    if not data.get("ok"):
        return None
    result = data.get("result")
    if not isinstance(result, dict):
        return None

    exit_code = result.get("exit_code", 0)
    if exit_code != 0:
        return None

    stack = result.get("stack")
    if not isinstance(stack, list) or not stack:
        return None
    first = stack[0]
    if isinstance(first, list) and len(first) >= 2:
        return _safe_int_from_stack_value(first[1])
    return None


def parse_tonapi_response(data, address, provider_name):
    """پاسخ TONAPI.io"""
    if not isinstance(data, dict):
        return None, None
    try:
        nano = int(data.get("balance", 0) or 0)
    except Exception:
        nano = 0
    ton_result = {
        "address": address,
        "total_nano": nano,
        "total_ton": nano / NANO_PER_TON,
        "tx_count": 0,
        "provider": provider_name,
        "active": nano > 0,
        # TONAPI آدرس را فعال حساب می‌کند اگر تراکنش داشته باشد
        "is_deployed": data.get("status") == "active" or nano > 0,
    }
    usdt_raw = 0
    jettons = data.get("jettons", []) or []
    for j in jettons:
        jetton_info = j.get("jetton", {}) if isinstance(j, dict) else {}
        if jetton_info.get("address") == USDT_JETTON_MASTER:
            try:
                usdt_raw = int(j.get("balance", 0) or 0)
            except Exception:
                pass
            break
    usdt_result = {
        "usdt_raw": usdt_raw,
        "usdt": usdt_raw / (10 ** USDT_DECIMALS),
    }
    return ton_result, usdt_result


# ==================== Provider Base ====================
class BaseTonProvider:
    BASE_BACKOFF = 60.0
    MAX_BACKOFF = 900.0

    def __init__(self, name, rate=1.0):
        self.name = name
        self.rate_limiter = RateLimiter(rate_per_sec=rate, burst=2)
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


# ---- Provider 1: TON Center ----
class TonCenterProvider(BaseTonProvider):
    """
    TON Center API v2 — پل HTTP روی ADNL.
    بدون کلید: 1 req/s
    با کلید رایگان: 10 req/s
    """

    def __init__(self):
        rate = 8.0 if TONCENTER_API_KEY else 0.8
        super().__init__("toncenter", rate=rate)
        self.base_url = "https://toncenter.com/api/v2"
        self.jsonrpc_url = f"{self.base_url}/jsonRPC"
        self.use_batch = USE_JSONRPC_BATCH
        self._extra_headers = {"Content-Type": "application/json"}
        if TONCENTER_API_KEY:
            self._extra_headers["X-API-Key"] = TONCENTER_API_KEY

    def headers(self):
        return self._extra_headers

    def build_requests(self, address):
        if self.use_batch:
            return self._build_batch(address)
        return self._build_rest(address)

    def _build_rest(self, address):
        b64 = _address_to_slice(address)
        if b64 is None:
            return []
        return [
            (
                f"{self.base_url}/getAddressInformation?address={address}",
                "GET", None, "ton",
            ),
            (
                f"{self.base_url}/runGetMethod",
                "POST",
                {
                    "address": USDT_JETTON_MASTER,
                    "method": "get_wallet_address",
                    "stack": [["tvm.Slice", b64]],
                },
                "jetton_addr",
            ),
        ]

    def _build_batch(self, address):
        b64 = _address_to_slice(address)
        if b64 is None:
            return []
        return [
            (
                self.jsonrpc_url,
                "POST",
                [
                    {
                        "jsonrpc": "2.0", "id": 1,
                        "method": "getAddressInformation",
                        "params": {"address": address},
                    },
                    {
                        "jsonrpc": "2.0", "id": 2,
                        "method": "runGetMethod",
                        "params": {
                            "address": USDT_JETTON_MASTER,
                            "method": "get_wallet_address",
                            "stack": [["tvm.Slice", b64]],
                        },
                    },
                ],
                "batch",
            )
        ]


# ---- Provider 2: TONAPI (tonapi.io) ----
class TonAPIIOProvider(BaseTonProvider):
    """
    TONAPI.io — REST API جایگزین.
    موجودی TON و Jetton را در یک درخواست برمی‌گرداند.
    """

    def __init__(self):
        rate = 2.0 if TONCENTER_API_KEY else 1.0
        super().__init__("tonapiio", rate=rate)
        self.base_url = "https://tonapi.io/v2"
        self._extra_headers = {"Accept": "application/json"}

    def headers(self):
        return self._extra_headers

    def build_requests(self, address):
        return [
            (f"{self.base_url}/accounts/{address}", "GET", None, "both"),
        ]


# ---- [پچ ۸] TonKeeperProvider حذف شد (endpoint 404 می‌داد) ----


def build_providers():
    return [
        TonCenterProvider(),
        TonAPIIOProvider(),
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
    "https://tonviewer.com/",
    "https://tonscan.org/",
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://ton.org/",
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
        "Origin": "https://tonviewer.com",
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
        بررسی موجودی TON و USDT (Jetton).
        خروجی: (result | None, api_call_made: bool)

        [پچ ۲ و ۳] منطق جدید:
          - اگر قرارداد دیپلوی نشده (code/data خالی)، حتی یک درخواست
            Jetton فرستاده نمی‌شود → جلوگیری از 429 و USDT کاذب.
          - فیلد is_deployed در ton_result برگردانده می‌شود.
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

            ton_result = None
            usdt_result = None

            for url, method, body, kind in requests_list:
                if kind == "ton" and ton_result is not None:
                    continue
                if kind == "usdt" and usdt_result is not None:
                    continue

                # [پچ ۳] اگر قرارداد دیپلوی نشده، Jetton را کلاً skip کن
                if (kind == "jetton_addr"
                        and ton_result is not None
                        and not ton_result.get("is_deployed", False)):
                    usdt_result = {"usdt_raw": 0, "usdt": 0.0}
                    continue

                # skip USDT برای اکانت‌های غیرفعال
                if (kind == "usdt"
                        and ton_result is not None
                        and not ton_result.get("active")):
                    usdt_result = {"usdt_raw": 0, "usdt": 0.0}
                    continue

                try:
                    api_call_made = True
                    r = await self._request(provider, url, method, body)

                    # ---- 429 ----
                    if r.status_code == 429:
                        print(f"⚠ [{provider.name}] 429 rate-limited")
                        await provider.rate_limiter.back_off(provider.name)
                        provider.mark_rate_limited("429")
                        await asyncio.sleep(2.0)
                        break

                    # ---- 422 ----
                    if r.status_code == 422:
                        try:
                            body_preview = r.text[:300]
                        except Exception:
                            body_preview = "<no body>"
                        print(
                            f"⚠ [{provider.name}] HTTP 422 (bad request) "
                            f"| {body_preview}"
                        )
                        break

                    # ---- 401/403/451 ----
                    if r.status_code in (401, 403, 451):
                        print(f"⚠ [{provider.name}] HTTP {r.status_code} (blocked)")
                        provider.mark_failure(f"HTTP {r.status_code}")
                        break

                    # ---- سایر 4xx/5xx ----
                    if r.status_code >= 400:
                        print(f"⚠ [{provider.name}] HTTP {r.status_code}")
                        provider.mark_failure(f"HTTP {r.status_code}")
                        break

                    try:
                        data = r.json()
                    except Exception as e:
                        print(f"⚠ [{provider.name}] JSON parse failed: {e}")
                        data = None

                    # --- TONAPI ---
                    if isinstance(provider, TonAPIIOProvider):
                        if kind == "both":
                            t_r, u_r = parse_tonapi_response(
                                data, address, provider.name
                            )
                            if t_r is not None:
                                ton_result = t_r
                            if u_r is not None:
                                usdt_result = u_r
                        continue

                    # --- TON Center REST ---
                    if isinstance(provider, TonCenterProvider):
                        if kind == "ton":
                            # [پچ ۲] استفاده از dict + is_deployed
                            parsed = _parse_ton_balance_from_rest(data)
                            if parsed is not None:
                                nano = parsed["balance_sun"]
                                is_deployed = parsed["is_deployed"]
                                ton_result = {
                                    "address": address,
                                    "total_nano": nano,
                                    "total_ton": nano / NANO_PER_TON,
                                    "tx_count": 0,
                                    "provider": provider.name,
                                    "active": nano > 0 or is_deployed,
                                    "is_deployed": is_deployed,
                                }
                        elif kind == "jetton_addr":
                            jw_addr = _parse_jetton_wallet_address_from_stack(data)
                            if jw_addr:
                                try:
                                    api_call_made = True
                                    jw_url = f"{provider.base_url}/runGetMethod"
                                    jw_body = {
                                        "address": jw_addr,
                                        "method": "get_wallet_data",
                                        "stack": [],
                                    }
                                    r2 = await self._request(
                                        provider, jw_url, "POST", jw_body
                                    )
                                    if r2.status_code == 200:
                                        try:
                                            d2 = r2.json()
                                        except Exception:
                                            d2 = None
                                        raw = _parse_jetton_balance_from_stack(d2)
                                        if raw is not None:
                                            usdt_result = {
                                                "usdt_raw": raw,
                                                "usdt": raw / (10 ** USDT_DECIMALS),
                                            }
                                except Exception as e:
                                    print(
                                        f"⚠ [{provider.name}] jetton balance "
                                        f"failed: {e}"
                                    )
                        continue

                except Exception as e:
                    print(
                        f"⚠ [{provider.name}] request error: "
                        f"{type(e).__name__}: {e}"
                    )
                    provider.mark_failure(type(e).__name__)
                    break

            # اگر TON داریم ولی USDT نداریم، از provider بعدی USDT بگیر
            # (فقط اگر قرارداد دیپلوی شده باشد)
            if (ton_result is not None
                    and usdt_result is None
                    and ton_result.get("is_deployed", False)):
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
                                    if kind == "both":
                                        _, usdt_result = parse_tonapi_response(
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

            if ton_result is not None:
                provider.mark_success()
                await provider.rate_limiter.speed_up()
                final = {
                    **ton_result,
                    "usdt_raw": (usdt_result or {}).get("usdt_raw", 0),
                    "usdt": (usdt_result or {}).get("usdt", 0.0),
                }
                await self.cache.set(address, final)
                return final, True

        return None, api_call_made


# ==================== Key Utils ====================
def generate_ton_wallet() -> tuple[bytes, str, str] | None:
    """
    تولید یک کیف پول TON جدید.
    خروجی: (private_key_bytes, address_friendly, mnemonic_str)
    """
    try:
        mnemonics = mnemonic_new()
        version = WalletVersionEnum.v4r2
        _mnemonics, _pub_k, _priv_k, wallet = Wallets.from_mnemonics(
            mnemonics, version, 0
        )
        address = wallet.address.to_string(True, True, True)
        return _priv_k, address, " ".join(mnemonics)
    except Exception as e:
        print(f"⚠ خطا در تولید کیف پول: {e}")
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


def save_found(private_key_hex, address, mnemonic, balance):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        f"[{ts}] کیف پول TON با موجودی پیدا شد!",
        f"Private Key (HEX): {private_key_hex}",
        f"Mnemonic:         {mnemonic}",
        f"Address (Friendly): {address}",
        f"موجودی TON:        {balance['total_ton']:.9f} TON",
        f"موجودی USDT:       {balance.get('usdt', 0.0):.6f} USDT",
        f"Deployed:          {balance.get('is_deployed', False)}",
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

        result = generate_ton_wallet()
        if not result:
            continue

        pk_bytes, address, mnemonic = result
        pk_hex = pk_bytes.hex()

        n = await stats.incr_keys()

        if n % 50 == 0:
            async with print_lock:
                elapsed = stats.elapsed
                rate = stats.total_requests / elapsed if elapsed > 0 else 0
                active = sum(1 for p in checker.providers if p.is_available())
                cache_total = checker.cache.hits + checker.cache.misses
                hit_rate = (
                    checker.cache.hits / cache_total * 100
                ) if cache_total > 0 else 0
                cache_label = (
                    f"{hit_rate:.0f}%" if checker.cache.enabled else "off"
                )
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

        # ═══════════════════════════════════════════════════════════════
        # [پچ ۵] شرط سخت‌گیرانه‌تر برای "پیدا شدن"
        # ═══════════════════════════════════════════════════════════════
        has_ton = info.get("total_nano", 0) > 0
        has_usdt = info.get("usdt_raw", 0) > 0
        is_deployed = info.get("is_deployed", False)

        # هیچ‌کدام → skip
        if not (has_ton or has_usdt):
            continue

        # شک: دیپلوی نشده ولی USDT مثبت است → احتمالاً کاذب
        if not is_deployed and has_usdt and not has_ton:
            async with print_lock:
                print(
                    f"⚠ مشکوک: دیپلوی نشده ولی USDT={info.get('usdt')} "
                    f"| addr={address} — skip"
                )
            continue

        # فقط الان واقعاً "پیدا شده"
        async with print_lock:
            save_found(pk_hex, address, mnemonic, info)
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
    print("  اسکنر TON — async + curl_cffi + USDT Jetton + Cache")
    print("  ویژگی‌ها: TON + USDT (Jetton) | TLS Fingerprint | Multi-API | Proxy")
    print(f"  تعداد Providerها: {len(build_providers())} | Workerها: {NUM_WORKERS}")
    if USE_JSONRPC_BATCH:
        print("  🔀 حالت batch JSON-RPC فعال")
    else:
        print("  ⚡ حالت REST + skip-empty فعال")
    print(f"  سقف اتصال همزمان: {MAX_CONCURRENT_REQUESTS}")
    print(f"  کش: {'فعال' if ENABLE_CACHE else 'غیرفعال'}")
    if TONCENTER_API_KEY:
        print(f"  ✅ TON Center API Key فعال (طول={len(TONCENTER_API_KEY)})")
        print(f"     محدودیت نرخ: ~10 req/s")
    else:
        print("  ⚠ TON Center API Key تنظیم نشده — محدودیت نرخ شدید (1 req/s)")
        print("     برای دریافت کلید رایگان: @toncenter در تلگرام")
        print("     سپس: export TONCENTER_API_KEY=\"your-key-here\"")
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