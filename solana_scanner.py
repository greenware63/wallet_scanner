"""
اسکنر آدرس سولانا (آموزشی)
- بررسی همزمان موجودی SOL و USDC (توکن SPL)
- ورودی/خروجی ناهمگام با curl_cffi (جعل هویت TLS/JA3 مرورگر)
- چند RPC با قابلیت fallback و بررسی سلامت
- حالت دسته‌ای JSON-RPC (یک رفت‌وبرگشت برای هر آدرس)
- کش کردن نتایج برای جلوگیری از درخواست‌های تکراری
- چرخش پروکسی
- استخر کارگرها (worker pool) با asyncio
- محدودکننده نرخ تطبیقی سطل‌توکنی (AIMD) برای هر ارائه‌دهنده
- استفاده از asyncio.Semaphore برای کنترل استخر اتصالات

اصلاحات اعمال‌شده در این نسخه:
  ۱) حذف RPC های عمومی غیرفعال/نیازمند کلید (projectserum، ankr، public-rpc.com)
  ۲) کلیدهای API به‌صورت ثابت در کد (Helius / QuickNode / Triton) — متغیرهای محیطی همچنان اولویت دارند
  ۳) ثبت کامل خطاها — دیگر خبری از `except Exception: break` بی‌صدا نیست
  ۴) متد mark_failure(reason) همراه با backoff نمایی و ثبت گزارش بازیابی
  ۵) کارگر در صورت غیرفعال بودن همه ارائه‌دهنده‌ها به خواب می‌رود (بدون مصرف بی‌مورد CPU)
  ۶) رد شدن از بررسی USDC وقتی موجودی SOL صفر است (حالت native)
  ۷) تایم‌اوت جداگانه برای هر ارائه‌دهنده — RPC عمومی سریع شکست می‌خورد (۶ ثانیه)، نسخه پولی ۱۲ ثانیه
  ۸) محدودکننده نرخ AIMD: خطای 429 نرخ را کاهش می‌دهد ولی ارائه‌دهنده را غیرفعال نمی‌کند
  ۹) متد mark_rate_limited(reason) ارائه‌دهنده را هنگام فشار برگشتی زنده نگه می‌دارد
 ۱۰) رفع اشکال تشخیص برچسب در build_providers (public-N، نه فقط public-1)
 ۱۱) کاهش نرخ شروع برای RPC عمومی (۰.۵ درخواست بر ثانیه، burst=1)
     و RPC پولی (۲.۰ درخواست بر ثانیه، burst=3) — AIMD آن‌ها را دوباره افزایش می‌دهد
 ۱۲) مقاوم‌سازی parse_usdc در برابر پاسخ base64 (فال‌بک خودکار برای فرمت باینری)
 ۱۳) یک session جداگانه به ازای هر پروکسی برای حفظ Connection Pooling و HTTP/2 multiplexing
 ۱۴) حذف کامل کلیدهای API از سورس — فقط از متغیرهای محیطی خوانده می‌شود (امنیت گیت)
"""
import asyncio
import os
import sys
import time
import signal
import random
import json
import base64
import struct
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

import base58
from curl_cffi.requests import AsyncSession
from solders.keypair import Keypair
from solders.pubkey import Pubkey

# ==================== کلیدهای API — فقط از متغیرهای محیطی ====================
# برای امنیت، هیچ کلید API در سورس کد نگه‌داری نمی‌شود. این کار خطر
# commit شدن ناخواسته کلید در گیت را از بین می‌برد.
#
# قبل از اجرا، متغیرهای محیطی را تنظیم کنید:
#
#   export HELIUS_API_KEY="your-key-here"
#   export QUICKNODE_SOLANA_URL="https://..."
#   export TRITON_RPC_URL="https://..."
#
# یا یک فایل .env در کنار اسکریپت بسازید (نیازمند python-dotenv):
#
#   echo 'HELIUS_API_KEY=your-key-here' > .env
#
# یک کلید رایگان Helius از https://dev.helius.xyz/ بگیرید
# (۳۰ ثانیه، بدون نیاز به کارت اعتباری، سطح رایگان حدود ۱۰ درخواست بر ثانیه)
HELIUS_API_KEY = os.environ.get("HELIUS_API_KEY", "").strip()
QUICKNODE_SOLANA_URL = os.environ.get("QUICKNODE_SOLANA_URL", "").strip()
TRITON_RPC_URL = os.environ.get("TRITON_RPC_URL", "").strip()

# ==================== تنظیمات ====================
NUM_WORKERS = 6
REQUEST_TIMEOUT = 12
MAX_RETRIES_PER_PROVIDER = 1  # شکست سریع (fail-fast)

# حالت دسته‌ای: یک آرایه JSON-RPC شامل هر دو متد getBalance و
# getTokenAccountsByOwner. برای سولانا به‌شدت توصیه می‌شود — RPC های
# عمومی نرخ را به‌ازای هر درخواست محدود می‌کنند و حالت دسته‌ای رفت‌وبرگشت‌ها را نصف می‌کند.
USE_BATCH_RPC = True

# سقف همزمانی برای درخواست‌های HTTP خروجی (مستقل از NUM_WORKERS)
MAX_CONCURRENT_REQUESTS = 32

# ساخت فهرست اندپوینت‌ها. فقط api.mainnet-beta.solana.com یک اندپوینت
# عمومی پایدار است؛ بقیه موارد نسخه قدیمی غیرفعال یا نیازمند کلید هستند.
SOLANA_RPC_ENDPOINTS = []
if HELIUS_API_KEY:
    SOLANA_RPC_ENDPOINTS.append(
        f"https://mainnet.helius-rpc.com/?api-key={HELIUS_API_KEY}"
    )
if QUICKNODE_SOLANA_URL:
    SOLANA_RPC_ENDPOINTS.append(QUICKNODE_SOLANA_URL)
if TRITON_RPC_URL:
    SOLANA_RPC_ENDPOINTS.append(TRITON_RPC_URL)
# fallback عمومی رسمی (محدودیت نرخ سخت‌گیرانه، حدود ۱ تا ۳ درخواست بر ثانیه به ازای هر IP)
SOLANA_RPC_ENDPOINTS.append("https://api.mainnet-beta.solana.com")

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


# ==================== محدودکننده نرخ (AIMD) ====================
class RateLimiter:
    """
    سطل‌توکنی (Token bucket) با الگوریتم AIMD:
      - back_off() : کاهش ضربی روی خطای 429
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
                    f"    ↳ {tag}نرخ {old_rate:.2f}→{self.rate:.2f} درخواست/ثانیه, "
                    f"burst {old_burst}→{self.capacity}"
                )

    async def speed_up(self):
        async with self.lock:
            if self.rate < self.initial_rate:
                self.rate = min(self.initial_rate, self.rate * 1.05)
            if self.capacity < self.initial_capacity:
                self.capacity = min(self.initial_capacity, self.capacity + 1)


# ==================== کش ====================
class BalanceCache:
    """کش LRU با TTL برای نتایج موجودی، که روی دیسک ذخیره می‌شود."""

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
            print(f"📦 تعداد {len(self.store)} آدرس از کش دیسک بارگذاری شد.")
        except Exception as e:
            print(f"⚠ خطا در بارگذاری کش: {e}")

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
            print(f"💾 تعداد {len(data)} آدرس دارای موجودی در کش دیسک ذخیره شد.")
        except Exception as e:
            print(f"⚠ خطا در ذخیره کش: {e}")


# ==================== ارائه‌دهنده (Provider) ====================
class SolanaProvider:
    BASE_BACKOFF = 60.0
    MAX_BACKOFF = 900.0  # سقف ۱۵ دقیقه

    def __init__(self, name, endpoint, rate=3.0, burst=3, timeout=None):
        self.name = name
        self.endpoint = endpoint
        self.rate_limiter = RateLimiter(rate_per_sec=rate, burst=burst)
        self.timeout = timeout if timeout is not None else REQUEST_TIMEOUT
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
                f"⛔ [{self.name}] به مدت {self.backoff:.0f} ثانیه غیرفعال شد "
                f"(دلیل: {self.last_disable_reason})"
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
                f"⛔ [{self.name}] به مدت {self.backoff:.0f} ثانیه غیرفعال شد "
                f"(دلیل: تکرار {reason} به تعداد {self.consecutive_rate_limits} بار)"
            )
            self.consecutive_rate_limits = 0
            self.backoff = min(self.backoff * 2, self.MAX_BACKOFF)

    def mark_success(self):
        self.fail_count = 0
        self.success_count += 1
        self.consecutive_rate_limits = 0
        if self.backoff != self.BASE_BACKOFF:
            print(f"✅ [{self.name}] بازیابی شد — backoff بازنشانی شد")
            self.backoff = self.BASE_BACKOFF
            self.last_disable_reason = ""

    def headers(self) -> dict:
        return {"Content-Type": "application/json"}

    # ---------- سازنده‌های درخواست ----------
    def build_requests(self, address: str):
        if USE_BATCH_RPC:
            return self._build_batch(address)
        return self._build_native(address)

    def _build_batch(self, address: str):
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

    # ---------- پارسرها ----------
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
    def _extract_raw_amount(acc) -> int:
        """
        استخراج مقدار خام توکن از یک اکانت، با پشتیبانی از jsonParsed و base64.
        در صورت خطا در هر مرحله، ۰ برمی‌گرداند تا کل batch خراب نشود.
        """
        data_field = acc.get("account", {}).get("data", None)
        if data_field is None:
            return 0

        # --- حالت اول: jsonParsed ---
        # ساختار: {"parsed": {"info": {"tokenAmount": {"amount": "..."}}}, ...}
        if isinstance(data_field, dict) and "parsed" in data_field:
            try:
                info = data_field.get("parsed", {}).get("info", {}) or {}
                token_amount = info.get("tokenAmount", {}) or {}
                # ترجیح: مقدار خام رشته‌ای
                if "amount" in token_amount:
                    return int(token_amount["amount"])
                # فال‌بک: اگر فقط uiAmountString داده شده باشد
                ui_str = token_amount.get("uiAmountString")
                if ui_str is not None:
                    scaled = float(ui_str) * (10 ** USDC_DECIMALS)
                    return int(round(scaled))
            except Exception:
                return 0
            return 0

        # --- حالت دوم: base64 خام ---
        # ساختار: ["<base64>", "base64"]  یا  ["<b64+zstd>", "base64+zstd"]
        if isinstance(data_field, list) and len(data_field) >= 2:
            try:
                encoding = data_field[1]
                if encoding != "base64":
                    # base64+zstd و سایر فرمت‌ها پشتیبانی نمی‌شوند
                    return 0
                raw_bytes = base64.b64decode(data_field[0])
                # چیدمان SPL Token Account (۱۶۵ بایت):
                #   mint       : 32 بایت (offset 0)
                #   owner      : 32 بایت (offset 32)
                #   amount     : u64 little-endian (offset 64)
                #   ...
                if len(raw_bytes) >= 72:
                    (amount,) = struct.unpack_from("<Q", raw_bytes, 64)
                    return amount
            except Exception:
                return 0
            return 0

        return 0

    @staticmethod
    def parse_usdc(result, address, provider_name):
        if result is None:
            return {"usdc_raw": 0, "usdc": 0.0}
        try:
            accounts = result.get("value", []) or []
            total_raw = 0
            for acc in accounts:
                total_raw += SolanaProvider._extract_raw_amount(acc)
            return {
                "usdc_raw": total_raw,
                "usdc": total_raw / (10 ** USDC_DECIMALS),
            }
        except Exception:
            return {"usdc_raw": 0, "usdc": 0.0}

    @classmethod
    def parse_batch(cls, data, address, provider_name):
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
    providers = []
    for i, endpoint in enumerate(SOLANA_RPC_ENDPOINTS):
        if "helius" in endpoint:
            label = "helius"
        elif "quiknode" in endpoint or "quicknode" in endpoint:
            label = "quicknode"
        elif "triton" in endpoint:
            label = "triton"
        else:
            label = f"public-{i+1}"

        # اندپوینت‌های عمومی: نرخ و burst اولیه بسیار کم، تایم‌اوت کوتاه.
        # اگر اندپوینت تحمل داشته باشد، AIMD آن‌ها را افزایش می‌دهد.
        # اندپوینت‌های پولی: نرخ اولیه متوسط — AIMD سقف را پیدا می‌کند.
        if label.startswith("public"):
            rate = 0.5
            burst = 1
            timeout = 6
        else:
            rate = 2.0
            burst = 3
            timeout = 12

        providers.append(
            SolanaProvider(
                label, endpoint,
                rate=rate, burst=burst, timeout=timeout,
            )
        )
    return providers


# ==================== استخر پروکسی ====================
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
        print(f"✅ تعداد {len(self.proxies)} پروکسی بارگذاری شد.")

    async def get(self):
        if not self.proxies:
            return None
        async with self.lock:
            p = self.proxies[self.idx % len(self.proxies)]
            self.idx += 1
        return {"http": p, "https": p}

    def __len__(self):
        return len(self.proxies)


# ==================== مدیر User-Agent ====================
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


# ==================== بررسی‌کننده موجودی ====================
class SolanaBalanceChecker:
    def __init__(self, providers, proxy_pool: ProxyPool, ua_mgr: UAManager,
                 cache: BalanceCache, max_concurrent: int = MAX_CONCURRENT_REQUESTS):
        self.providers = providers
        self.proxy_pool = proxy_pool
        self.ua_mgr = ua_mgr
        self.cache = cache
        # یک session مجزا به ازای هر پروکسی برای حفظ Connection Pooling.
        # کلید "__direct__" یعنی بدون پروکسی.
        self._sessions: dict[str, AsyncSession] = {}
        self._sessions_lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        # بستن تمام session ها
        for sess in self._sessions.values():
            try:
                await sess.close()
            except Exception:
                pass
        self._sessions.clear()

    async def _get_session(self, proxy_url: str | None) -> AsyncSession:
        """دریافت یا ساخت session مخصوص یک پروکسی مشخص."""
        key = proxy_url or "__direct__"
        async with self._sessions_lock:
            sess = self._sessions.get(key)
            if sess is None:
                if proxy_url:
                    sess = AsyncSession(
                        proxies={"http": proxy_url, "https": proxy_url}
                    )
                else:
                    sess = AsyncSession()
                self._sessions[key] = sess
            return sess

    async def _request(self, provider, url, method, body):
        async with self._sem:
            await provider.rate_limiter.acquire()
            headers = build_headers(self.ua_mgr.next(), provider.headers())

            proxy_dict = await self.proxy_pool.get()
            proxy_url = None
            if proxy_dict:
                proxy_url = proxy_dict.get("http") or proxy_dict.get("https")

            session = await self._get_session(proxy_url)
            impersonate = random.choice(IMPERSONATE_TARGETS)

            kwargs = {
                "headers": headers,
                "timeout": provider.timeout,
                "impersonate": impersonate,
            }
            if method == "POST" and body is not None:
                kwargs["json"] = body

            return await session.request(method, url, **kwargs)

    async def check(self, address: str):
        """
        بررسی موجودی SOL و USDC.
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
                print(f"⚠ [{provider.name}] ساخت درخواست (build_requests) ناموفق بود: {e}")
                continue

            sol_result = None
            usdc_result = None

            for url, method, body, kind in requests_list:
                if kind == "sol" and sol_result is not None:
                    continue
                if kind == "usdc" and usdc_result is not None:
                    continue

                # رد شدن از بررسی USDC وقتی موجودی SOL صفر است (حالت native)
                if (kind == "usdc"
                        and sol_result is not None
                        and not sol_result.get("active")):
                    usdc_result = {"usdc_raw": 0, "usdc": 0.0}
                    continue

                try:
                    api_call_made = True
                    r = await self._request(provider, url, method, body)

                    if r.status_code == 429:
                        # فشار برگشتی: نرخ را کاهش بده، ارائه‌دهنده را غیرفعال نکن.
                        print(f"⚠ [{provider.name}] محدودیت نرخ 429")
                        await provider.rate_limiter.back_off(provider.name)
                        provider.mark_rate_limited("429")
                        await asyncio.sleep(1.0)
                        break

                    if r.status_code in (401, 403, 451):
                        print(
                            f"⚠ [{provider.name}] HTTP {r.status_code} (مسدود شده)"
                        )
                        provider.mark_failure(f"HTTP {r.status_code}")
                        break
                    if r.status_code >= 400:
                        print(f"⚠ [{provider.name}] HTTP {r.status_code}")
                        provider.mark_failure(f"HTTP {r.status_code}")
                        break

                    try:
                        data = r.json()
                    except Exception as e:
                        print(f"⚠ [{provider.name}] تجزیه JSON ناموفق بود: {e}")
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

                except Exception as e:
                    print(
                        f"⚠ [{provider.name}] خطای درخواست: "
                        f"{type(e).__name__}: {e}"
                    )
                    provider.mark_failure(type(e).__name__)
                    break

            # Fallback: موجودی SOL موجود است ولی USDC نه — ارائه‌دهنده دیگری برای USDC امتحان کن
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
                await provider.rate_limiter.speed_up()
                final = {
                    **sol_result,
                    "usdc_raw": (usdc_result or {}).get("usdc_raw", 0),
                    "usdc": (usdc_result or {}).get("usdc", 0.0),
                }
                await self.cache.set(address, final)
                return final, True

        return None, api_call_made


# ==================== ابزارهای کلید ====================
def generate_keypair() -> Keypair:
    return Keypair()


def keypair_to_private_key_b58(kp: Keypair) -> str:
    return base58.b58encode(bytes(kp)).decode()


def keypair_to_address(kp: Keypair) -> str:
    return str(kp.pubkey())


# ==================== وضعیت / آمار ====================
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


def save_found(private_key_b58, address, balance):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        "=" * 70,
        f"[{ts}] کیف‌پول سولانای دارای موجودی پیدا شد!",
        f"کلید خصوصی (Base58):   {private_key_b58}",
        f"آدرس (Base58):         {address}",
        f"موجودی SOL:            {balance['sol']:.9f} SOL",
        f"موجودی USDC:           {balance.get('usdc', 0.0):.6f} USDC",
        f"ارائه‌دهنده:            {balance.get('provider', '?')}",
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


# ==================== کارگر (Worker) ====================
async def worker(
    worker_id: int,
    checker: SolanaBalanceChecker,
    stats: Stats,
    stop_event: asyncio.Event,
    print_lock: asyncio.Lock,
):
    while not stop_event.is_set():
        # اگر همه ارائه‌دهنده‌ها غیرفعال هستند، به‌جای مصرف بی‌مورد CPU بخواب.
        if not any(p.is_available() for p in checker.providers):
            async with print_lock:
                now = time.monotonic()
                if now - stats.last_all_down_warn >= 30.0:
                    stats.last_all_down_warn = now
                    reasons = ", ".join(
                        f"{p.name}→{p.last_disable_reason or '?'}"
                        for p in checker.providers
                    )
                    print(f"⏸ همه RPC ها غیرفعال هستند — ۵ ثانیه در حال خواب. دلایل: {reasons}")
            await asyncio.sleep(5.0)
            continue

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
                    f"📊 کلید #{n} | "
                    f"{stats.total_requests} درخواست | "
                    f"{elapsed:.1f} ثانیه | {rate:.2f} درخواست/ثانیه | "
                    f"RPC فعال: {active}/{len(checker.providers)} | "
                    f"کش: {hit_rate:.0f}%"
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


# ==================== تابع اصلی ====================
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
    print("  اسکنر سولانا — async + curl_cffi + USDC + کش")
    print("  امکانات: SOL + USDC | اثرانگشت TLS | چند RPC | پروکسی | کش")
    print(f"  تعداد اندپوینت‌های RPC: {len(SOLANA_RPC_ENDPOINTS)} | تعداد کارگرها: {NUM_WORKERS}")
    if USE_BATCH_RPC:
        print("  🔀 حالت دسته‌ای JSON-RPC فعال است (یک رفت‌وبرگشت برای هر آدرس)")
    else:
        print("  ⚡ حالت native فعال است (دو درخواست برای هر آدرس)")
    print(f"  حداکثر درخواست‌های همزمان: {MAX_CONCURRENT_REQUESTS}")

    if HELIUS_API_KEY:
        print(f"  ✅ کلید API هلیوس تنظیم شده است (طول={len(HELIUS_API_KEY)})")
    else:
        print("  ⚠ کلید API هلیوس تنظیم نشده است")
    if QUICKNODE_SOLANA_URL:
        print("  ✅ اندپوینت QuickNode تنظیم شده است")
    if TRITON_RPC_URL:
        print("  ✅ اندپوینت Triton تنظیم شده است")

    print("  برای توقف، کلیدهای Ctrl+C را فشار دهید")
    print("=" * 70)

    if not HELIUS_API_KEY and not QUICKNODE_SOLANA_URL and not TRITON_RPC_URL:
        print()
        print("=" * 70)
        print("  ❌  هیچ RPC پولی/رایگان تنظیم نشده است")
        print("=" * 70)
        print("  RPC عمومی سولانا (api.mainnet-beta.solana.com) اجازه می‌دهد")
        print("  کمتر از ۱ درخواست در ثانیه به ازای هر IP، و بلافاصله 429 می‌دهد.")
        print("  اسکنر اجرا خواهد شد، اما سرعت حدود ۰.۵ کلید بر ثانیه خواهد بود")
        print("  و پیام‌های هشدار 429 را به‌طور مداوم خواهید دید.")
        print()
        print("  برای رفع این مشکل، یک کلید API رایگان Helius بگیرید (۳۰ ثانیه، بدون کارت):")
        print("    1. به آدرس  https://dev.helius.xyz/  بروید")
        print("    2. ثبت‌نام / ورود کنید")
        print("    3. یک کلید API بسازید")
        print("    4. این متغیر محیطی را قبل از اجرا تنظیم کنید:")
        print("         export HELIUS_API_KEY=\"your-key-here\"")
        print("       یا یک فایل .env در کنار اسکریپت بسازید:")
        print("         echo 'HELIUS_API_KEY=your-key-here' > .env")
        print("    5. این اسکنر را مجدداً اجرا کنید")
        print()
        print("  با کلید Helius حدود ۱۰ درخواست بر ثانیه می‌گیرید، که ۲۰ برابر سریع‌تر است.")
        print("=" * 70)
        print()

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
    print(f"\n📁 آمار در {STATS_FILE} ذخیره شد.")
    print(f"⏱  مجموع: {stats.elapsed:.1f} ثانیه | تعداد کلیدها: {stats.total_keys}")
    print(f"📦 کش: {cache.hits} برخورد / {cache.misses} عدم‌برخورد")
    print("👋 پایان کار.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass