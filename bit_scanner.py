"""
اسکنر آدرس بیت‌کوین (آموزشی) — ویرایش ۴

هشدار امنیتی:
    این اسکریپت کلیدهای خصوصی بیت‌کوین را به‌صورت محلی مشتق کرده و هر کلید
    دارای موجودی را به‌صورت متن ساده (plaintext) در فایل found_wallets.txt
    ذخیره می‌کند. کلیدهای خصوصی اعتبارنامه‌های نگهداری دارایی هستند؛ ذخیره‌سازی
    به‌صورت متن ساده ذاتاً ناامن است. اگر هدف شما پایش موجودی‌هاست، سازوکار
    موجود را روی آدرس‌های *عمومی* متمرکز کنید و بخش تولید کلید را غیرفعال نمایید.

بررسی واقعیت:
    کلیدهای ۲۵۶ بیتی که به‌طور یکنواخت نمونه‌برداری می‌شوند، با احتمال تقریبی
    2^-134 به یک آدرس دارای موجودی برخورد می‌کنند. با سرعت 10^15 کلید بر ثانیه،
    این کار حدود 10^21 سال زمان می‌برد. تنها دلیل تاریخی که چنین اسکریپت‌هایی
    تا به حال چیزی «پیدا کرده‌اند»، کلیدهای ضعیف (مولد اعداد تصادفی معیوب،
    کیف‌پول‌های ذهنی یا brainwallets، و عبارات عبور با آنتروپی پایین) بوده است —
    بخش بسیار ناچیزی که نمونه‌برداری یکنواخت از نظر ساختاری قادر به رسیدن به آن
    نیست. مهندسی کد زیر اصولی و صحیح است، اما فرضیه پایه آن عملی نیست.

تغییرات در ویرایش ۴ (این ویرایش):
  - رفع باگ: شرایط مسابقه (race condition) همزمانی در تغییر وضعیت‌های
    BitcoinAPIProvider. با burst=3، تا سه درخواست می‌توانند همزمان برای یک
    سرویس‌دهنده در جریان (in-flight) باشند. سه خطای تقریباً همزمان باعث
    غیرفعال شدن سرویس‌دهنده و صفر شدن fail_count می‌شدند؛ سپس چهارمین خطای
    در جریان، مقدار fail_count را *در حین غیرفعال بودن* به ۱ افزایش می‌داد،
    بنابراین غیرفعال‌سازی بعدی به جای سه خطا تنها با دو خطای دیگر رخ می‌داد.
    همچنین رسیدن یک پاسخ موفق مربوط به درخواستی که پیش از غیرفعال‌سازی ارسال
    شده بود، پیام "recovered" را چاپ کرده و backoff را در حالی که سرویس‌دهنده
    هنوز غیرفعال بود بازنشانی می‌کرد. این مشکل با یک asyncio.Lock به ازای هر
    سرویس‌دهنده و نگهبان disabled_until برطرف شد: تغییرات وضعیتی که پس از
    غیرفعال شدن می‌رسند نادیده گرفته می‌شوند. مقدار fail_count در زمان فعال‌سازی
    مجدد از قبل ۰ است (در زمان غیرفعال شدن بازنشانی شده)، بنابراین زمان‌بندی
    backoff کاملاً قطعی (deterministic) است.
  - متدهای mark_failure / mark_rate_limited / mark_success اکنون async هستند؛
    محل‌های فراخوانی در BalanceChecker.check() با await منتظر آن‌ها می‌مانند.

تغییرات در ویرایش ۳:
  1) کلاس UAManager حذف شد. ویژگی `impersonate` در curl_cffi اکنون مدیریت
     User-Agent و تمام هدرهای مختص مرورگر را بر عهده دارد؛ بازنویسی آن‌ها باعث
     ایجاد مجدد امضای عدم تطابق JA3/UA می‌شد که نسخه اولیه منتشر می‌کرد.
  2) تابع _btc_com_parser پاسخ {"data": null, "err_no": 0} را مدیریت می‌کند —
     پاسخ btc.com برای آدرسی که هیچ سابقه تراکنشی در بلاک‌چین ندارد.
  3) فراخوانی rate_limiter.acquire() به بیرون از سمافور سراسری منتقل شد. یک
     پنجره زمانی Retry-After دیگر جایگاه سمافور را اشغال نمی‌کند.
  4) تابع private_key_to_addresses فقط فرمت‌های موجود در CHECK_ADDRESS_TYPES
     را مشتق می‌کند؛ save_found در صورت پیدا شدن موجودی، تمام فرمت‌ها را مجدداً
     مشتق می‌کند.
  5) عملیات دیسک (I/O) مربوط به کش به asyncio.to_thread منتقل شد.
  6) متد RateLimiter.speed_up() ظرفیت (capacity) را متناسب با نرخ (rate) مقیاس‌بندی می‌کند.
  7) بررسی آمادگی Workerها هم غیرفعال‌سازی سخت (hard-disable) و هم محدودیت نرم
     (soft-throttle) را در نظر می‌گیرد.
  8) آمارها (Stats) هر تلاش HTTP را شمارش کرده و به سرویس‌دهنده مربوطه نسبت می‌دهند.

منتقل‌شده از ویرایش ۲:
  - MAX_ATTEMPTS_PER_PROVIDER (قبلاً MAX_RETRIES_PER_PROVIDER=1 بود که کد مرده محسوب می‌شد)
  - خطای 404 به عنوان خطای سرویس‌دهنده در نظر گرفته می‌شود، نه موجودی صفر
  - ویژگی impersonate به ازای هر نشست (session) ثابت شده و با الگوریتم LRU به سقف MAX_SESSIONS محدود شده است
  - کلاس RateLimiter به هدر Retry-After (برحسب ثانیه یا تاریخ HTTP) احترام می‌گذارد
  - تابع _detect_api_error فیلد error_code مربوط به bitaps را تشخیص می‌دهد
  - پارسرها در صورت مواجهه با ساختار غیرمنتظره، خطای ParseError صادر می‌کنند
  - ناظر (Supervisor) ورکرهای متوقف‌شده (crashed) را مجدداً راه‌اندازی می‌کند
  - کش پس از بارگذاری از دیسک به اندازه CACHE_MAX_SIZE کوتاه (trim) می‌شود
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
from collections import OrderedDict
from email.utils import parsedate_to_datetime

from curl_cffi.requests import AsyncSession
from bit import Key
from bit.base32 import bech32_encode, convertbits
from bit.format import ripemd160_sha256

# ==================== تنظیمات ====================
HRP = "bc"
NUM_WORKERS = 8
REQUEST_TIMEOUT = 6
MAX_ATTEMPTS_PER_PROVIDER = 2

ENABLE_CACHE = False
MAX_CONCURRENT_REQUESTS = 32
MAX_SESSIONS = 64

CHECK_ADDRESS_TYPES = (
    "Native SegWit (P2WPKH)",
)

FOUND_FILE = Path("found_wallets.txt")
STATS_FILE = Path("scan_stats.txt")
CACHE_FILE = Path("btc_cache.json")
PROXY_FILE = Path("proxies.txt")

CACHE_MAX_SIZE = 50_000
CACHE_TTL = 3600

IMPERSONATE_TARGETS = [
    "chrome124", "chrome123", "chrome120",
    "chrome116", "chrome110",
    "edge101", "safari17_0", "safari15_5",
]

REFERERS = [
    "https://www.google.com/",
    "https://duckduckgo.com/",
    "https://www.bing.com/",
    "https://mempool.space/",
    "https://blockstream.info/",
    "https://blockchain.info/",
    "https://bitcoin.org/",
]

CURVE_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass


# ==================== خطاهای تجزیه (Parse) ====================
class ParseError(Exception):
    """زمانی توسط پارسر صادر می‌شود که ساختار پاسخ مطابق انتظار ما نباشد."""


# ==================== محدودکننده نرخ درخواست (AIMD) ====================
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
        self.blocked_until = 0.0
        self.lock = asyncio.Lock()

    def is_blocked(self) -> bool:
        return time.monotonic() < self.blocked_until

    async def acquire(self):
        while True:
            async with self.lock:
                now = time.monotonic()
                if now < self.blocked_until:
                    wait = self.blocked_until - now
                else:
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

    async def back_off(self, label: str = "", retry_after: float | None = None):
        async with self.lock:
            old_rate = self.rate
            old_burst = self.capacity
            self.rate = max(self.min_rate, self.rate * 0.5)
            self.capacity = max(1, self.capacity // 2)
            self.tokens = 0.0
            if retry_after is not None:
                self.blocked_until = max(
                    self.blocked_until,
                    time.monotonic() + max(0.0, retry_after),
                )
            if old_rate != self.rate or old_burst != self.capacity:
                tag = f"[{label}] " if label else ""
                extra = (
                    f", blocked {retry_after:.1f}s" if retry_after else ""
                )
                print(
                    f"    ↳ {tag}rate {old_rate:.2f}→{self.rate:.2f} req/s, "
                    f"burst {old_burst}→{self.capacity}{extra}"
                )

    async def speed_up(self):
        async with self.lock:
            if self.rate < self.initial_rate:
                self.rate = min(self.initial_rate, self.rate * 1.10)
            target_cap = max(
                1,
                int(round(self.initial_capacity * self.rate / self.initial_rate)),
            )
            if self.capacity < target_cap:
                self.capacity = min(self.initial_capacity, target_cap)


# ==================== کش (Cache) ====================
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

    @staticmethod
    def _read_cache_file():
        with open(CACHE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    @staticmethod
    def _write_cache_file(data):
        with open(CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f)

    async def load_from_disk(self):
        if not self.enabled or not CACHE_FILE.exists():
            return
        try:
            data = await asyncio.to_thread(self._read_cache_file)
        except Exception as e:
            print(f"⚠ خطا در بارگذاری کش: {e}")
            return

        now = time.time()
        items = []
        for addr, entry in data.items():
            try:
                ts, result = entry
            except (TypeError, ValueError):
                continue
            if now - ts <= self.ttl:
                items.append((ts, addr, result))
        items.sort(key=lambda t: t[0])

        async with self.lock:
            for ts, addr, result in items:
                self.store[addr] = (ts, result)
            while len(self.store) > self.max_size:
                self.store.popitem(last=False)
            loaded = len(self.store)
        print(f"📦 {loaded} آدرس از کش دیسک بارگذاری شد.")

    async def save_to_disk(self):
        if not self.enabled:
            return
        async with self.lock:
            snapshot = {
                addr: (ts, res)
                for addr, (ts, res) in self.store.items()
                if res.get("total_sats", 0) > 0 or res.get("tx_count", 0) > 0
            }
        try:
            await asyncio.to_thread(self._write_cache_file, snapshot)
        except Exception as e:
            print(f"⚠ خطا در ذخیره کش: {e}")


# ==================== تشخیص خطای API ====================
def _detect_api_error(data) -> str | None:
    if not isinstance(data, dict):
        return None

    if data.get("error"):
        return f"error: {str(data['error'])[:200]}"

    if "err_no" in data:
        err_no = data.get("err_no")
        if err_no not in (0, None):
            msg = data.get("err_msg") or data.get("message") or ""
            return f"err_no={err_no}: {str(msg)[:200]}"

    if "error_code" in data:                        # سرویس bitaps
        code = data.get("error_code")
        if code not in (0, None):
            msg = data.get("error_message") or data.get("message") or ""
            return f"error_code={code}: {str(msg)[:200]}"

    ctx = data.get("context")
    if isinstance(ctx, dict):
        code = ctx.get("code")
        if isinstance(code, int) and code >= 400:
            return f"context code={code}: {str(ctx.get('error', ''))[:200]}"

    return None


def _parse_retry_after(response) -> float | None:
    raw = (
        response.headers.get("Retry-After")
        or response.headers.get("retry-after")
    )
    if not raw:
        return None
    raw = str(raw).strip()
    try:
        return max(0.0, float(raw))
    except (TypeError, ValueError):
        pass
    try:
        dt = parsedate_to_datetime(raw)
        if dt is not None:
            return max(0.0, dt.timestamp() - time.time())
    except Exception:
        pass
    return None


# ==================== سرویس‌دهنده (Provider) ====================
class BitcoinAPIProvider:
    BASE_BACKOFF = 45.0
    MAX_BACKOFF = 600.0

    def __init__(self, name, base_url, parser=None, rate=3.0,
                 impersonate=True, timeout=None):
        self.name = name
        self.base_url = base_url
        self.parser = parser or self._default_mempool_parser
        self.rate_limiter = RateLimiter(rate_per_sec=rate, burst=3)
        self.impersonate = impersonate
        self.timeout = timeout if timeout is not None else REQUEST_TIMEOUT
        self.fail_count = 0
        self.disabled_until = 0.0
        self.success_count = 0
        self.backoff = self.BASE_BACKOFF
        self.last_disable_reason = ""
        self.consecutive_rate_limits = 0
        # اصلاحیه (ویرایش ۴): محافظت از fail_count / consecutive_rate_limits /
        # backoff / disabled_until در برابر به‌روزرسانی‌های متداخل از سوی
        # ورکرهای همزمان (burst=3 اجازه ۳ درخواست همزمان به ازای هر سرویس‌دهنده را می‌دهد).
        self._state_lock = asyncio.Lock()

    def is_available(self) -> bool:
        """فقط غیرفعال‌سازی سخت را بررسی می‌کند. محدودیت نرم توسط rate_limiter.is_blocked() بررسی می‌شود.

        فقط-خواندنی؛ قفل _state_lock را درگیر نمی‌کند. خواندن صفت‌ها تحت GIL
        اتمی است و این مسیر به دفعات بسیار زیاد فراخوانی می‌شود.
        """
        return time.monotonic() >= self.disabled_until

    async def mark_failure(self, reason: str = ""):
        # اصلاحیه (ویرایش ۴): نادیده گرفتن خطاهای با تأخیر که پس از غیرفعال شدن
        # سرویس‌دهنده توسط یک خطای همزمان دیگر می‌رسند. بدون این بخش، چهارمین
        # خطای در جریان، مقدار fail_count را در زمان غیرفعال بودن به بالای ۰ می‌برد،
        # و در نتیجه غیرفعال‌سازی بعدی به جای ۳ خطا، با ۲ خطا فعال می‌شد.
        async with self._state_lock:
            if time.monotonic() < self.disabled_until:
                return
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

    async def mark_rate_limited(self, reason: str = "429"):
        async with self._state_lock:
            if time.monotonic() < self.disabled_until:
                return
            self.consecutive_rate_limits += 1
            if self.consecutive_rate_limits >= 30:
                self.disabled_until = time.monotonic() + self.backoff
                self.last_disable_reason = f"persistent {reason}"
                print(
                    f"⛔ [{self.name}] disabled for {self.backoff:.0f}s "
                    f"(reason: persistent {reason} × "
                    f"{self.consecutive_rate_limits})"
                )
                self.consecutive_rate_limits = 0
                self.backoff = min(self.backoff * 2, self.MAX_BACKOFF)

    async def mark_success(self):
        # اصلاحیه (ویرایش ۴): نادیده گرفتن پاسخ‌های موفقی که در زمان غیرفعال بودن
        # می‌رسند — این‌ها پاسخ‌هایی به درخواست‌های ارسال‌شده پیش از غیرفعال شدن هستند،
        # و بازنشانی backoff روی آن‌ها سرویس‌دهنده را در وضعیت ناسازگاری قرار می‌دهد
        # (چاپ شدن پیام "recovered" در حالی که disabled_until مربوط به زمان آینده است).
        async with self._state_lock:
            if time.monotonic() < self.disabled_until:
                return
            self.fail_count = 0
            self.success_count += 1
            self.consecutive_rate_limits = 0
            if self.backoff != self.BASE_BACKOFF:
                print(f"✅ [{self.name}] recovered — backoff reset")
                self.backoff = self.BASE_BACKOFF
                self.last_disable_reason = ""

    def build_url(self, address: str) -> str:
        return self.base_url.format(address=address)

    @staticmethod
    def _default_mempool_parser(data, address, provider_name):
        if not isinstance(data, dict):
            raise ParseError("not an object")
        chain = data.get("chain_stats")
        if not isinstance(chain, dict):
            raise ParseError("missing chain_stats")
        for f in ("funded_txo_sum", "spent_txo_sum"):
            if f not in chain:
                raise ParseError(f"missing chain_stats.{f}")
        mempool = data.get("mempool_stats") or {}
        if not isinstance(mempool, dict):
            mempool = {}
        confirmed = int(chain["funded_txo_sum"]) - int(chain["spent_txo_sum"])
        unconfirmed = (
            int(mempool.get("funded_txo_sum", 0))
            - int(mempool.get("spent_txo_sum", 0))
        )
        total = confirmed + unconfirmed
        tx_count = (
            int(chain.get("tx_count", 0)) + int(mempool.get("tx_count", 0))
        )
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
    if not isinstance(data, dict):
        raise ParseError("not an object")
    b_data = data.get("data") if isinstance(data.get("data"), dict) else data
    if "balance" not in b_data:
        raise ParseError("missing balance")
    confirmed = int(b_data.get("balance") or 0)
    pending_rec = int(b_data.get("pendingReceivedAmount") or 0)
    pending_sent = int(b_data.get("pendingSentAmount") or 0)
    unconfirmed = pending_rec - pending_sent
    total = confirmed + unconfirmed
    tx_count = (
        int(b_data.get("receivedTxCount") or 0)
        + int(b_data.get("sentTxCount") or 0)
    )
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


def _blockchain_info_parser(data, address, name):
    if not isinstance(data, dict):
        raise ParseError("not an object")
    for f in ("final_balance", "n_tx"):
        if f not in data:
            raise ParseError(f"missing {f}")
    confirmed = int(data.get("final_balance") or 0)
    received = int(data.get("total_received") or 0)
    spent = int(data.get("total_sent") or 0)
    tx_count = int(data.get("n_tx") or 0)
    return {
        "address": address,
        "confirmed_sats": confirmed,
        "unconfirmed_sats": 0,
        "total_sats": confirmed,
        "confirmed_btc": confirmed / 100_000_000,
        "total_btc": confirmed / 100_000_000,
        "tx_count": tx_count,
        "received_sats": received,
        "spent_sats": spent,
        "provider": name,
    }


def _blockchair_parser(data, address, name):
    if not isinstance(data, dict):
        raise ParseError("not an object")
    root = data.get("data")
    if not isinstance(root, dict):
        raise ParseError("missing data")
    entry = root.get(address)
    if not isinstance(entry, dict):
        raise ParseError("missing address entry")
    addr_data = entry.get("address")
    if not isinstance(addr_data, dict):
        raise ParseError("missing address detail")
    if "balance" not in addr_data:
        raise ParseError("missing balance")
    confirmed = int(addr_data.get("balance") or 0)
    tx_count = int(addr_data.get("transaction_count") or 0)
    return {
        "address": address,
        "confirmed_sats": confirmed,
        "unconfirmed_sats": 0,
        "total_sats": confirmed,
        "confirmed_btc": confirmed / 100_000_000,
        "total_btc": confirmed / 100_000_000,
        "tx_count": tx_count,
        "provider": name,
    }


def _btc_com_parser(data, address, name):
    if not isinstance(data, dict):
        raise ParseError("not an object")
    # سرویس btc.com برای آدرس بدون سابقه تراکنش در بلاک‌چین، مقدار
    # {"data": null, "err_no": 0} برمی‌گرداند. این یک موجودی صفر معتبر است، نه خطای تجزیه.
    if data.get("data") is None and data.get("err_no") == 0:
        return {
            "address": address,
            "confirmed_sats": 0,
            "unconfirmed_sats": 0,
            "total_sats": 0,
            "confirmed_btc": 0.0,
            "total_btc": 0.0,
            "tx_count": 0,
            "provider": name,
        }
    d = data.get("data") if isinstance(data.get("data"), dict) else data
    if "balance" not in d:
        raise ParseError("missing balance")
    confirmed = int(d.get("balance") or 0)
    tx_count = int(d.get("tx_count") or 0)
    return {
        "address": address,
        "confirmed_sats": confirmed,
        "unconfirmed_sats": 0,
        "total_sats": confirmed,
        "confirmed_btc": confirmed / 100_000_000,
        "total_btc": confirmed / 100_000_000,
        "tx_count": tx_count,
        "provider": name,
    }


def _blockcypher_parser(data, address, name):
    if not isinstance(data, dict):
        raise ParseError("not an object")
    if "address" not in data or "balance" not in data:
        raise ParseError("missing address/balance")
    confirmed = int(data.get("balance") or 0)
    unconfirmed = int(data.get("unconfirmed_balance") or 0)
    total = confirmed + unconfirmed
    tx_count = int(data.get("final_n_tx") or data.get("n_tx") or 0)
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
            "blockchain.info",
            "https://blockchain.info/rawaddr/{address}?limit=1",
            _blockchain_info_parser, rate=2.0, timeout=8,
        ),
        BitcoinAPIProvider(
            "blockchair",
            "https://api.blockchair.com/bitcoin/dashboards/address/{address}",
            _blockchair_parser, rate=2.0, timeout=8,
        ),
        BitcoinAPIProvider(
            "blockcypher",
            "https://api.blockcypher.com/v1/btc/main/addrs/{address}/balance",
            _blockcypher_parser, rate=2.0, timeout=8,
        ),
        BitcoinAPIProvider(
            "btc.com",
            "https://chain.api.btc.com/v3/address/{address}",
            _btc_com_parser, rate=2.0, timeout=8,
        ),
        BitcoinAPIProvider(
            "bitaps",
            "https://api.bitaps.com/btc/v1/blockchain/address/state/{address}",
            _bitaps_parser, rate=1.5, timeout=6,
        ),
        BitcoinAPIProvider(
            "mempool.space",
            "https://mempool.space/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser, rate=2.0, timeout=3,
        ),
        BitcoinAPIProvider(
            "blockstream.info",
            "https://blockstream.info/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser, rate=2.0, timeout=3,
        ),
        BitcoinAPIProvider(
            "mempool.ninja",
            "https://mempool.ninja/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser, rate=2.0, timeout=3,
        ),
        BitcoinAPIProvider(
            "mempool.emzy.de",
            "https://mempool.emzy.de/api/address/{address}",
            BitcoinAPIProvider._default_mempool_parser, rate=2.0, timeout=3,
        ),
    ]


# ==================== استخر پروکسی (Proxy Pool) ====================
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
        return p

    def __len__(self):
        return len(self.proxies)


# ==================== هدرها (Headers) ====================
def build_headers() -> dict:
    """هدرهای حداقلی به ازای هر درخواست.

    هدرهای User-Agent، Sec-Fetch-*، Accept-Language و Accept-Encoding توسط
    قابلیت `impersonate` در curl_cffi تنظیم می‌شوند تا با پروفایل TLS مرورگر
    انتخاب‌شده مطابقت داشته باشند. بازنویسی هر یک از آن‌ها امضای عدم تطابق
    JA3/UA را دوباره ایجاد می‌کند. تنها Referer (که curl_cffi نمی‌تواند بداند)
    و Accept (برای اولویت دادن به JSON) در اینجا تنظیم می‌شوند.
    """
    return {
        "Accept": "application/json, text/plain, */*",
        "Referer": random.choice(REFERERS),
    }


# ==================== آمار (Stats) ====================
class Stats:
    def __init__(self, providers):
        self.lock = asyncio.Lock()
        self.total_keys = 0
        self.total_http_requests = 0
        self.start_time = time.monotonic()
        self.provider_stats = {
            p.name: {"success": 0, "fail": 0, "rate_limited": 0}
            for p in providers
        }
        self.found = False
        self.last_all_down_warn = 0.0

    async def incr_keys(self):
        async with self.lock:
            self.total_keys += 1
            return self.total_keys

    async def incr_request(self, provider_name: str | None, ok: bool):
        async with self.lock:
            self.total_http_requests += 1
            if provider_name in self.provider_stats:
                key = "success" if ok else "fail"
                self.provider_stats[provider_name][key] += 1

    async def incr_rate_limited(self, provider_name: str | None):
        async with self.lock:
            if provider_name in self.provider_stats:
                self.provider_stats[provider_name]["rate_limited"] += 1

    @property
    def elapsed(self):
        return time.monotonic() - self.start_time


# ==================== بررسی‌کننده موجودی (Balance Checker) ====================
class BalanceChecker:
    def __init__(self, providers, proxy_pool: ProxyPool,
                 cache: BalanceCache, stats: Stats,
                 max_concurrent: int = MAX_CONCURRENT_REQUESTS):
        self.providers = providers
        self.proxy_pool = proxy_pool
        self.cache = cache
        self.stats = stats
        self._sessions: OrderedDict[str, tuple[AsyncSession, str]] = OrderedDict()
        self._sessions_lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max_concurrent)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        for sess, _imp in self._sessions.values():
            try:
                await sess.close()
            except Exception:
                pass
        self._sessions.clear()

    async def _get_session(self, proxy_url: str | None):
        key = proxy_url or "__direct__"
        async with self._sessions_lock:
            existing = self._sessions.get(key)
            if existing is not None:
                self._sessions.move_to_end(key)
                return existing
            if len(self._sessions) >= MAX_SESSIONS:
                _, evicted = self._sessions.popitem(last=False)
                ev_sess, _ev_imp = evicted
                try:
                    await ev_sess.close()
                except Exception:
                    pass
            impersonate = random.choice(IMPERSONATE_TARGETS)
            if proxy_url:
                sess = AsyncSession(
                    proxies={"http": proxy_url, "https": proxy_url}
                )
            else:
                sess = AsyncSession()
            record = (sess, impersonate)
            self._sessions[key] = record
            return record

    async def check(self, address: str):
        cached = await self.cache.get(address)
        if cached is not None:
            return cached

        start = random.randrange(len(self.providers))
        ordered = self.providers[start:] + self.providers[:start]

        for provider in ordered:
            if not provider.is_available():
                continue
            if provider.rate_limiter.is_blocked():
                continue

            for attempt in range(MAX_ATTEMPTS_PER_PROVIDER):
                try:
                    # دریافت توکن پیش از سمافور، تا خواب ناشی از Retry-After
                    # یک جایگاه سراسری را اشغال نکند.
                    await provider.rate_limiter.acquire()

                    async with self._sem:
                        url = provider.build_url(address)
                        headers = build_headers()

                        proxy_url = await self.proxy_pool.get()
                        session, sess_imp = await self._get_session(proxy_url)
                        impersonate = sess_imp if provider.impersonate else None

                        r = await session.get(
                            url,
                            headers=headers,
                            timeout=provider.timeout,
                            impersonate=impersonate,
                        )

                    if r.status_code == 429:
                        retry_after = _parse_retry_after(r)
                        print(
                            f"⚠ [{provider.name}] 429"
                            + (f" (Retry-After {retry_after:.0f}s)"
                               if retry_after else "")
                        )
                        await provider.rate_limiter.back_off(
                            provider.name, retry_after=retry_after
                        )
                        await provider.mark_rate_limited("429")
                        await self.stats.incr_request(provider.name, ok=False)
                        await self.stats.incr_rate_limited(provider.name)
                        break

                    if r.status_code in (401, 403, 451):
                        print(
                            f"⚠ [{provider.name}] HTTP {r.status_code} (blocked)"
                        )
                        await provider.mark_failure(f"HTTP {r.status_code}")
                        await self.stats.incr_request(provider.name, ok=False)
                        break

                    if r.status_code == 404:
                        # کد 404 نشانه موجودی صفر نیست.
                        print(f"⚠ [{provider.name}] HTTP 404 (unexpected)")
                        await provider.mark_failure("HTTP 404")
                        await self.stats.incr_request(provider.name, ok=False)
                        break

                    if r.status_code >= 400:
                        print(f"⚠ [{provider.name}] HTTP {r.status_code}")
                        await self.stats.incr_request(provider.name, ok=False)
                        if attempt < MAX_ATTEMPTS_PER_PROVIDER - 1:
                            await asyncio.sleep(0.5 * (attempt + 1))
                            continue
                        await provider.mark_failure(f"HTTP {r.status_code}")
                        break

                    try:
                        data = r.json()
                    except Exception as e:
                        print(f"⚠ [{provider.name}] JSON parse failed: {e}")
                        await provider.mark_failure("JSON parse")
                        await self.stats.incr_request(provider.name, ok=False)
                        break

                    err = _detect_api_error(data)
                    if err is not None:
                        print(f"⚠ [{provider.name}] API error: {err}")
                        await provider.mark_failure("api-error")
                        await self.stats.incr_request(provider.name, ok=False)
                        break

                    try:
                        result = provider.parser(data, address, provider.name)
                    except ParseError as e:
                        print(f"⚠ [{provider.name}] parse error: {e}")
                        await provider.mark_failure("parse")
                        await self.stats.incr_request(provider.name, ok=False)
                        break

                    await provider.mark_success()
                    await provider.rate_limiter.speed_up()
                    await self.stats.incr_request(provider.name, ok=True)
                    await self.cache.set(address, result)
                    return result

                except Exception as e:
                    print(
                        f"⚠ [{provider.name}] request error: "
                        f"{type(e).__name__}: {e}"
                    )
                    await self.stats.incr_request(provider.name, ok=False)
                    if attempt < MAX_ATTEMPTS_PER_PROVIDER - 1:
                        await asyncio.sleep(0.5 * (attempt + 1))
                        continue
                    await provider.mark_failure(type(e).__name__)
                    break

        return None


# ==================== ابزارهای کلید و آدرس ====================
def generate_private_key() -> str:
    while True:
        k = int.from_bytes(secrets.token_bytes(32), "big")
        if 1 <= k < CURVE_ORDER:
            return f"{k:064x}"


def public_key_to_native_segwit(pub_bytes: bytes, hrp=HRP) -> str:
    wp = ripemd160_sha256(pub_bytes)
    h = convertbits(wp, 8, 5)
    if h is None:
        raise ValueError("convertbits returned None for a 20-byte hash")
    data = [0] + h
    return bech32_encode(hrp, data)


def _all_addresses_for_key(key: Key) -> dict:
    return {
        "Legacy (P2PKH)": key.address,
        "Nested SegWit (P2SH-P2WPKH)": key.segwit_address,
        "Native SegWit (P2WPKH)": public_key_to_native_segwit(key.public_key),
    }


def private_key_to_addresses(pk_hex: str):
    try:
        key = Key.from_hex(pk_hex)
        result = {}
        if "Legacy (P2PKH)" in CHECK_ADDRESS_TYPES:
            result["Legacy (P2PKH)"] = key.address
        if "Nested SegWit (P2SH-P2WPKH)" in CHECK_ADDRESS_TYPES:
            result["Nested SegWit (P2SH-P2WPKH)"] = key.segwit_address
        if "Native SegWit (P2WPKH)" in CHECK_ADDRESS_TYPES:
            result["Native SegWit (P2WPKH)"] = public_key_to_native_segwit(
                key.public_key
            )
        return result
    except Exception as e:
        print(f"⚠ خطا در تبدیل کلید: {e}")
        return None


# ==================== ذخیره‌سازی (Persistence) ====================
def save_found(private_key: str, balance: dict, found_address: str):
    try:
        key = Key.from_hex(private_key)
        addresses = _all_addresses_for_key(key)
    except Exception as e:
        print(f"⚠ خطا در مشتق کردن آدرس‌ها: {e}")
        addresses = {found_address: found_address}

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
    rate = stats.total_http_requests / elapsed if elapsed > 0 else 0
    total_cache = cache.hits + cache.misses
    hit_rate = (cache.hits / total_cache * 100) if total_cache > 0 else 0
    with open(STATS_FILE, "w", encoding="utf-8") as f:
        f.write(f"کلیدهای تولیدشده: {stats.total_keys}\n")
        f.write(f"درخواست‌های HTTP:  {stats.total_http_requests}\n")
        f.write(f"زمان اجرا:         {elapsed:.2f} ثانیه\n")
        f.write(f"نرخ درخواست HTTP:  {rate:.2f} req/s\n")
        f.write(f"کش فعال:           {'بله' if cache.enabled else 'خیر'}\n")
        f.write(f"کش hit rate:       {hit_rate:.1f}%\n\n")
        f.write("آمار Providerها:\n")
        for name, s in stats.provider_stats.items():
            f.write(
                f"  {name}: موفق={s['success']} | "
                f"خطا={s['fail']} | 429={s['rate_limited']}\n"
            )


# ==================== ورکر (Worker) ====================
async def worker(
    worker_id: int,
    checker: BalanceChecker,
    stats: Stats,
    stop_event: asyncio.Event,
    print_lock: asyncio.Lock,
):
    while not stop_event.is_set():
        ready = [
            p for p in checker.providers
            if p.is_available() and not p.rate_limiter.is_blocked()
        ]
        if not ready:
            async with print_lock:
                now = time.monotonic()
                if now - stats.last_all_down_warn >= 30.0:
                    stats.last_all_down_warn = now
                    reasons = ", ".join(
                        f"{p.name}→"
                        f"{p.last_disable_reason or 'throttled'}"
                        for p in checker.providers
                    )
                    print(f"⏸ هیچ API آماده‌ای نیست — 2s صبر. دلایل: {reasons}")
            await asyncio.sleep(2.0)
            continue

        pk_hex = generate_private_key()
        addresses = private_key_to_addresses(pk_hex)
        if not addresses:
            continue

        n = await stats.incr_keys()

        if n % 50 == 0:
            async with print_lock:
                elapsed = stats.elapsed
                rate = (
                    stats.total_http_requests / elapsed if elapsed > 0 else 0
                )
                active = sum(
                    1 for p in checker.providers if p.is_available()
                )
                cache_total = checker.cache.hits + checker.cache.misses
                hit_rate = (
                    checker.cache.hits / cache_total * 100
                    if cache_total > 0 else 0
                )
                cache_label = (
                    f"{hit_rate:.0f}%" if checker.cache.enabled else "off"
                )
                print(
                    f"📊 کلید #{n} | "
                    f"{stats.total_http_requests} HTTP | "
                    f"{elapsed:.1f}s | {rate:.2f} req/s | "
                    f"API فعال: {active}/{len(checker.providers)} | "
                    f"کش: {cache_label}"
                )

        for _kind, addr in addresses.items():
            if stop_event.is_set():
                return

            info = await checker.check(addr)
            if info is not None and info.get("total_sats", 0) > 0:
                async with print_lock:
                    save_found(pk_hex, info, addr)
                stats.found = True
                stop_event.set()
                return


# ==================== تابع اصلی (Main) ====================
async def main():
    providers = build_providers()

    print("=" * 70)
    print("  اسکنر بیت‌کوین — نسخه async + curl_cffi + Cache (rev 4)")
    print("  TLS: impersonate-pinned per session | Multi-API | LRU Cache | Proxy")
    print(f"  تعداد APIها: {len(providers)} | Workerها: {NUM_WORKERS}")
    print(f"  نوع آدرس‌ها: {', '.join(CHECK_ADDRESS_TYPES)}")
    print(f"  سقف اتصال همزمان: {MAX_CONCURRENT_REQUESTS}")
    print(f"  کش: {'فعال' if ENABLE_CACHE else 'غیرفعال'}")
    print("  برای توقف: Ctrl+C")
    print("=" * 70)

    proxy_pool = ProxyPool(PROXY_FILE)
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

    def _stop():
        if not stop_event.is_set():
            print("\n⏹ درخواست توقف دریافت شد...")
            stop_event.set()

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
        async with BalanceChecker(
            providers, proxy_pool, cache, stats,
            max_concurrent=MAX_CONCURRENT_REQUESTS,
        ) as checker:
            tasks = {
                i: asyncio.create_task(
                    worker(i, checker, stats, stop_event, print_lock),
                    name=f"worker-{i}",
                )
                for i in range(NUM_WORKERS)
            }

            while not stop_event.is_set():
                for i, t in list(tasks.items()):
                    if t.done() and not stop_event.is_set():
                        try:
                            exc = t.exception()
                        except asyncio.CancelledError:
                            print(f"⚠ worker-{i} cancelled; restarting")
                            exc = None
                        else:
                            if exc is not None:
                                print(
                                    f"⚠ worker-{i} crashed: "
                                    f"{type(exc).__name__}: {exc}"
                                )
                            else:
                                print(f"⚠ worker-{i} exited unexpectedly")
                        tasks[i] = asyncio.create_task(
                            worker(i, checker, stats, stop_event, print_lock),
                            name=f"worker-{i}",
                        )
                await asyncio.sleep(0.5)

            for t in tasks.values():
                t.cancel()
            await asyncio.gather(*tasks.values(), return_exceptions=True)

    except (KeyboardInterrupt, asyncio.CancelledError):
        _stop()

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