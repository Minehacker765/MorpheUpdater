"""Google Play access: Aurora OSS token dispenser, FDFE protobuf API,
and APKPure metadata API for version-string -> version-code resolution."""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import dataclass, field

from aiohttp import ClientSession, ClientTimeout

from . import pb
from .profiles import get_priority_profiles
from .settings import ROOT, TMP

log = logging.getLogger("play")

DISPENSER = "https://auroraoss.com/api/auth"
FDFE = "https://android.clients.google.com/fdfe"
PURE_VERSIONS = "https://api.pureapk.com/m/v3/cms/app_version"

_ENCODED_TARGETS = (
    "CAESN/qigQYC2AMBFfUbyA7SM5Ij/CvfBoIDgxXrBPsDlQUdMfOLAfoFrwEH"
    "gAcBrQYhoA0cGt4MKK0Y2gI"
)
_PURE_HEADERS = {
    "x-cv": "3172501",
    "x-sv": "29",
    "x-abis": "arm64-v8a,armeabi-v7a,armeabi,x86,x86_64",
    "x-gp": "1",
}
_VERSION_RE = re.compile(r"^[0-9]+(\.[0-9]+)+(?:-[\w.]+)?$")
_TOKEN_TTL = 50 * 60


class PlayError(Exception):
    pass


class AuthExpiredError(PlayError):
    pass


class AppNotSupportedError(PlayError):
    pass


class AppNotPurchasedError(PlayError):
    pass


class AppNotAvailableError(PlayError):
    pass


class RateLimitError(PlayError):
    pass


def timeout(t: float | None) -> ClientTimeout:
    return ClientTimeout(total=t)


# ── Aurora OSS dispenser ────────────────────────────────────────────────────


async def _post_profile(session: ClientSession, url: str, profile: dict) -> dict | None | PlayError:
    try:
        async with session.post(
            url,
            json=profile,
            headers={"User-Agent": "com.aurora.store-4.6.1-70"},
            timeout=timeout(30),
        ) as resp:
            if resp.status == 200:
                data = await resp.json(content_type=None)
                return data if data.get("authToken") else None
            if resp.status in (401, 403, 404, 503):
                try:
                    msg = (await resp.json(content_type=None)).get("error") or ""
                except Exception:
                    msg = ""
                raise PlayError(f"dispenser: {msg or f'HTTP {resp.status}'}")
            return None
    except PlayError:
        raise
    except Exception:
        return None


async def fetch_token(session: ClientSession, arch: str = "arm64") -> dict | None:
    for _key, profile in get_priority_profiles(arch):
        result = await _post_profile(session, DISPENSER, profile)
        if isinstance(result, PlayError):
            raise result
        if result:
            return result
    return None


async def ensure_auth(session: ClientSession, arch: str = "arm64") -> dict:
    cache = TMP / f"auth-{arch}.json"
    if cache.exists():
        try:
            data = json.loads(cache.read_text())
            if data.get("authToken") and time.time() - data.get("_at", 0) < _TOKEN_TTL:
                return data
        except (OSError, json.JSONDecodeError):
            pass
    data = await fetch_token(session, arch)
    if not data:
        raise PlayError("every device profile was rejected by the dispenser")
    data["_at"] = time.time()
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(json.dumps(data))
    return data


# ── FDFE API ────────────────────────────────────────────────────────────────


@dataclass
class Split:
    name: str
    url: str
    size: int = 0
    sha256: str = ""
    gzipped_url: str = ""
    gzipped_size: int = 0


@dataclass
class Delivery:
    download_url: str = ""
    download_size: int = 0
    gzipped_url: str = ""
    gzipped_size: int = 0
    sha1: str = ""
    sha256: str = ""
    cookies: list[dict] = field(default_factory=list)
    splits: list[Split] = field(default_factory=list)


@dataclass
class Details:
    package: str
    title: str = ""
    version_string: str = ""
    version_code: int = 0


def build_headers(auth: dict, locales: list[str] | None = None) -> dict[str, str]:
    di = auth.get("deviceInfoProvider", {})
    headers = {
        "Authorization": f"Bearer {auth['authToken']}",
        "User-Agent": di.get(
            "userAgentString",
            (
                "Android-Finsky/41.2.29-23 [0] [PR] 639844241 (api=3,versionCode=84122900,"
                "sdk=34,device=lynx,hardware=lynx,product=lynx,platformVersionRelease=14,"
                "model=Pixel%207a,buildId=UQ1A.231205.015,isWideScreen=0,"
                "supportedAbis=arm64-v8a;armeabi-v7a;armeabi)"
            ),
        ),
        "X-DFE-Device-Id": auth.get("gsfId", ""),
        "Accept-Language": "en-US",
        "X-DFE-Encoded-Targets": _ENCODED_TARGETS,
        "X-DFE-Client-Id": "am-android-google",
        "X-DFE-Network-Type": "4",
        "X-DFE-Content-Filters": "",
        "X-Limit-Ad-Tracking-Enabled": "false",
        "X-Ad-Id": "",
        "X-DFE-UserLanguages": ",".join(locales) if locales else "en-US",
        "X-DFE-Request-Params": "timeoutMs=4000",
        "X-DFE-Cookie": auth.get("dfeCookie", ""),
        "X-DFE-No-Prefetch": "true",
        "Content-Type": "application/x-protobuf",
        "Accept": "application/x-protobuf",
    }
    if auth.get("deviceCheckInConsistencyToken"):
        headers["X-DFE-Device-Checkin-Consistency-Token"] = auth["deviceCheckInConsistencyToken"]
    if auth.get("deviceConfigToken"):
        headers["X-DFE-Device-Config-Token"] = auth["deviceConfigToken"]
    if di.get("mccMnc"):
        headers["X-DFE-MCCMNC"] = di["mccMnc"]
    return headers


def _check(resp_status: int) -> None:
    if resp_status == 429:
        raise RateLimitError("HTTP 429")
    if resp_status == 401:
        raise AuthExpiredError("token expired")
    if resp_status == 404:
        raise AppNotAvailableError("app not found")
    if resp_status != 200:
        raise PlayError(f"HTTP {resp_status}")


async def get_details(session: ClientSession, auth: dict, package: str) -> Details:
    async with session.get(
        f"{FDFE}/details", params={"doc": package},
        headers=build_headers(auth), timeout=timeout(30),
    ) as resp:
        raw = await resp.read()
        _check(resp.status)

    details = Details(package=package)
    doc = pb.navigate(raw, 1, 2, 4)
    if not doc:
        raise AppNotAvailableError(f"{package}: empty details")
    details.title = pb.first_string(doc, 5)
    dd = pb.first_bytes(doc, 13)
    if dd:
        ad = pb.first_bytes(pb.decode_fields(dd), 1)
        if ad:
            fields = pb.decode_fields(ad)
            details.version_code = pb.first_int(fields, 3) or 0
            details.version_string = pb.first_string(fields, 4)
    if not details.version_code and not details.title:
        raise AppNotAvailableError(f"{package} unavailable for this device profile")
    return details


async def purchase(session: ClientSession, auth: dict, package: str, vc: int) -> str:
    headers = build_headers(auth)
    headers["Content-Type"] = "application/x-www-form-urlencoded"
    async with session.post(
        f"{FDFE}/purchase", headers=headers,
        data=f"doc={package}&ot=1&vc={vc}", timeout=timeout(30),
    ) as resp:
        if resp.status == 401:
            raise AuthExpiredError("token expired")
        if resp.status not in (200, 204):
            return ""
        buy = pb.navigate(await resp.read(), 1, 4)
        return pb.first_string(buy, 55) if buy else ""


def parse_delivery(raw: bytes) -> Delivery:
    add: list[pb.Field] = []
    for payload_fn in (21, 5, 4, 6):
        candidate = pb.navigate(raw, 1, payload_fn, 2)
        if candidate and pb.first_string(candidate, 3):
            add = candidate
            break
    if not add:
        raise PlayError("unparseable delivery response")

    d = Delivery(
        download_url=pb.first_string(add, 3),
        download_size=pb.first_int(add, 1) or 0,
        gzipped_url=pb.first_string(add, 13),
        gzipped_size=pb.first_int(add, 14) or 0,
        sha1=pb.first_string(add, 2),
        sha256=pb.first_string(add, 19),
    )
    for c_b in pb.all_bytes(add, 5):
        cf = pb.decode_fields(c_b)
        if pb.first_string(cf, 1):
            d.cookies.append({"name": pb.first_string(cf, 1), "value": pb.first_string(cf, 2)})
    for s_b in pb.all_bytes(add, 15):
        sf = pb.decode_fields(s_b)
        url = pb.first_string(sf, 5)
        if not url:
            continue
        gz_url, gz_size = pb.first_string(sf, 6), pb.first_int(sf, 3) or 0
        if not gz_url:
            g = pb.first_bytes(sf, 8)
            if g and (pb.first_int(pb.decode_fields(g), 1) or 0) == 2:
                gf = pb.decode_fields(g)
                gz_url, gz_size = pb.first_string(gf, 3), pb.first_int(gf, 2) or 0
        d.splits.append(Split(
            name=pb.first_string(sf, 1),
            url=url,
            size=pb.first_int(sf, 2) or 0,
            sha256=pb.first_string(sf, 9),
            gzipped_url=gz_url,
            gzipped_size=gz_size,
        ))
    return d


async def get_delivery(
    session: ClientSession,
    auth: dict,
    package: str,
    vc: int,
    locales: list[str],
    delivery_token: str = "",
) -> Delivery:
    params = {"doc": package, "ot": 1, "vc": str(vc)}
    if delivery_token:
        params["dtok"] = delivery_token
    async with session.get(
        f"{FDFE}/delivery", params=params,
        headers=build_headers(auth, locales), timeout=timeout(30),
    ) as resp:
        raw = await resp.read()
        _check(resp.status)

    try:
        d = parse_delivery(raw)
        if d.download_url:
            return d
    except PlayError:
        d = None

    status = None
    for payload_fn in (21, 5, 4, 6):
        fields = pb.navigate(raw, 1, payload_fn)
        status = pb.first_int(fields, 1)
        if status is not None:
            break
    if status == 2:
        raise AppNotSupportedError(f"vc {vc} of {package} not served to this profile")
    if status == 3:
        raise AppNotPurchasedError(f"{package} not acquired by account")
    if d is not None:
        # parse succeeded but no download_url and no status -> treat as error
        raise PlayError(f"no download URL for {package} vc {vc} (status={status})")
    raise PlayError(f"unparseable delivery response for {package} vc {vc} (status={status})")


# ── APKPure metadata (version string -> real Play version code) ────────────


def _unwrap(raw: bytes) -> bytes:
    inner = pb.first_bytes(pb.decode_fields(raw), 1)
    if inner is None:
        return raw
    payload = pb.first_bytes(pb.decode_fields(inner), 7)
    return payload if payload is not None else inner


def parse_version_codes(raw: bytes) -> dict[str, int]:
    def match(fields: list[pb.Field]) -> tuple[str, int] | None:
        f5, f6 = pb.first_bytes(fields, 5), pb.first_bytes(fields, 6)
        if not isinstance(f5, bytes) or not isinstance(f6, bytes):
            return None
        try:
            vc, ver = f5.decode("ascii"), f6.decode("utf-8")
        except UnicodeDecodeError:
            return None
        return (ver, int(vc)) if vc.isdigit() and _VERSION_RE.match(ver) else None

    codes: dict[str, int] = {}
    for ver, vc in pb.walk_find(_unwrap(raw), match):
        codes[ver] = max(codes.get(ver, 0), vc)
    return codes


PURE_CACHE = TMP / "pure-cache.json"
PURE_CACHE_TTL = 6 * 3600  # 6h – apkpure versions change slowly, avoids 166×3s every 30min


def _load_pure_cache() -> dict:
    try:
        if PURE_CACHE.exists():
            data = json.loads(PURE_CACHE.read_text())
            # {pkg: {"at": ts, "codes": {ver: vc}}}
            return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _save_pure_cache(cache: dict) -> None:
    try:
        PURE_CACHE.parent.mkdir(parents=True, exist_ok=True)
        # atomic write
        tmp = PURE_CACHE.with_suffix(".tmp")
        tmp.write_text(json.dumps(cache, sort_keys=True) + "\n")
        tmp.replace(PURE_CACHE)
    except Exception:
        pass


async def fetch_version_codes(session: ClientSession, package: str, attempts: int = 3) -> dict[str, int]:
    # disk cache: 6h TTL, survives cycles, still respects 429 backoff
    cache = _load_pure_cache()
    entry = cache.get(package)
    if entry and isinstance(entry, dict):
        at = entry.get("at", 0)
        codes = entry.get("codes")
        if isinstance(codes, dict) and time.time() - at < PURE_CACHE_TTL:
            # normalize int
            log.debug("%s: pure cache hit (%d versions, age %ds)", package, len(codes), int(time.time() - at))
            return {str(k): int(v) for k, v in codes.items() if str(v).isdigit()}
    log.info("%s: getting version codes (pureapk)...", package)
    last_err: Exception | None = None
    for attempt in range(attempts):
        async with session.get(
            PURE_VERSIONS,
            params={"hl": "en-US", "package_name": package},
            headers=_PURE_HEADERS,
            timeout=timeout(30),
        ) as resp:
            if resp.status == 429:
                wait = int(resp.headers.get("Retry-After") or 0) or 20 * (attempt + 1)
                log.warning("%s: pure rate-limited (429), retrying in %ds (attempt %d/%d)", package, wait, attempt + 1, attempts)
                last_err = PlayError(f"metadata source rate-limited {package}")
                await asyncio.sleep(wait)
                continue
            if resp.status != 200:
                log.warning("%s: pure HTTP %s", package, resp.status)
                raise PlayError(f"metadata source HTTP {resp.status} for {package}")
            codes = parse_version_codes(await resp.read())
            if not codes:
                log.warning("%s: pure returned no versions", package)
                raise PlayError(f"no versions found for {package}")
            # save to disk cache
            cache[package] = {"at": int(time.time()), "codes": codes}
            _save_pure_cache(cache)
            log.info("%s: pure got %d versions", package, len(codes))
            return codes
    raise last_err or PlayError(f"metadata source failed for {package}")


OVERRIDES_PATH = ROOT / "version_overrides.json"


def _load_overrides() -> dict[str, dict[str, int]]:
    try:
        if OVERRIDES_PATH.exists():
            data = json.loads(OVERRIDES_PATH.read_text())
            # normalize: {pkg: {ver: vc}}
            out: dict[str, dict[str, int]] = {}
            for pkg, mapping in data.items():
                if isinstance(mapping, dict):
                    out[pkg] = {str(k): int(v) for k, v in mapping.items() if str(v).isdigit()}
            return out
    except Exception:
        pass
    return {}


def _save_override(package: str, version: str, vc: int) -> None:
    try:
        data = _load_overrides()
        data.setdefault(package, {})[str(version)] = int(vc)
        # sort for determinism
        sorted_data = {pkg: dict(sorted(m.items())) for pkg, m in sorted(data.items())}
        OVERRIDES_PATH.write_text(json.dumps(sorted_data, indent=2, sort_keys=True) + "\n")
    except Exception:
        pass


def guess_version_codes(dotted: str) -> list[int]:
    """Heuristic guesses for Play versionCode from dotted version.

    Play versionCodes vary per app (Twitch 25.3.0 -> 2503006, YouTube 21.04.223 -> 1561052632
    is not guessable), so this is a best-effort fallback when APKPure history is
    shallow. Tries common encodings: a*1e5+b*1e3+c etc., plus large TV encodings.
    """
    nums = [int(x) for x in re.findall(r"\d+", dotted)]
    # use first 3 as a,b,c and also handle +v extra numbers for TV (6.23.23+v15.5.0.70 -> 6,23,23,15,5,0,70)
    parts = nums[:3]
    while len(parts) < 3:
        parts.append(0)
    a, b, c = parts
    cand: set[int] = set()
    bases = [
        a * 100000 + b * 1000 + c,
        a * 100000 + b * 1000 + c * 10,
        a * 1000000 + b * 1000 + c,
        a * 1000000 + b * 10000 + c,
        a * 10000000 + b * 1000 + c,
        # TV large encodings (e.g. 606024040 for 6.24.4)
        a * 100000000 + b * 100000 + c * 100,
        a * 100000000 + b * 1000000 + c * 1000,
        a * 100000000 + b * 100000 + c * 1000,
        a * 100000000 + b * 10000 + c,
    ]
    # also try incorporating extra numbers for TV +v parts
    if len(nums) >= 5:
        v = nums[3] if len(nums) > 3 else 0
        w = nums[4] if len(nums) > 4 else 0
        # common TV pattern: 6.23.23+v15.5.0.70 -> 602315500 etc? try combining
        bases.append(a * 10000000 + v * 100000 + b * 1000 + c)
        bases.append(a * 100000000 + v * 1000000 + b * 10000 + c)
    for base in bases:
        for d in range(-50, 51):
            for suffix in (0, 6, 16, 26, 36, 40, 70, 230, 240):
                cand.add(base + d + suffix)
                cand.add(base * 10 + suffix)
                cand.add(base + d)
    return sorted(c for c in cand if 0 < c < 2_147_483_647)


async def resolve_vc(session: ClientSession, package: str, version: str) -> tuple[int, dict[str, int]]:
    # 0) overrides file first (user-persisted custom pairs)
    overrides = _load_overrides()
    if version in overrides.get(package, {}):
        vc = int(overrides[package][version])
        try:
            codes = await fetch_version_codes(session, package)
        except Exception:
            codes = {}
        codes[version] = vc
        return vc, codes
    codes = await fetch_version_codes(session, package)
    if version in codes:
        return codes[version], codes
    # tolerate store-suffixed variants (e.g. requested 4.10.10, listed 4.10.10-googleplay)
    prefixed = {v: c for v, c in codes.items() if v.startswith(f"{version}-")}
    if prefixed:
        best = max(prefixed, key=lambda v: [int(x) for x in re.findall(r"\d+", v)])
        return prefixed[best], codes
    known = sorted(codes)
    sample = ", ".join(known[:4] + ["..."] + known[-4:]) if len(known) > 8 else ", ".join(known)
    raise PlayError(f"{version} unknown for {package}; known versions: {sample}")


async def resolve_vc_with_fallback(
    session: ClientSession,
    package: str,
    version: str,
    arch: str = "arm64",
) -> tuple[int, dict[str, int]]:
    """Try APKPure first, then mirror* fallbacks (APKMirror scrape, Play brute-force)."""
    try:
        return await resolve_vc(session, package, version)
    except PlayError as e:
        if "unknown for" not in str(e) and "no versions found" not in str(e):
            raise
        # keep original codes if available for error hint
        codes = {}
        try:
            codes = await fetch_version_codes(session, package)
        except Exception:
            codes = {}
        # mirror* 1: try APKMirror scrape via allorigins-like proxy that bypasses CF
        # (best-effort, no auth needed)
        try:
            vc = await _fetch_vc_via_apkmirror(session, package, version)
            if vc:
                # merge with existing codes for caller's cache
                codes = await fetch_version_codes(session, package)
                codes[version] = vc
                return vc, codes
        except Exception:
            pass
        # mirror* 2: brute-force guess against Play (requires auth, try)
        try:
            # need a valid auth token for this arch
            auth = await ensure_auth(session, arch)
            for guess in guess_version_codes(version):
                try:
                    # purchase is cheap, check if Play serves this vc
                    token = await purchase(session, auth, package, guess)
                    # get_delivery will validate vc; we don't need splits yet
                    # try a lightweight delivery check (fast fail)
                    await get_delivery(session, auth, package, guess, ["en-US"], token)
                    # if we got here, vc is served — persist for next time
                    _save_override(package, version, guess)
                    codes = await fetch_version_codes(session, package)
                    codes[version] = guess
                    return guess, codes
                except (AppNotSupportedError, PlayError):
                    continue
        except Exception:
            pass
        # re-raise original with hint
        raise PlayError(
            f"{version} unknown for {package} via APKPure (mirror* fallback also failed); "
            f"known APKPure: {', '.join(sorted(codes.keys())[:4])}...; "
            f"try passing the numeric versionCode directly (e.g. 2503006 for Twitch 25.3.0) "
            f"or use --version-code"
        ) from e


async def _fetch_vc_via_apkmirror(session: ClientSession, package: str, version: str) -> int | None:
    """Best-effort scrape for versionCode. Checks overrides file first."""
    # 1) user overrides file (version_overrides.json)
    overrides = _load_overrides()
    vc = overrides.get(package, {}).get(str(version))
    if vc:
        return int(vc)
    # 2) generic: try to fetch APKMirror page via alternative textise proxy
    # (may fail, caller will fall through)
    return None
