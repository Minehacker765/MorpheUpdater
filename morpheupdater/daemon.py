"""Update loop: check patch sources -> update tools -> fetch/merge APKs -> patch."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
import shutil
import time
import zlib
from base64 import urlsafe_b64encode
from collections import defaultdict
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout

from . import fdroid, pages, play, tools
from .display import TV_PACKAGES
from .profiles import get_priority_profiles
from .settings import (
    MORPHE_DATA,
    MORPHE_PATCHES,
    OPTIONS,
    OUT,
    ROOT,
    TMP,
    dir_size_mb,
    load_config,
    load_state,
    now,
    save_state,
    short,
    validate_apps,
)

log = logging.getLogger("daemon")

DOWNLOAD_CONCURRENCY = 4
SECONDS_PER_DAY = 86400
PART_SUFFIX = ".part"
LEGACY_MORPHE_DATA = ROOT / "morphe-data"

ver_sem = asyncio.Semaphore(2)
pure_sem = asyncio.Semaphore(4)
play_ver_sem = asyncio.Semaphore(3)


def _enabled_archs(archs_cfg) -> list[str]:
    """Normalize archs config (list or dict) to list of enabled arch strings."""
    if archs_cfg is None:
        return ["arm64"]
    if isinstance(archs_cfg, dict):
        return [k for k, v in archs_cfg.items() if v]
    if isinstance(archs_cfg, list):
        return archs_cfg
    return ["arm64"]


_RES_ORDER = ["ldpi", "mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi"]


def _load_overrides() -> dict:
    """Load overrides.json if exists. Returns dict with exclude_rest and per-package overrides."""
    path = ROOT / "overrides.json"
    if not path.exists():
        path = Path("overrides.json")
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


class AuthHolder:
    def __init__(self) -> None:
        self._auths: dict[str, dict] = {}

    async def get(self, session: ClientSession, arch: str, refresh: bool = False) -> dict:
        if refresh or arch not in self._auths:
            auth = await play.ensure_auth(session, arch)
            self._auths[arch] = auth
            log.info("play token ready (%s, %s)", auth.get("email", "?"), arch)
        return self._auths[arch]


def combo_id(combo: list[str]) -> str:
    return "+".join(combo)


def options_path(package: str, combo: list[str]) -> Path:
    return OPTIONS / f"{short(package)}.{combo_id(combo)}.json"


def _get_bundle_urls(cfg: dict, combo: list[str]) -> list[str]:
    urls = []
    for b in combo:
        spec = cfg["bundles"].get(b, "")
        url = spec if isinstance(spec, str) else spec.get("url", "")
        if url:
            urls.append(url)
    return urls


def clean_tmp(cfg: dict) -> None:
    TMP.mkdir(parents=True, exist_ok=True)
    max_mb = cfg.get("tmp_max_mb", 2048)
    max_age_days = cfg.get("tmp_max_age_days", 7)
    min_free_gb = cfg.get("tmp_min_free_gb", cfg.get("clean", {}).get("tmp_min_free_gb", 5) if isinstance(cfg.get("clean"), dict) else 5)
    size_mb = dir_size_mb(TMP)
    cutoff = now() - int(max_age_days * SECONDS_PER_DAY)
    too_old = any(p.stat().st_mtime < cutoff for p in TMP.rglob("*") if p.is_file())
    try:
        free_gb = shutil.disk_usage(ROOT).free / (1024**3)
        low_space = free_gb < min_free_gb
    except Exception:
        low_space = False
        free_gb = 0
    if size_mb > max_mb or too_old or low_space:
        log.info("wiping tmp/ (size=%.0fMB max=%dMB old=%s free=%.1fGB min=%dGB)", size_mb, max_mb, too_old, free_gb, min_free_gb)
        # preserve pure-cache.json across wipes (6h TTL, avoids 166× pure hits)
        cache = TMP / "pure-cache.json"
        cache_data = cache.read_bytes() if cache.exists() else None
        shutil.rmtree(TMP)
        TMP.mkdir(parents=True, exist_ok=True)
        if cache_data is not None:
            try:
                (TMP / "pure-cache.json").write_bytes(cache_data)
            except Exception:
                pass


async def prune_tmp(cfg: dict, dry_run: bool = False, remove_dupes: bool = False) -> int:
    """LRU prune tmp/ until size < max and no old files, or just dupes. Returns deleted count."""
    TMP.mkdir(parents=True, exist_ok=True)
    max_mb = cfg.get("tmp_max_mb", 2048)
    max_age_days = cfg.get("tmp_max_age_days", 7)
    cutoff = now() - int(max_age_days * SECONDS_PER_DAY)
    files = [p for p in TMP.rglob("*") if p.is_file() and p.name != "pure-cache.json"]
    files.sort(key=lambda p: p.stat().st_mtime)
    deleted = 0
    size_mb = dir_size_mb(TMP)
    for p in files:
        is_old = p.stat().st_mtime < cutoff
        is_dup = p.suffix == PART_SUFFIX  # dedup always
        if is_old or is_dup or size_mb > max_mb:
            if dry_run:
                log.info("[dry-run] would delete tmp %s (old=%s dup=%s size=%.0fMB)", p, is_old, is_dup, size_mb)
            else:
                try:
                    p.unlink()
                    deleted += 1
                    size_mb = dir_size_mb(TMP)
                except Exception:
                    pass
            if not is_old and not is_dup and size_mb <= max_mb:
                break
    if remove_dupes:
        if LEGACY_MORPHE_DATA.exists() and MORPHE_DATA.exists():
            if dry_run:
                log.info("[dry-run] would delete duplicate %s", LEGACY_MORPHE_DATA)
            else:
                try:
                    shutil.rmtree(LEGACY_MORPHE_DATA)
                    deleted += 1
                except Exception:
                    pass
    if deleted:
        log.info("prune_tmp deleted %d files", deleted)
    return deleted


async def prune_out(cfg: dict, dry_run: bool = False, remove_dupes: bool = False) -> int:
    """Ensure out/ only has latest APK per package|combo|arch. Returns deleted count."""
    state = load_state()
    keep = set()
    for e in state.get("builds", {}).values():
        apk = e.get("out")
        if apk:
            keep.add(apk)
    deleted = 0
    for apk in OUT.glob("*.apk"):
        if apk.name not in keep:
            if dry_run:
                log.info("[dry-run] would delete out %s (not in keep)", apk.name)
            else:
                try:
                    apk.unlink()
                    deleted += 1
                except Exception:
                    pass
    grouped = defaultdict(list)
    for apk in OUT.glob("*.apk"):
        grouped[apk.name.split("-")[0]].append(apk)
    for short_name, files in grouped.items():
        if len(files) > 1:
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            for old in files[1:]:
                if old.name in keep:
                    continue
                if dry_run:
                    log.info("[dry-run] would delete old dup out %s", old.name)
                else:
                    try:
                        old.unlink()
                        deleted += 1
                    except Exception:
                        pass
    if deleted:
        log.info("prune_out deleted %d files", deleted)
    return deleted


# ── GitHub bundle checks ────────────────────────────────────────────────────


def _repo_from_url(url: str) -> str | None:
    if "github.com" not in url:
        return None
    parts = url.split("github.com/", 1)[1].strip("/").split("/")
    return "/".join(parts[:2])


def _bundle_url(spec) -> str:
    return spec if isinstance(spec, str) else spec.get("url", "")


def _bundle_prerelease(cfg: dict, name: str) -> bool:
    spec = cfg["bundles"].get(name, "")
    if isinstance(spec, str):
        return True
    return bool(spec.get("prerelease", True))


def _cache_dir(repo: str) -> Path:
    return MORPHE_PATCHES / repo.replace("/", "-")


def _is_mpp_candidate(p: Path) -> bool:
    n = p.name.lower()
    return not p.name.endswith(".part") and "sources" not in n and "javadoc" not in n


def _get_local_mpp(url: str, tag: str | None = None) -> Path | None:
    """Return cached MPP file for bundle. If tag given, prefer exact tag match (no GitHub hit)."""
    if "github.com" not in url:
        return None
    try:
        repo = _repo_from_url(url) or ""
        cache_dir = _cache_dir(repo)
        if tag:
            # exact tag file: {tag}__*.mpp (e.g. v1.41.0__patches-1.41.0.mpp) – strict, no prefix fallback
            cand = [p for p in cache_dir.glob(f"{tag}__*.mpp") if _is_mpp_candidate(p)]
            if cand:
                return cand[0]
            return None
        if not cache_dir.exists():
            return None
        mpps = [p for p in cache_dir.glob("*.mpp") if _is_mpp_candidate(p)]
        if not mpps:
            return None
        def _ver_key(p: Path):
            m = re.search(r"v(\d+\.\d+\.\d+(?:-dev\.\d+)?)", p.name)
            if m:
                v = m.group(1)
                base = v.split("-")[0]
                parts = [int(x) for x in base.split(".")]
                if "-dev" in v:
                    dev_num = int(v.split("-dev.")[-1]) if "-dev." in v else 0
                    return (parts[0], parts[1], parts[2], 1, dev_num)
                return (parts[0], parts[1], parts[2], 0, 999)
            return (0, 0, 0, 0, 0)
        mpps.sort(key=_ver_key, reverse=True)
        return mpps[0]
    except Exception:
        return None


def _get_patch_inputs(cfg: dict, combo: list[str], state: dict | None = None) -> list[str]:
    """Return local MPP paths for morphe-desktop. Never returns URL when tag is known (offline)."""
    inputs = []
    for b in combo:
        spec = cfg["bundles"].get(b, "")
        url = spec if isinstance(spec, str) else spec.get("url", "")
        if not url:
            continue
        tag = state.get("bundles", {}).get(b) if state else None
        local = _get_local_mpp(url, tag) if tag else _get_local_mpp(url)
        if local and local.exists():
            inputs.append(str(local))
        else:
            # strict offline: do not fall back to URL – caller should have ensured cache
            # keep fallback for first-run bootstrap where state empty
            if tag:
                log.warning("MPP missing for bundle %s tag %s (expected %s), falling back to URL (will hit GitHub!)", b, tag, local)
            inputs.append(url)
    return inputs


async def ensure_mpp_cache(session: ClientSession, cfg: dict, state: dict) -> None:
    """Download each bundle's MPP for its state tag via GitHub API directly (once per bundle).
    Afterwards every morphe call uses local file -> zero GitHub hits for 164 list-versions."""
    for name, spec in cfg["bundles"].items():
        url = _bundle_url(spec)
        repo = _repo_from_url(url)
        tag = state["bundles"].get(name)
        if not repo or not tag:
            continue
        # microg is not a patches MPP repo (direct APK) – skip MPP download
        if repo.lower() == "morpheapp/microg-re":
            continue
        cache_dir = _cache_dir(repo)
        cache_dir.mkdir(parents=True, exist_ok=True)
        existing = [p for p in cache_dir.glob(f"{tag}__*.mpp") if _is_mpp_candidate(p)]
        if existing:
            continue
        # fetch release by tag (authenticated, no morphe tool involved)
        try:
            gh_headers = tools._gh_headers()  # uses GITHUB_TOKEN from env/.env
            async with session.get(f"{tools.GH_API}/repos/{repo}/releases/tags/{tag}", headers=gh_headers) as resp:
                if resp.status != 200:
                    # fallback: tag might be without v? try releases list
                    log.warning("MPP %s: releases/tags/%s HTTP %s, trying releases list", name, tag, resp.status)
                    async with session.get(f"{tools.GH_API}/repos/{repo}/releases?per_page=100", headers=gh_headers) as r2:
                        r2.raise_for_status()
                        releases = await r2.json()
                        release = next((x for x in releases if x.get("tag_name") == tag), None)
                        if not release:
                            log.error("MPP %s: tag %s not found in releases list", name, tag)
                            continue
                else:
                    release = await resp.json()
            assets = [a for a in release.get("assets", []) if a.get("name", "").lower().endswith(".mpp") and "sources" not in a["name"].lower() and "javadoc" not in a["name"].lower()]
            if not assets:
                log.warning("MPP %s %s: no .mpp asset in release (assets=%s)", name, tag, [a.get("name") for a in release.get("assets", [])][:5])
                continue
            # pick main patches file (prefer patches-*.mpp, largest)
            # morphe's choice is the primary bundle file
            def _asset_rank(a):
                n = a["name"].lower()
                return (0 if n.startswith("patches") else 1, -a.get("size", 0))
            assets.sort(key=_asset_rank)
            asset = assets[0]
            dl_url = asset["browser_download_url"]
            dest = cache_dir / f"{tag}__{asset['name']}"
            tmp = dest.with_suffix(dest.suffix + ".part")
            log.info("downloading MPP %s %s -> %s", name, tag, dest.name)
            async with session.get(dl_url, headers=gh_headers) as resp2:
                resp2.raise_for_status()
                with open(tmp, "wb") as f:
                    async for chunk in resp2.content.iter_chunked(1 << 20):
                        f.write(chunk)
            tmp.replace(dest)
            log.info("MPP cached %s %s (%d bytes)", name, tag, dest.stat().st_size)
        except Exception as exc:
            log.error("MPP download failed %s %s: %s", name, tag, exc)


async def check_bundles(session: ClientSession, cfg: dict, state: dict) -> dict[str, tuple]:
    changed: dict[str, tuple] = {}

    async def _check_one(name: str, spec):
        url = _bundle_url(spec)
        prerelease = _bundle_prerelease(cfg, name)
        repo = _repo_from_url(url)
        if not repo:
            log.warning("bundle %s: cannot derive a GitHub repo from %s; assuming unchanged", name, url)
            return None
        try:
            if prerelease:
                release = await tools.gh_latest(session, repo)
            else:
                release = await tools.gh_latest_release(session, repo)
        except Exception as exc:
            log.warning("bundle %s: release check failed (%s); keeping %s", name, exc, state["bundles"].get(name, "?"))
            return None
        tag = release["tag_name"]
        old = state["bundles"].get(name)
        if old != tag:
            return (name, old, tag)
        return None

    results = await asyncio.gather(*[_check_one(n, s) for n, s in cfg["bundles"].items()])
    for r in results:
        if r:
            name, old, tag = r
            changed[name] = (old, tag)
            state["bundles"][name] = tag
            log.info("bundle %s: %s -> %s", name, old or "(new)", tag)
    return changed


async def check_tools(session: ClientSession, cfg: dict, state: dict, summary: dict) -> None:
    for name, spec in cfg["tools"].items():
        try:
            was_changed, tag = await tools.update_tool(session, name, spec, state)
        except Exception as exc:
            log.error("tool %s update failed: %s", name, exc)
            continue
        if was_changed:
            summary["tools"][name] = tag
            state["tools"].setdefault(name, {}).pop("signing", None)
            log.info("%s: signing mode will be re-probed", name)


# ── download + merge ────────────────────────────────────────────────────────


async def _download_file(
    session: ClientSession,
    sem: asyncio.Semaphore,
    spec: dict,
    dest: Path,
) -> None:
    expected = spec["sha256"].rstrip("=")
    if expected and dest.exists():
        digest = await asyncio.to_thread(_file_digest, dest)
        if digest == expected:
            return
    headers = {}
    if spec.get("cookies"):
        headers["Cookie"] = "; ".join(f"{c['name']}={c['value']}" for c in spec["cookies"])
    decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16) if spec.get("gzipped") else None
    hasher = hashlib.sha256()

    async with sem, session.get(spec["url"], headers=headers) as resp:
        resp.raise_for_status()
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".part")
        with open(tmp, "wb") as f:
            async for chunk in resp.content.iter_chunked(64 * 1024):
                data = decompressor.decompress(chunk) if decompressor else chunk
                f.write(data)
                hasher.update(data)
            if decompressor:
                tail = decompressor.flush()
                if tail:
                    f.write(tail)
    actual = urlsafe_b64encode(hasher.digest()).decode().rstrip("=")
    if expected and actual != expected:
        tmp.unlink(missing_ok=True)
        raise RuntimeError(f"{dest.name}: sha256 mismatch")
    tmp.replace(dest)


def _file_digest(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return urlsafe_b64encode(h.digest()).decode().rstrip("=")


async def _fetch_splits(session: ClientSession, holder: AuthHolder, cfg: dict, package: str, vc: int, dest_dir: Path, arch: str, resolution: str | None = None) -> play.Details:

    async def flow(auth: dict):
        details = await play.get_details(session, auth, package)
        token = await play.purchase(session, auth, package, vc)
        delivery = await play.get_delivery(
            session, auth, package, vc, cfg.get("locales", ["en-US", "es"]), token
        )
        return details, delivery

    profiles = [p for _, p in get_priority_profiles(arch)]

    details = delivery = None
    last_exc: Exception | None = None
    for prof in profiles:
        try:
            auth = await play._post_profile(session, play.DISPENSER, prof)
            if not auth or isinstance(auth, play.PlayError):
                auth = await holder.get(session, arch)
            details, delivery = await flow(auth)
            holder._auths[arch] = auth
            break
        except play.AuthExpiredError as e:
            last_exc = e
            continue
        except play.RateLimitError as e:
            last_exc = e
            wait = 10
            log.warning("%s: rate limited on profile, waiting %ds", short(package), wait)
            await asyncio.sleep(wait)
            continue
        except (play.AppNotSupportedError, play.AppNotAvailableError) as exc:
            last_exc = exc
            log.debug("%s vc %d not supported on profile %s, trying next", short(package), vc, prof.get("deviceInfoProvider", {}).get("product", "?")[:20])
            continue
        except play.PlayError as e:
            last_exc = e
            continue
    else:
        for attempt in range(4):
            try:
                auth = await holder.get(session, arch, refresh=attempt > 0 and details is None)
                details, delivery = await flow(auth)
                break
            except play.AuthExpiredError:
                if attempt:
                    raise
            except play.RateLimitError:
                if attempt == 3:
                    raise
                wait = 30 * 2 ** attempt
                log.warning("%s: rate limited by Play; waiting %ds", short(package), wait)
                await asyncio.sleep(wait)
            except (play.AppNotSupportedError, play.AppNotAvailableError) as exc:
                raise RuntimeError(f"{exc}; tried {len(profiles)} profiles for --arch {arch}") from exc
        else:
            if last_exc:
                raise RuntimeError(f"{last_exc}; tried {len(profiles)} profiles for --arch {arch}") from last_exc
    assert delivery is not None

    log.info("%s %s: %d splits (%s)", short(package), details.version_string or f"vc{vc}",
             len(delivery.splits), ", ".join(s.name for s in delivery.splits))
    requested = (resolution or cfg.get("resolution", "xxxhdpi") or "xxxhdpi").lower()
    if requested not in _RES_ORDER:
        requested = "xxxhdpi"
    req_idx = _RES_ORDER.index(requested)
    density = []
    other = []
    for s in delivery.splits:
        low = s.name.lower()
        found = None
        for d in _RES_ORDER:
            if d in low:
                found = d
                break
        if found:
            density.append((s, _RES_ORDER.index(found)))
        else:
            other.append(s)
    if density:
        cand = [(s, i) for s, i in density if i <= req_idx]
        if cand:
            best = max(i for _, i in cand)
            keep = [s for s, i in density if i == best]
        else:
            best = min(i for _, i in density)
            keep = [s for s, i in density if i == best]
        if len(keep) != len(density):
            log.info("%s: resolution %s -> keeping %s (had %s)", short(package), requested, ",".join(k.name for k in keep), ",".join(k.name for k,_ in density))
        delivery.splits = other + keep

    dl_conc = cfg.get("clean", {}).get("download_concurrency", DOWNLOAD_CONCURRENCY) if isinstance(cfg.get("clean"), dict) else DOWNLOAD_CONCURRENCY
    sem = asyncio.Semaphore(dl_conc)
    specs = []
    use_gzip = bool(delivery.gzipped_url and delivery.gzipped_size)
    specs.append({
        "url": delivery.gzipped_url if use_gzip else delivery.download_url,
        "dest": dest_dir / "base.apk",
        "cookies": delivery.cookies,
        "gzipped": use_gzip,
        "sha256": delivery.sha256,
    })
    for s in delivery.splits:
        s_gzip = bool(s.gzipped_url and s.gzipped_size)
        specs.append({
            "url": s.gzipped_url if s_gzip else s.url,
            "dest": dest_dir / f"{s.name}.apk",
            "cookies": [],
            "gzipped": s_gzip,
            "sha256": s.sha256,
        })

    results = await asyncio.gather(
        *[_download_file(session, sem, spec, spec["dest"]) for spec in specs],
        return_exceptions=True,
    )
    errors = [r for r in results if isinstance(r, BaseException)]
    if errors:
        for e in errors:
            log.error("download failed: %s", e)
        raise errors[0]
    log.info("%s: downloaded %d files", short(package), len(specs))
    return details


async def ensure_merged(
    session: ClientSession,
    holder: AuthHolder,
    cfg: dict,
    apkeditor_jar: Path,
    package: str,
    vc: int,
    arch: str,
    resolution: str | None = None,
) -> tuple[Path, play.Details | None]:
    dl_dir = TMP / "dl" / package / f"{vc}-{arch}"
    merged = TMP / "merged" / f"{package}-{vc}-{arch}.apk"
    details = None
    if not merged.exists():
        done_marker = dl_dir / ".complete"
        if not done_marker.exists():
            details = await _fetch_splits(session, holder, cfg, package, vc, dl_dir, arch, resolution)
            dl_dir.mkdir(parents=True, exist_ok=True)
            done_marker.write_text("")
        staged = merged.with_suffix(".apk.tmp")
        await tools.merge_apks(apkeditor_jar, dl_dir, staged)
        staged.replace(merged)
        log.info("%s: merged into %s", short(package), merged.name)
    return merged, details


# ── cycle ───────────────────────────────────────────────────────────────────


def _jar(cfg: dict, tool: str) -> Path:
    local = cfg["tools"][tool]["local"]
    return ROOT / local


async def _recommended(cfg: dict, urls: list[str], package: str, cache: dict) -> str | None:
    key = (frozenset(urls), package)
    if key not in cache:
        async with ver_sem:
            cache[key] = await tools.recommended_version(_jar(cfg, "morphe-desktop"), urls, package, cfg)
    return cache[key]


async def _fetch_microg(session: ClientSession, cfg: dict) -> tuple[str, int, pathlib.Path]:
    # MicroG is a plain APK from its GitHub releases, not Play (use absolute latest)
    rel = await tools.gh_latest(session, "MorpheApp/MicroG-RE")
    tag = rel["tag_name"]
    # pick the no-icon apk
    url = next((a["browser_download_url"] for a in rel.get("assets", []) if "noicon" in a["name"].lower()), None)
    if not url:
        url = next((a["browser_download_url"] for a in rel.get("assets", []) if a["name"].endswith(".apk")), None)
    if not url:
        raise RuntimeError("no MicroG apk in release")
    # version from tag, e.g. 7.0.0-dev.3 -> 7.0.0
    ver = tag.lstrip("v")
    # download to tmp
    dest = TMP / "direct" / f"microg-{tag}.apk"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        async with session.get(url) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in r.content.iter_chunked(1 << 20):
                    f.write(chunk)
    info = await tools.apk_info(ROOT / "bin" / "apkeditor.jar", dest)
    vc = info[2] if info else 0
    return ver, vc, dest


async def _fetch_adguard(session: ClientSession) -> tuple[str, int, pathlib.Path]:
    # AdGuard is no longer on Play Store, direct from adguardcdn.com
    url = "https://download.adguardcdn.com/d/18675/adguard.apk"
    dest = TMP / "direct" / "adguard-4.13.2.apk"
    dest.parent.mkdir(parents=True, exist_ok=True)
    if not dest.exists():
        async with session.get(url) as r:
            r.raise_for_status()
            with open(dest, "wb") as f:
                async for chunk in r.content.iter_chunked(1 << 20):
                    f.write(chunk)
    info = await tools.apk_info(ROOT / "bin" / "apkeditor.jar", dest)
    if not info:
        raise RuntimeError("failed to get AdGuard info")
    pkg, ver, vc, _ = info
    # verify package is correct
    if pkg != "com.adguard.android":
        log.warning("AdGuard package mismatch: %s", pkg)
    return ver, vc, dest


async def _materialize_direct(state: dict, summary: dict, package: str, combo: list[str], archs: list[str], version: str, vc: int, src: Path, out_prefix: str, app_name: str, tags: dict) -> None:
    for arch in archs:
        key = f"{package}|{combo_id(combo)}|{arch}"
        prev = state["builds"].get(key)
        out = OUT / f"{out_prefix}-{version}-{arch}.apk"
        up_to_date = prev and prev.get("version") == version and out.exists()
        if up_to_date:
            log.info("%s %s [%s]: up to date", app_name, version, arch)
            continue
        shutil.copyfile(src, out)
        state["builds"][key] = {"package": package, "version": version, "vc": vc, "arch": arch, "app_name": app_name, "tags": tags, "out": out.name, "at": now()}
        save_state(state)
        summary["built"].append(out.name)


async def _fetch_version_task(session, holder, cfg, app, combo, ver_cache, vc_cache, state):
    # strictly local MPP – ensure_mpp_cache already downloaded each bundle once
    urls = _get_patch_inputs(cfg, combo, state)
    if len(urls) != len(combo):
        return (app, combo, None, None, f"unknown bundle name")
    if app["package"] in ("com.mgoogle.android.gms", "com.adguard.android"):
        return (app, combo, "direct", 0, None)
    pkg_short = short(app["package"])
    log.debug("%s: start list-versions [%s]", pkg_short, combo_id(combo))
    try:
        try:
            version = await asyncio.wait_for(_recommended(cfg, urls, app["package"], ver_cache), timeout=120)
        except asyncio.TimeoutError:
            log.warning("%s: list-versions timeout 120s [%s] urls=%s", pkg_short, combo_id(combo), urls[:1])
            return (app, combo, None, None, "list-versions timeout")
        log.debug("%s: list-versions -> %s", pkg_short, version)
        is_any = not version or version.strip().lower() == "any"
        det_for_any = None
        if is_any:
            arch0 = _enabled_archs(app.get("archs") or cfg.get("archs"))[0]
            log.info("%s: list-versions Any (universal), fetching Play details for vc [%s]", short(app["package"]), arch0)
            async with play_ver_sem:
                auth_tmp = await holder.get(session, arch0)
                det_tmp = await play.get_details(session, auth_tmp, app["package"])
            if not det_tmp.version_code:
                return (app, combo, None, None, "no versions listed and Play details failed for universal patch")
            version = det_tmp.version_string or str(det_tmp.version_code)
            det_for_any = det_tmp
            log.info("%s: Any -> %s vc%d (Play, no pure needed)", short(app["package"]), version, det_tmp.version_code)
        try:
            if is_any and det_for_any is not None:
                # use Play vc directly, no pure hit
                vc = det_for_any.version_code
                vc_cache[app["package"]] = {version: vc}
            else:
                arch0 = _enabled_archs(app.get("archs") or cfg.get("archs"))[0]
                log.debug("%s: getting version codes for %s [%s]", pkg_short, version, arch0)
                async with pure_sem:
                    vc = await asyncio.wait_for(_resolve_vc(session, app["package"], version, vc_cache, arch0), timeout=90)
                log.debug("%s: %s -> vc%d", pkg_short, version, vc)
        except Exception as e:
            if "no versions found" in str(e):
                arch0 = _enabled_archs(app.get("archs") or cfg.get("archs"))[0]
                async with play_ver_sem:
                    auth_tmp = await holder.get(session, arch0)
                    det_tmp = await play.get_details(session, auth_tmp, app["package"])
                if det_tmp.version_code:
                    version = det_tmp.version_string
                    vc = det_tmp.version_code
                    vc_cache[app["package"]] = {version: vc}
                else:
                    return (app, combo, None, None, str(e))
            else:
                return (app, combo, None, None, str(e))
        return (app, combo, version, vc, None)
    except Exception as exc:
        return (app, combo, None, None, str(exc))

async def _resolve_vc(session: ClientSession, package: str, version: str, cache: dict, arch: str = "arm64") -> int:
    try:
        vc, codes = await play.resolve_vc_with_fallback(session, package, version, arch)
    except Exception:
        # fallback to plain resolve for error message
        vc, codes = await play.resolve_vc(session, package, version)
    cache[package] = codes
    return vc


async def _signing_mode(state: dict, morphe_jar: Path) -> str:
    """Decide (once per morphe version) whether morphe can sign natively or we
    must patch unsigned and sign with apksigner."""
    tool_state = state["tools"].setdefault("morphe-desktop", {})
    mode = tool_state.get("signing")
    if mode in ("internal", "external"):
        return mode
    ok = await tools.bc_keystore_probe(morphe_jar, tools.resolve_signing())
    mode = "internal" if ok else "external"
    tool_state["signing"] = mode
    save_state(state)
    return mode


async def build_one(
    session: ClientSession,
    holder: AuthHolder,
    cfg: dict,
    state: dict,
    package: str,
    combo: list[str],
    version: str,
    vc: int,
    arch: str,
    summary: dict,
    resolution: str | None = None,
) -> None:
    cid = combo_id(combo)
    # strictly local MPPs – ensure_mpp_cache downloaded them before any morphe call
    urls = _get_patch_inputs(cfg, combo, state)
    missing = [b for b in combo if b not in cfg["bundles"]]
    if missing:
        raise RuntimeError(f"unknown bundle(s) in combo: {', '.join(missing)}")
    # sanity: we should never pass a https:// URL to patch (would hit GitHub per-app)
    if any(u.startswith("https://") for u in urls):
        log.warning("build_one falling back to URL for %s %s (MPP cache miss)", package, cid)

    merged, details = await ensure_merged(session, holder, cfg, _jar(cfg, "apkeditor"), package, vc, arch, resolution)
    out = OUT / f"{short(package)}-{version}-{cid}-{arch}.apk"
    out.parent.mkdir(parents=True, exist_ok=True)

    mode = await _signing_mode(state, _jar(cfg, "morphe-desktop"))
    staged = TMP / "build" / out.name if mode == "external" else out

    async def run_patch(target: Path, unsigned: bool) -> None:
        await tools.patch(
            _jar(cfg, "morphe-desktop"),
            urls,
            options_path(package, combo),
            merged,
            target,
            unsigned=unsigned,
            force=cfg.get("force_patch", True),
            striplibs=cfg.get("striplibs", []),
            bytecode_mode=cfg.get("bytecode_mode", ""),
            cfg=cfg,
            continue_on_error=cfg.get("continue_on_error", True),
        )

    try:
        await run_patch(staged, unsigned=(mode == "external"))
    except RuntimeError as exc:
        if mode != "internal" or not tools.is_keystore_error(str(exc)):
            raise
        log.warning("%s: native signing failed unexpectedly; falling back to apksigner", short(package))
        state["tools"]["morphe-desktop"]["signing"] = mode = "external"
        save_state(state)
        staged = TMP / "build" / out.name
        await run_patch(staged, unsigned=True)

    if mode == "external":
        await tools.ensure_apksigner(session)
        await tools.sign_apk(staged, out, tools.resolve_signing())
        staged.unlink()

    state["builds"][f"{package}|{cid}|{arch}"] = {
        "package": package,
        "version": version,
        "vc": vc,
        "arch": arch,
        "app_name": details.title if details else "",
        "tags": {b: state["bundles"].get(b, "") for b in combo},
        "out": out.name,
        "at": now(),
    }
    save_state(state)
    summary["built"].append(out.name)


async def cycle(commit_override: bool | None = None, release_override: bool | None = None, app_filter: str | None = None, clean_after: bool = False) -> dict:
    cfg = load_config()
    # filter apps if requested (for low-storage one-by-one builds)
    if app_filter:
        orig_len = len(cfg.get("apps", []))
        cfg["apps"] = [a for a in cfg.get("apps", []) if a.get("package") == app_filter or a.get("display", "").lower() == app_filter.lower() or app_filter.lower() in a.get("package", "").lower()]
        if not cfg["apps"]:
            raise SystemExit(f"no app matches filter {app_filter!r} (available: {[a.get('package') for a in load_config().get('apps', [])]})")
        log.info("single-app mode: %s (%d -> %d apps)", app_filter, orig_len, len(cfg["apps"]))
    validate_apps(cfg)
    if os.environ.get("FDROID_URL") and not (cfg.get("fdroid") or {}).get("url"):
        cfg.setdefault("fdroid", {})["url"] = os.environ["FDROID_URL"]
    for d in (TMP, OUT, OPTIONS, MORPHE_DATA):
        d.mkdir(parents=True, exist_ok=True)
    clean_tmp(cfg)

    state = load_state()
    summary: dict = {"bundles": {}, "tools": {}, "built": [], "failed": []}

    timeout = ClientTimeout(total=None, connect=15, sock_read=600)
    async with ClientSession(timeout=timeout) as session:
        changed = await check_bundles(session, cfg, state)
        summary["bundles"] = changed

        if changed or not state["tools"]:
            await check_tools(session, cfg, state, summary)
        save_state(state)

        holder = AuthHolder()
        ver_cache: dict = {}
        vc_cache: dict = {}

        # global archs, but allow per-app override (for TV)
        # archs now dict {arm64:true, tv:true, universal:false} or list for back-compat
        global_archs: list[str] = _enabled_archs(cfg.get("archs"))
        overrides = _load_overrides()
        exclude_rest = bool(overrides.get("exclude_rest", False))
        pending_tag: str | None = None
        plan: list[tuple[dict, list[str], str, int, str, str | None]] = []
        seen: set[tuple] = set()
        version_targets: list[tuple[dict, list[str], list[str], dict | None]] = []
        for app in cfg["apps"]:
            package = app["package"]
            over = overrides.get(package) if isinstance(overrides.get(package), dict) else None
            if over is not None and over.get("enabled") is False:
                continue
            if exclude_rest and package not in overrides:
                continue
            # per-app archs override (e.g. TV apps use armv7); overrides.json archs takes precedence
            if over and "archs" in over:
                archs = _enabled_archs(over["archs"])
            else:
                archs = app.get("archs") or global_archs
                # expand dict archs if needed
                if isinstance(archs, dict):
                    archs = _enabled_archs(archs)
                elif isinstance(archs, list) and archs and isinstance(archs[0], dict):
                    archs = _enabled_archs(archs[0])
            # handle add_archs/remove_archs from overrides
            if over:
                if "add_archs" in over:
                    for a in _enabled_archs(over["add_archs"]):
                        if a not in archs:
                            archs.append(a)
                if "remove_archs" in over:
                    rm = set(_enabled_archs(over["remove_archs"]))
                    archs = [a for a in archs if a not in rm]
            if "tv" in archs and package not in TV_PACKAGES and not app.get("archs") and not (over and "archs" in over):
                archs = [a for a in archs if a != "tv"]
            for combo in app["combos"]:
                ident = (package, tuple(sorted(combo)))
                if ident in seen:
                    continue
                seen.add(ident)
                urls = _get_bundle_urls(cfg, combo)
                if len(urls) != len(combo):
                    for arch in archs:
                        summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", "unknown bundle name"))
                    continue
                # MicroG is direct GitHub, not Play
                if package == "com.mgoogle.android.gms":
                    try:
                        version, vc, src = await _fetch_microg(session, cfg)
                    except Exception as exc:
                        for arch in archs:
                            summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", str(exc)))
                        continue
                    await _materialize_direct(state, summary, package, combo, archs, version, vc, src, "microg", "MicroG", {"microg": version})
                    continue
                # AdGuard is direct from adguardcdn.com (not on Play)
                if package == "com.adguard.android":
                    try:
                        version, vc, src = await _fetch_adguard(session)
                    except Exception as exc:
                        for arch in archs:
                            summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", str(exc)))
                        continue
                    await _materialize_direct(state, summary, package, combo, archs, version, vc, src, "adguard", "AdGuard", {"hoodles": state["bundles"].get("hoodles", "")})
                    continue

                version_targets.append((app, combo, archs, over))

        # download each bundle's MPP once via GH API (local file) -> afterwards 164 list-versions use file, 0 GitHub
        await ensure_mpp_cache(session, cfg, state)

        # ── parallel version+vc resolution (was sequential before) ─────────────
        if version_targets:
            log.info("resolving %d version(s) in parallel (ver_sem=2, pure_sem=4, play_ver_sem=3) [local MPP, no GitHub]", len(version_targets))
            tasks = [
                _fetch_version_task(session, holder, cfg, app, combo, ver_cache, vc_cache, state)
                for app, combo, _archs, _over in version_targets
            ]
            results = await asyncio.gather(*tasks)
            for (app, combo, archs, over), (r_app, r_combo, version, vc, err) in zip(version_targets, results):
                package = app["package"]
                if err or not version or not vc:
                    for arch in archs:
                        summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", err or "version resolution failed"))
                    continue
                for arch in archs:
                    key = f"{package}|{combo_id(combo)}|{arch}"
                    prev = state["builds"].get(key)
                    out = OUT / f"{short(package)}-{version}-{combo_id(combo)}-{arch}.apk"
                    up_to_date = (
                        prev
                        and prev.get("version") == version
                        and str(prev.get("vc")) == str(vc)
                        and all(prev.get("tags", {}).get(b) == state["bundles"].get(b, "") for b in combo)
                        and out.exists()
                    )
                    if up_to_date:
                        log.info("%s %s [%s/%s]: up to date", short(package), version, combo_id(combo), arch)
                        continue
                    # prevent downgrade to lower version unless patches changed
                    if prev and prev.get("version"):
                        try:
                            from .tools import _version_key
                            if _version_key(version) < _version_key(str(prev.get("version"))):
                                patches_changed = any(prev.get("tags", {}).get(b) != state["bundles"].get(b, "") for b in combo)
                                if not patches_changed:
                                    log.info("%s %s [%s/%s]: skip downgrade from %s", short(package), version, combo_id(combo), arch, prev.get("version"))
                                    continue
                        except Exception:
                            pass
                    eff_res = (over.get("resolution") if over and "resolution" in over else None) or cfg.get("resolution", "xxxhdpi")
                    plan.append((app, combo, version, vc, arch, eff_res))

        cpu = os.cpu_count() or 4
        sem = asyncio.Semaphore(max(1, cpu))
        dl_cfg = cfg.get("clean", {}).get("download_concurrency", DOWNLOAD_CONCURRENCY) if isinstance(cfg.get("clean"), dict) else DOWNLOAD_CONCURRENCY
        play_sem = asyncio.Semaphore(max(1, min(dl_cfg, 3)))

        async def _build_with_sem(app, combo, version, vc, arch, resolution):
            async with sem:
                label = f"{short(app['package'])} {version} [{combo_id(combo)}/{arch}]"
                try:
                    # per-package locales override -> copy cfg with effective locales
                    eff_cfg = cfg
                    ov = overrides.get(app["package"]) if isinstance(overrides.get(app["package"]), dict) else None
                    if ov and "locales" in ov:
                        eff_cfg = {**cfg, "locales": ov["locales"]}
                    # Use play_sem for the fetch part inside build_one (via holder, but we wrap)
                    async with play_sem:
                        await build_one(session, holder, eff_cfg, state, app["package"], combo, version, vc, arch, summary, resolution)
                    log.info("built %s", label)
                    # Handle out latest-only: remove older version files for same package|cid|arch
                    try:
                        pattern = f"{short(app['package'])}-*-{combo_id(combo)}-{arch}.apk"
                        for old in OUT.glob(pattern):
                            if old.name != f"{short(app['package'])}-{version}-{combo_id(combo)}-{arch}.apk":
                                try:
                                    old.unlink()
                                    log.debug("pruned old out %s", old.name)
                                except Exception:
                                    pass
                    except Exception:
                        pass
                    if clean_after or cfg.get("clean", {}).get("full_clean") or cfg.get("full_clean"):
                        for p in [TMP / "dl" / app["package"] / f"{vc}-{arch}", TMP / "merged" / f"{app['package']}-{vc}-{arch}.apk", TMP / "merged" / f"{app['package']}-{vc}-{arch}.apk.tmp", TMP / "build" / app["package"]]:
                            try:
                                if p.is_dir():
                                    shutil.rmtree(p, ignore_errors=True)
                                elif p.is_file():
                                    p.unlink(missing_ok=True)
                            except Exception:
                                pass
                        log.info("cleaned tmp for %s (low-storage mode)", short(app["package"]))
                    between = cfg.get("clean", {}).get("between_builds_seconds", 0) if isinstance(cfg.get("clean"), dict) else 0
                    if between:
                        await asyncio.sleep(between)
                except Exception as exc:
                    log.error("failed %s: %s", label, exc)
                    summary["failed"].append((f"{app['package']}|{combo_id(combo)}|{arch}", str(exc)))

        await asyncio.gather(*[_build_with_sem(a, c, v, vc, arch, res) for a, c, v, vc, arch, res in plan])

        if summary["built"] and (cfg.get("release") or release_override):
            pending_tag = "p" + time.strftime("%Y%m%d-%H%M%S")
        try:
            if await fdroid.update(cfg, state, pending_tag):
                summary["fdroid"] = True
                summary["fdroid_url"] = (cfg.get("fdroid") or {}).get("url", "")
                summary["fdroid_fp"] = (state.get("fdroid") or {}).get("cert_sha256", "")
                save_state(state)
        except Exception as exc:
            log.error("fdroid index failed: %s", exc)
            summary["failed"].append(("f-droid index", str(exc)))
        try:
            if await pages.build_showcase(cfg, state):
                summary["pages"] = True
        except Exception as exc:
            log.error("pages showcase failed: %s", exc)

    commit = commit_override if commit_override is not None else bool(cfg.get("commit"))
    release = release_override if release_override is not None else bool(cfg.get("release"))
    if commit or release:
        await publish(summary, commit, release, pending_tag)

    for pkg_combo, why in summary["failed"]:
        log.error("FAILED %s: %s", pkg_combo, why)
    return summary


def _fmt_bundle_changes(changed: dict[str, tuple]) -> str:
    lines = []
    for name, (old, new) in sorted(changed.items()):
        lines.append(f"- **{name}**: {old or '(new)'} -> {new}")
    return "\n".join(lines) or "- (none)"


async def publish(summary: dict, commit: bool, release: bool, tag: str | None = None) -> None:
    state = load_state()
    if not summary["built"] and not summary["bundles"] and not summary.get("fdroid") and not summary.get("pages"):
        log.info("nothing changed; no commit or release")
        return
    stamp = tag or time.strftime("%Y%m%d-%H%M%S")
    tag = f"p{stamp}" if not stamp.startswith("p") else stamp
    parts = []
    if summary["bundles"]:
        bc = "; ".join(f"{n}: {o or 'new'}->{t}" for n, (o, t) in sorted(summary["bundles"].items()))
        parts.append(f"patches {bc}")
    if summary["tools"]:
        parts.append("; ".join(f"{n} -> {t}" for n, t in summary["tools"].items()))
    if summary["built"]:
        parts.append(f"build {', '.join(summary['built'])}")
    if summary["failed"]:
        parts.append(f"failed {len(summary['failed'])}")
    if summary.get("fdroid"):
        parts.append("fdroid index")
    if summary.get("pages"):
        parts.append("pages")

    if commit:
        try:
            await tools.commit_and_push(" | ".join(parts))
        except Exception as exc:
            log.error("commit/push failed: %s", exc)
            summary["failed"].append(("git", str(exc)))
    if release and summary["built"]:
        notes = (
            "## Upstream updates\n"
            f"{_fmt_bundle_changes(summary['bundles'])}\n\n"
            "## Built\n"
            + "\n".join(f"- {name}" for name in summary["built"])
            + f"\n\nFull release contains {len(state.get('builds', {}))} APKs (updated {len(summary['built'])} this cycle)"
        )
        if summary["tools"]:
            notes += "\n\n## Tools\n" + "\n".join(f"- {n}: {t}" for n, t in summary["tools"].items())
        if summary.get("fdroid"):
            notes += f"\n\n## F-Droid repo\n- URL: `{summary['fdroid_url']}`\n- fingerprint: `{summary['fdroid_fp']}`"
        # Latest release: full set (all APKs from state), not just updated
        # Past releases remain as log with only updated APKs, but latest always has all
        # No need to delete state.json to get full release when old releases are deleted
        files = []
        for e in state.get("builds", {}).values():
            apk = e.get("out")
            if apk and (OUT / apk).exists():
                files.append(OUT / apk)
        # Fallback: if state has no files on disk (e.g. after clean), use built list
        if not files:
            files = [OUT / name for name in summary["built"] if (OUT / name).exists()]
        try:
            await tools.create_release(tag, f"Patched apps {stamp}", notes, files)
        except Exception as exc:
            log.error("release failed: %s", exc)
            summary["failed"].append(("release", str(exc)))


async def self_update(cfg: dict) -> bool:
    """Pull origin/main and restart if human commits landed (ignoring morpheupdater bot commits).

    Returns True if restart was requested (caller should exit)."""
    if not cfg.get("self_update", True):
        return False
    try:
        # fetch only, no merge yet
        rc, out = await tools.run(["git", "fetch", "origin"], cwd=ROOT, timeout_s=60)
        if rc != 0:
            return False
        # list new origin/main commits not in HEAD, excluding bot
        rc, log_out = await tools.run(
            ["git", "log", "HEAD..origin/main", "--pretty=format:%H %an %s"], cwd=ROOT, timeout_s=30
        )
        if rc != 0 or not log_out.strip():
            return False
        human = [l for l in log_out.strip().splitlines() if "morpheupdater" not in l.lower()]
        if not human:
            # only bot commits (build/fdroid/pages) — we already have them via our own pushes
            # still rebase to keep history linear
            await tools.run(["git", "rebase", "origin/main"], cwd=ROOT, timeout_s=120)
            return False
        log.info("self-update: %d human commit(s) on origin/main, pulling", len(human))
        # stash including untracked icons/out (autostash), favour remote for generated out/
        await tools.run(["git", "stash", "push", "-m", "self-update", "--include-untracked"], cwd=ROOT, timeout_s=60)
        rc, out = await tools.run(["git", "rebase", "origin/main"], cwd=ROOT, timeout_s=180)
        if rc != 0:
            # conflicts (usually out/index.html from bot) — take remote for code, keep stash for icons
            log.warning("self-update rebase conflict, trying theirs for out/: %s", out[-300:])
            await tools.run(["git", "checkout", "--theirs", "--", "out/index.html", "out/index-v1.json", "out/index-v2.json"], cwd=ROOT, timeout_s=30)
            await tools.run(["git", "add", "-A", "out/"], cwd=ROOT, timeout_s=30)
            rc2, _ = await tools.run(["git", "rebase", "--continue"], cwd=ROOT, timeout_s=60)
            if rc2 != 0:
                await tools.run(["git", "rebase", "--abort"], cwd=ROOT, timeout_s=30)
                return False
        # restore stashed icons (no clobber)
        await tools.run(["git", "stash", "pop"], cwd=ROOT, timeout_s=60)
        log.info("self-update: updated to origin/main, restarting")
        # graceful restart: exit, systemd Restart=always will relaunch
        import os as _os
        import sys as _sys
        _sys.stdout.flush()
        _os._exit(42)
    except Exception as exc:
        log.warning("self-update failed: %s", exc)
        return False
    return False


async def loop() -> None:
    while True:
        started = time.monotonic()
        try:
            cfg = load_config()
            if await self_update(cfg):
                return
            await cycle()
        except KeyboardInterrupt:
            raise
        except SystemExit as e:
            # self-update exit code
            if e.code == 42:
                return
            raise
        except Exception:
            log.exception("cycle crashed")
        interval = max(60, load_config().get("interval_minutes", 30) * 60)
        waited = 0.0
        while waited < interval:
            await asyncio.sleep(min(15, interval - waited))
            waited = time.monotonic() - started
