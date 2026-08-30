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
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout

from . import fdroid, pages, play, tools
from .display import CLONE_PACKAGE_MAP, SHORT_TO_PACKAGE, TV_PACKAGES
from .profiles import get_priority_profiles
from .settings import (
    ICONS,
    MORPHE_DATA,
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
from .tools import apk_info

log = logging.getLogger("daemon")

DOWNLOAD_CONCURRENCY = 4


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
    cutoff = now() - int(max_age_days * 86400)
    too_old = any(p.stat().st_mtime < cutoff for p in TMP.rglob("*") if p.is_file())
    # Check free space
    try:
        free_gb = shutil.disk_usage(ROOT).free / (1024**3)
        low_space = free_gb < min_free_gb
    except Exception:
        low_space = False
        free_gb = 0
    if size_mb > max_mb or too_old or low_space:
        log.info("wiping tmp/ (size=%.0fMB max=%dMB old=%s free=%.1fGB min=%dGB)", size_mb, max_mb, too_old, free_gb, min_free_gb)
        shutil.rmtree(TMP)
        TMP.mkdir(parents=True, exist_ok=True)


async def prune_tmp(cfg: dict, dry_run: bool = False, remove_dupes: bool = False) -> int:
    """LRU prune tmp/ until size < max and no old files, or just dupes. Returns deleted count."""
    TMP.mkdir(parents=True, exist_ok=True)
    max_mb = cfg.get("tmp_max_mb", 2048)
    max_age_days = cfg.get("tmp_max_age_days", 7)
    cutoff = now() - int(max_age_days * 86400)
    files = [p for p in TMP.rglob("*") if p.is_file()]
    # Sort by mtime (oldest first) for LRU
    files.sort(key=lambda p: p.stat().st_mtime)
    deleted = 0
    size_mb = dir_size_mb(TMP)
    for p in files:
        is_old = p.stat().st_mtime < cutoff
        is_dup = remove_dupes and p.suffix == ".part"
        # Delete if old, or if dupes flag and it's a .part, or if size still over max
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
    # Also handle morphe-data duplicate cache
    if remove_dupes:
        for dup in [ROOT / "morphe-data", ROOT / "bin" / "morphe-data"]:
            if dup.exists():
                # Keep only bin/morphe-data as canonical, delete old morphe-data if duplicate
                if dup == ROOT / "morphe-data" and (ROOT / "bin" / "morphe-data").exists():
                    if dry_run:
                        log.info("[dry-run] would delete duplicate %s", dup)
                    else:
                        try:
                            shutil.rmtree(dup)
                            deleted += 1
                        except Exception:
                            pass
    if deleted:
        log.info("prune_tmp deleted %d files", deleted)
    return deleted


async def prune_out(cfg: dict, dry_run: bool = False, remove_dupes: bool = False) -> int:
    """Ensure out/ only has latest APK per package|combo|arch. Returns deleted count."""
    from collections import defaultdict
    state = load_state()
    # Group by package|cid|arch -> keep only latest per state, delete older version files
    keep = set()
    for e in state.get("builds", {}).values():
        apk = e.get("out")
        if apk:
            keep.add(apk)
    # Also check actual files in out/
    deleted = 0
    for apk in OUT.glob("*.apk"):
        if apk.name not in keep:
            # Check if it's an old version for a package that has newer in keep
            # Use short to group
            is_old_dup = False
            if remove_dupes:
                # If dupes flag, delete any file not in keep (old versions)
                is_old_dup = True
            if is_old_dup or apk.name not in keep:
                if dry_run:
                    log.info("[dry-run] would delete out %s (not in keep)", apk.name)
                else:
                    try:
                        apk.unlink()
                        deleted += 1
                    except Exception:
                        pass
    # Also handle duplicate old version files for same package (keep only latest per short|cid|arch)
    if remove_dupes or True:  # always enforce latest-only
        grouped = defaultdict(list)
        for apk in OUT.glob("*.apk"):
            # Parse package short and version from filename: short-version-cid-arch.apk
            # Use state to find latest, but fallback to mtime
            grouped[apk.name.split("-")[0]].append(apk)
        for short_name, files in grouped.items():
            if len(files) > 1:
                # Keep only newest by mtime (which should correspond to latest state)
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


def _get_local_mpp(bundle_name: str, url: str) -> Path | None:
    """Return cached MPP file for bundle if present (avoids GitHub API rate limit)."""
    if "github.com" not in url:
        return None
    try:
        repo = _repo_from_url(url) or ""
        sanitized = repo.replace("/", "-")
        cache_dir = ROOT / "bin" / "morphe-data" / "patches" / sanitized
        if not cache_dir.exists():
            return None
        mpps = list(cache_dir.glob("*.mpp"))
        mpps = [p for p in mpps if not p.name.endswith(".part")]
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


def _get_patch_inputs(cfg: dict, combo: list[str]) -> list[str]:
    """Return patch inputs for morphe-desktop: prefer local MPP cache to avoid GitHub rate limit."""
    inputs = []
    for b in combo:
        spec = cfg["bundles"].get(b, "")
        url = spec if isinstance(spec, str) else spec.get("url", "")
        if not url:
            continue
        local = _get_local_mpp(b, url)
        if local and local.exists():
            inputs.append(str(local))
        else:
            inputs.append(url)
    return inputs


def _get_bundle_urls(cfg: dict, combo: list[str]) -> list[str]:
    urls = []
    for b in combo:
        spec = cfg["bundles"].get(b, "")
        url = spec if isinstance(spec, str) else spec.get("url", "")
        if url:
            urls.append(url)
    return urls


def _enable_all_patches(options_file: Path) -> int:
    """Set enabled=true for every patch in options file, except Clone and known broken. Returns count changed."""
    BROKEN = {
        "com.facebook.katana": {"Hide 'Sponsored Stories'"},
        "com.facebook.orca": set(),
    }
    pkg_hint = options_file.name.split(".")[0]
    broken_for_this = BROKEN.get(SHORT_TO_PACKAGE.get(pkg_hint, ""), set())
    if not options_file.exists():
        return 0
    try:
        data = json.loads(options_file.read_text())
    except Exception:
        return 0
    changed = 0
    entries = data if isinstance(data, list) else [data]
    for entry in entries:
        patches = entry.get("patches") if isinstance(entry, dict) else None
        if not isinstance(patches, dict):
            continue
        for name, opts in patches.items():
            if "Clone" in name or "Change package name" in name:
                if isinstance(opts, dict) and opts.get("enabled"):
                    opts["enabled"] = False
                    changed += 1
                continue
            if name in broken_for_this:
                if isinstance(opts, dict) and opts.get("enabled"):
                    opts["enabled"] = False
                    changed += 1
                continue
            if isinstance(opts, dict) and "enabled" in opts:
                if not opts["enabled"]:
                    opts["enabled"] = True
                    changed += 1
    if changed:
        if isinstance(data, list):
            options_file.write_text(json.dumps(data, indent=4) + "\n")
        else:
            options_file.write_text(json.dumps(data, indent=4) + "\n")
    return changed


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


async def _fetch_splits(session: ClientSession, holder: AuthHolder, cfg: dict, package: str, vc: int, dest_dir: Path, arch: str) -> play.Details:

    async def flow(auth: dict):
        details = await play.get_details(session, auth, package)
        token = await play.purchase(session, auth, package, vc)
        delivery = await play.get_delivery(
            session, auth, package, vc, cfg.get("locales", ["en-US", "es"]), token
        )
        return details, delivery

    profiles = [p for _, p in get_priority_profiles(arch)]
    # also include holder's cached profile first for speed
    tried: set[str] = set()
    details = delivery = None
    last_exc: Exception | None = None
    # attempt up to 4 tries per profile, but overall try each profile
    for prof in profiles:
        # try to get auth for this specific profile (bypass holder cache)
        try:
            # _post_profile directly to avoid holder's first-profile bias
            auth = await play._post_profile(session, play.DISPENSER, prof)
            if not auth or isinstance(auth, play.PlayError):
                # fall back to holder's generic token
                auth = await holder.get(session, arch)
            # quick check that this profile can see the package
            details, delivery = await flow(auth)
            # cache successful auth for next time
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
            # try next profile for same arch before giving up
            log.debug("%s vc %d not supported on profile %s, trying next", short(package), vc, prof.get("deviceInfoProvider", {}).get("product", "?")[:20])
            continue
        except play.PlayError as e:
            # unparseable delivery etc. — try next profile
            last_exc = e
            continue
    else:
        # no profile succeeded, fall back to original 4-attempt logic with holder for RateLimit etc.
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

    sem = asyncio.Semaphore(DOWNLOAD_CONCURRENCY)
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
) -> tuple[Path, play.Details | None]:
    dl_dir = TMP / "dl" / package / f"{vc}-{arch}"
    merged = TMP / "merged" / f"{package}-{vc}-{arch}.apk"
    details = None
    if not merged.exists():
        done_marker = dl_dir / ".complete"
        if not done_marker.exists():
            details = await _fetch_splits(session, holder, cfg, package, vc, dl_dir, arch)
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
    info = await apk_info(ROOT / "bin" / "apkeditor.jar", dest)
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
    info = await apk_info(ROOT / "bin" / "apkeditor.jar", dest)
    if not info:
        raise RuntimeError("failed to get AdGuard info")
    pkg, ver, vc, _ = info
    # verify package is correct
    if pkg != "com.adguard.android":
        log.warning("AdGuard package mismatch: %s", pkg)
    return ver, vc, dest


async def _resolve_vc(session: ClientSession, package: str, version: str, cache: dict, arch: str = "arm64") -> int:
    # use fallback that handles no Pure history and brute-force for TV etc.
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
) -> None:
    cid = combo_id(combo)
    urls = _get_bundle_urls(cfg, combo)
    missing = [b for b in combo if b not in cfg["bundles"]]
    if missing:
        raise RuntimeError(f"unknown bundle(s) in combo: {', '.join(missing)}")

    merged, details = await ensure_merged(session, holder, cfg, _jar(cfg, "apkeditor"), package, vc, arch)
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
        import logging as _log
        _log.getLogger("daemon").info("single-app mode: %s (%d -> %d apps)", app_filter, orig_len, len(cfg["apps"]))
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
        # TV apks should build if tv is in global archs; filter tv for non-TV packages
        global_archs: list[str] = cfg["archs"] or ["arm64"]
        pending_tag: str | None = None
        plan: list[tuple[dict, list[str], str, int, str]] = []
        seen: set[tuple] = set()
        for app in cfg["apps"]:
            package = app["package"]
            # per-app archs override (e.g. TV apps use armv7); if tv in global but package not TV, filter it
            archs = app.get("archs") or global_archs
            if "tv" in archs and package not in TV_PACKAGES and not app.get("archs"):
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
                        version, vc, _ = await _fetch_microg(session, cfg)
                    except Exception as exc:
                        for arch in archs:
                            summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", str(exc)))
                        continue
                    # MicroG has no arch splits, single apk
                    for arch in archs:
                        key = f"{package}|{combo_id(combo)}|{arch}"
                        prev = state["builds"].get(key)
                        # use version as-is, arch is still part of key for consistency
                        out = OUT / f"microg-{version}-{arch}.apk"
                        up_to_date = prev and prev.get("version") == version and out.exists()
                        if up_to_date:
                            log.info("MicroG %s [%s]: up to date", version, arch)
                            continue
                        # copy direct apk to out
                        import shutil as _sh
                        _sh.copyfile(_ , out)
                        state["builds"][key] = {"package": package, "version": version, "vc": vc, "arch": arch, "app_name": "MicroG", "tags": {"microg": version}, "out": out.name, "at": now()}
                        save_state(state)
                        summary["built"].append(out.name)
                    continue
                # AdGuard is direct from adguardcdn.com (not on Play)
                if package == "com.adguard.android":
                    try:
                        version, vc, _ = await _fetch_adguard(session)
                    except Exception as exc:
                        for arch in archs:
                            summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", str(exc)))
                        continue
                    for arch in archs:
                        key = f"{package}|{combo_id(combo)}|{arch}"
                        prev = state["builds"].get(key)
                        out = OUT / f"adguard-{version}-{arch}.apk"
                        up_to_date = prev and prev.get("version") == version and out.exists()
                        if up_to_date:
                            log.info("AdGuard %s [%s]: up to date", version, arch)
                            continue
                        import shutil as _sh2
                        _sh2.copyfile(_, out)
                        state["builds"][key] = {"package": package, "version": version, "vc": vc, "arch": arch, "app_name": "AdGuard", "tags": {"hoodles": state["bundles"].get("hoodles", "")}, "out": out.name, "at": now()}
                        save_state(state)
                        summary["built"].append(out.name)
                    continue

                try:
                    version = await _recommended(cfg, urls, package, ver_cache)
                    if not version or version.strip().lower() == "any":
                        # universal patches (Any) -> use latest Play version
                        auth_tmp = await holder.get(session, archs[0])
                        det_tmp = await play.get_details(session, auth_tmp, package)
                        if not det_tmp.version_code:
                            raise RuntimeError("no versions listed and Play details failed for universal patch")
                        version = det_tmp.version_string or str(det_tmp.version_code)
                        log.info("%s: universal patches, using latest Play %s", short(package), version)
                    try:
                        vc = await _resolve_vc(session, package, version, vc_cache, archs[0])
                    except Exception as e:
                        # Pure has no history for this package (e.g. TV livingroom) -> fallback to latest Play
                        if "no versions found" in str(e):
                            auth_tmp = await holder.get(session, archs[0])
                            det_tmp = await play.get_details(session, auth_tmp, package)
                            if det_tmp.version_code:
                                log.info("%s: no Pure history, using latest Play %s (%d) for %s", short(package), det_tmp.version_string, det_tmp.version_code, version)
                                version = det_tmp.version_string
                                vc = det_tmp.version_code
                                vc_cache[package] = {version: vc}
                            else:
                                raise
                        else:
                            raise
                except Exception as exc:
                    for arch in archs:
                        summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", str(exc)))
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
                    plan.append((app, combo, version, vc, arch))

        # Parallel patching: morphe is single-core, so run up to cpu_count in parallel via asyncio subprocess pool
        import os as _os
        cpu = _os.cpu_count() or 4
        # Respect clean config: if full_clean, use more aggressive cleanup; else keep tmp for speed
        sem = asyncio.Semaphore(max(1, cpu))
        # Also limit concurrent Play downloads to avoid dispenser rate limit
        play_sem = asyncio.Semaphore(3)

        async def _build_with_sem(app, combo, version, vc, arch):
            async with sem:
                label = f"{short(app['package'])} {version} [{combo_id(combo)}/{arch}]"
                try:
                    # Use play_sem for the fetch part inside build_one (via holder, but we wrap)
                    async with play_sem:
                        await build_one(session, holder, cfg, state, app["package"], combo, version, vc, arch, summary)
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
                except Exception as exc:
                    log.error("failed %s: %s", label, exc)
                    summary["failed"].append((f"{app['package']}|{combo_id(combo)}|{arch}", str(exc)))

        await asyncio.gather(*[_build_with_sem(a, c, v, vc, arch) for a, c, v, vc, arch in plan])

        if summary["built"] and (cfg.get("release") or release_override):
            pending_tag = "p" + __import__("time").strftime("%Y%m%d-%H%M%S")
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


async def loop() -> None:
    while True:
        started = time.monotonic()
        try:
            await cycle()
        except KeyboardInterrupt:
            raise
        except Exception:
            log.exception("cycle crashed")
        interval = max(60, load_config().get("interval_minutes", 30) * 60)
        waited = 0.0
        while waited < interval:
            await asyncio.sleep(min(15, interval - waited))
            waited = time.monotonic() - started
