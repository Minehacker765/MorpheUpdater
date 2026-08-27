"""Update loop: check patch sources -> update tools -> fetch/merge APKs -> patch."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import time
import zlib
from base64 import urlsafe_b64encode
from pathlib import Path

from aiohttp import ClientSession, ClientTimeout

from . import fdroid, pages, play, tools
from .settings import (
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
    validate_apps,
)

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


def short(package: str) -> str:
    return package.rsplit(".", 1)[-1]


def options_path(package: str, combo: list[str]) -> Path:
    return OPTIONS / f"{short(package)}.{combo_id(combo)}.json"


def clean_tmp(cfg: dict) -> None:
    TMP.mkdir(parents=True, exist_ok=True)
    max_mb = cfg["tmp_max_mb"]
    max_age_days = cfg["tmp_max_age_days"]
    size_mb = dir_size_mb(TMP)
    cutoff = now() - int(max_age_days * 86400)
    too_old = any(p.stat().st_mtime < cutoff for p in TMP.rglob("*") if p.is_file())
    if size_mb > max_mb or too_old:
        log.info("wiping tmp/ (size=%.0fMB max=%dMB old=%s)", size_mb, max_mb, too_old)
        shutil.rmtree(TMP)
        TMP.mkdir(parents=True, exist_ok=True)


# ── GitHub bundle checks ────────────────────────────────────────────────────


def _repo_from_url(url: str) -> str | None:
    if "github.com" not in url:
        return None
    parts = url.split("github.com/", 1)[1].strip("/").split("/")
    return "/".join(parts[:2])


async def check_bundles(session: ClientSession, cfg: dict, state: dict) -> dict[str, tuple]:
    changed: dict[str, tuple] = {}
    for name, url in cfg["bundles"].items():
        repo = _repo_from_url(url)
        if not repo:
            log.warning("bundle %s: cannot derive a GitHub repo from %s; assuming unchanged", name, url)
            continue
        try:
            release = await tools.gh_latest_prerelease(session, repo)
        except Exception as exc:
            log.warning("bundle %s: release check failed (%s); keeping %s", name, exc, state["bundles"].get(name, "?"))
            continue
        tag = release["tag_name"]
        old = state["bundles"].get(name)
        if old != tag:
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

    details = delivery = None
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
            raise RuntimeError(f"{exc}; consider a different --arch profile") from exc
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
        cache[key] = await tools.recommended_version(_jar(cfg, "morphe-desktop"), urls, package)
    return cache[key]


async def _resolve_vc(session: ClientSession, package: str, version: str, cache: dict) -> int:
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
    urls = [cfg["bundles"][b] for b in combo]
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


async def cycle(commit_override: bool | None = None, release_override: bool | None = None) -> dict:
    cfg = load_config()
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

        archs: list[str] = cfg["archs"] or ["arm64"]
        pending_tag: str | None = None
        plan: list[tuple[dict, list[str], str, int, str]] = []
        seen: set[tuple] = set()
        for app in cfg["apps"]:
            package = app["package"]
            for combo in app["combos"]:
                ident = (package, tuple(sorted(combo)))
                if ident in seen:
                    continue
                seen.add(ident)
                urls = [cfg["bundles"][b] for b in combo if b in cfg["bundles"]]
                if len(urls) != len(combo):
                    for arch in archs:
                        summary["failed"].append((f"{package}|{combo_id(combo)}|{arch}", "unknown bundle name"))
                    continue
                try:
                    version = await _recommended(cfg, urls, package, ver_cache)
                    if not version:
                        raise RuntimeError("no versions listed")
                    vc = await _resolve_vc(session, package, version, vc_cache)
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

        for idx, (app, combo, version, vc, arch) in enumerate(plan):
            label = f"{short(app['package'])} {version} [{combo_id(combo)}/{arch}]"
            if idx:
                await asyncio.sleep(10)
            try:
                await build_one(session, holder, cfg, state, app["package"], combo, version, vc, arch, summary)
                log.info("built %s", label)
            except Exception as exc:
                log.error("failed %s: %s", label, exc)
                summary["failed"].append((f"{app['package']}|{combo_id(combo)}|{arch}", str(exc)))

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
            if pages.build_showcase(cfg, state):
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
        )
        if summary["tools"]:
            notes += "\n\n## Tools\n" + "\n".join(f"- {n}: {t}" for n, t in summary["tools"].items())
        if summary.get("fdroid"):
            notes += f"\n\n## F-Droid repo\n- URL: `{summary['fdroid_url']}`\n- fingerprint: `{summary['fdroid_fp']}`"
        files = [OUT / name for name in summary["built"]]
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
