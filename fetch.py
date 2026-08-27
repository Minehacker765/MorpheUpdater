#!/usr/bin/env python3
"""fetch.py — download an APK (+ splits) from Play and antisplit (merge) it.

Library reuse: Aurora dispenser (play.py:16), APKPure version→code (play.py:348),
Play delivery (play.py:285) and APKEditor merge (tools.py:322) via
daemon.ensure_merged.

Usage:
  uv run python fetch.py com.google.android.youtube
  uv run python fetch.py com.google.android.youtube 21.04.223
  uv run python fetch.py com.google.android.youtube 1561052632 --arch arm64 --out ./yt.apk
  uv run python fetch.py com.google.android.youtube --version 21.04.223 --locales en-US,es
"""

from __future__ import annotations

import argparse
import asyncio
import logging
import pathlib
import re
import shutil
import sys

from aiohttp import ClientSession, ClientTimeout

from morpheupdater.daemon import AuthHolder, ensure_merged
from morpheupdater import play
from morpheupdater.settings import ROOT, TMP, load_config, load_env

log = logging.getLogger("fetch")


def _is_version_code(s: str) -> bool:
    return bool(re.fullmatch(r"\d+", s or ""))


def _short(pkg: str) -> str:
    return pkg.rsplit(".", 1)[-1]


async def _resolve_version(
    session: ClientSession,
    holder: AuthHolder,
    package: str,
    version_arg: str | None,
    arch: str,
) -> tuple[int, str]:
    """Return (vc, dotted_version) for the requested version_arg.

    - version_arg is None  -> latest Play version (play.get_details)
    - digits only          -> treated as versionCode directly
    - else                 -> dotted version, resolved via APKPure (play.resolve_vc)
    """
    if version_arg is None:
        auth = await holder.get(session, arch)
        details = await play.get_details(session, auth, package)
        if not details.version_code:
            raise RuntimeError(f"Play returned no version for {package}")
        log.info("latest %s -> %s (vc %d)", package, details.version_string or "?", details.version_code)
        return details.version_code, details.version_string or str(details.version_code)

    if _is_version_code(version_arg):
        vc = int(version_arg)
        # try to reverse-lookup dotted for nice naming, best-effort
        try:
            codes = await play.fetch_version_codes(session, package)
            rev = {v: k for k, v in codes.items()}
            # there may be multiple dotted for same vc (store variants); pick first
            dotted = next((k for k, v in codes.items() if v == vc), version_arg)
            if dotted != version_arg:
                log.info("%s vc %d -> dotted %s (via APKPure)", package, vc, dotted)
                return vc, dotted
        except Exception:
            pass
        return vc, version_arg

    # dotted -> vc via APKPure (play.py:371)
    vc, _ = await play.resolve_vc(session, package, version_arg)
    log.info("%s %s -> vc %d (via APKPure)", package, version_arg, vc)
    return vc, version_arg


async def fetch_one(
    package: str,
    version_arg: str | None,
    arch: str,
    locales: list[str],
    out_path: pathlib.Path | None,
) -> pathlib.Path:
    cfg = load_config()
    # allow CLI locales override, else use config
    if locales:
        cfg["locales"] = locales
    editor_jar = ROOT / cfg["tools"]["apkeditor"]["local"]
    if not editor_jar.exists():
        log.warning("APKEditor jar not found at %s — will be fetched on demand", editor_jar)

    holder = AuthHolder()
    timeout = ClientTimeout(total=None, connect=15, sock_read=600)
    async with ClientSession(timeout=timeout) as session:
        vc, dotted = await _resolve_version(session, holder, package, version_arg, arch)
        log.info("fetching %s %s (vc %d) [%s] locales=%s", package, dotted, vc, arch, ",".join(cfg.get("locales", [])))
        merged, details = await ensure_merged(session, holder, cfg, editor_jar, package, vc, arch)
        # merged is TMP/merged/<pkg>-<vc>-<arch>.apk
        if out_path is None:
            # default: ./<short>-<dotted>.apk  (like youtube-21.04.223.apk)
            safe_dotted = re.sub(r"[^A-Za-z0-9._-]+", "_", dotted)
            out_path = pathlib.Path(f"{_short(package)}-{safe_dotted}.apk")
        out_path = out_path.resolve()
        out_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(merged, out_path)
        log.info("merged %d bytes -> %s", out_path.stat().st_size, out_path)
        if details and details.version_string:
            log.info("Play reports: %s (%s) vc %d", details.title or package, details.version_string, details.version_code)
        return out_path


def main() -> None:
    p = argparse.ArgumentParser(
        prog="fetch.py",
        description="Download an APK (+ splits) from Play and merge them with APKEditor.",
        epilog="Version can be dotted (21.04.223) — resolved to Play vc via APKPure — or a numeric versionCode. Omit to fetch the latest Play version.",
    )
    p.add_argument("package", help="Play package name, e.g. com.google.android.youtube")
    p.add_argument("version", nargs="?", default=None, help="dotted version (21.04.223) or versionCode (1561052632); omit for latest")
    p.add_argument("--version", dest="version_opt", default=None, help="same as positional version (explicit)")
    p.add_argument("--arch", default="arm64", help="device profile arch: arm64 (default), arm, x86, x86_64 (see profiles/)")
    p.add_argument("--locales", default=None, help="comma-separated locales, e.g. en-US,es (default from config.json)")
    p.add_argument("--out", dest="out", default=None, help="output merged APK path (default: ./<short>-<version>.apk)")
    p.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    args = p.parse_args()

    version_arg = args.version_opt if args.version_opt is not None else args.version
    locales = [s.strip() for s in args.locales.split(",") if s.strip()] if args.locales else []

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    load_env()

    # normalize arch alias
    arch = args.arch.strip().lower()
    if arch in ("arm64-v8a", "arm64_v8a"):
        arch = "arm64"

    out_path = pathlib.Path(args.out) if args.out else None

    try:
        result = asyncio.run(fetch_one(args.package, version_arg, arch, locales, out_path))
    except KeyboardInterrupt:
        print("interrupted", file=sys.stderr)
        raise SystemExit(130)
    except Exception as exc:
        log.error("fetch failed: %s", exc)
        if args.verbose:
            import traceback

            traceback.print_exc()
        raise SystemExit(1)
    print(result)


if __name__ == "__main__":
    main()
