"""F-Droid repository generation: scans out/, extracts per-APK metadata,
builds index-v1.json (+signed .jar) and index-v2.json (+signed .jar) with
icons at repo/icons/<pkg>.png (v1 top-level `icon` -> /icons/; v2 fileEntry)."""

from __future__ import annotations

import base64
import hashlib
import json
import logging
import re
import struct
import subprocess
import time
import zipfile
from pathlib import Path

from . import tools
from .settings import OUT, ROOT

log = logging.getLogger("fdroid")

RES_STRING_POOL = 0x0001
RES_XML_START_ELEMENT = 0x0102


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _file_entry(path: Path, name_override: str | None = None) -> dict:
    """Mimic fdroidserver/common.file_entry: {name, sha256, size} with leading slash."""
    sha = _sha256_file(path)
    size = path.stat().st_size
    name = name_override if name_override is not None else f"/icons/{path.name}"
    # repo expects leading slash for v2
    if not name.startswith("/"):
        name = "/" + name
    return {"name": name, "sha256": sha, "size": size}


# ── minimal AXML parsing for <uses-sdk> ─────────────────────────────────────


def _read_pooled_len(data: bytes, i: int, wide: bool) -> tuple[int, int]:
    if wide:
        n = struct.unpack_from("<H", data, i)[0]
        i += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, i)[0]
            i += 2
        return n, i
    n = data[i]
    i += 1
    if n & 0x80:
        n = ((n & 0x7F) << 8) | data[i]
        i += 1
    return n, i


def _pool_strings(data: bytes, off: int) -> list[str]:
    string_count, _styles, flags, strings_start, _ss = struct.unpack_from(
        "<IIIII", data, off + 8
    )
    utf8 = bool(flags & 0x100)
    offsets = struct.unpack_from(f"<{string_count}I", data, off + 28)
    base = off + strings_start
    out: list[str] = []
    for o in offsets:
        i = base + o
        try:
            if utf8:
                _u16len, i = _read_pooled_len(data, i, False)
                blen, i = _read_pooled_len(data, i, False)
                out.append(data[i : i + blen].decode("utf-8", "replace"))
            else:
                n, i = _read_pooled_len(data, i, True)
                out.append(data[i : i + n * 2].decode("utf-16-le", "replace"))
        except Exception:
            out.append("")
    return out


def parse_manifest_sdk(apk: Path) -> tuple[int | None, int | None]:
    """(minSdkVersion, targetSdkVersion) from AndroidManifest.xml."""
    try:
        with zipfile.ZipFile(apk) as z:
            data = z.read("AndroidManifest.xml")
    except Exception:
        return None, None

    strings: list[str] = []
    pos = 8
    while pos + 8 <= len(data):
        ctype, _hdr, size = struct.unpack_from("<HHI", data, pos)
        if size <= 0 or pos + size > len(data):
            break
        if ctype == RES_STRING_POOL and not strings:
            strings = _pool_strings(data, pos)
        elif ctype == RES_XML_START_ELEMENT and strings:
            _ns, name_idx, attr_start, attr_size, attr_count = struct.unpack_from(
                "<IIHHH", data, pos + 16
            )
            name = strings[name_idx] if name_idx < len(strings) else ""
            if name == "uses-sdk":
                found: dict[str, int] = {}
                for i in range(attr_count):
                    base = pos + 16 + attr_start + i * attr_size
                    _a_ns, a_name, _raw = struct.unpack_from("<III", data, base)
                    _tsize, _tres, dtype = struct.unpack_from("<HBB", data, base + 12)
                    tdata = struct.unpack_from("<I", data, base + 16)[0]
                    key = strings[a_name] if a_name < len(strings) else ""
                    if dtype == 0x10 and key:
                        found[key] = tdata
                return found.get("minSdkVersion"), found.get("targetSdkVersion")
        pos += size
    return None, None


# ── icon extraction ─────────────────────────────────────────────────────────

_DPI_RANK = {"xxxhdpi": 5, "xxhdpi": 4, "xhdpi": 3, "hdpi": 2, "mdpi": 1, "ldpi": 0}


def _fallback_microg_icon(dest: Path) -> str | None:
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        import struct, zlib
        w = h = 512
        try:
            from PIL import Image, ImageDraw, ImageFont  # type: ignore
            im = Image.new("RGB", (w, h), "#1e1e1e")
            d = ImageDraw.Draw(im)
            d.ellipse([96, 96, 416, 416], fill="#3DDC84")
            try:
                d.text((w//2, h//2), "μG", fill="white", anchor="mm", font=ImageFont.load_default())
            except Exception:
                pass
            im.save(dest, "PNG")
            return dest.name
        except Exception:
            pass
        import base64
        dest.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="))
        return dest.name
    except Exception:
        return None


def extract_icon(apk: Path, dest: Path) -> str | None:
    if "microg" in apk.name.lower() and "noicon" in apk.name.lower():
        fb = _fallback_microg_icon(dest)
        if fb:
            return fb
    try:
        with zipfile.ZipFile(apk) as z:
            candidates = []
            for name in z.namelist():
                low = name.lower()
                if not low.endswith((".png", ".webp")):
                    continue
                if "ic_launcher" not in low and "morphe_adaptive" not in low:
                    continue
                m = re.search(r"-(xxxhdpi|xxhdpi|xhdpi|hdpi|mdpi|ldpi)", low)
                rank = _DPI_RANK.get(m.group(1), 0) if m else 0
                plain = 1 if re.search(r"ic_launcher\.png$", low) else 0
                fg = 1 if "foreground" in low else 0
                score = (plain, fg, rank, z.getinfo(name).file_size)
                candidates.append((score, name))
            if not candidates:
                for name in z.namelist():
                    low = name.lower()
                    if not low.endswith((".png", ".webp")) or "mipmap" not in low:
                        continue
                    m = re.search(r"-(xxxhdpi|xxhdpi|xhdpi|hdpi|mdpi)", low)
                    rank = _DPI_RANK.get(m.group(1), 0) if m else 0
                    candidates.append(((0, 0, rank, z.getinfo(name).file_size), name))
            if not candidates:
                if "microg" in apk.name.lower() or "mgoogle" in dest.name.lower():
                    return _fallback_microg_icon(dest)
                return None
            best = max(candidates, key=lambda x: x[0])[1]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(z.read(best))
            return dest.name
    except Exception as exc:
        log.warning("icon extraction from %s failed: %s", apk.name, exc)
        if "microg" in apk.name.lower() or "mgoogle" in dest.name.lower():
            return _fallback_microg_icon(dest)
        return None


# ── repo certificate fingerprint ────────────────────────────────────────────


async def cert_fingerprint(creds: dict) -> tuple[str, str] | None:
    """(base64-of-sha256(cert-DER), hex-sha256-fingerprint)."""
    cmd = ["keytool", "-list", "-v", "-keystore", creds["path"], "-storepass", creds["store_pw"]]
    if creds["alias"]:
        cmd += ["-alias", creds["alias"]]
    rc, out = await tools.run(cmd)
    m = re.search(r"SHA256:\s*([0-9A-Fa-f:]+)", out)
    if rc != 0 or not m:
        log.warning("could not read repo certificate: %s", out.strip().splitlines()[-1][:120])
        return None
    hex_fp = m.group(1).replace(":", "").lower()
    b64 = base64.b64encode(bytes.fromhex(hex_fp)).decode()
    return b64, hex_fp


# ── index build ─────────────────────────────────────────────────────────────


def sign_index(index_json: Path, creds: dict) -> None:
    import tempfile

    jar_path = index_json.with_suffix(".jar")
    if not creds["alias"]:
        raise RuntimeError("KEYSTORE_ENTRY_ALIAS is required for the F-Droid index")
    with tempfile.TemporaryDirectory() as td:
        staged = Path(td) / index_json.name
        staged.write_bytes(index_json.read_bytes())
        jar_tmp = Path(td) / jar_path.name

        subprocess.run(
            ["jar", "--create", "--file", str(jar_tmp), "-C", str(td), index_json.name],
            check=True,
        )
        cmd = [
            "jarsigner",
            "-keystore", creds["path"],
            "-storepass", creds["store_pw"],
        ]
        if creds["entry_pw"]:
            cmd += ["-keypass", creds["entry_pw"]]
        proc = subprocess.run(cmd + [str(jar_tmp), creds["alias"]], capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError(f"jarsigner failed:\n{proc.stdout[-400:]}{proc.stderr[-400:]}")
        jar_path.write_bytes(jar_tmp.read_bytes())


def _ensure_repo_icon() -> str:
    """Ensure out/icons/icon.png exists for repo.icon; return filename."""
    icons_dir = OUT / "icons"
    icons_dir.mkdir(parents=True, exist_ok=True)
    repo_icon = icons_dir / "icon.png"
    if repo_icon.exists():
        return repo_icon.name
    # Prefer an existing app icon as repo icon, else generate a tiny fallback
    for cand in sorted(icons_dir.glob("*.png")):
        # skip the generic mgoogle fallback if possible, pick first real
        if cand.name != "icon.png":
            try:
                import shutil
                shutil.copyfile(cand, repo_icon)
                return repo_icon.name
            except Exception:
                pass
    # fallback: create 1x1
    try:
        import base64
        repo_icon.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="))
    except Exception:
        pass
    return repo_icon.name if repo_icon.exists() else "icon.png"


def build_index(cfg: dict, state: dict, tag: str | None = None) -> bool:
    """Regenerate out/index-v1.json (+signed .jar) and out/index-v2.json when contents changed."""
    editor_jar = ROOT / cfg["tools"]["apkeditor"]["local"]
    meta = cfg.get("fdroid") or {}
    by_out = {e.get("out"): e for e in state["builds"].values() if e.get("out")}
    creds = tools.resolve_signing()

    fdroid_state = state.get("fdroid") or {}
    signer_hex = fdroid_state.get("cert_sha256", "")
    sig = signer_hex[:8] if signer_hex else ""
    packages: dict[str, list[dict]] = {}
    apps: dict[str, dict] = {}

    # Keep previous index's packages as fallback when APK missing locally (APKs are gitignored)
    prev_packages: dict[str, list[dict]] = {}
    prev_apps: dict[str, dict] = {}
    existing_path = OUT / "index-v1.json"
    if existing_path.exists():
        try:
            prev = json.loads(existing_path.read_text())
            for pkg, lst in prev.get("packages", {}).items():
                prev_packages[pkg] = lst
            for app in prev.get("apps", []):
                prev_apps[app.get("packageName")] = app
        except Exception:
            pass

    # Collect APKs: try from out/*.apk, else from state builds (so index doesn't vanish)
    apk_files = sorted(OUT.glob("*.apk"))
    # If no APKs on disk but we have a previous index, reuse it (APKs are gitignored and live on releases)
    if not apk_files:
        if prev_packages and prev_apps:
            packages = {k: v for k, v in prev_packages.items()}
            apps = {k: v for k, v in prev_apps.items()}
            log.info("index: no APKs on disk, reusing previous index (%d packages)", len(packages))
            # Fix legacy indexes that put icon in localized (wrong path for our icons/ layout)
            for pkg, app in list(apps.items()):
                loc = app.get("localized", {}).get("en-US", {})
                loc_icon = loc.get("icon")
                top_icon = app.get("icon")
                if loc_icon and not top_icon:
                    # icon was in localized but file is actually in icons/ -> move to top-level
                    if (OUT / "icons" / loc_icon).exists():
                        app["icon"] = loc_icon
                        loc.pop("icon", None)
                elif loc_icon and top_icon and loc_icon == top_icon:
                    # duplicate: keep only top-level
                    loc.pop("icon", None)
        elif state.get("builds"):
            for key, entry in state["builds"].items():
                apk_name = entry.get("out") or ""
                if not apk_name:
                    continue
                raw_pkg = entry.get("package", key.split("|")[0])
                # normalize clones: mgoogle -> revanced, google youtube -> morphe
                pkg = {
                    "com.mgoogle.android.gms": "app.revanced.android.gms",
                    "com.google.android.youtube": "app.morphe.android.youtube",
                    "com.google.android.apps.youtube.music": "app.morphe.android.apps.youtube.music",
                    "com.chess": "com.chess.prathxm",
                }.get(raw_pkg, raw_pkg)
                if pkg in prev_packages:
                    packages[pkg] = prev_packages[pkg]
                    if pkg not in apps and pkg in prev_apps:
                        apps[pkg] = prev_apps[pkg]
                    continue
                # also try raw key
                if raw_pkg in prev_packages:
                    packages[pkg] = prev_packages[raw_pkg]
                    if pkg not in apps and raw_pkg in prev_apps:
                        apps[pkg] = prev_apps[raw_pkg]
                        apps[pkg]["packageName"] = pkg
                    continue
                log.warning("index: no APK and no prev entry for %s (%s); skipping until APK present", pkg, apk_name)
        else:
            log.warning("index: no APKs and no previous index")
    if apk_files:
        for apk in apk_files:
            entry = by_out.get(apk.name) or {}
            try:
                info = tools.apk_info(editor_jar, apk)
            except Exception:
                info = None
            if info:
                package, version, vc, app_name_real = info
                # normalize package: mgoogle clone
                if package == "com.mgoogle.android.gms":
                    package = "app.revanced.android.gms"
                disp_map = {"com.google.android.youtube": "YouTube", "app.morphe.android.youtube": "YouTube", "com.google.android.apps.youtube.music": "YouTube Music", "app.morphe.android.apps.youtube.music": "YouTube Music", "com.reddit.frontpage": "Reddit", "com.chess": "Chess", "com.chess.prathxm": "Chess", "com.mgoogle.android.gms": "MicroG", "app.revanced.android.gms": "MicroG"}
                app_name = disp_map.get(package) or disp_map.get(entry.get("package","")) or app_name_real or package.rsplit(".", 1)[-1].capitalize()
            else:
                if not (entry.get("package") and entry.get("version") and entry.get("vc")):
                    log.warning("index: skipping %s (no metadata)", apk.name)
                    continue
                package, version, vc = entry["package"], entry["version"], int(entry["vc"])
                if package == "com.mgoogle.android.gms":
                    package = "app.revanced.android.gms"
                disp_map2 = {"com.google.android.youtube": "YouTube", "app.morphe.android.youtube": "YouTube", "com.google.android.apps.youtube.music": "YouTube Music", "app.morphe.android.apps.youtube.music": "YouTube Music", "com.reddit.frontpage": "Reddit", "com.chess": "Chess", "com.chess.prathxm": "Chess", "com.mgoogle.android.gms": "MicroG", "app.revanced.android.gms": "MicroG"}
                app_name = disp_map2.get(package) or entry.get("app_name") or package.rsplit(".", 1)[-1].capitalize()

            min_sdk, target_sdk = parse_manifest_sdk(apk)
            apk_name = apk.name
            pkg_entry: dict = {
                "added": int(time.time() * 1000),
                "apkName": apk_name,
                "hash": _sha256_file(apk),
                "hashType": "sha256",
                "packageName": package,
                "versionCode": vc,
                "versionName": version,
                "size": apk.stat().st_size,
            }
            if app_name:
                pkg_entry["appName"] = app_name
            if min_sdk:
                pkg_entry["minSdkVersion"] = min_sdk
            if target_sdk:
                pkg_entry["targetSdkVersion"] = target_sdk
            if signer_hex:
                pkg_entry["signer"] = signer_hex
                pkg_entry["sig"] = sig
            packages.setdefault(package, []).append(pkg_entry)

            icon_file = f"{package}.png"
            icon_rel = icon_file
            # ensure icon exists at out/icons/<package>.png
            icon_path = OUT / "icons" / icon_file
            if not icon_path.exists():
                got = extract_icon(apk, icon_path)
                if got:
                    icon_rel = got
                else:
                    # keep icon_rel as filename; file may be fallback microg
                    if icon_path.exists():
                        icon_rel = icon_path.name
                    else:
                        icon_rel = ""
            else:
                icon_rel = icon_path.name

            display = app_name.removesuffix(" Morphe")
            summary = f"{display} patched with Morphe"
            # For v1, prefer top-level `icon` (legacy /icons/ path) and keep
            # localized without icon so fdroidclient doesn't look in /$pkg/en-US/
            en: dict = {"name": app_name, "summary": summary, "description": summary}
            if package not in apps:
                apps[package] = {
                    "packageName": package,
                    "name": app_name,
                    "localized": {"en-US": en},
                }
                if icon_rel:
                    apps[package]["icon"] = icon_rel
            else:
                # ensure icon present if missing earlier
                if icon_rel and "icon" not in apps[package]:
                    apps[package]["icon"] = icon_rel

    # If we fell back to prev_packages path above, ensure apps have icon fields
    if not packages and prev_packages:
        packages = prev_packages
        apps = prev_apps
        # retro-fix missing top-level icon for apps that only have localized.icon
        for pkg, app in list(apps.items()):
            loc_icon = app.get("localized", {}).get("en-US", {}).get("icon")
            if loc_icon and "icon" not in app:
                # move from localized to top-level if file is in icons/
                if (OUT / "icons" / loc_icon).exists():
                    app["icon"] = loc_icon
                    # remove from localized to avoid fdroidclient's /$pkg/en-US/ lookup
                    app["localized"]["en-US"].pop("icon", None)
            # ensure icon file exists; otherwise fallback microg
            if "icon" not in app:
                icon_path = OUT / "icons" / f"{pkg}.png"
                if not icon_path.exists():
                    # try to create fallback for microg
                    if "microg" in pkg or "mgoogle" in pkg:
                        _fallback_microg_icon(icon_path)
                        if icon_path.exists():
                            app["icon"] = icon_path.name
                elif icon_path.exists():
                    app["icon"] = icon_path.name

    # Ensure every app has a top-level icon pointing to icons/...
    for pkg, app in apps.items():
        if "icon" not in app:
            # try to find existing icon file
            icon_path = OUT / "icons" / f"{pkg}.png"
            if icon_path.exists():
                app["icon"] = icon_path.name
            else:
                # for packages that never had APK locally, ensure fallback from prev or create
                got = None
                if "microg" in pkg:
                    got = _fallback_microg_icon(icon_path)
                if got:
                    app["icon"] = got
                elif icon_path.exists():
                    app["icon"] = icon_path.name

    repo_icon = _ensure_repo_icon()
    repo: dict = {
        "name": meta.get("name", "morpheupdater"),
        "description": meta.get("description", "Patched apps"),
        "timestamp": int(time.time() * 1000),
        "version": 20001,
        "maxage": 0,
        "packages": {},
        "icon": repo_icon,
    }
    if meta.get("url"):
        repo["address"] = meta["url"]
    # sort packages for determinism
    for k in packages:
        packages[k] = sorted(packages[k], key=lambda p: p["versionCode"], reverse=True)
    apps_list = sorted(apps.values(), key=lambda a: a["name"].lower())
    # ensure localized.name matches top-level for clients that use localized
    for a in apps_list:
        if "localized" in a and "en-US" in a["localized"]:
            if "name" not in a["localized"]["en-US"]:
                a["localized"]["en-US"]["name"] = a.get("name", "")
    index = {"repo": repo, "apps": apps_list, "packages": packages}

    existing = OUT / "index-v1.json"
    changed_v1 = True
    if existing.exists():
        try:
            old = json.loads(existing.read_text())
            old["repo"].pop("timestamp", None)
            new_cmp = json.loads(json.dumps(index))
            new_cmp["repo"].pop("timestamp", None)
            if old == new_cmp:
                changed_v1 = False
        except (OSError, json.JSONDecodeError):
            pass

    if changed_v1:
        existing.write_text(json.dumps(index, indent=2))
        sign_index(existing, creds)
        fp = (state.get("fdroid") or {}).get("cert_sha256", "")
        log.info("f-droid index-v1 written (%d apks)%s", len(packages), f"; repo fp {fp}" if fp else "")

    # ── index-v2 generation (modern, with fileEntry for icons) ──────────────
    changed_v2 = _build_index_v2(index, creds)

    return changed_v1 or changed_v2


def _build_index_v2(index_v1: dict, creds: dict) -> bool:
    """Generate index-v2.json (+ .jar) from the v1 index. Returns True if changed."""
    repo_v1 = index_v1.get("repo", {})
    apps_v1 = index_v1.get("apps", [])
    packages_v1 = index_v1.get("packages", {})

    # repo fileEntry for icon
    repo_icon_name = repo_v1.get("icon", "icon.png")
    repo_icon_path = OUT / "icons" / repo_icon_name
    if not repo_icon_path.exists():
        # try fallback
        repo_icon_path = OUT / "icons" / _ensure_repo_icon()
    try:
        repo_icon_entry = _file_entry(repo_icon_path, f"/icons/{repo_icon_path.name}")
    except Exception:
        repo_icon_entry = {"name": f"/icons/{repo_icon_path.name}", "sha256": "0"*64, "size": 0}

    repo_v2 = {
        "name": {"en-US": repo_v1.get("name", "Morphe Updater")},
        "description": {"en-US": repo_v1.get("description", "")},
        "icon": {"en-US": repo_icon_entry},
        "address": repo_v1.get("address", ""),
        "timestamp": repo_v1.get("timestamp", int(time.time()*1000)),
        "mirrors": [{"url": repo_v1["address"]}] if repo_v1.get("address") else [],
    }
    # version not needed in v2 repo, but keep for entry.json compatibility
    packages_v2: dict[str, dict] = {}
    for app in apps_v1:
        pkg = app.get("packageName")
        if not pkg:
            continue
        # find packages list for this pkg
        pkg_list = packages_v1.get(pkg, [])
        if not pkg_list:
            continue
        # metadata
        loc = app.get("localized", {}).get("en-US", {})
        icon_name = app.get("icon")
        if icon_name:
            icon_path = OUT / "icons" / icon_name
            if icon_path.exists():
                icon_entry = _file_entry(icon_path, f"/icons/{icon_name}")
            else:
                icon_entry = {"name": f"/icons/{icon_name}", "sha256": "0"*64, "size": 0}
        elif loc.get("icon"):
            # fallback if we still have localized icon (legacy)
            p = OUT / "icons" / loc["icon"]
            if p.exists():
                icon_entry = _file_entry(p, f"/icons/{p.name}")
            else:
                # try per-package path
                p2 = OUT / pkg / "en-US" / loc["icon"]
                if p2.exists():
                    icon_entry = _file_entry(p2, f"/{pkg}/en-US/{loc['icon']}")
                else:
                    icon_entry = {"name": f"/{pkg}/en-US/{loc['icon']}", "sha256": "0"*64, "size": 0}
        else:
            # synthesize fallback microg
            p = OUT / "icons" / f"{pkg}.png"
            if p.exists():
                icon_entry = _file_entry(p, f"/icons/{p.name}")
            else:
                icon_entry = {"name": f"/icons/{pkg}.png", "sha256": "0"*64, "size": 0}

        metadata = {
            "name": {"en-US": app.get("name", pkg)},
            "summary": {"en-US": loc.get("summary", app.get("name", ""))},
            "description": {"en-US": loc.get("description", "")},
            "icon": {"en-US": icon_entry},
            "categories": app.get("categories", ["Other"]),
            "license": app.get("license", "Unknown"),
            "added": app.get("added") or pkg_list[0].get("added", int(time.time()*1000)),
            "lastUpdated": app.get("lastUpdated") or pkg_list[0].get("added", int(time.time()*1000)),
            "preferredSigner": pkg_list[0].get("signer", ""),
        }
        # clean empty
        if not metadata["categories"]:
            metadata["categories"] = ["Other"]
        versions: dict[str, dict] = {}
        for pkg_entry in pkg_list:
            h = pkg_entry.get("hash") or pkg_entry.get("sha256") or ""
            # file entry
            f_name = f"/{pkg_entry.get('apkName','')}"
            file_entry = {"name": f_name, "sha256": h, "size": pkg_entry.get("size", 0)}
            # ipfsCIDv1 not needed
            manifest: dict = {}
            if pkg_entry.get("versionName"):
                manifest["versionName"] = pkg_entry["versionName"]
            if pkg_entry.get("versionCode") is not None:
                manifest["versionCode"] = pkg_entry["versionCode"]
            # usesSdk
            usesSdk = {}
            if pkg_entry.get("minSdkVersion"):
                usesSdk["minSdkVersion"] = pkg_entry["minSdkVersion"]
            if pkg_entry.get("targetSdkVersion"):
                usesSdk["targetSdkVersion"] = pkg_entry["targetSdkVersion"]
            if usesSdk:
                manifest["usesSdk"] = usesSdk
            if pkg_entry.get("signer"):
                manifest["signer"] = {"sha256": [pkg_entry["signer"]]}
            # nativecode if present
            if pkg_entry.get("nativecode"):
                manifest["nativecode"] = pkg_entry["nativecode"]
            # uses-permission if any
            if pkg_entry.get("uses-permission"):
                manifest["usesPermission"] = [{"name": p[0]} for p in pkg_entry["uses-permission"]]
            versions[h] = {
                "added": pkg_entry.get("added", int(time.time()*1000)),
                "file": file_entry,
                "manifest": manifest,
            }
        packages_v2[pkg] = {"metadata": metadata, "versions": versions}

    output = {"repo": repo_v2, "packages": packages_v2}
    # Add top-level timestamp for easier diffing (fdroidserver stores repo.timestamp)
    # Keep output deterministic
    out_path = OUT / "index-v2.json"
    changed = True
    if out_path.exists():
        try:
            old = json.loads(out_path.read_text())
            # compare without timestamp
            old_cmp = json.loads(json.dumps(old))
            new_cmp = json.loads(json.dumps(output))
            old_cmp.get("repo", {}).pop("timestamp", None)
            new_cmp.get("repo", {}).pop("timestamp", None)
            if old_cmp == new_cmp:
                changed = False
        except Exception:
            pass
    if changed:
        out_path.write_text(json.dumps(output, indent=2))
        sign_index(out_path, creds)
        log.info("f-droid index-v2 written (%d packages)", len(packages_v2))
        # also write entry.json minimal (like fdroidserver)
        entry = {
            "timestamp": repo_v2["timestamp"],
            "version": 20001,
            "index": _file_entry(out_path, "/index-v2.json"),
        }
        entry["index"]["numPackages"] = len(packages_v2)
        (OUT / "entry.json").write_text(json.dumps(entry, indent=2))
        try:
            sign_index(OUT / "entry.json", creds)
            # entry.jar is the signed entry; fdroidserver signs entry.json as entry.jar
            # our sign_index creates entry.jar from entry.json
            if (OUT / "entry.jar").exists():
                pass
            else:
                # rename if sign created entry.json.jar
                pass
        except Exception as exc:
            log.warning("entry.json signing failed: %s", exc)
    return changed


async def update(cfg: dict, state: dict, tag: str | None = None) -> bool:
    if not (cfg.get("fdroid") or {}).get("enabled", True):
        return False
    if not (state.get("fdroid") or {}).get("cert_b64"):
        fp = await cert_fingerprint(tools.resolve_signing())
        if not fp:
            return False
        state.setdefault("fdroid", {}).update({"cert_b64": fp[0], "cert_sha256": fp[1]})
        log.info("repo certificate fingerprint: %s", fp[1])
    return build_index(cfg, state, tag)
