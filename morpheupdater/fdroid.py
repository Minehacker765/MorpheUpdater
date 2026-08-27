"""F-Droid repository generation: scans out/, extracts per-APK metadata,
builds index-v1.json and signs index-v1.jar with the repo keystore."""

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


def extract_icon(apk: Path, dest: Path) -> str | None:
    try:
        with zipfile.ZipFile(apk) as z:
            # Prefer the manifest's launcher icon: ic_launcher.png at highest density
            candidates = []
            for name in z.namelist():
                low = name.lower()
                if not low.endswith((".png", ".webp")):
                    continue
                # only mipmap launcher variants
                if "ic_launcher" not in low and "morphe_adaptive" not in low:
                    continue
                # rank by density and prefer plain ic_launcher.png over background/foreground variants
                m = re.search(r"-(xxxhdpi|xxhdpi|xhdpi|hdpi|mdpi|ldpi)", low)
                rank = _DPI_RANK.get(m.group(1), 0) if m else 0
                # plain ic_launcher.png scores higher than _foreground/_background
                plain = 1 if re.search(r"ic_launcher\.png$", low) else 0
                # for adaptive icons without plain png, prefer foreground
                fg = 1 if "foreground" in low else 0
                score = (plain, fg, rank, z.getinfo(name).file_size)
                candidates.append((score, name))
            # fallback to any mipmap if no launcher found (should not happen)
            if not candidates:
                for name in z.namelist():
                    low = name.lower()
                    if not low.endswith((".png", ".webp")) or "mipmap" not in low:
                        continue
                    m = re.search(r"-(xxxhdpi|xxhdpi|xhdpi|hdpi|mdpi)", low)
                    rank = _DPI_RANK.get(m.group(1), 0) if m else 0
                    candidates.append(((0, 0, rank, z.getinfo(name).file_size), name))
            if not candidates:
                return None
            best = max(candidates, key=lambda x: x[0])[1]
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(z.read(best))
            return dest.name
    except Exception as exc:
        log.warning("icon extraction from %s failed: %s", apk.name, exc)
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


def build_index(cfg: dict, state: dict, tag: str | None = None) -> bool:
    """Regenerate out/index-v1.json (+signed .jar) when contents changed."""
    editor_jar = ROOT / cfg["tools"]["apkeditor"]["local"]
    meta = cfg.get("fdroid") or {}
    by_out = {e.get("out"): e for e in state["builds"].values() if e.get("out")}
    creds = tools.resolve_signing()

    fdroid_state = state.get("fdroid") or {}
    signer_hex = fdroid_state.get("cert_sha256", "")
    sig = signer_hex[:8] if signer_hex else ""
    packages: dict[str, list[dict]] = {}
    apps: dict[str, dict] = {}

    for apk in sorted(OUT.glob("*.apk")):
        entry = by_out.get(apk.name) or {}
        try:
            info = tools.apk_info(editor_jar, apk)
        except Exception:
            info = None
        if info:
            package, version, vc, app_name_real = info
            app_name = app_name_real or entry.get("app_name") or package.rsplit(".", 1)[-1].capitalize()
        else:
            if not (entry.get("package") and entry.get("version") and entry.get("vc")):
                log.warning("index: skipping %s (no metadata)", apk.name)
                continue
            package, version, vc = entry["package"], entry["version"], int(entry["vc"])
            app_name = entry.get("app_name") or package.rsplit(".", 1)[-1].capitalize()

        min_sdk, target_sdk = parse_manifest_sdk(apk)
        apk_name = apk.name
        pkg_entry: dict = {
            "added": int(__import__("time").time() * 1000),
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
        if not (OUT / "icons" / icon_file).exists():
            got = extract_icon(apk, OUT / "icons" / icon_file)
            icon_rel = got if got else ""
        display = app_name.removesuffix(" Morphe")
        summary = f"{display} patched with Morphe"
        en: dict = {"name": app_name, "summary": summary, "description": summary}
        if icon_rel:
            en["icon"] = icon_rel
        if package not in apps:
            apps[package] = {
                "packageName": package,
                "name": app_name,
                "localized": {"en-US": en},
            }

    repo: dict = {
        "name": meta.get("name", "morpheupdater"),
        "description": meta.get("description", "Patched apps"),
        "timestamp": int(time.time() * 1000),
        "version": 20001,
        "maxage": 0,
        "packages": {},
    }
    if meta.get("url"):
        repo["address"] = meta["url"]
    # sort packages for determinism
    for k in packages:
        packages[k] = sorted(packages[k], key=lambda p: p["versionCode"], reverse=True)
    index = {"repo": repo, "apps": sorted(apps.values(), key=lambda a: a["name"].lower()), "packages": packages}

    existing = OUT / "index-v1.json"
    if existing.exists():
        try:
            old = json.loads(existing.read_text())
            old["repo"].pop("timestamp", None)
            new_cmp = json.loads(json.dumps(index))
            new_cmp["repo"].pop("timestamp", None)
            if old == new_cmp:
                return False
        except (OSError, json.JSONDecodeError):
            pass

    existing.write_text(json.dumps(index, indent=1))
    sign_index(existing, creds)
    fp = (state.get("fdroid") or {}).get("cert_sha256", "")
    log.info("f-droid index written (%d apks)%s", len(packages), f"; repo fp {fp}" if fp else "")
    return True


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
