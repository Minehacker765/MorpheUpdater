from __future__ import annotations

import base64
import json
import logging
import os
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"
STATE_PATH = ROOT / "state.json"
TMP = ROOT / "tmp"
OUT = ROOT / "out"
ICONS = ROOT / "icons"
OPTIONS = ROOT / "options"
MORPHE_DATA = ROOT / "bin" / "morphe-data"
MORPHE_PATCHES = MORPHE_DATA / "patches"

DEFAULT_CONFIG: dict = {
    "interval_minutes": 30,
    "archs": {"arm64": True, "arm": False, "armv7": False, "x86": False, "x86_64": False, "tv": True, "universal": False},
    "resolution": "xxxhdpi",
    "locales": ["en-US", "es"],
    "force_patch": True,
    "continue_on_error": True,
    "striplibs": [],
    "bytecode_mode": "",
    "bundles": {"morphe": "https://github.com/MorpheApp/morphe-patches"},
    "apps": [
        {"package": "com.google.android.youtube", "combos": [["morphe"]]},
        {"package": "com.google.android.apps.youtube.music", "combos": [["morphe"]]},
    ],
    "tools": {
        "morphe-desktop": {"repo": "MorpheApp/morphe-desktop", "local": "bin/morphe-desktop.jar"},
        "apkeditor": {"repo": "REAndroid/APKEditor", "local": "bin/apkeditor.jar"},
    },
    "fdroid": {
        "enabled": True,
        "name": "Morphe Updater",
        "description": "Apps patched with Morphe, rebuilt automatically",
        "url": "",
    },
    "tmp_max_mb": 2048,
    "tmp_max_age_days": 7,
    "tmp_min_free_gb": 5,
    "commit": False,
    "release": False,
    "clean": {
        "full_clean": False,
        "full_clean_out": False,
        "between_builds_seconds": 2,
        "download_concurrency": 4,
    },
}

log = logging.getLogger("settings")


def load_env() -> None:
    env_file = ROOT / ".env"
    if env_file.exists():
        for line in env_file.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip("'\""))
    b64 = (os.environ.get("KEYSTORE_B64") or "").strip()
    path = (os.environ.get("KEYSTORE_PATH") or "release.keystore").strip() or "release.keystore"
    env_path = Path(path)
    if not env_path.is_absolute():
        env_path = ROOT / env_path
    if b64 and not env_path.exists():
        env_path.parent.mkdir(parents=True, exist_ok=True)
        env_path.write_bytes(base64.b64decode(b64))
        log.info("decoded KEYSTORE_B64 into %s", env_path)


def keystore() -> str:
    raw = (os.environ.get("KEYSTORE_PATH") or "").strip()
    return raw if raw else "release.keystore"


def _deep_merge(a: dict, b: dict) -> dict:
    out = {**a}
    for k, v in b.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


def load_config() -> dict:
    if not CONFIG_PATH.exists():
        CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2) + "\n")
        log.info("created default config.json")
    cfg = json.loads(CONFIG_PATH.read_text())
    return _deep_merge(DEFAULT_CONFIG, cfg)


def _empty_state() -> dict:
    return {"bundles": {}, "tools": {}, "builds": {}}


def _read_state_file(path: Path) -> dict | None:
    try:
        state = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return None
    return state if isinstance(state, dict) else None


def load_state() -> dict:
    state = _read_state_file(STATE_PATH) if STATE_PATH.exists() else None
    if state is None:
        backup = STATE_PATH.with_suffix(".json.bak")
        state = _read_state_file(backup) if backup.exists() else None
        if state is not None:
            log.warning("state.json unreadable; recovered from %s", backup.name)
    if state is None:
        return _empty_state()
    state.setdefault("bundles", {})
    state.setdefault("tools", {})
    state.setdefault("builds", {})
    return state


def short(package: str) -> str:
    """Short name for out/ and options/ (handles collisions like bandcamp.android vs pxv.android)."""
    last = package.rsplit(".", 1)[-1]
    if last in {"android", "app", "client", "mobile", "launcher", "reader", "gallery", "converter", "manager"}:
        parts = package.split(".")
        if len(parts) >= 2:
            return f"{parts[-2]}.{last}"
        return package.replace(".", "_")
    return last


def validate_apps(cfg: dict) -> None:
    """Reject configs whose app short-names would collide in out/ or options/."""
    seen: dict[str, str] = {}
    for app in cfg["apps"]:
        name = short(app["package"])
        if name in seen and seen[name] != app["package"]:
            raise SystemExit(
                f"config error: packages {seen[name]!r} and {app['package']!r} "
                f"both shorten to {name!r}; outputs would overwrite each other"
            )
        seen[name] = app["package"]


def save_state(state: dict) -> None:
    tmp = STATE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")
    if STATE_PATH.exists():
        STATE_PATH.with_suffix(".json.bak").write_bytes(STATE_PATH.read_bytes())
    tmp.replace(STATE_PATH)


def dir_size_mb(path: Path) -> float:
    total = 0
    for p in path.rglob("*"):
        try:
            if p.is_file():
                total += p.stat().st_size
        except OSError:
            continue
    return total / 1e6


def now() -> int:
    return int(time.time())
