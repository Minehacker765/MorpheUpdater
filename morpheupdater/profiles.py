"""Aurora Store device profiles for Google Play token dispensing.

Profiles are from the Calyx Institute / Aurora OSS device database (GPL-3.0),
as distributed with gplaydl. See README for provenance.
"""

from __future__ import annotations

from pathlib import Path

PROFILES_DIR = Path(__file__).resolve().parent / "profiles"

ABI_TOKENS = {
    "arm64": "arm64-v8a",
    "armv7": "armeabi-v7a",
    "x86": "x86",
    "x86_64": "x86_64",
}

_PRIORITY = {
    "arm64": ["Pv", "D2", "eV", "iq", "Fj", "HE", "VP", "Hb", "p6", "B1"],
    "armv7": ["XK", "Gj", "IV", "Gb"],
    "x86": ["x8", "7M"],
    "x86_64": ["x8", "7M"],
    "tv": ["Gb"],
    "universal": ["7M", "Pv", "D2", "eV"],
}


def _load(fp: Path) -> dict[str, str]:
    profile: dict[str, str] = {}
    for line in fp.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, _, val = line.partition("=")
            profile[key] = val
    return profile


_ALL: dict[str, tuple[str, dict[str, str]]] = {}
for _fp in sorted(PROFILES_DIR.glob("*.properties")):
    _p = _load(_fp)
    _plats = _p.get("Platforms", "")
    if "arm64-v8a" in _plats:
        _arch = "arm64"
    elif "armeabi-v7a" in _plats:
        _arch = "armv7"
    elif "x86" in _plats:
        _arch = "x86"
    else:
        _arch = "unknown"
    _ALL[_fp.stem] = (_arch, _p)


def _of_arch(arch: str) -> list[tuple[str, dict[str, str]]]:
    return [(k, p) for k, (a, p) in _ALL.items() if a == arch]


def _supporting(abi: str) -> list[tuple[str, dict[str, str]]]:
    return [(k, p) for k, (a, p) in _ALL.items() if abi in p.get("Platforms", "")]


def get_priority_profiles(arch: str = "arm64") -> list[tuple[str, dict[str, str]]]:
    priority = _PRIORITY.get(arch, _PRIORITY["arm64"])
    if arch == "universal":
        pool = [(k, p) for k, (a, p) in _ALL.items() if "arm64-v8a" in p.get("Platforms", "") and "armeabi" in p.get("Platforms", "")]
        if not pool:
            pool = list(_ALL.items())
    elif arch == "tv":
        pool = [(k, p) for k, (a, p) in _ALL.items() if "android.software.leanback" in p.get("Features", "")]
        if not pool:
            for k, (a, p) in _ALL.items():
                if k == "Gb":
                    pool = [(k, p)]
                    break
    elif arch in ("arm64", "armv7"):
        pool = list(_of_arch(arch))
    else:
        pool = _supporting(ABI_TOKENS[arch])
    seen: set[str] = set()
    result: list[tuple[str, dict[str, str]]] = []
    for key in priority:
        for pkey, profile in pool:
            if pkey == key and pkey not in seen:
                result.append((pkey, profile))
                seen.add(pkey)
    result += [(k, p) for k, p in pool if k not in seen]
    return result


def get_compat_profiles(arch: str = "arm64") -> list[tuple[str, dict[str, str]]]:
    if arch == "tv":
        pool = [(k, p) for k, (a, p) in _ALL.items()
                if "android.software.leanback" in p.get("Features", "")]
    else:
        pool = _supporting(ABI_TOKENS.get(arch, "arm64-v8a"))

    def sort_key(item):
        profile = item[1]
        try:
            sdk = int(profile.get("Build.VERSION.SDK_INT", "99"))
        except ValueError:
            sdk = 99
        return (sdk, -len(profile.get("Platforms", "").split(",")))

    return sorted(pool, key=sort_key)


def get_discovery_profiles(arch: str = "arm64") -> list[tuple[str, dict[str, str]]]:
    tv = [(k, p) for k, (a, p) in _ALL.items()
          if "android.software.leanback" in p.get("Features", "")]
    candidates = get_compat_profiles(arch)[:1] + tv
    for other in ("armv7", "arm64", "x86_64"):
        if other != arch:
            candidates += get_compat_profiles(other)[:1]
    seen: set[str] = set()
    result = []
    for key, profile in candidates:
        if key not in seen:
            seen.add(key)
            result.append((key, profile))
    return result
