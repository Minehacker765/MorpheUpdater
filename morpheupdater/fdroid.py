"""F-Droid repository generation: scans out/, extracts per-APK metadata,
builds index-v1.json (+signed .jar) and index-v2.json (+signed .jar) with
icons at repo/icons/<pkg>.png (v1 top-level `icon` -> /icons/; v2 fileEntry)."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path

from . import tools
from .display import CLONE_PACKAGE_MAP, PACKAGE_DISPLAY, TV_PACKAGES
from .settings import ICONS, OUT, ROOT, short

log = logging.getLogger("fdroid")

RES_STRING_POOL = 0x0001
RES_XML_START_ELEMENT = 0x0102


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def _combos_for_package(state: dict, package: str) -> list[str]:
    """Combo ids (the middle of state key pkg|combo|arch) for a package."""
    out = []
    try:
        for k in state.get("builds", {}):
            parts = k.split("|")
            if len(parts) >= 2 and parts[0] == package and parts[1] not in out:
                out.append(parts[1])
    except Exception:
        pass
    return out


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
# Proper pipeline (no filename guessing — resources are routinely obfuscated,
# e.g. res/-B.png, and launcher icons are often adaptive/vector XML):
#   AndroidManifest.xml -> application android:icon ref -> resources.arsc
#   -> file path(s) -> adaptive-icon composite / raster / vector render.
# Returns None when nothing real can be extracted (callers leave the icon
# hidden instead of inventing a placeholder).

ANDROID_NS = "http://schemas.android.com/apk/res/android"
_ICON_OUT_MAX = 256  # long edge; downscaled with LANCZOS to keep repo light

_DTYPE_REF = 0x01
_DTYPE_STR = 0x03
_DTYPE_INT_FIRST = 0x10
_DENSITY_ANY = 0xFFFE

_ARSC_CACHE: dict[str, tuple] = {}


def _axml_tree(data: bytes):
    """Parse binary AXML into (strings, root-node). Node = [tag, attrs, children],
    attrs = list of (ns_uri|None, name, dtype, udata, raw_str|None)."""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("not binary xml")
    strings: list[str] = []
    nodes: list = []
    stack: list = []
    pos = 8
    while pos + 8 <= len(data):
        ctype, hsize, size = struct.unpack_from("<HHI", data, pos)
        if size <= 0 or pos + size > len(data):
            break
        if ctype == 0x0001 and not strings:
            strings = _pool_strings(data, pos)
        elif ctype in (0x0100, 0x0101):
            pass  # namespace prefix mappings; ns URIs come from the pool
        elif ctype == 0x0102:  # START_ELEMENT
            base = pos + 16  # after ResXMLTree_node header
            ns_i, name_i = struct.unpack_from("<II", data, base)
            a_start, a_size, a_count = struct.unpack_from("<HHH", data, base + 8)
            tag = strings[name_i] if 0 <= name_i < len(strings) else ""
            attrs = []
            for i in range(a_count):
                b = base + a_start + i * a_size
                a_ns, a_name, _raw = struct.unpack_from("<III", data, b)
                _sz, _r0, dtype = struct.unpack_from("<HBB", data, b + 12)
                udata = struct.unpack_from("<I", data, b + 16)[0]
                ns_uri = None
                if a_ns != 0xFFFFFFFF and 0 <= a_ns < len(strings):
                    ns_uri = strings[a_ns]
                aname = strings[a_name] if 0 <= a_name < len(strings) else ""
                raw_s = None
                if dtype == _DTYPE_STR and 0 <= udata < len(strings):
                    raw_s = strings[udata]
                attrs.append((ns_uri, aname, dtype, udata, raw_s))
            node = [tag, attrs, []]
            if stack:
                stack[-1][2].append(node)
            else:
                nodes.append(node)
            stack.append(node)
        elif ctype == 0x0103:  # END_ELEMENT
            if stack:
                stack.pop()
        pos += size
    root = nodes[0] if nodes else None
    return strings, root


def _find_nodes(root, tag: str) -> list:
    out = []

    def _walk(n):
        if n[0] == tag:
            out.append(n)
        for c in n[2]:
            _walk(c)

    if root is not None:
        _walk(root)
    return out


def _android_attr(node, name: str):
    """(dtype, udata, raw_str) for the android: namespaced attr, or None."""
    for ns, aname, dtype, udata, raw_s in node[1]:
        if ns == ANDROID_NS and aname == name:
            return dtype, udata, raw_s
    return None


def _manifest_icon_refs(manifest: bytes) -> tuple[int | None, int | None]:
    """(icon_ref, round_ref) resource IDs from the manifest (application first,
    then launcher activity / activity-alias)."""
    try:
        _, root = _axml_tree(manifest)
    except Exception:
        return None, None
    if root is None:
        return None, None
    icon = rnd = None
    for app in _find_nodes(root, "application"):
        a = _android_attr(app, "icon")
        if a and a[0] == _DTYPE_REF:
            icon = a[1]
        a = _android_attr(app, "roundIcon")
        if a and a[0] == _DTYPE_REF:
            rnd = a[1]
        break
    if icon is None:
        # dynamic-launcher case: icon overridden on activity / activity-alias
        for tag in ("activity-alias", "activity"):
            for n in _find_nodes(root, tag):
                a = _android_attr(n, "icon")
                if a and a[0] == _DTYPE_REF:
                    icon = a[1]
                    break
            if icon is not None:
                break
    return icon, rnd


def _parse_arsc(data: bytes) -> dict | None:
    """Minimal resources.arsc model: {strings, packages: [{id, types, keys,
    entries: {(type_id, entry_id): [(density, sdk, kind, value)]}}]}.
    value = ('ref', resid) | ('str', idx) | ('color', argb) | ('int', n)."""
    if len(data) < 12 or struct.unpack_from("<H", data, 0)[0] != 0x0002:
        return None
    try:
        pkg_count = struct.unpack_from("<I", data, 8)[0]
    except Exception:
        return None
    g_strings: list[str] = []
    packages: list[dict] = []
    pos = 12
    cur_pkg = None
    pkg_end = 0
    seen_global = False
    while pos + 8 <= len(data):
        if cur_pkg is not None and pos >= pkg_end:
            cur_pkg = None
        try:
            ctype, hsize, size = struct.unpack_from("<HHI", data, pos)
        except Exception:
            break
        if size <= 0 or pos + size > len(data):
            break
        if ctype == 0x0001 and not seen_global and cur_pkg is None:
            g_strings = _pool_strings(data, pos)
            seen_global = True
        elif ctype == 0x0200:  # PACKAGE — descend into children, don't skip
            try:
                pid = struct.unpack_from("<I", data, pos + 8)[0]
            except Exception:
                break
            cur_pkg = {"id": pid, "types": [], "keys": [], "entries": {}}
            packages.append(cur_pkg)
            pkg_end = pos + size
            pos += hsize or 288
            continue
        elif cur_pkg is not None and ctype == 0x0001:
            # first string pool after a package header = type names, second = keys
            if not cur_pkg["types"]:
                cur_pkg["types"] = _pool_strings(data, pos)
            elif not cur_pkg["keys"]:
                cur_pkg["keys"] = _pool_strings(data, pos)
        elif cur_pkg is not None and ctype == 0x0201:  # TYPE
            # Two header variants observed in the wild:
            #  V1 (aapt2): id u32, entryCount u32, entriesStart u32, cfgSize u32,
            #      config body @+24 (density @+34, sdk @+44)
            #  V0 (classic): id u8, flags u8, entryCount u16, entriesStart u32,
            #      config @+16 (density @+26, sdk @+36)
            _KNOWN_D = frozenset((0, 120, 160, 213, 240, 320, 480, 640, _DENSITY_ANY))
            try:
                v8 = struct.unpack_from("<I", data, pos + 8)[0]
                v12 = struct.unpack_from("<I", data, pos + 12)[0]
                v16 = struct.unpack_from("<I", data, pos + 16)[0]
                v20 = struct.unpack_from("<I", data, pos + 20)[0]
                d34 = struct.unpack_from("<H", data, pos + 34)[0] if size >= 36 else 0xFFFF
                s44 = struct.unpack_from("<H", data, pos + 44)[0] if size >= 46 else 99
                d26 = struct.unpack_from("<H", data, pos + 26)[0] if size >= 28 else 0xFFFF
                s36 = struct.unpack_from("<H", data, pos + 36)[0] if size >= 38 else 99
                tid8, tflags = v8 & 0xFF, (v8 >> 8) & 0xFF
                # NOTE: the flag byte (often 0x01, "sparse") is set on many
                # chunks whose entries are still plain dense inline structs;
                # mode is decided by content validation below, not the flag.
                use_v1 = (
                    1 <= tid8 <= 255 and (tflags & ~0x01) == 0
                    and v12 < 100000 and 20 <= v16 <= size
                    and v20 in (28, 32, 36, 40, 44, 48, 52, 56, 60, 64, 68)
                    and 24 + v20 <= size and d34 in _KNOWN_D and s44 <= 40
                )
                use_v0 = (
                    not use_v1 and 1 <= tid8 <= 255 and (tflags & ~0x01) == 0
                    and ((v8 >> 16) & 0xFFFF) < 100000
                    and 16 <= v12 <= size and d26 in _KNOWN_D and s36 <= 40
                )
                if use_v1:
                    tid, ecount, estart = tid8, v12, v16
                    density, sdk = d34, s44
                elif use_v0:
                    tid = tid8
                    ecount = (v8 >> 16) & 0xFFFF
                    estart = v12
                    density, sdk = d26, s36
                else:
                    pos += size
                    continue
            except Exception:
                pos += size
                continue
            _KNOWN_DTYPES = frozenset(
                [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
                + list(range(0x10, 0x20)))
            nkeys = len(cur_pkg["keys"])

            def _struct_at(at: int):
                """Parse any entry struct -> (step, flags, key, value|None), None if implausible.
                step = bytes to the next entry (16 for simple, more for bags)."""
                try:
                    if at < 0 or at + 16 > size:
                        return None
                    esz, eflags, key_i = struct.unpack_from("<HHI", data, pos + at)
                    if esz != 8 or (eflags & ~0x7) or key_i >= nkeys:
                        return None
                    if eflags & 0x0001:  # bag: parent + count + count*map entries
                        _p, count = struct.unpack_from("<II", data, pos + at + 8)
                        if count > 256:
                            return None
                        step = 16 + count * 12
                        if at + step > size:
                            return None
                        return step, eflags, key_i, None
                    _vsz, _vr0, dtype, udata = struct.unpack_from("<HBBI", data, pos + at + 8)
                    if _vsz != 8 or dtype not in _KNOWN_DTYPES:
                        return None
                except Exception:
                    return None
                if dtype == _DTYPE_REF:
                    val = ("ref", udata)
                elif dtype == _DTYPE_STR:
                    val = ("str", udata)
                elif 0x1C <= dtype <= 0x1F:
                    val = ("color", udata)
                elif dtype == 0x10:
                    val = ("int", udata if udata < 0x80000000 else udata - 0x100000000)
                else:
                    val = ("int", udata)
                return 16, eflags, key_i, val

            def _simple_at(at: int):
                r = _struct_at(at)
                if r is None or r[3] is None:
                    return None
                _step, eflags, key_i, val = r
                return key_i, eflags, val

            mode = None
            if ecount > 0 and estart + ecount * 4 <= size:
                # offset-table hypothesis: every slot -1 or a valid struct
                try:
                    ok = True
                    for i in range(ecount):
                        v = struct.unpack_from("<i", data, pos + estart + i * 4)[0]
                        if v == -1:
                            continue
                        if v < 0 or _simple_at(estart + v) is None:
                            ok = False
                            break
                    if ok:
                        mode = "offsets"
                except Exception:
                    pass
            if mode is None and ecount > 0:
                # inline hypothesis: ecount structs back-to-back from estart.
                # Accepted ONLY when the run fills the chunk exactly: packed
                # overlay tables (entry subset, unknown eid base) must never be
                # stored positionally — a wrong eid mapping yields wrong icons.
                try:
                    at = estart
                    ok = True
                    for _ in range(ecount):
                        r = _struct_at(at)
                        if r is None:
                            ok = False
                            break
                        at += r[0]
                    if ok and at == size and ecount > 0:
                        # fills exactly: dense chunk, slots == entry ids
                        mode = "inline"
                except Exception:
                    pass
            if mode == "offsets":
                for i in range(ecount):
                    try:
                        v = struct.unpack_from("<i", data, pos + estart + i * 4)[0]
                    except Exception:
                        continue
                    if v == -1:
                        continue
                    r = _simple_at(estart + v)
                    if r is None:
                        continue
                    _ki, _fl, val = r
                    cur_pkg["entries"].setdefault((tid, i), []).append((density, sdk, val))
            elif mode == "inline":
                at = estart
                for i in range(ecount):
                    r = _struct_at(at)
                    if r is None:
                        break
                    step, _fl, _ki, val = r
                    if val is not None:
                        cur_pkg["entries"].setdefault((tid, i), []).append((density, sdk, val))
                    at += step
        pos += size
    if not packages:
        return None
    return {"strings": g_strings, "packages": packages}


def _arsc_pkg(table: dict, pid: int) -> dict | None:
    for p in table["packages"]:
        if p["id"] == pid:
            return p
    return None


def _resolve_simple(table: dict, default_pid: int, resid: int, _depth=0):
    """Resolve a resource ID to [(density, sdk, value)] simple values."""
    if _depth > 4:
        return []
    pid = (resid >> 24) & 0xFF
    if pid == 0x00:
        pid = default_pid
    if pid == 0x01:
        return []  # android framework table not available
    pkg = _arsc_pkg(table, pid)
    if pkg is None:
        return []
    tid = (resid >> 16) & 0xFF
    eid = resid & 0xFFFF
    out = []
    for density, sdk, val in pkg["entries"].get((tid, eid), []):
        if val[0] == "ref":
            out.extend(_resolve_simple(table, pid, val[1], _depth + 1))
        else:
            out.append((density, sdk, val))
    return out


def _entry_file_candidates(table: dict, default_pid: int, resid: int) -> list[tuple[int, int, str]]:
    """[(density, sdk, zip_path)] for every file value of the resource."""
    cands = []
    for density, sdk, val in _resolve_simple(table, default_pid, resid):
        if val[0] == "str":
            idx = val[1]
            if 0 <= idx < len(table["strings"]):
                p = table["strings"][idx]
                if p.lower().endswith((".png", ".webp", ".jpg", ".jpeg", ".xml")):
                    cands.append((density, sdk, p))
    # highest density first; anydpi (0xFFFE) sorts above nodpi(0)
    cands.sort(key=lambda c: (0xFFFF if c[0] == _DENSITY_ANY else c[0], c[1]), reverse=True)
    return cands


def _color_of_value(table: dict, default_pid: int, dtype: int, udata: int, raw_s, z=None, _depth: int = 0) -> tuple | None:
    """-> (r, g, b, a), ("xmlcolor", path), or None. Color XML refs resolve
    immediately when the zip is available (depth-capped)."""
    if _depth > 3:
        return None
    if 0x1C <= dtype <= 0x1F:
        a = (udata >> 24) & 0xFF
        return ((udata >> 16) & 0xFF, (udata >> 8) & 0xFF, udata & 0xFF, a)
    if dtype == _DTYPE_STR and raw_s:
        return _parse_hex_color(raw_s)
    if dtype == _DTYPE_REF:
        for _d, _s, val in _resolve_simple(table, default_pid, udata):
            if val[0] == "color":
                c = val[1]
                return ((c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF, (c >> 24) & 0xFF)
            if val[0] == "str":
                idx = val[1]
                if 0 <= idx < len(table["strings"]):
                    p = table["strings"][idx]
                    if p.lower().endswith(".xml"):
                        if z is not None:
                            got = _resolve_color_xml(z, p, table, default_pid, _depth + 1)
                            if got:
                                return got
                            continue
                        return ("xmlcolor", p)
        return None
    return None


def _parse_hex_color(s: str) -> tuple | None:
    s = s.strip().lstrip("#")
    try:
        if len(s) == 3:
            r, g, b = (int(c * 2, 16) for c in s)
            return (r, g, b, 255)
        if len(s) == 4:
            a, r, g, b = (int(c * 2, 16) for c in s)
            return (r, g, b, a)
        if len(s) == 6:
            return (int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16), 255)
        if len(s) == 8:
            return (int(s[2:4], 16), int(s[4:6], 16), int(s[6:8], 16), int(s[0:2], 16))
    except Exception:
        return None
    return None


def _load_raster(z: zipfile.ZipFile, path: str):
    """Load a zip image as RGBA (strips .9-patch borders)."""
    from PIL import Image  # type: ignore

    try:
        data = z.read(path)
    except KeyError:
        return None
    import io as _io

    try:
        im = Image.open(_io.BytesIO(data)).convert("RGBA")
    except Exception:
        return None
    if path.endswith(".9.png") and im.width > 2 and im.height > 2:
        im = im.crop((1, 1, im.width - 1, im.height - 1))
    return im


def _resolve_color_xml(z: zipfile.ZipFile, path: str, table=None, pid: int = 0, _depth: int = 0):
    """Default android:color from a ColorStateList XML (binary or text).

    Item colors may themselves be @color/ refs — resolved recursively (depth
    capped) when the resource table is available."""
    if _depth > 3:
        return None
    try:
        data = z.read(path)
    except KeyError:
        return None

    def _col_of(c):
        if isinstance(c, tuple):
            _dt, _ud, _rs = c
            if _dt == _DTYPE_STR and _rs:
                return _parse_hex_color(_rs)
            if _dt == _DTYPE_REF and table is not None:
                return _color_of_value(table, pid, _dt, _ud, _rs, z, _depth + 1)
            if 0x1C <= _dt <= 0x1F:
                return ((_ud >> 16) & 0xFF, (_ud >> 8) & 0xFF, _ud & 0xFF, (_ud >> 24) & 0xFF)
            return None
        return _parse_hex_color(c)

    items = []
    if data[:2] != b"<?":
        try:
            _, root = _axml_tree(data)
        except Exception:
            return None
        if root is None:
            return None
        for item in _find_nodes(root, "item"):
            has_state = any(
                ns == ANDROID_NS and n.startswith("state_") for ns, n, *_ in item[1]
            )
            c = _android_attr(item, "color")
            if c:
                items.append((has_state, c))
    else:
        import xml.etree.ElementTree as _ET

        try:
            root = _ET.fromstring(data)
        except Exception:
            return None
        for item in root.iter("item"):
            has_state = any(k.startswith("{http://schemas.android.com/apk/res/android}state_") for k in item.attrib)
            for k, v in item.attrib.items():
                if k.endswith("}color"):
                    items.append((has_state, v))
    for has_state, c in items:
        if not has_state:
            col = _col_of(c)
            if col and len(col) == 4:
                return col
    for has_state, c in items:
        col = _col_of(c)
        if col and len(col) == 4:
            return col
    return None


def _drawable_to_image(z, table, default_pid, dtype, udata, raw_s, size: int, transparent_ok=True):
    """Render any drawable value to an RGBA `size`px image (full-bleed)."""
    from PIL import Image  # type: ignore

    if 0x1C <= dtype <= 0x1F or (dtype == _DTYPE_STR and raw_s and raw_s.startswith("#")):
        col = _color_of_value(table, default_pid, dtype, udata, raw_s, z)
        if col and len(col) == 4:
            return Image.new("RGBA", (size, size), col)
        return None
    if dtype != _DTYPE_REF:
        if dtype == _DTYPE_STR and raw_s and raw_s.lower().endswith((".png", ".webp", ".jpg", ".jpeg")):
            try:
                im = _load_raster(z, raw_s)
                return im.resize((size, size), Image.LANCZOS) if im else None
            except Exception:
                return None
        return None
    for _d, _s, val in _resolve_simple(table, default_pid, udata):
        if val[0] == "color":
            c = val[1]
            return Image.new("RGBA", (size, size), ((c >> 16) & 0xFF, (c >> 8) & 0xFF, c & 0xFF, (c >> 24) & 0xFF))
        if val[0] == "str":
            idx = val[1]
            if not (0 <= idx < len(table["strings"])):
                continue
            p = table["strings"][idx]
            low = p.lower()
            if low.endswith((".png", ".webp", ".jpg", ".jpeg")):
                im = _load_raster(z, p)
                if im:
                    return im.resize((size, size), Image.LANCZOS)
            elif low.endswith(".xml"):
                try:
                    im = _render_xml_drawable(z, table, default_pid, p, size)
                except Exception:
                    im = None
                if im:
                    return im
    return None


def _render_xml_drawable(z, table, default_pid, path: str, size: int):
    """Render a drawable XML (vector / shape / gradient / bitmap / layer-list,
    including nested adaptive-icon / inset structures)."""
    from PIL import Image  # type: ignore

    try:
        data = z.read(path)
    except KeyError:
        return None
    if data[:2] == b"<?":
        return None  # APK resources are always binary; text only via fallback
    # binary AXML
    try:
        _, root = _axml_tree(data)
    except Exception:
        return None
    if root is None:
        return None
    tag = root[0]
    if tag == "vector":
        return _rasterize_vector_node(root, size, z, table, default_pid)
    if tag == "shape":
        for c in root[2]:
            if c[0] == "solid":
                a = _android_attr(c, "color")
                if a:
                    col = _color_of_value(table, default_pid, *a, z)
                    if col and len(col) == 4:
                        from PIL import Image  # type: ignore

                        return Image.new("RGBA", (size, size), col)
        return None
    if tag == "gradient":
        from PIL import Image  # type: ignore

        cols = []
        for an in ("startColor", "centerColor", "endColor"):
            a = _android_attr(root, an)
            if a:
                col = _color_of_value(table, default_pid, *a, z)
                if col and len(col) == 4:
                    cols.append(col)
        if cols:
            return _gradient_colors(cols, size)
        return None
    # every other drawable kind goes through the shared recursive renderer
    # (handles nesting: adaptive-in-inset, bitmap foregrounds, etc.)
    return _render_drawable_node(z, table, default_pid, root, size)


def _render_layer_node(z, table, default_pid, node, size: int):
    """Render one drawable holder node (background/foreground/item/inset...):
    explicit drawable attr first, else first nested drawable element. Applies
    InsetDrawable shrinking when the node itself is an <inset>."""
    inner = None
    a = _android_attr(node, "drawable") or _android_attr(node, "color") or _android_attr(node, "src")
    if a:
        _dt, _ud, _rs = a
        inner = _drawable_to_image(z, table, default_pid, _dt, _ud, _rs, size)
    if inner is None:
        for sub in node[2]:
            if isinstance(sub, list) and sub[0] in _DRAWABLE_TAGS:
                inner = _render_drawable_node(z, table, default_pid, sub, size)
                if inner is not None:
                    break
    if inner is None:
        return None
    if node[0] == "inset":
        def _in(name):
            b = _android_attr(node, name)
            if b is None:
                return None
            return _inset_px(*b, size)
        allv = _android_attr(node, "inset")
        allpx = _inset_px(*allv, size) if allv else 0
        left = _in("insetLeft")
        if left is None:
            left = _in("insetStart")
        top = _in("insetTop")
        right = _in("insetRight")
        if right is None:
            right = _in("insetEnd")
        bottom = _in("insetBottom")
        left = allpx if left is None else left
        top = allpx if top is None else top
        right = allpx if right is None else right
        bottom = allpx if bottom is None else bottom
        if left or top or right or bottom:
            inner = _apply_inset(inner, size, left, top, right, bottom)
    return inner


def _render_drawable_node(z, table, default_pid, node, size: int):
    """Render any binary-AXML drawable node (recursive for nesting)."""
    tag = node[0]
    if tag == "vector":
        return _rasterize_vector_node(node, size, z, table, default_pid)
    if tag == "adaptive-icon":
        return _render_adaptive_node(z, table, default_pid, node, size)
    if tag == "shape":
        for c in node[2]:
            if c[0] == "solid":
                a = _android_attr(c, "color")
                if a:
                    col = _color_of_value(table, default_pid, *a, z)
                    if col and len(col) == 4:
                        from PIL import Image  # type: ignore

                        return Image.new("RGBA", (size, size), col)
        return None
    if tag == "gradient":
        cols = []
        for an in ("startColor", "centerColor", "endColor"):
            a = _android_attr(node, an)
            if a:
                col = _color_of_value(table, default_pid, *a, z)
                if col and len(col) == 4:
                    cols.append(col)
        return _gradient_colors(cols, size) if cols else None
    if tag == "bitmap":
        a = _android_attr(node, "src")
        if a:
            return _drawable_to_image(z, table, default_pid, *a, size)
        return None
    if tag in ("layer-list", "level-list"):
        from PIL import Image  # type: ignore

        base = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        for item in node[2]:
            if not isinstance(item, list):
                continue
            layer = _render_layer_node(z, table, default_pid, item, size)
            if layer is not None:
                base = Image.alpha_composite(base, layer.convert("RGBA").resize((size, size)))
        return base if base.getbbox() else None
    if tag in ("inset", "scale", "clip"):
        return _render_layer_node(z, table, default_pid, node, size)
    if tag == "selector":
        for item in _find_nodes(node, "item"):
            a = _android_attr(item, "color")
            if a:
                col = _color_of_value(table, default_pid, *a, z)
                if col and len(col) == 4:
                    from PIL import Image  # type: ignore

                    return Image.new("RGBA", (size, size), col)
        return None
    return None


def _render_adaptive_node(z, table, default_pid, node, size: int):
    """Composite an adaptive-icon node (background + foreground)."""
    from PIL import Image  # type: ignore

    bg = fg = None
    for child in node[2]:
        if not isinstance(child, list):
            continue
        if child[0] == "background" and bg is None:
            bg = _render_layer_node(z, table, default_pid, child, size)
        elif child[0] == "foreground" and fg is None:
            fg = _render_layer_node(z, table, default_pid, child, size)
    if bg is None:
        bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    if fg is None or fg.convert("RGBA").getbbox() is None:
        # no (visible) foreground: broken adaptive icon — fail so callers
        # try the next source instead of emitting a flat square
        return None
    return Image.alpha_composite(bg.convert("RGBA"), fg.convert("RGBA").resize((size, size)))



def _gradient_colors(cols: list, size: int):
    from PIL import Image  # type: ignore

    if len(cols) == 1:
        cols = [cols[0], cols[0]]
    top, bot = cols[0], cols[-1]
    im = Image.new("RGBA", (size, size))
    px = im.load()
    for y in range(size):
        t = y / max(1, size - 1)
        px_line = tuple(int(top[i] + (bot[i] - top[i]) * t) for i in range(4))
        for x in range(size):
            px[x, y] = px_line
    return im


# ── VectorDrawable rasterizer ──────────────────────────────────────────────


def _parse_floats(s: str) -> list[float]:
    import re as _re

    return [float(x) for x in _re.findall(r"[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", s)]


def _parse_path_data(d: str) -> list[tuple[str, list[float]]]:
    """SVG/Android pathData -> [(cmd, args)]."""
    import re as _re

    toks = _re.findall(r"[AaCcHhLlMmQqSsTtVvZz]|[+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?", d)
    out: list[tuple[str, list[float]]] = []
    cur = None
    buf: list[float] = []
    counts = {"M": 2, "L": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "T": 2, "A": 7, "Z": 0}
    for t in toks:
        if len(t) == 1 and t.isalpha():
            if cur is not None and (buf or counts[cur.upper()] == 0):
                if counts[cur.upper()] == 0:
                    out.append((cur, []))
                else:
                    while len(buf) >= counts[cur.upper()]:
                        n = counts[cur.upper()]
                        out.append((cur, buf[:n]))
                        buf = buf[n:]
                        if cur in ("M", "m"):
                            cur = "L" if cur == "M" else "l"
            cur = t
            buf = []
        else:
            buf.append(float(t))
            n = counts[cur.upper()]
            while cur is not None and n and len(buf) >= n:
                out.append((cur, buf[:n]))
                buf = buf[n:]
                if cur in ("M", "m"):
                    cur = "L" if cur == "M" else "l"
                n = counts[cur.upper()]
    if cur is not None:
        if counts[cur.upper()] == 0:
            out.append((cur, []))
        else:
            while len(buf) >= counts[cur.upper()]:
                n = counts[cur.upper()]
                out.append((cur, buf[:n]))
                buf = buf[n:]
    return out


def _arc_to_beziers(x0, y0, rx, ry, rot, large, sweep, x1, y1):
    """SVG endpoint arc -> list of cubic segments (x1,y1,x2,y2,x,y)."""
    import math as _m

    if rx == 0 or ry == 0 or (x0 == x1 and y0 == y1):
        return []
    rx, ry = abs(rx), abs(ry)
    phi = _m.radians(rot % 360)
    cp, sp = _m.cos(phi), _m.sin(phi)
    dx, dy = (x0 - x1) / 2.0, (y0 - y1) / 2.0
    x1p, y1p = cp * dx + sp * dy, -sp * dx + cp * dy
    lam = x1p * x1p / (rx * rx) + y1p * y1p / (ry * ry)
    if lam > 1:
        s = _m.sqrt(lam)
        rx, ry = rx * s, ry * s
    num = rx * rx * ry * ry - rx * rx * y1p * y1p - ry * ry * x1p * x1p
    den = rx * rx * y1p * y1p + ry * ry * x1p * x1p
    f = _m.sqrt(max(0.0, num / den)) if den else 0.0
    if large == sweep:
        f = -f
    cxp, cyp = f * rx * y1p / ry, -f * ry * x1p / rx
    cx, cy = cp * cxp - sp * cyp + (x0 + x1) / 2.0, sp * cxp + cp * cyp + (y0 + y1) / 2.0

    def _ang(ux, uy, vx, vy):
        d = _m.sqrt((ux * ux + uy * uy) * (vx * vx + vy * vy))
        c = max(-1.0, min(1.0, (ux * vx + uy * vy) / d)) if d else 1.0
        a = _m.degrees(_m.acos(c))
        return -a if ux * vy - uy * vx < 0 else a

    t1 = _ang(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry)
    dt = _ang((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry) % 360.0
    if not sweep:
        dt -= 360.0
    n = max(1, int(abs(dt) / 45.0) + 1)
    segs = []
    for i in range(n):
        a1 = _m.radians(t1 + dt * i / n)
        a2 = _m.radians(t1 + dt * (i + 1) / n)
        k = 4.0 / 3.0 * _m.tan((a2 - a1) / 4.0)

        def _pt(a):
            return (cx + cp * rx * _m.cos(a) - sp * ry * _m.sin(a),
                    cy + sp * rx * _m.cos(a) + cp * ry * _m.sin(a))

        def _d(a):
            return (-cp * rx * _m.sin(a) - sp * ry * _m.cos(a),
                    -sp * rx * _m.sin(a) + cp * ry * _m.cos(a))

        p0, p3 = _pt(a1), _pt(a2)
        d0, d3 = _d(a1), _d(a2)
        segs.append((p0[0] + k * d0[0], p0[1] + k * d0[1],
                     p3[0] - k * d3[0], p3[1] - k * d3[1], p3[0], p3[1]))
    return segs


def _flatten_subpaths(cmds) -> list[list[tuple[float, float]]]:
    """Path commands -> list of point-loop subpaths (flattened)."""
    subs: list[list[tuple[float, float]]] = []
    cur: list[tuple[float, float]] = []
    x = y = 0.0
    sx = sy = 0.0
    pcx = pcy = None  # prev cubic control for S
    pqx = pqy = None  # prev quad control for T
    started = False
    for cmd, a in cmds:
        rel = cmd.islower()
        c = cmd.upper()
        if c == "M":
            if cur:
                subs.append(cur)
            x = a[0] + (x if rel else 0)
            y = a[1] + (y if rel else 0)
            cur = [(x, y)]
            sx, sy = x, y
            started = True
            pcx = pcy = pqx = pqy = None
        elif not started:
            continue
        elif c == "Z":
            if cur:
                cur.append((sx, sy))
                subs.append(cur)
            cur = []
            x, y = sx, sy
            started = False
            pcx = pcy = pqx = pqy = None
        elif c == "L":
            x = a[0] + (x if rel else 0)
            y = a[1] + (y if rel else 0)
            cur.append((x, y))
            pcx = pcy = pqx = pqy = None
        elif c == "H":
            x = a[0] + (x if rel else 0)
            cur.append((x, y))
            pcx = pcy = pqx = pqy = None
        elif c == "V":
            y = a[0] + (y if rel else 0)
            cur.append((x, y))
            pcx = pcy = pqx = pqy = None
        elif c == "C":
            pts = [(a[i] + (x if rel and i % 2 == 0 else 0),
                    a[i + 1] + (y if rel and i % 2 else 0)) for i in (0, 2, 4)]
            (x1, y1), (x2, y2), (x3, y3) = pts
            for i in range(1, 25):
                t = i / 24.0
                mt = 1 - t
                cur.append((
                    mt**3 * x + 3 * mt * mt * t * x1 + 3 * mt * t * t * x2 + t**3 * x3,
                    mt**3 * y + 3 * mt * mt * t * y1 + 3 * mt * t * t * y2 + t**3 * y3,
                ))
            pcx, pcy = x2, y2
            pqx = pqy = None
            x, y = x3, y3
        elif c == "S":
            x2 = a[0] + (x if rel else 0)
            y2 = a[1] + (y if rel else 0)
            x3 = a[2] + (x if rel else 0)
            y3 = a[3] + (y if rel else 0)
            x1 = 2 * x - pcx if pcx is not None else x
            y1 = 2 * y - pcy if pcy is not None else y
            for i in range(1, 25):
                t = i / 24.0
                mt = 1 - t
                cur.append((
                    mt**3 * x + 3 * mt * mt * t * x1 + 3 * mt * t * t * x2 + t**3 * x3,
                    mt**3 * y + 3 * mt * mt * t * y1 + 3 * mt * t * t * y2 + t**3 * y3,
                ))
            pcx, pcy = x2, y2
            pqx = pqy = None
            x, y = x3, y3
        elif c == "Q":
            x1 = a[0] + (x if rel else 0)
            y1 = a[1] + (y if rel else 0)
            x3 = a[2] + (x if rel else 0)
            y3 = a[3] + (y if rel else 0)
            for i in range(1, 17):
                t = i / 16.0
                mt = 1 - t
                cur.append((
                    mt * mt * x + 2 * mt * t * x1 + t * t * x3,
                    mt * mt * y + 2 * mt * t * y1 + t * t * y3,
                ))
            pqx, pqy = x1, y1
            pcx = pcy = None
            x, y = x3, y3
        elif c == "T":
            x3 = a[0] + (x if rel else 0)
            y3 = a[1] + (y if rel else 0)
            x1 = 2 * x - pqx if pqx is not None else x
            y1 = 2 * y - pqy if pqy is not None else y
            for i in range(1, 17):
                t = i / 16.0
                mt = 1 - t
                cur.append((
                    mt * mt * x + 2 * mt * t * x1 + t * t * x3,
                    mt * mt * y + 2 * mt * t * y1 + t * t * y3,
                ))
            pqx, pqy = x1, y1
            pcx = pcy = None
            x, y = x3, y3
        elif c == "A":
            rx, ry, rot, large, sweep, x3, y3 = a
            if rel:
                x3 += x
                y3 += y
            segs = _arc_to_beziers(x, y, rx, ry, rot, large, sweep, x3, y3)
            if not segs:
                cur.append((x3, y3))
            for x1, y1, x2, y2, xe, ye in segs:
                for i in range(1, 13):
                    t = i / 12.0
                    mt = 1 - t
                    cur.append((
                        mt**3 * x + 3 * mt * mt * t * x1 + 3 * mt * t * t * x2 + t**3 * xe,
                        mt**3 * y + 3 * mt * mt * t * y1 + 3 * mt * t * t * y2 + t**3 * ye,
                    ))
                x, y = xe, ye
            pcx = pcy = pqx = pqy = None
    if cur:
        subs.append(cur)
    return [s for s in subs if len(s) > 1]


def _mat_mul(a, b):
    return (
        a[0] * b[0] + a[1] * b[3] + a[2] * b[6],
        a[0] * b[1] + a[1] * b[4] + a[2] * b[7],
        a[0] * b[2] + a[1] * b[5] + a[2] * b[8],
        a[3] * b[0] + a[4] * b[3] + a[5] * b[6],
        a[3] * b[1] + a[4] * b[4] + a[5] * b[7],
        a[3] * b[2] + a[4] * b[5] + a[5] * b[8],
        a[6] * b[0] + a[7] * b[3] + a[8] * b[6],
        a[6] * b[1] + a[7] * b[4] + a[8] * b[7],
        a[6] * b[2] + a[7] * b[5] + a[8] * b[8],
    )


def _mat_pt(m, x, y):
    return (m[0] * x + m[1] * y + m[2], m[3] * x + m[4] * y + m[5])


def _group_matrix(get, pivot_default=(0.0, 0.0)):
    import math as _m

    tx = get("translateX", 0.0)
    ty = get("translateY", 0.0)
    sx = get("scaleX", 1.0)
    sy = get("scaleY", 1.0)
    rot = get("rotation", 0.0)
    px = get("pivotX", pivot_default[0])
    py = get("pivotY", pivot_default[1])
    r = _m.radians(rot)
    c, s = _m.cos(r), _m.sin(r)
    m = (1, 0, tx + px, 0, 1, ty + py, 0, 0, 1)
    m = _mat_mul(m, (c, -s, 0, s, c, 0, 0, 0, 1))
    m = _mat_mul(m, (sx, 0, 0, 0, sy, 0, 0, 0, 1))
    m = _mat_mul(m, (1, 0, -px, 0, 1, -py, 0, 0, 1))
    return m


def _rasterize_vector_paths(paths: list, size: int, vp_w: float, vp_h: float):
    """paths = [(d, fill_rgba|None, stroke_rgba|None, stroke_w, evenodd, matrix)] ->
    RGBA image. Painter's algorithm."""
    from PIL import Image, ImageDraw  # type: ignore

    scale = size / max(vp_w, vp_h)
    ox = (size - vp_w * scale) / 2.0
    oy = (size - vp_h * scale) / 2.0
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    for d, fill, stroke, sw, evenodd, mat in paths:
        try:
            subs = _flatten_subpaths(_parse_path_data(d))
        except Exception:
            continue
        if not subs:
            continue
        tsubs = []
        for s in subs:
            tsubs.append([(_mat_pt(mat, px, py)[0] * scale + ox,
                           _mat_pt(mat, px, py)[1] * scale + oy) for px, py in s])
        layer = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        if fill and fill[3] > 0:
            mask = _fill_mask_device(tsubs, size, evenodd)
            solid = Image.new("RGBA", (size, size), fill[:3])
            # effective alpha = fill alpha * coverage mask
            eff = mask.point(lambda v: v * fill[3] // 255)
            solid.putalpha(eff)
            layer = Image.alpha_composite(layer, solid)
        if stroke and stroke[3] > 0 and sw > 0:
            dr = ImageDraw.Draw(layer)
            w = max(1, int(round(sw * scale)))
            for s in tsubs:
                if len(s) > 1:
                    dr.line(s, fill=stroke, width=w, joint="curve")
        canvas = Image.alpha_composite(canvas, layer)
    if paths and canvas.getbbox() is None:
        # vector parsed but painted nothing (e.g. all fills unresolvable) —
        # report failure so callers try the next source, not a blank image
        return None
    return canvas


def _fill_mask_device(tsubs, size: int, evenodd=False):
    """Scanline fill for device-space subpaths."""
    from PIL import Image  # type: ignore

    edges = []
    for s in tsubs:
        for i in range(len(s) - 1):
            x0, y0 = s[i]
            x1, y1 = s[i + 1]
            if y0 != y1:
                edges.append((x0, y0, x1, y1))
    mask = bytearray(size * size)
    for yy in range(size):
        cy = yy + 0.5
        xs = []
        for x0, y0, x1, y1 in edges:
            if (y0 <= cy < y1) or (y1 <= cy < y0):
                t = (cy - y0) / (y1 - y0)
                xs.append((x0 + t * (x1 - x0), 1 if y1 > y0 else -1))
        if not xs:
            continue
        xs.sort(key=lambda e: e[0])
        if evenodd:
            for i in range(0, len(xs) - 1, 2):
                x0 = max(0, int(xs[i][0] + 0.5))
                x1 = min(size, int(xs[i + 1][0] + 0.5))
                for xx in range(x0, x1):
                    mask[yy * size + xx] = 255
        else:
            wind = 0
            prev = None
            for xe, d in xs:
                if prev is not None and wind != 0:
                    x0 = max(0, int(prev + 0.5))
                    x1 = min(size, int(xe + 0.5))
                    for xx in range(x0, x1):
                        mask[yy * size + xx] = 255
                wind += d
                prev = xe
    return Image.frombytes("L", (size, size), bytes(mask))


def _complex_float(udata) -> float:
    """Decode Android complex packing (dimension or fraction) to float."""
    mant = (udata >> 8) & 0xFFFFFF
    if mant & 0x800000:
        mant -= 0x1000000
    radix = (udata >> 4) & 0x3
    mult = (1.0, 1.0 / 128.0, 1.0 / 32768.0, 1.0 / 8388608.0)[radix]
    return mant * mult


def _num_attr(dtype, udata, raw_s, default: float) -> float:
    """Decode a numeric XML attribute in any binary/text encoding."""
    import re as _re
    import struct as _st

    if dtype == _DTYPE_STR and raw_s:
        s = raw_s.strip()
        m = _re.match(r"^([+-]?(?:\d+\.?\d*|\.\d+)(?:[eE][+-]?\d+)?)\s*(dp|dip|sp|px|%)?$", s)
        if m:
            try:
                v = float(m.group(1))
            except Exception:
                return default
            if m.group(2) == "%":
                return v / 100.0
            return v
        try:
            return float(s)
        except Exception:
            return default
    if dtype == 0x04:  # float
        try:
            return float(_st.unpack("<f", _st.pack("<I", udata & 0xFFFFFFFF))[0])
        except Exception:
            return default
    if dtype in (0x05, 0x06):  # dimension complex / fraction complex
        try:
            return _complex_float(udata)
        except Exception:
            return default
    if dtype == 0x10:  # int
        v = udata if udata < 0x80000000 else udata - 0x100000000
        return float(v)
    return default


def _inset_px(dtype, udata, raw_s, size: int, viewport: float = 108.0) -> int:
    """Inset amount in px for a `size` render. Fractions are relative to the
    box; dp values are relative to the 108dp adaptive viewport."""
    import re as _re

    if dtype == _DTYPE_STR and isinstance(raw_s, str) and raw_s.strip().endswith("%"):
        try:
            return int(float(raw_s.strip()[:-1]) / 100.0 * size)
        except Exception:
            return 0
    if dtype == 0x06:  # fraction complex: value is already a fraction
        try:
            return int(_complex_float(udata) * size)
        except Exception:
            return 0
    return int(_num_attr(dtype, udata, raw_s, 0.0) / viewport * size)


_DRAWABLE_TAGS = frozenset({
    "vector", "shape", "gradient", "bitmap", "layer-list", "level-list",
    "inset", "scale", "clip", "adaptive-icon", "selector",
})


def _apply_inset(inner, size: int, left: int, top: int, right: int, bottom: int):
    """InsetDrawable semantics: content drawn in the shrunken box."""
    from PIL import Image  # type: ignore

    w, h = max(1, size - left - right), max(1, size - top - bottom)
    small = inner.convert("RGBA")
    if small.size != (w, h):
        small = small.resize((w, h), Image.LANCZOS)
    canvas = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    canvas.paste(small, (left, top), small)
    return canvas


def _collect_vector_paths(node, mat, out: list, z=None, table=None, pid: int = 0):
    """Walk vector/group/path nodes (binary-AXML node form)."""
    if node[0] == "group":
        def _f(name, default):
            a = _android_attr(node, name)
            if not a:
                return default
            return _num_attr(*a, default)

        vals = {k: _f(k, d) for k, d in (
            ("translateX", 0.0), ("translateY", 0.0), ("scaleX", 1.0),
            ("scaleY", 1.0), ("rotation", 0.0), ("pivotX", 0.0), ("pivotY", 0.0))}
        mat = _mat_mul(mat, _group_matrix(vals))
        for c in node[2]:
            _collect_vector_paths(c, mat, out, z, table, pid)
        return
    if node[0] == "path":
        d = fill = stroke = None
        sw = 1.0
        evenodd = False
        for ns, aname, dtype, udata, raw_s in node[1]:
            if ns != ANDROID_NS:
                continue
            if aname == "pathData" and raw_s:
                d = raw_s
            elif aname == "fillColor":
                fill = _color_attr_full(z, table, pid, dtype, udata, raw_s)
            elif aname == "fillAlpha":
                pass  # folded below
            elif aname == "strokeColor":
                stroke = _color_attr_full(z, table, pid, dtype, udata, raw_s)
            elif aname == "strokeWidth":
                sw = _num_attr(dtype, udata, raw_s, 1.0)
            elif aname == "fillType" and raw_s == "evenOdd":
                evenodd = True
        if d:
            fa = 1.0
            for ns, aname, dtype, udata, raw_s in node[1]:
                if ns == ANDROID_NS and aname == "fillAlpha":
                    fa = _num_attr(dtype, udata, raw_s, 1.0)
                    break
            if fill is not None:
                fill = (fill[0], fill[1], fill[2], int(fill[3] * fa))
            out.append((d, fill, stroke, sw, evenodd, mat))
        return
    if node[0] in ("vector", "adaptive-icon"):
        for c in node[2]:
            _collect_vector_paths(c, mat, out, z, table, pid)


def _color_attr(dtype, udata, raw_s):
    if 0x1C <= dtype <= 0x1F:
        return ((udata >> 16) & 0xFF, (udata >> 8) & 0xFF, udata & 0xFF, (udata >> 24) & 0xFF)
    if dtype == _DTYPE_STR and raw_s:
        return _parse_hex_color(raw_s)
    return None


def _color_attr_full(z, table, pid: int, dtype, udata, raw_s):
    """Like _color_attr but also resolves @color/ refs (dense tables + files)."""
    got = _color_attr(dtype, udata, raw_s)
    if got is not None:
        return got
    if dtype != _DTYPE_REF or table is None:
        return None
    col = _color_of_value(table, pid, dtype, udata, raw_s, z)
    if col is None:
        return None
    if len(col) == 4:
        return col
    if col[0] == "xmlcolor" and z is not None:
        try:
            return _resolve_color_xml(z, col[1], table, pid)
        except Exception:
            return None
    return None


def _rasterize_vector_node(node, size: int, z=None, table=None, pid: int = 0):
    vw = vh = 24.0
    for ns, aname, dtype, udata, raw_s in node[1]:
        if ns != ANDROID_NS:
            continue
        if aname == "viewportWidth":
            vw = _num_attr(dtype, udata, raw_s, 24.0) or 24.0
        if aname == "viewportHeight":
            vh = _num_attr(dtype, udata, raw_s, 24.0) or 24.0
    ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
    paths: list = []
    for c in node[2]:
        _collect_vector_paths(c, ident, paths, z, table, pid)
    if not paths:
        return None
    return _rasterize_vector_paths(paths, size, vw, vh)


def _rasterize_vector_et(root, size: int):
    A = "http://schemas.android.com/apk/res/android"

    def _a(el, name, default=None):
        return el.attrib.get(f"{{{A}}}{name}", default)

    try:
        vw = float(_a(root, "viewportWidth", "24"))
        vh = float(_a(root, "viewportHeight", "24"))
    except Exception:
        vw = vh = 24.0
    ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
    paths = []

    def _walk(el, mat):
        tag = el.tag.split("}")[-1]
        if tag == "group":
            def _f(n, d):
                try:
                    return float(_a(el, n, d))
                except Exception:
                    return d

            m = _group_matrix({"translateX": _f("translateX", 0.0), "translateY": _f("translateY", 0.0),
                               "scaleX": _f("scaleX", 1.0), "scaleY": _f("scaleY", 1.0),
                               "rotation": _f("rotation", 0.0), "pivotX": _f("pivotX", 0.0),
                               "pivotY": _f("pivotY", 0.0)})
            for c in el:
                _walk(c, _mat_mul(mat, m))
        elif tag == "path":
            d = _a(el, "pathData")
            if not d:
                return
            fill = _parse_hex_color(_a(el, "fillColor", "") or "")
            sc = _a(el, "strokeColor")
            stroke = _parse_hex_color(sc) if sc else None
            try:
                sw = float(_a(el, "strokeWidth", "1"))
            except Exception:
                sw = 1.0
            if fill is not None:
                try:
                    fa = float(_a(el, "fillAlpha", "1"))
                except Exception:
                    fa = 1.0
                fill = (fill[0], fill[1], fill[2], int(fill[3] * fa))
            evenodd = _a(el, "fillType") == "evenOdd"
            paths.append((d, fill, stroke, sw, evenodd, mat))

    for c in root:
        _walk(c, ident)
    if not paths:
        return None
    return _rasterize_vector_paths(paths, size, vw, vh)


def _render_adaptive(z, table, default_pid, xml_path: str, size: int):
    """Composite adaptive-icon (background + foreground) at `size`px.

    APK resources are always binary AXML (res/*.xml never ships as text),
    so only the binary form is handled here; apkeditor-decoded text goes
    through the fallback path's own renderer."""
    try:
        data = z.read(xml_path)
    except KeyError:
        return None
    if data[:2] == b"<?":
        return None
    try:
        _, root = _axml_tree(data)
    except Exception:
        return None
    if root is None or root[0] != "adaptive-icon":
        return None
    return _render_adaptive_node(z, table, default_pid, root, size)


def _table_for_apk(apk: Path):
    key = str(apk)
    try:
        st = apk.stat()
        sig = (st.st_mtime, st.st_size)
    except OSError:
        return None
    hit = _ARSC_CACHE.get(key)
    if hit and hit[0] == sig:
        return hit[1]
    try:
        with zipfile.ZipFile(apk) as z:
            data = z.read("resources.arsc")
    except Exception:
        return None
    try:
        table = _parse_arsc(data)
    except Exception:
        return None
    if table is None:
        return None
    # default package = first non-android package
    pid = next((p["id"] for p in table["packages"] if p["id"] != 0x01), table["packages"][0]["id"])
    out = (table, pid)
    _ARSC_CACHE[key] = (sig, out)
    # bound cache
    if len(_ARSC_CACHE) > 8:
        _ARSC_CACHE.pop(next(iter(_ARSC_CACHE)))
    return out


def _apkeditor_info(apk: Path, *args: str, timeout: int = 90) -> str | None:
    """Run `apkeditor info` offline; stdout or None."""
    jar = ROOT / "bin" / "apkeditor.jar"
    if not jar.exists():
        return None
    try:
        proc = subprocess.run(
            [tools.java_bin(), "-jar", str(jar), "info", "-i", str(apk), *args],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception as exc:
        log.debug("apkeditor info failed for %s: %s", apk.name, exc)
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout


def _parse_icon_configs(out: str) -> list[tuple[str, str]]:
    """Parse `-app-icon -v` output -> [(config, zip_path)] in listed order."""
    res = []
    for line in out.splitlines():
        m = re.match(r"\s*\(([^)]*)\)\s*(\S+)\s*$", line)
        if m:
            res.append((m.group(1).strip(), m.group(2).strip()))
    return res


def _pick_icon_file(configs: list[tuple[str, str]]) -> str | None:
    """Prefer adaptive XML (anydpi) else highest density raster."""
    if not configs:
        return None
    for cfg, path in configs:
        if path.lower().endswith(".xml") and "anydpi" in cfg:
            return path
    order = ["xxxhdpi", "xxhdpi", "xhdpi", "hdpi", "mdpi", "ldpi"]

    def _rank(cfg: str) -> int:
        for i, d in enumerate(order):
            if d in cfg:
                return len(order) - i
        return 0 if cfg.strip("-") == "" else -1

    best = None
    for cfg, path in configs:
        if not path.lower().endswith((".png", ".webp", ".jpg", ".jpeg")):
            continue
        if best is None or _rank(cfg) > _rank(best[0]):
            best = (cfg, path)
    if best:
        return best[1]
    for _cfg, path in configs:
        if path.lower().endswith(".xml"):
            return path
    return None


def _parse_xmltree(out: str):
    """Parse apkeditor `-xmltree -t text` into (tag, attrs, children) nodes.
    attrs: {name: ('str', value) | ('int', dtype, udata)}."""
    import struct as _st

    root = None
    stack: list[tuple[int, list]] = []

    def _val(s: str):
        s = s.strip()
        if s.startswith('"'):
            # first quoted string only: apkeditor appends (Raw: "...") suffixes
            m = re.match(r'"((?:[^"\\]|\\.)*)"', s)
            v = m.group(1) if m else s.strip('"')
            # unescape simple entities
            v = v.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
            return ("str", v)
        m = re.match(r"\(type\s+(0x[0-9a-fA-F]+)\)(0x[0-9a-fA-F]+)", s)
        if m:
            return ("int", int(m.group(1), 16), int(m.group(2), 16))
        return ("str", s)

    for line in out.splitlines():
        if not line.strip() or line.strip().startswith("source-path"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if body.startswith("N:"):
            continue
        if body.startswith("E:"):
            tag = body[2:].split("(")[0].strip()
            node = [tag, {}, []]
            while stack and stack[-1][0] >= indent:
                stack.pop()
            if stack:
                stack[-1][1][2].append(node)
            else:
                root = node
            stack.append((indent, node))
        elif body.startswith("A:"):
            rest = body[2:].strip()
            name, _, aval = rest.partition("=")
            name = name.split("(")[0].strip()
            if ":" in name:
                name = name.split(":")[-1]
            if stack:
                stack[-1][1][1][name] = _val(aval)
    return root


def _tree_attr(node, name: str):
    return node[1].get(name)


def _tree_color(val) -> tuple | None:
    if val is None:
        return None
    if val[0] == "str":
        return _parse_hex_color(val[1])
    if val[0] == "int":
        _t, dtype, udata = val
        if 0x1C <= dtype <= 0x1F:
            return ((udata >> 16) & 0xFF, (udata >> 8) & 0xFF, udata & 0xFF, (udata >> 24) & 0xFF)
    return None


def _tree_float(val, default=0.0) -> float:
    import struct as _st

    if val is None:
        return default
    if val[0] == "str":
        try:
            return float(val[1])
        except Exception:
            return default
    if val[0] == "int":
        _t, dtype, udata = val
        if dtype == 0x04:  # float
            try:
                return float(_st.unpack(">f", _st.pack(">I", udata & 0xFFFFFFFF))[0])
            except Exception:
                return default
        if dtype in (0x05, 0x06):  # dimension / fraction complex
            try:
                return _complex_float(udata)
            except Exception:
                return default
        if dtype == 0x10:
            v = udata if udata < 0x80000000 else udata - 0x100000000
            return float(v)
    if val[0] == "str":
        # "25%" fractions / "18dp" dimensions in plain-text trees
        return _num_attr(0x03, 0, val[1], default)
    return default


def _tree_ref_values(apk: Path, node, _depth: int = 0) -> dict[int, str]:
    """Batch-resolve every drawable/color/src ref ID in an xmltree node via one
    apkeditor -res call -> {rid: value}. Values are #hex or zip paths."""
    if _depth > 4:
        return {}
    want: list[int] = []

    def _walk(el):
        for k, v in el[1].items():
            if k in ("drawable", "color", "src") and isinstance(v, tuple) and v[0] == "int" and v[1] == 0x01:
                if v[2] not in want:
                    want.append(v[2])
        for c in el[2]:
            _walk(c)

    _walk(node)
    if not want:
        return {}
    out = _apkeditor_info(apk, *[a for rid in want for a in ("-res", hex(rid))], "-t", "text")
    if not out:
        return {}
    vals: dict[int, str] = {}
    lines = [l for l in out.splitlines() if l.strip().startswith("resource=")]
    for rid, line in zip(want, lines):
        m = re.match(r'resource="(.*)"\s*$', line.strip())
        if m:
            vals[rid] = m.group(1)
    return vals


def _render_text_node(apk: Path, z: zipfile.ZipFile, node, size: int, _depth: int = 0):
    """Render an xmltree-text drawable node (recursive: adaptive/inset/bitmap/
    vector/layer-list/shape/gradient/selector). Refs resolve via -res batch."""
    from PIL import Image  # type: ignore

    if _depth > 4:
        return None
    if _depth == 0:
        # substitute every @color/ ref in the subtree once, up front
        try:
            _resolve_tree_refs(node, apk)
        except Exception:
            pass
    tag = node[0]
    if tag == "vector":
        return _render_vector_treenode(node, size)
    if tag == "adaptive-icon":
        bg = fg = None
        for child in node[2]:
            if child[0] == "background" and bg is None:
                bg = _render_text_layer(apk, z, child, size, _depth)
            elif child[0] == "foreground" and fg is None:
                fg = _render_text_layer(apk, z, child, size, _depth)
        if bg is None:
            bg = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        if fg is None or fg.convert("RGBA").getbbox() is None:
            return None
        return Image.alpha_composite(bg.convert("RGBA"), fg.convert("RGBA").resize((size, size)))
    if tag in ("layer-list", "level-list"):
        base = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        for item in node[2]:
            layer = _render_text_layer(apk, z, item, size, _depth)
            if layer is not None:
                base = Image.alpha_composite(base, layer.convert("RGBA").resize((size, size)))
        return base if base.getbbox() else None
    if tag in ("inset", "scale", "clip"):
        return _render_text_layer(apk, z, node, size, _depth)
    if tag == "bitmap":
        return _render_text_layer(apk, z, node, size, _depth)
    if tag == "shape":
        for c in node[2]:
            if c[0] == "solid":
                col = _tree_color(c[1].get("color"))
                if col:
                    return Image.new("RGBA", (size, size), col)
        return None
    if tag == "gradient":
        cols = []
        for an in ("startColor", "centerColor", "endColor"):
            col = _tree_color(node[1].get(an))
            if col:
                cols.append(col)
        return _gradient_colors(cols, size) if cols else None
    if tag == "selector":
        for item in node[2]:
            if item[0] != "item":
                continue
            col = _tree_color(item[1].get("color"))
            if col:
                return Image.new("RGBA", (size, size), col)
        return None
    return None


def _render_text_layer(apk: Path, z: zipfile.ZipFile, node, size: int, _depth: int = 0):
    """Render one text-tree holder (background/foreground/item/inset/bitmap):
    explicit drawable ref first, else nested drawable element."""
    from PIL import Image  # type: ignore

    for aname in ("drawable", "color", "src"):
        aval = node[1].get(aname)
        if aval is not None and aval[0] == "int" and aval[1] == 0x01:
            img = _render_text_ref(apk, z, aval[2], size, _depth)
            if img is not None:
                break
    else:
        img = None
    if img is None:
        for sub in node[2]:
            if sub[0] in _DRAWABLE_TAGS:
                img = _render_text_node(apk, z, sub, size, _depth)
                if img is not None:
                    break
    if img is None:
        return None
    if node[0] == "inset":
        def _in(name):
            return _tree_inset_px(node[1].get(name), size)

        allv = _tree_inset_px(node[1].get("inset"), size)
        left = _in("insetLeft")
        if left is None:
            left = _in("insetStart")
        top = _in("insetTop")
        right = _in("insetRight")
        if right is None:
            right = _in("insetEnd")
        bottom = _in("insetBottom")
        left = allv if left is None else left
        top = allv if top is None else top
        right = allv if right is None else right
        bottom = allv if bottom is None else bottom
        if left or top or right or bottom:
            img = _apply_inset(img, size, left, top, right, bottom)
    return img


def _tree_inset_px(val, size: int) -> int | None:
    """Inset amount from an xmltree attr (fraction of box, dp, or px)."""
    if val is None:
        return None
    if val[0] == "str":
        s = val[1].strip()
        if s.endswith("%"):
            try:
                return int(float(s[:-1]) / 100.0 * size)
            except Exception:
                return None
        return _inset_px(0x03, 0, s, size)
    if val[0] == "int":
        _t, dtype, udata = val
        if dtype == 0x06:
            try:
                return int(_complex_float(udata) * size)
            except Exception:
                return None
        return _inset_px(dtype, udata, None, size)
    return None


def _render_text_ref(apk: Path, z: zipfile.ZipFile, rid: int, size: int, _depth: int = 0):
    """Render one ref ID from a text tree (batch-resolve, then draw)."""
    from PIL import Image  # type: ignore

    if _depth > 4:
        return None
    out = _apkeditor_info(apk, "-res", hex(rid), "-t", "text")
    if not out:
        return None
    for line in out.splitlines():
        m = re.match(r'resource="(.*)"\s*$', line.strip())
        if not m:
            continue
        v = m.group(1)
        if v.startswith("#"):
            col = _parse_hex_color(v)
            return Image.new("RGBA", (size, size), col) if col else None
        low = v.lower()
        if low.endswith((".png", ".webp", ".jpg", ".jpeg")):
            im = _load_raster(z, v)
            return im.resize((size, size), Image.LANCZOS) if im else None
        if low.endswith(".xml"):
            tree_out = _apkeditor_info(apk, "-xmltree", v, "-t", "text")
            if not tree_out:
                return None
            root = _parse_xmltree(tree_out)
            if root is None:
                return None
            if root[0] == "vector":
                _resolve_tree_refs(root, apk)
                return _render_vector_treenode(root, size)
            _resolve_tree_refs(root, apk)
            return _render_text_node(apk, z, root, size, _depth + 1)
    return None


def _resolve_tree_refs(root, apk: Path) -> None:
    """Replace ("int", REF, rid) color attrs in an xmltree node with the
    resolved #hex via one batched apkeditor -res call. Mutates in place.
    Covers vector fills/strokes as well as shape/solid/gradient/item colors
    (e.g. adaptive-icon backgrounds defined as <shape>)."""
    want: dict[int, list] = {}

    def _walk(el):
        for k, v in el[1].items():
            if k in ("fillColor", "strokeColor", "color", "startColor", "centerColor", "endColor") and isinstance(v, tuple) and v[0] == "int" and v[1] == 0x01:
                want.setdefault(v[2], []).append((el, k))
        for c in el[2]:
            _walk(c)

    _walk(root)
    if not want:
        return
    args: list[str] = []
    for rid in want:
        args += ["-res", hex(rid)]
    out = _apkeditor_info(apk, *args, "-t", "text")
    if not out:
        return
    lines = [l for l in out.splitlines() if l.strip().startswith("resource=")]
    for rid, line in zip(want, lines):
        m = re.match(r'resource="(.*)"\s*$', line.strip())
        if m and m.group(1).startswith("#"):
            for el, k in want[rid]:
                el[1][k] = ("str", m.group(1))


def _render_vector_treenode(root, size: int):
    """Rasterize an xmltree-parsed <vector> node."""
    vw = _tree_float(_tree_attr(root, "viewportWidth"), 24.0) or 24.0
    vh = _tree_float(_tree_attr(root, "viewportHeight"), 24.0) or 24.0
    ident = (1, 0, 0, 0, 1, 0, 0, 0, 1)
    paths = []

    def _walk(el, mat):
        tag = el[0]
        if tag == "group":
            g = {
                "translateX": _tree_float(_tree_attr(el, "translateX")),
                "translateY": _tree_float(_tree_attr(el, "translateY")),
                "scaleX": _tree_float(_tree_attr(el, "scaleX"), 1.0),
                "scaleY": _tree_float(_tree_attr(el, "scaleY"), 1.0),
                "rotation": _tree_float(_tree_attr(el, "rotation")),
                "pivotX": _tree_float(_tree_attr(el, "pivotX")),
                "pivotY": _tree_float(_tree_attr(el, "pivotY")),
            }
            for c in el[2]:
                _walk(c, _mat_mul(mat, _group_matrix(g)))
        elif tag == "path":
            d = _tree_attr(el, "pathData")
            if not d or d[0] != "str" or not d[1]:
                return
            fill = _tree_color(_tree_attr(el, "fillColor"))
            sc = _tree_attr(el, "strokeColor")
            stroke = _tree_color(sc) if sc else None
            sw = _tree_float(_tree_attr(el, "strokeWidth"), 1.0)
            if fill is not None:
                fa = _tree_attr(el, "fillAlpha")
                if fa and fa[0] == "str":
                    try:
                        faf = float(fa[1])
                    except Exception:
                        faf = 1.0
                elif fa and fa[0] == "int":
                    faf = _tree_float(fa, 1.0)
                else:
                    faf = 1.0
                fill = (fill[0], fill[1], fill[2], int(fill[3] * faf))
            ft = _tree_attr(el, "fillType")
            evenodd = ft is not None and ft[0] == "str" and ft[1] == "evenOdd"
            paths.append((d[1], fill, stroke, sw, evenodd, mat))

    for c in root[2]:
        _walk(c, ident)
    if not paths:
        return None
    return _rasterize_vector_paths(paths, size, vw, vh)


def _extract_icon_via_apkeditor(apk: Path) -> object:
    """Resolve the launcher icon through apkeditor (handles obfuscated tables).
    Returns a PIL RGBA image or None. Offline, ~2-6s."""
    out = _apkeditor_info(apk, "-app-icon", "-v", "-t", "text")
    if not out:
        out = _apkeditor_info(apk, "-app-round-icon", "-v", "-t", "text")
    if not out:
        return None
    configs = _parse_icon_configs(out)
    picked = _pick_icon_file(configs)
    if not picked:
        return None
    from PIL import Image  # type: ignore

    RENDER = 512
    try:
        z = zipfile.ZipFile(apk)
    except Exception:
        return None
    with z:
        if not picked.lower().endswith(".xml"):
            return _load_raster(z, picked)
        # adaptive (or vector) XML -> resolve layers via xmltree + -res
        tree_out = _apkeditor_info(apk, "-xmltree", picked, "-t", "text")
        if not tree_out:
            return None
        root = _parse_xmltree(tree_out)
        if root is None:
            return None
        if root[0] == "vector":
            _resolve_tree_refs(root, apk)
            return _render_vector_treenode(root, RENDER)
        # adaptive-icon and any other drawable: recursive renderer (handles
        # nested inset/adaptive/bitmap structures like Nova's icon)
        return _render_text_node(apk, z, root, RENDER)


def _value_to_image(z: zipfile.ZipFile, value: str, size: int, apk: Path | None = None):
    """Turn an apkeditor `-res` value (#hex | zip path) into an RGBA image."""
    from PIL import Image  # type: ignore

    if apk is None:
        try:
            apk = Path(z.filename or "")
        except Exception:
            apk = None

    value = (value or "").strip()
    if not value:
        return None
    if value.startswith("#"):
        col = _parse_hex_color(value)
        return Image.new("RGBA", (size, size), col) if col else None
    low = value.lower()
    if low.endswith((".png", ".webp", ".jpg", ".jpeg")):
        im = _load_raster(z, value)
        return im.resize((size, size), Image.LANCZOS) if im else None
    if low.endswith(".xml"):
        tree_out = _apkeditor_info(Path(z.filename or ""), "-xmltree", value, "-t", "text")
        if not tree_out:
            return None
        root = _parse_xmltree(tree_out)
        if root is None or apk is None or not apk.name:
            return None
        if root[0] == "vector":
            _resolve_tree_refs(root, apk)
            return _render_vector_treenode(root, size)
        return _render_text_node(apk, z, root, size)
    return None


def extract_icon(apk: Path, dest: Path) -> str | None:
    """Extract the real launcher icon at web-friendly resolution.

    Fast native path (manifest -> resources.arsc -> adaptive composite /
    raster / vector); falls back to apkeditor queries when the resource table
    uses packed overlay encoding. Returns dest.name on success, None when
    nothing real can be extracted (callers leave the icon hidden)."""
    from PIL import Image  # type: ignore

    def _save(img) -> str | None:
        try:
            img = img.convert("RGBA")
            if max(img.width, img.height) > _ICON_OUT_MAX:
                img.thumbnail((_ICON_OUT_MAX, _ICON_OUT_MAX), Image.LANCZOS)
            dest.parent.mkdir(parents=True, exist_ok=True)
            img.save(dest, "PNG")
            return dest.name
        except Exception:
            return None

    try:
        with zipfile.ZipFile(apk) as z:
            try:
                manifest = z.read("AndroidManifest.xml")
            except KeyError:
                return None
            icon_ref, round_ref = _manifest_icon_refs(manifest)
            got = _table_for_apk(apk)
            if got is None:
                return None
            table, pid = got
            RENDER = 512
            img = None
            saw_unresolved_adaptive = False
            for ref in (icon_ref, round_ref):
                if ref is None:
                    continue
                cands = _entry_file_candidates(table, pid, ref)
                if not cands:
                    continue
                # 1) adaptive-icon XML (anydpi) -> proper composite
                for _d, _s, path in cands:
                    if path.lower().endswith(".xml"):
                        try:
                            img = _render_adaptive(z, table, pid, path, RENDER)
                        except Exception as exc:
                            log.debug("adaptive render failed for %s: %s", path, exc)
                            img = None
                        if img is None:
                            saw_unresolved_adaptive = True
                        else:
                            break
                if img is not None:
                    break
                # 2) highest-density raster
                for _d, _s, path in cands:
                    if path.lower().endswith((".png", ".webp", ".jpg", ".jpeg")):
                        try:
                            img = _load_raster(z, path)
                        except Exception:
                            img = None
                        if img is not None:
                            break
                if img is not None:
                    break
                # 3) single vector drawable referenced directly
                for _d, _s, path in cands:
                    if path.lower().endswith(".xml"):
                        try:
                            img = _render_xml_drawable(z, table, pid, path, RENDER)
                        except Exception:
                            img = None
                        if img is not None:
                            break
                if img is not None:
                    break
            if img is None or saw_unresolved_adaptive:
                # Nothing usable natively, or an adaptive icon whose layers the
                # native table can't resolve (packed overlay encoding): ask
                # apkeditor, which parses the table authoritatively. Its result
                # (proper adaptive composite) wins over a low-res raster.
                try:
                    fb = _extract_icon_via_apkeditor(apk)
                except Exception as exc:
                    log.debug("apkeditor icon fallback failed for %s: %s", apk.name, exc)
                    fb = None
                if fb is not None:
                    img = fb
            if img is None:
                return None
            return _save(img)
    except Exception as exc:
        log.debug("icon extraction from %s failed: %s", apk.name, exc)
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
    icons_dir = ICONS
    icons_dir.mkdir(parents=True, exist_ok=True)
    repo_icon = icons_dir / "icon.png"
    if repo_icon.exists():
        return repo_icon.name
    # Prefer an existing app icon as repo icon, else generate a tiny fallback
    for cand in sorted(icons_dir.glob("*.png")):
        # skip the generic mgoogle fallback if possible, pick first real
        if cand.name != "icon.png":
            try:
                shutil.copyfile(cand, repo_icon)
                return repo_icon.name
            except Exception:
                pass
    # fallback: create 1x1
    try:
        repo_icon.write_bytes(base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAwMCAO+ip1sAAAAASUVORK5CYII="))
    except Exception:
        pass
    return repo_icon.name if repo_icon.exists() else "icon.png"


async def build_index(cfg: dict, state: dict, tag: str | None = None) -> bool:
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
                    if (ICONS / loc_icon).exists():
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
                pkg = CLONE_PACKAGE_MAP.get(raw_pkg, raw_pkg)
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
        # Process APKs concurrently (async) – apk_info is now async via subprocess
        async def _process_apk(apk: Path):
            entry = by_out.get(apk.name) or {}
            try:
                info = await tools.apk_info(editor_jar, apk)
            except Exception:
                info = None
            return apk, entry, info

        # Gather with concurrency limit to avoid spawning too many JVMs
        sem = asyncio.Semaphore(4)
        async def _bounded(apk):
            async with sem:
                return await _process_apk(apk)
        results = await asyncio.gather(*[_bounded(a) for a in apk_files])
        for apk, entry, info in results:
            if info:
                package, version, vc, app_name_real = info
                # normalize package: mgoogle clone
                if package in CLONE_PACKAGE_MAP:
                    package = CLONE_PACKAGE_MAP[package]
                disp_map = PACKAGE_DISPLAY
                cfg_display = next((a.get("display") for a in cfg.get("apps", []) if a.get("package") == package), None)
                app_name = cfg_display or disp_map.get(package) or disp_map.get(entry.get("package","")) or app_name_real or package
            else:
                if not (entry.get("package") and entry.get("version") and entry.get("vc")):
                    log.warning("index: skipping %s (no metadata)", apk.name)
                    continue
                try:
                    package, version, vc = entry["package"], entry["version"], int(entry["vc"])
                except (TypeError, ValueError):
                    log.warning("index: skipping %s (bad versionCode %r)", apk.name, entry.get("vc"))
                    continue
                if package in CLONE_PACKAGE_MAP:
                    package = CLONE_PACKAGE_MAP[package]
                disp_map2 = PACKAGE_DISPLAY
                cfg_display2 = next((a.get("display") for a in cfg.get("apps", []) if a.get("package") == package), None)
                app_name = cfg_display2 or disp_map2.get(package) or entry.get("app_name") or package

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
            icon_rel = ""
            # canonical icon locations (mirrors fdroidserver 2.x layout):
            #   icons/<package>.png            (repo root, also used by website)
            #   out/<package>/en-US/<package>.png  (per-app, referenced by index)
            icon_path = ICONS / icon_file
            if not icon_path.exists():
                extract_icon(apk, icon_path)
            per_app_dir = OUT / package / "en-US"
            per_app_icon = per_app_dir / icon_file
            if icon_path.exists():
                try:
                    per_app_dir.mkdir(parents=True, exist_ok=True)
                    if not per_app_icon.exists() or icon_path.stat().st_mtime > per_app_icon.stat().st_mtime:
                        shutil.copyfile(icon_path, per_app_icon)
                    icon_rel = icon_file
                except OSError:
                    icon_rel = icon_file if icon_path.exists() else ""
            # raw (store) package id for links; `package` may be a clone alias
            store_pkg = entry.get("package", package)
            for orig, alias in CLONE_PACKAGE_MAP.items():
                if alias == package:
                    store_pkg = orig
                    break

            display = app_name.removesuffix(" Morphe")
            # Enabled patch names for THIS app only: exact options paths
            # (short(pkg).combo.json, same files the patch runs used). Never
            # globbed — short names collide (android.app x2, app.* etc.) and
            # globbing leaks other apps' patch lists into this description.
            enabled_patches: list[str] = []
            try:
                _raw_pkg = entry.get("package", package)
                _combos = _combos_for_package(state, _raw_pkg) or _combos_for_package(state, package)
                _opt_files = [ROOT / "options" / f"{short(_raw_pkg)}.{c}.json" for c in _combos]
                _opt_files += [ROOT / "options" / f"{short(package)}.{c}.json" for c in _combos]
                for _opt in dict.fromkeys(_opt_files):
                    if not _opt.exists():
                        continue
                    _d = json.loads(_opt.read_text())
                    _entries = _d if isinstance(_d, list) else [_d]
                    for _e in _entries:
                        _patches = _e.get("patches", {})
                        _enabled = sorted(k for k, v in _patches.items() if isinstance(v, dict) and v.get("enabled"))
                        if _enabled:
                            enabled_patches = _enabled
                            break
                    if enabled_patches:
                        break
            except Exception:
                pass
            # Check if this is Android TV
            is_tv = package in TV_PACKAGES
            tv_note = " [Android TV]" if is_tv else ""
            bundle_tags = entry.get("bundle_tags") or {}
            if not bundle_tags and isinstance(entry.get("tags"), dict):
                bundle_tags = entry["tags"]
            bundle_str = ", ".join(f"{k} {v}" for k, v in sorted(bundle_tags.items()))
            summary = f"{display}{tv_note} patched with Morphe"
            desc_lines = [f"{summary}."]
            if bundle_str:
                desc_lines.append(f"Patches: {bundle_str}.")
            if enabled_patches:
                desc_lines.append(f"Enabled patches ({len(enabled_patches)}): " + ", ".join(enabled_patches) + ".")
            desc_lines.append(f"Original app: {store_pkg} {version} (patched APK signed with the F-Droid repo key).")
            if package in ("com.google.android.youtube", "app.morphe.android.youtube", "com.google.android.apps.youtube.music", "app.morphe.android.apps.youtube.music"):
                desc_lines.append("Requires MicroG for login and playback.")
            desc = "\n\n".join(desc_lines)
            # Keep it brief for F-Droid (max 4000 chars)
            if len(desc) > 3500:
                desc = desc[:3500]
            # Bundle source URL for the sourceCode link (first known bundle)
            bundle_url = ""
            try:
                bundles_cfg = cfg.get("bundles", {})
                for b in sorted(bundle_tags):
                    spec = bundles_cfg.get(b, "")
                    u = spec if isinstance(spec, str) else spec.get("url", "")
                    if u:
                        bundle_url = u
                        break
            except Exception:
                pass
            app_entry: dict = {
                "packageName": package,
                "name": app_name,
                "summary": summary,
                "description": desc,
                "categories": ["Other"],
                "license": "Unknown",
                "added": pkg_entry["added"],
                "lastUpdated": pkg_entry["added"],
                "webSite": f"https://play.google.com/store/apps/details?id={store_pkg}",
                "sourceCode": bundle_url or "https://github.com/Minehacker765/MorpheUpdater",
                "changelog": "https://github.com/Minehacker765/MorpheUpdater/releases",
                "issueTracker": "https://github.com/Minehacker765/MorpheUpdater/issues",
                "localized": {"en-US": {"name": app_name}},
            }
            if icon_rel:
                # icon lives at out/<pkg>/en-US/<file>, like fdroidserver 2.x
                app_entry["localized"]["en-US"]["icon"] = icon_rel
            if package not in apps:
                apps[package] = app_entry
            else:
                # merge: keep earliest added, newest metadata
                prev = apps[package]
                try:
                    app_entry["added"] = min(int(prev.get("added", app_entry["added"])), int(app_entry["added"]))
                except Exception:
                    pass
                try:
                    app_entry["lastUpdated"] = max(int(prev.get("lastUpdated", 0)), int(app_entry["lastUpdated"]))
                except Exception:
                    pass
                if not icon_rel and prev.get("localized", {}).get("en-US", {}).get("icon"):
                    app_entry["localized"]["en-US"]["icon"] = prev["localized"]["en-US"]["icon"]
                apps[package] = app_entry

    # If we fell back to prev_packages path above, drop legacy top-level icon
    # fields: clients resolve localized en-US icons to /<pkg>/en-US/<file>,
    # a bare top-level filename points nowhere.
    if not packages and prev_packages:
        packages = prev_packages
        apps = prev_apps
        for _pkg, _app in list(apps.items()):
            _app.pop("icon", None)

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
    for pkg, app in apps.items():
        try:
            if packages.get(pkg):
                app["suggestedVersionCode"] = packages[pkg][0]["versionCode"]
        except Exception:
            pass
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
    repo_icon_path = ICONS / repo_icon_name
    if not repo_icon_path.exists():
        # try fallback
        repo_icon_path = ICONS / _ensure_repo_icon()
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
        # metadata (summary/description live top-level in v1; mirror into maps)
        loc = app.get("localized", {}).get("en-US", {})
        # per-package icon dir, like fdroidserver 2.x: out/<pkg>/en-US/<file>
        icon_name = loc.get("icon") or app.get("icon")
        if icon_name:
            p = OUT / pkg / "en-US" / icon_name
            if not p.exists():
                p = ICONS / icon_name
            if p.exists():
                icon_entry = _file_entry(p, f"/{pkg}/en-US/{icon_name}")
            else:
                icon_entry = {"name": f"/{pkg}/en-US/{icon_name}", "sha256": "0"*64, "size": 0}
        else:
            icon_entry = {"name": f"/{pkg}/en-US/{pkg}.png", "sha256": "0"*64, "size": 0}

        metadata = {
            "name": {"en-US": loc.get("name", app.get("name", pkg))},
            "summary": {"en-US": app.get("summary", loc.get("summary", app.get("name", "")))},
            "description": {"en-US": app.get("description", loc.get("description", ""))},
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


ICON_EXTRACTOR_VERSION = 4


async def ensure_icons(state: dict) -> bool:
    """(Re)extract launcher icons from OUT APKs into ICONS/. Returns True if
    state changed. Tracks per-package (mtime, size) plus a global extractor
    version in state.json, so old placeholder icons are replaced exactly once
    and new/changed APKs always refresh their icon."""
    from .settings import OUT as _OUT

    jobs: list[tuple[str, Path, Path, tuple]] = []
    for key, entry in state.get("builds", {}).items():
        apk_name = entry.get("out") or ""
        if not apk_name:
            continue
        raw_pkg = entry.get("package", key.split("|")[0])
        pkg = CLONE_PACKAGE_MAP.get(raw_pkg, raw_pkg)
        src = _OUT / apk_name
        if not src.exists():
            continue
        try:
            cur = (int(src.stat().st_mtime), src.stat().st_size)
        except OSError:
            continue
        dest = ICONS / f"{pkg}.png"
        rec = (state.get("icons") or {}).get(pkg)
        if (
            state.get("icons_version") != ICON_EXTRACTOR_VERSION
            or rec is None
            or tuple(rec) != cur
            or not dest.exists()
        ):
            jobs.append((pkg, src, dest, cur))
    if not jobs:
        if state.get("icons_version") != ICON_EXTRACTOR_VERSION:
            state["icons_version"] = ICON_EXTRACTOR_VERSION
            return True
        return False
    log.info("extracting %d icon(s) (extractor v%d)", len(jobs), ICON_EXTRACTOR_VERSION)
    sem = asyncio.Semaphore(3)

    async def _one(pkg: str, src: Path, dest: Path, cur: tuple) -> tuple[str, tuple | None]:
        async with sem:
            try:
                got = await asyncio.to_thread(extract_icon, src, dest)
            except Exception as exc:
                log.debug("icon %s failed: %s", pkg, exc)
                return pkg, None
            return pkg, cur if got else None

    for pkg, cur in await asyncio.gather(*[_one(*j) for j in jobs]):
        if cur is not None:
            state.setdefault("icons", {})[pkg] = list(cur)
    state["icons_version"] = ICON_EXTRACTOR_VERSION
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
    return await build_index(cfg, state, tag)
