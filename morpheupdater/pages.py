"""Showcase page for GitHub Pages: apps, versions, patches, F-Droid QR."""

from __future__ import annotations

import json
import time
from pathlib import Path

from .settings import OUT, ROOT

TEMPLATE = """<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — MorpheUpdater</title>
<style>
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui;background:#0e0e10;color:#e6e6e6}
header{padding:2.5rem 1rem;text-align:center;border-bottom:1px solid #222}
h1{margin:0 0 .25rem;font-size:2rem}small{color:#9aa}
main{max-width:960px;margin:auto;padding:1.5rem}
.fdr{display:flex;gap:1.5rem;flex-wrap:wrap;align-items:center;background:#16161a;border:1px solid #2a2a30;border-radius:12px;padding:1rem 1.2rem;margin:1.2rem 0}
.fdr code{background:#0e0e10;padding:.2rem .4rem;border-radius:6px;font-size:.9rem;word-break:break-all}
#qrcode{background:#fff;padding:8px;border-radius:8px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:1rem}
.card{background:#16161a;border:1px solid #2a2a30;border-radius:12px;padding:1rem;display:flex;gap:1rem}
.card img{width:56px;height:56px;border-radius:12px;background:#222;object-fit:cover;flex-shrink:0}
.card h3{margin:.1rem 0 .2rem;font-size:1.05rem}.muted{color:#9aa;font-size:.85rem}a{color:#8ab4ff;text-decoration:none}a:hover{text-decoration:underline}
footer{text-align:center;color:#777;padding:2rem 1rem;font-size:.85rem}
</style>
<header>
  <h1>${title}</h1>
  <small>${description} · updated ${updated}</small>
</header>
<main>
  <div class="fdr">
    <div id="qrcode"></div>
    <div style="flex:1;min-width:240px">
      <div><b>F-Droid repo</b> — add to <a href="https://droidify.eu.org/">Droidify</a> / Neo Store</div>
      <div><code id="repoUrl">${repo_url}</code> <a href="#" onclick="navigator.clipboard.writeText(document.getElementById('repoUrl').textContent);return false">[copy]</a></div>
      <div class="muted">fingerprint: <code>${fingerprint}</code></div>
      <div style="margin-top:.6rem"><a id="addBtn" href="">Add to Droidify</a> · <a href="${repo_url}index-v1.jar">index-v1.jar</a></div>
    </div>
  </div>
  <div class="grid">${cards}</div>
</main>
<footer>Built from <a href="https://github.com/Minehacker765/MorpheUpdater">Minehacker765/MorpheUpdater</a> · patches ${patches}</footer>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<script>
const url=document.getElementById('repoUrl').textContent.trim();
new QRCode(document.getElementById("qrcode"),{text:url,width:132,height:132,correctLevel:QRCode.CorrectLevel.M}});
document.getElementById('addBtn').href="fdroidrepos://"+url.replace(/^https?:\\/\\//,"");
</script>
</html>
"""

CARD = """<div class="card">
  <img src="${icon}" onerror="this.style.visibility='hidden'">
  <div>
    <h3>${name}</h3>
    <div class="muted">${pkg} · ${ver} · ${arch}</div>
    <div class="muted">${patches}</div>
    <div style="margin-top:.4rem"><a href="${dl}">Download APK</a></div>
  </div>
</div>"""


def build_showcase(cfg: dict, state: dict) -> bool:
    meta = cfg.get("fdroid") or {}
    repo_url = meta.get("url") or "https://morpheupdater.minehacker765.workers.dev"
    fp = (state.get("fdroid") or {}).get("cert_sha256", "")
    title = meta.get("name", "Morphe Updater")
    desc = meta.get("description", "Patched apps")

    # patches summary e.g. "morphe v1.41.0-dev.1, prathxm v1.13.1-dev.4"
    patches = ", ".join(f"{k} {v}" for k, v in sorted(state.get("bundles", {}).items())) or "—"

    # per-app cards from state builds (one per pkg|combo|arch)
    # Map original -> actual (e.g. com.mgoogle -> app.revanced) via APK inspection when possible
    try:
        import json as _js2
        _idx2 = _js2.load(open(OUT / "index-v1.json"))
        _actual_map = {e["packageName"]: e["packageName"] for e in _idx2.get("apps", [])}
        # Also map original package from state to actual via APK
        for _k, _b in state.get("builds", {}).items():
            _orig = _b.get("package", _k.split("|")[0])
            # Find matching app in index by version/out
            for _a in _idx2.get("apps", []):
                if _a["packageName"] in (_orig, _orig.replace("com.mgoogle", "app.revanced")):
                    _actual_map[_orig] = _a["packageName"]
    except Exception:
        _actual_map = {}
    cards_html = ""
    for key in sorted(state.get("builds", {})):
        b = state["builds"][key]
        _orig_pkg = b.get("package", key.split("|")[0])
        pkg = _actual_map.get(_orig_pkg, _orig_pkg)
        ver = b.get("version", "?")
        arch = b.get("arch", "")
        apk = b.get("out", "")
        tag = next(iter(b.get("tags", {}).values()), "") or next(iter(state.get("bundles", {}).values()), "")
        dl = f"https://github.com/Minehacker765/MorpheUpdater/releases/latest/download/{apk}" if apk else "#"
        patches_str = ", ".join(f"{k} {v}" for k, v in sorted(b.get("tags", {}).items()))
        # YouTube/Music need MicroG
        if pkg in ("com.google.android.youtube", "app.morphe.android.youtube", "com.google.android.apps.youtube.music", "app.morphe.android.apps.youtube.music"):
            patches_str += " · requires MicroG"
        # icons are named after the *actual* (cloned) package, not the original
        icon = ""
        for cand in [pkg.replace("com.google.android.youtube", "app.morphe.android.youtube").replace("com.google.android.apps.youtube.music", "app.morphe.android.apps.youtube.music").replace("com.chess", "com.chess.prathxm"), pkg]:
            cand_path = f"icons/{cand}.png"
            if (OUT / cand_path).exists():
                icon = cand_path
                break
        # also try without the replace (for non-cloned)
        if not icon:
            for cand in [pkg, pkg.replace("com.chess", "com.chess.prathxm")]:
                cand_path = f"icons/{cand}.png"
                if (OUT / cand_path).exists():
                    icon = cand_path
                    break
        if not icon:
            apk_file = OUT / apk if apk else None
            if apk_file and apk_file.exists():
                try:
                    from morpheupdater.fdroid import extract_icon as _ei
                    got = _ei(apk_file, OUT / f"icons/{pkg}.png")
                    if got:
                        icon = f"icons/{got}"
                except Exception:
                    pass
        display = {
            "com.google.android.youtube": "YouTube", "app.morphe.android.youtube": "YouTube",
            "com.google.android.apps.youtube.music": "YouTube Music", "app.morphe.android.apps.youtube.music": "YouTube Music",
            "com.reddit.frontpage": "Reddit", "com.reddit.frontpage.morphe": "Reddit",
            "com.chess": "Chess", "com.chess.prathxm": "Chess",
            "com.mgoogle.android.gms": "MicroG", "app.revanced.android.gms": "MicroG",
            "tv.twitch.android.app": "Twitch",
            "com.strava": "Strava",
            "com.google.android.apps.photos": "Google Photos",
            "com.microblink.photomath": "Photomath",
            "com.facebook.katana": "Facebook",
            "com.amazon.mp3": "Amazon Music",
            "com.bandcamp.android": "Bandcamp",
            "de.gmx.mobile.android.mail": "GMX Mail",
            "ginlemon.iconpackstudio": "Icon Pack Studio",
            "com.facebook.orca": "Messenger",
            "com.letterboxd.letterboxd": "Letterboxd",
            "com.nothing.smartcenter": "Nothing X",
            "jp.pxv.android": "Pixiv",
        }
        cfg_display = next((a.get("display") for a in cfg.get("apps", []) if a.get("package") == pkg), None)
        name = cfg_display or display.get(pkg) or display.get(b.get("package","")) or pkg
        # Build patch dropdown for webpage
        patch_list_html = ""
        try:
            import json as _js3
            for _opt in (ROOT / "options").glob(f"{pkg.split('.')[-1]}.*.json"):
                if not _opt.exists():
                    continue
                _d = json.loads(_opt.read_text())
                _entries = _d if isinstance(_d, list) else [_d]
                for _e in _entries:
                    _patches = _e.get("patches", {})
                    _enabled = [k for k, v in _patches.items() if isinstance(v, dict) and v.get("enabled")]
                    if _enabled:
                        patch_list_html = "<details><summary>" + str(len(_enabled)) + " patches</summary><ul>"
                        for _pn in sorted(_enabled):
                            patch_list_html += f"<li>{_pn}</li>"
                        patch_list_html += "</ul></details>"
                        break
                if patch_list_html:
                    break
        except Exception:
            pass
        # Check TV
        is_tv = pkg in ["com.netflix.ninja", "com.amazon.amazonvideo.livingroom", "tv.pluto.android", "com.disney.disneyplus", "com.wbd.hbomax", "com.peacocktv.peacockandroid", "com.fox.foxone", "com.tubitv", "com.bamnetworks.mobile.android.gameday.atbat", "com.cbs.ott"]
        tv_badge = " <span style='background:#2a2a30;padding:2px 6px;border-radius:4px;font-size:0.7rem'>TV</span>" if is_tv else ""
        from string import Template as _T
        cards_html += _T(CARD).substitute(icon=icon, name=name+tv_badge, pkg=pkg, ver=ver, arch=arch, patches=patches_str+patch_list_html, dl=dl)

    if not cards_html:
        for app in cfg.get("apps", []):
            pkg = app["package"]
            disp2 = {
                "com.google.android.youtube": "YouTube", "com.google.android.apps.youtube.music": "YouTube Music",
                "com.reddit.frontpage": "Reddit", "com.chess": "Chess",
                "tv.twitch.android.app": "Twitch", "com.strava": "Strava",
                "com.google.android.apps.photos": "Google Photos", "com.microblink.photomath": "Photomath",
                "com.facebook.katana": "Facebook", "com.amazon.mp3": "Amazon Music",
                "com.bandcamp.android": "Bandcamp", "de.gmx.mobile.android.mail": "GMX Mail",
                "ginlemon.iconpackstudio": "Icon Pack Studio", "com.facebook.orca": "Messenger",
                "com.letterboxd.letterboxd": "Letterboxd", "com.nothing.smartcenter": "Nothing X",
                "jp.pxv.android": "Pixiv",
            }.get(pkg, pkg)
            from string import Template as _T2
            cards_html += _T2(CARD).substitute(icon=f"icons/{pkg}.png", name=disp2, pkg=pkg, ver="—", arch=",".join(cfg.get("archs", [])), patches="—", dl="#")

    from string import Template
    html = Template(TEMPLATE).substitute(title=title, description=desc, repo_url=repo_url, fingerprint=fp or "—", updated=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), cards=cards_html, patches=patches)
    dest = OUT / "index.html"
    if dest.exists() and dest.read_text() == html:
        return False
    dest.write_text(html)
    return True
