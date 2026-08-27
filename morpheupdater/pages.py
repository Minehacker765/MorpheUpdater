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
    cards_html = ""
    for key in sorted(state.get("builds", {})):
        b = state["builds"][key]
        pkg = b.get("package", key.split("|")[0])
        ver = b.get("version", "?")
        arch = b.get("arch", "")
        apk = b.get("out", "")
        tag = next(iter(b.get("tags", {}).values()), "") or next(iter(state.get("bundles", {}).values()), "")
        dl = f"https://github.com/Minehacker765/MorpheUpdater/releases/download/{tag}/{apk}" if tag and apk else "#"
        patches_str = ", ".join(f"{k} {v}" for k, v in sorted(b.get("tags", {}).items()))
        icon = f"icons/{pkg}.png"
        if not (OUT / icon).exists():
            icon = ""
        from string import Template as _T
        cards_html += _T(CARD).substitute(icon=icon, name=b.get("app_name") or pkg.rsplit(".", 1)[-1].capitalize(), pkg=pkg, ver=ver, arch=arch, patches=patches_str, dl=dl)

    if not cards_html:
        for app in cfg.get("apps", []):
            pkg = app["package"]
            from string import Template as _T2
            cards_html += _T2(CARD).substitute(icon=f"icons/{pkg}.png", name=pkg.rsplit(".", 1)[-1].capitalize(), pkg=pkg, ver="—", arch=",".join(cfg.get("archs", [])), patches="—", dl="#")

    from string import Template
    html = Template(TEMPLATE).substitute(title=title, description=desc, repo_url=repo_url, fingerprint=fp or "—", updated=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), cards=cards_html, patches=patches)
    dest = OUT / "index.html"
    if dest.exists() and dest.read_text() == html:
        return False
    dest.write_text(html)
    return True
