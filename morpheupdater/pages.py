"""Showcase page for GitHub Pages: apps, versions, patches, F-Droid QR."""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from string import Template

from .display import CLONE_PACKAGE_MAP, PACKAGE_DISPLAY, TV_PACKAGES
from .settings import ICONS, OUT, ROOT, short

TEMPLATE = """<!doctype html>
<html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title} — MorpheUpdater</title>
<style>
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,-apple-system,Segoe UI,Roboto,Ubuntu,sans-serif;background:#0e0e10;color:#e6e6e6}
header{padding:2.5rem 1rem 1.5rem;text-align:center;border-bottom:1px solid #222}
h1{margin:0 0 .25rem;font-size:2.1rem;letter-spacing:-.02em}small{color:#9aa}
main{max-width:1100px;margin:auto;padding:1.5rem}
.fdr{display:flex;gap:1.5rem;flex-wrap:wrap;align-items:center;background:#16161a;border:1px solid #2a2a30;border-radius:14px;padding:1.1rem 1.2rem;margin:1.2rem 0}
.fdr code{background:#0e0e10;padding:.2rem .45rem;border-radius:7px;font-size:.88rem;word-break:break-all}
#qrcode{background:#fff;padding:8px;border-radius:10px}
.controls{display:flex;gap:.8rem;flex-wrap:wrap;align-items:center;background:#16161a;border:1px solid #2a2a30;border-radius:14px;padding:.9rem 1rem;margin:1rem 0}
.controls input[type=search]{flex:1;min-width:220px;background:#0e0e10;border:1px solid #2a2a30;color:#e6e6e6;border-radius:10px;padding:.6rem .8rem;font:inherit;outline:none}
.controls input[type=search]:focus{border-color:#3a3a44}
.controls select{background:#0e0e10;border:1px solid #2a2a30;color:#e6e6e6;border-radius:10px;padding:.55rem .7rem;font:inherit}
.toggle{user-select:none;cursor:pointer;display:inline-flex;align-items:center;justify-content:center;background:#2a2a30;border:1px solid #3a3a44;border-radius:10px;padding:.6rem 1rem;font-weight:700;transition:.18s;min-width:190px}
.toggle.on{background:#1a7f4a;border-color:#1a7f4a;color:#fff;box-shadow:0 2px 12px rgba(26,127,74,.35)}
.bundle{margin:1.1rem 0;border:1px solid #2a2a30;border-radius:14px;background:#16161a;overflow:hidden}
.bundle summary{list-style:none;cursor:pointer;padding:.85rem 1rem;font-weight:700;display:flex;justify-content:space-between;align-items:center;background:#1b1b20}
.bundle summary::-webkit-details-marker{display:none}
.bundle summary .count{background:#0e0e10;border:1px solid #2a2a30;border-radius:999px;padding:.15rem .5rem;font-size:.8rem;color:#9aa}
.bundle[open] summary{border-bottom:1px solid #2a2a30}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:1rem;padding:1rem}
.card{background:#0e0e10;border:1px solid #2a2a30;border-radius:14px;padding:1rem;display:flex;gap:1rem;transition:.15s}
.card:hover{border-color:#3a3a44;transform:translateY(-1px)}
.card img{width:56px;height:56px;border-radius:12px;background:#1e1e1e;object-fit:cover;flex-shrink:0}
.card h3{margin:.1rem 0 .15rem;font-size:1.02rem;line-height:1.2}
.muted{color:#9aa;font-size:.84rem}
.card a{color:#8ab4ff;text-decoration:none} .card a:hover{text-decoration:underline}
.patches{margin-top:.3rem}
.patches details summary{cursor:pointer;color:#9aa;font-size:.84rem}
.patches ul{margin:.3rem 0 0 1rem;color:#c9c9c9}
footer{text-align:center;color:#777;padding:2rem 1rem;font-size:.85rem}
.empty{padding:2rem;text-align:center;color:#9aa}
</style>
<header>
  <h1>${title}</h1>
  <small>${description} · updated ${updated} · ${total} apps</small>
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

  <div class="controls">
    <input id="search" type="search" placeholder="Search apps, packages…">
    <select id="sort"><option value="name">Sort: Name A→Z</option><option value="name_desc">Sort: Name Z→A</option><option value="patches_desc">Sort: Most patches</option><option value="patches_asc">Sort: Fewest patches</option></select>
    <div id="bundleToggle" class="toggle" role="button" tabindex="0" aria-pressed="false">Separate by bundle</div>
  </div>

  <div id="grouped" style="display:none">${grouped}</div>
  <div id="flat" class="grid">${flat}</div>
  <div id="empty" class="empty" style="display:none">No apps match.</div>
</main>
<footer>Built from <a href="https://github.com/Minehacker765/MorpheUpdater">Minehacker765/MorpheUpdater</a> · patches ${patches}</footer>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function(){
  const urlEl=document.getElementById('repoUrl');
  if(urlEl){
    const url=urlEl.textContent.trim();
    const qr=document.getElementById("qrcode");
    if(qr) new QRCode(qr,{text:url,width:132,height:132,correctLevel:QRCode.CorrectLevel.M});
    const btn=document.getElementById('addBtn');
    if(btn) btn.href="fdroidrepos://"+url.replace(/^https?:\\/\\//,"");
  }
  const search=document.getElementById('search');
  const sort=document.getElementById('sort');
  const toggle=document.getElementById('bundleToggle');
  const grouped=document.getElementById('grouped');
  const flat=document.getElementById('flat');
  const empty=document.getElementById('empty');
  let separate=false;
  function apply(){
    const q=(search.value||"").trim().toLowerCase();
    let any=false;
    const cards=(separate?grouped:flat).querySelectorAll('.card');
    cards.forEach(c=>{
      const hay=(c.dataset.name+" "+c.dataset.pkg+" "+c.dataset.bundle).toLowerCase();
      const show=!q||hay.includes(q);
      c.style.display=show?"":"none";
      if(show) any=true;
    });
    if(separate){
      grouped.querySelectorAll('.bundle').forEach(b=>{
        const vis=[...b.querySelectorAll('.card')].some(c=>c.style.display!=="none");
        b.style.display=vis||!q?"":"none";
        if(vis) any=true;
      });
    }
    empty.style.display=any?"none":"block";
  }
  function sortCards(){
    const v=sort.value;
    const cmp=(a,b)=>{
      if(v==="name") return a.dataset.name.localeCompare(b.dataset.name);
      if(v==="name_desc") return b.dataset.name.localeCompare(a.dataset.name);
      if(v==="patches_desc") return (+b.dataset.patches)-(+a.dataset.patches);
      if(v==="patches_asc") return (+a.dataset.patches)-(+b.dataset.patches);
      return 0;
    };
    const flatCards=[...flat.children].filter(c=>c.classList.contains('card'));
    flatCards.sort(cmp).forEach(c=>flat.appendChild(c));
    grouped.querySelectorAll('.bundle .grid').forEach(g=>{
      const cards=[...g.children].filter(c=>c.classList.contains('card'));
      cards.sort(cmp).forEach(c=>g.appendChild(c));
    });
  }
  if(search) search.addEventListener('input',apply);
  if(sort) sort.addEventListener('change',sortCards);
  if(toggle){
    toggle.addEventListener('click',()=>{
      separate=!separate;
      toggle.classList.toggle('on',separate);
      toggle.setAttribute('aria-pressed',separate);
      grouped.style.display=separate?"":"none";
      flat.style.display=separate?"none":"grid";
      apply();
    });
    toggle.addEventListener('keydown',e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); toggle.click(); }});
  }
  sortCards(); apply();
});
</script>
</html>
"""

CARD = """<div class="card" data-name="${name_attr}" data-pkg="${pkg}" data-bundle="${bundle}" data-patches="${patches_count}">
  <img src="${icon}" loading="lazy" onerror="this.style.display='none'">
  <div style="min-width:0;flex:1">
    <h3>${name}</h3>
    <div class="muted">${pkg} · ${ver} · ${arch}</div>
    <div class="muted">${bundle_label}</div>
    <div class="patches">${patches_html}</div>
    <div style="margin-top:.45rem"><a href="${dl}">Download APK</a></div>
  </div>
</div>"""


def _load_patch_compat(mpp_path: str) -> dict[str, set[str] | None]:
    """Map patch name -> compatible packages for a bundle MPP via list-patches.

    Same patch name can target several apps (e.g. "Skip ads" x6 in androidtv),
    so packages UNION across duplicates. None = never seen with a packages
    section (unknown, keep); empty set = universal (keep for all).

    Runs a JVM subprocess; callers should run it in a worker thread."""
    import re
    import subprocess
    from pathlib import Path
    try:
        jar = ROOT / "bin" / "morphe-desktop.jar"
        if not Path(mpp_path).exists() or not jar.exists():
            return {}
        cmd = ["java", "-jar", str(jar), "list-patches", "--patches", mpp_path, "--with-packages", "--with-versions=false", "--with-descriptions=false", "--with-options=false"]
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if out.returncode != 0:
            return {}
        compat: dict[str, set[str] | None] = {}
        current = None
        # state: wait for Name, then Compatible packages block
        lines = out.stdout.splitlines()
        i = 0
        while i < len(lines):
            raw = lines[i]
            stripped = raw.strip()
            # Name line: "Name: PatchName" or "1. PatchName"
            if stripped.startswith("Name:"):
                current = stripped.split("Name:", 1)[1].strip()
                compat.setdefault(current, None)
            elif re.match(r'^\d+\.\s*.+', stripped):
                # fallback for older format
                m = re.match(r'^\d+\.\s*(.+)$', stripped)
                if m:
                    current = m.group(1).strip()
                    compat.setdefault(current, None)
            elif stripped == "Compatible packages:" and current:
                # next lines are "Package name: xxx" until blank or next field
                pkgs: set[str] = set()
                j = i + 1
                while j < len(lines):
                    nxt = lines[j].strip()
                    if not nxt:
                        j += 1
                        continue
                    if nxt.startswith("Package name:"):
                        pkgs.add(nxt.split("Package name:", 1)[1].strip())
                        j += 1
                    elif nxt.startswith("Compatible") or nxt.startswith("Name:") or re.match(r'^\d+\.', nxt) or nxt.startswith("Index:"):
                        break
                    else:
                        j += 1
                prev = compat.get(current)
                compat[current] = (prev or set()) | pkgs
                i = j - 1
            i += 1
        return compat
    except Exception:
        return {}


def _compat_allows(compat: dict, patch: str, pkg: str, orig_pkg: str) -> bool:
    """True if the patch may apply to the package (unknown/universal keep)."""
    if not compat:
        return True
    pkgs = compat.get(patch)
    if pkgs is None or not pkgs:
        return True
    return pkg in pkgs or orig_pkg in pkgs


async def build_showcase(cfg: dict, state: dict) -> bool:
    meta = cfg.get("fdroid") or {}
    repo_url = meta.get("url") or "https://morpheupdater.minehacker765.workers.dev"
    fp = (state.get("fdroid") or {}).get("cert_sha256", "")
    title = meta.get("name", "Morphe Updater")
    desc = meta.get("description", "Patched apps")

    patches = ", ".join(f"{k} {v}" for k, v in sorted(state.get("bundles", {}).items())) or "—"

    # ensure icons are available under out/icons for Pages (out is the artifact)
    try:
        (OUT / "icons").mkdir(parents=True, exist_ok=True)
        if ICONS.exists():
            for p in ICONS.glob("*.png"):
                if p.name == "icon.png":
                    continue
                dest = OUT / "icons" / p.name
                if not dest.exists() or p.stat().st_mtime > dest.stat().st_mtime:
                    shutil.copyfile(p, dest)
            if (ICONS / "icon.png").exists() and not (OUT / "icons" / "icon.png").exists():
                shutil.copyfile(ICONS / "icon.png", OUT / "icons" / "icon.png")
    except Exception:
        pass

    # map original -> actual (e.g. com.mgoogle -> app.revanced) via index-v1
    try:
        with open(OUT / "index-v1.json") as f:
            _idx2 = json.load(f)
        _actual_map = {e["packageName"]: e["packageName"] for e in _idx2.get("apps", [])}
        for _k, _b in state.get("builds", {}).items():
            _orig = _b.get("package", _k.split("|")[0])
            for _a in _idx2.get("apps", []):
                _clone = CLONE_PACKAGE_MAP.get(_orig, _orig)
                if _a["packageName"] in (_orig, _clone):
                    _actual_map[_orig] = _a["packageName"]
    except Exception:
        _actual_map = {}

    # per-bundle patch compat, loaded concurrently off the event loop
    # (each load spawns a JVM via list-patches)
    from morpheupdater.daemon import _get_local_mpp

    def _mpp_for(bundle: str) -> str | None:
        url = cfg.get("bundles", {}).get(bundle, "")
        u = url if isinstance(url, str) else url.get("url", "")
        if u and "github.com" in u:
            tag = state.get("bundles", {}).get(bundle)
            p = _get_local_mpp(u, tag) if tag else _get_local_mpp(u)
            if p and p.exists():
                return str(p)
        return None

    bundles_needed: set[str] = set()
    for _b in state.get("builds", {}).values():
        _tags = _b.get("tags", {}) or {}
        bundles_needed.update(_tags.keys())

    async def _load_one(bundle: str) -> tuple[str, dict[str, set[str] | None]]:
        mpp = _mpp_for(bundle)
        if not mpp:
            return bundle, {}
        try:
            return bundle, await asyncio.to_thread(_load_patch_compat, mpp)
        except Exception:
            return bundle, {}

    compat_cache: dict[str, dict[str, set[str] | None]] = dict(
        await asyncio.gather(*[_load_one(bn) for bn in sorted(bundles_needed)])
    )

    def get_compat(bundle: str) -> dict[str, set[str] | None]:
        return compat_cache.get(bundle, {})

    # collect cards data
    cards = []
    for key in sorted(state.get("builds", {})):
        b = state["builds"][key]
        _orig_pkg = b.get("package", key.split("|")[0])
        pkg = _actual_map.get(_orig_pkg, _orig_pkg)
        ver = b.get("version", "?")
        arch = b.get("arch", "")
        apk = b.get("out", "")
        dl = f"https://github.com/Minehacker765/MorpheUpdater/releases/latest/download/{apk}" if apk else "#"
        tags = b.get("tags", {})
        bundle = next(iter(tags.keys()), key.split("|")[1] if "|" in key else "—")
        bundle_label = ", ".join(f"{k}" for k in tags.keys()) or bundle
        patches_str = ", ".join(f"{k} {v}" for k, v in sorted(tags.items()))
        if pkg in ("com.google.android.youtube", "app.morphe.android.youtube", "com.google.android.apps.youtube.music", "app.morphe.android.apps.youtube.music"):
            patches_str += " · requires MicroG"

        # icon: try clone then original, else extract from apk, else per-pkg placeholder
        icon = ""
        candidates = []
        clone = CLONE_PACKAGE_MAP.get(pkg)
        if clone:
            candidates.append(clone)
        if _orig_pkg != pkg and _orig_pkg not in candidates:
            candidates.append(_orig_pkg)
        candidates.append(pkg)
        for cand in candidates:
            cand_path = f"icons/{cand}.png"
            if (OUT / cand_path).exists() or (ICONS / f"{cand}.png").exists():
                try:
                    if (ICONS / f"{cand}.png").exists() and not (OUT / cand_path).exists():
                        (OUT / "icons").mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(ICONS / f"{cand}.png", OUT / cand_path)
                except Exception:
                    pass
                icon = cand_path
                break
        if not icon:
            apk_file = OUT / apk if apk else None
            if apk_file and apk_file.exists():
                try:
                    from morpheupdater.fdroid import extract_icon
                    tmp_icon = ICONS / f"{pkg}.png"
                    got = extract_icon(apk_file, tmp_icon)
                    if got and (ICONS / got).exists():
                        dest = OUT / "icons" / got
                        if not dest.exists():
                            dest.parent.mkdir(parents=True, exist_ok=True)
                            shutil.copyfile(ICONS / got, dest)
                        icon = f"icons/{got}"
                    elif tmp_icon.exists():
                        dest = OUT / "icons" / tmp_icon.name
                        if not dest.exists():
                            shutil.copyfile(tmp_icon, dest)
                        icon = f"icons/{tmp_icon.name}"
                except Exception:
                    pass
        if not icon:
            # no icon found and apk extraction failed — leave hidden (no generic youtube music fallback)
            icon = ""

        display = PACKAGE_DISPLAY
        cfg_display = next((a.get("display") for a in cfg.get("apps", []) if a.get("package") == pkg), None)
        name = cfg_display or display.get(pkg) or display.get(b.get("package", "")) or pkg
        # patch count for sort - only patches compatible with THIS app.
        # Options file is addressed exactly (short(pkg).combo.json, same as the
        # patch run used) — never globbed, so colliding short names (android.app
        # x2, app.* etc.) can't leak another app's list in.
        patches_count = 0
        patch_list_html = ""
        try:
            compat = get_compat(bundle)
            compat_for_pkg = [pn for pn in compat if _compat_allows(compat, pn, pkg, _orig_pkg)]
            # exact options file for this state entry (pkg|combo|arch)
            cid = key.split("|")[1] if "|" in key else bundle
            opt_files = [ROOT / "options" / f"{short(_orig_pkg)}.{cid}.json"]
            _opt = next((p for p in opt_files if p.exists()), None)
            if _opt is not None:
                _d = json.loads(_opt.read_text())
                _entries = _d if isinstance(_d, list) else [_d]
                for _e in _entries:
                    _patches = _e.get("patches", {})
                    _enabled = [
                        pn for pn, pv in _patches.items()
                        if isinstance(pv, dict) and pv.get("enabled")
                        and _compat_allows(compat, pn, pkg, _orig_pkg)
                    ]
                    if _enabled:
                        patches_count = len(_enabled)
                        patch_list_html = "<details><summary>" + str(len(_enabled)) + " patches</summary><ul>"
                        for _pn in sorted(_enabled):
                            patch_list_html += f"<li>{_pn}</li>"
                        patch_list_html += "</ul></details>"
                        break
            # fallback: no usable options file -> show MPP-compatible patches
            if not patch_list_html and compat_for_pkg:
                patches_count = len(compat_for_pkg)
                patch_list_html = "<details><summary>" + str(patches_count) + " patches</summary><ul>"
                for _pn in sorted(compat_for_pkg):
                    patch_list_html += f"<li>{_pn}</li>"
                patch_list_html += "</ul></details>"
        except Exception:
            pass
        patches_html = patch_list_html if patch_list_html else f"<span class='muted'>{patches_str or '—'}</span>"

        is_tv = pkg in TV_PACKAGES
        tv_badge = " <span style='background:#2a2a30;padding:2px 6px;border-radius:4px;font-size:0.7rem'>TV</span>" if is_tv else ""
        name_html = name + tv_badge
        name_attr = name.replace('"', "&quot;")
        card_html = Template(CARD).substitute(
            icon=icon, name=name_html, name_attr=name_attr, pkg=pkg, ver=ver, arch=arch,
            bundle=bundle, bundle_label=bundle_label, patches_count=patches_count,
            patches_html=patches_html, dl=dl,
        )
        cards.append((bundle, card_html, name.lower(), patches_count))

    from collections import defaultdict
    by_bundle: dict[str, list] = defaultdict(list)
    for bundle, html, lname, pc in cards:
        by_bundle[bundle].append((html, lname, pc))
    grouped_html = ""
    for bundle in sorted(by_bundle.keys()):
        items = by_bundle[bundle]
        items.sort(key=lambda x: x[1])
        inner = "\n".join(h for h, _, _ in items)
        grouped_html += f'<details class="bundle" open><summary>{bundle} <span class="count">{len(items)}</span></summary><div class="grid">{inner}</div></details>\n'
    flat_sorted = sorted(cards, key=lambda x: x[2])
    flat_html = "\n".join(h for _, h, _, _ in flat_sorted)

    if not cards:
        from morpheupdater.daemon import _enabled_archs
        flat_html = ""
        for app in cfg.get("apps", []):
            pkg = app["package"]
            disp2 = PACKAGE_DISPLAY.get(pkg, pkg)
            archs = _enabled_archs(cfg.get("archs"))
            flat_html += Template(CARD).substitute(icon=f"icons/{pkg}.png", name=disp2, name_attr=disp2, pkg=pkg, ver="—", arch=",".join(archs), bundle="—", bundle_label="—", patches_count=0, patches_html="—", dl="#")
        grouped_html = f'<details class="bundle" open><summary>apps <span class="count">{len(cfg.get("apps", []))}</span></summary><div class="grid">{flat_html}</div></details>'

    total = len(cards)
    html = Template(TEMPLATE).substitute(title=title, description=desc, repo_url=repo_url, fingerprint=fp or "—", updated=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime()), grouped=grouped_html, flat=flat_html, patches=patches, total=total)
    dest = OUT / "index.html"
    if dest.exists() and dest.read_text() == html:
        return False
    dest.write_text(html)
    return True
