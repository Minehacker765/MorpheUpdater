"""Showcase page for GitHub Pages: apps, versions, patches, F-Droid QR."""

from __future__ import annotations

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
.toggle{user-select:none;cursor:pointer;display:inline-flex;align-items:center;gap:.6rem;background:#24242a;border:1px solid #2a2a30;border-radius:999px;padding:.38rem .6rem .38rem .5rem;font-weight:600;transition:.18s}
.toggle.on{background:#1a7f4a;border-color:#1a7f4a;color:#fff;box-shadow:0 2px 10px rgba(26,127,74,.35)}
.toggle .dot{width:18px;height:18px;border-radius:50%;background:#fff;transition:.18s;box-shadow:0 1px 4px rgba(0,0,0,.3)}
.toggle.on .dot{transform:translateX(2px)}
.toggle .label{font-size:.92rem}
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
    <select id="sort"><option value="name">Sort: Name ↑</option><option value="name_desc">Sort: Name ↓</option><option value="patches_desc">Sort: Patches ↓</option><option value="patches_asc">Sort: Patches ↑</option></select>
    <div id="bundleToggle" class="toggle on" role="button" tabindex="0" aria-pressed="true"><span class="dot"></span><span class="label">Separate by bundle</span></div>
  </div>

  <div id="grouped">${grouped}</div>
  <div id="flat" class="grid" style="display:none">${flat}</div>
  <div id="empty" class="empty" style="display:none">No apps match.</div>
</main>
<footer>Built from <a href="https://github.com/Minehacker765/MorpheUpdater">Minehacker765/MorpheUpdater</a> · patches ${patches}</footer>
<script src="https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js"></script>
<script>
const url=document.getElementById('repoUrl').textContent.trim();
new QRCode(document.getElementById("qrcode"),{text:url,width:132,height:132,correctLevel:QRCode.CorrectLevel.M}});
document.getElementById('addBtn').href="fdroidrepos://"+url.replace(/^https?:\\/\\//,"");
const search=document.getElementById('search');
const sort=document.getElementById('sort');
const toggle=document.getElementById('bundleToggle');
const grouped=document.getElementById('grouped');
const flat=document.getElementById('flat');
const empty=document.getElementById('empty');
let separate=true;
function apply(){
  const q=search.value.trim().toLowerCase();
  let any=false;
  document.querySelectorAll('.card').forEach(c=>{
    const hay=(c.dataset.name+" "+c.dataset.pkg+" "+c.dataset.bundle).toLowerCase();
    const show=!q||hay.includes(q);
    c.style.display=show?"":"none";
    if(show) any=true;
  });
  document.querySelectorAll('.bundle').forEach(b=>{
    const vis=[...b.querySelectorAll('.card')].some(c=>c.style.display!=="none");
    b.style.display=vis||!q?"":"none";
  });
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
  document.querySelectorAll('.bundle .grid, #flat').forEach(g=>{
    [...g.children].sort(cmp).forEach(c=>g.appendChild(c));
  });
}
search.addEventListener('input',apply);
sort.addEventListener('change',sortCards);
toggle.addEventListener('click',()=>{
  separate=!separate;
  toggle.classList.toggle('on',separate);
  toggle.setAttribute('aria-pressed',separate);
  grouped.style.display=separate?"":"none";
  flat.style.display=separate?"none":"grid";
});
toggle.addEventListener('keydown',e=>{ if(e.key==="Enter"||e.key===" "){ e.preventDefault(); toggle.click(); }});
sortCards(); apply();
</script>
</html>
"""

CARD = """<div class="card" data-name="${name_attr}" data-pkg="${pkg}" data-bundle="${bundle}" data-patches="${patches_count}">
  <img src="${icon}" loading="lazy" onerror="this.style.visibility='hidden'">
  <div style="min-width:0;flex:1">
    <h3>${name}</h3>
    <div class="muted">${pkg} · ${ver} · ${arch}</div>
    <div class="muted">${bundle_label}</div>
    <div class="patches">${patches_html}</div>
    <div style="margin-top:.45rem"><a href="${dl}">Download APK</a></div>
  </div>
</div>"""


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
                dest = OUT / "icons" / p.name
                if not dest.exists() or p.stat().st_mtime > dest.stat().st_mtime:
                    shutil.copyfile(p, dest)
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
        # bundle label: first tag key or combo
        tags = b.get("tags", {})
        bundle = next(iter(tags.keys()), key.split("|")[1] if "|" in key else "—")
        bundle_label = ", ".join(f"{k}" for k in tags.keys()) or bundle
        patches_str = ", ".join(f"{k} {v}" for k, v in sorted(tags.items()))
        if pkg in ("com.google.android.youtube", "app.morphe.android.youtube", "com.google.android.apps.youtube.music", "app.morphe.android.apps.youtube.music"):
            patches_str += " · requires MicroG"

        icon = ""
        for cand in [CLONE_PACKAGE_MAP.get(pkg, pkg), pkg]:
            cand_path = f"icons/{cand}.png"
            if (ICONS / f"{cand}.png").exists() or (OUT / cand_path).exists():
                icon = cand_path
                break
        if not icon:
            apk_file = OUT / apk if apk else None
            if apk_file and apk_file.exists():
                try:
                    from morpheupdater.fdroid import extract_icon
                    got = extract_icon(apk_file, ICONS / f"{pkg}.png")
                    if got:
                        # ensure copied to out/icons
                        try:
                            src = ICONS / got
                            dst = OUT / "icons" / got
                            if src.exists() and not dst.exists():
                                dst.parent.mkdir(parents=True, exist_ok=True)
                                shutil.copyfile(src, dst)
                        except Exception:
                            pass
                        icon = f"icons/{got}"
                except Exception:
                    pass
        if not icon:
            icon = "icons/icon.png"

        display = PACKAGE_DISPLAY
        cfg_display = next((a.get("display") for a in cfg.get("apps", []) if a.get("package") == pkg), None)
        name = cfg_display or display.get(pkg) or display.get(b.get("package", "")) or pkg
        # patch count for sort
        patches_count = 0
        patch_list_html = ""
        try:
            for _opt in (ROOT / "options").glob(f"{short(pkg)}.*.json"):
                if not _opt.exists():
                    continue
                _d = json.loads(_opt.read_text())
                _entries = _d if isinstance(_d, list) else [_d]
                for _e in _entries:
                    _patches = _e.get("patches", {})
                    _enabled = [k for k, v in _patches.items() if isinstance(v, dict) and v.get("enabled")]
                    if _enabled:
                        patches_count = len(_enabled)
                        patch_list_html = "<details><summary>" + str(len(_enabled)) + " patches</summary><ul>"
                        for _pn in sorted(_enabled):
                            patch_list_html += f"<li>{_pn}</li>"
                        patch_list_html += "</ul></details>"
                        break
                if patch_list_html:
                    break
        except Exception:
            pass
        # also fallback count from tags if no options file
        if patches_count == 0 and patch_list_html:
            pass
        # if no patch list, still show patches_str
        patches_html = patch_list_html if patch_list_html else f"<span class='muted'>{patches_str or '—'}</span>"

        is_tv = pkg in TV_PACKAGES
        tv_badge = " <span style='background:#2a2a30;padding:2px 6px;border-radius:4px;font-size:0.7rem'>TV</span>" if is_tv else ""
        name_html = name + tv_badge
        # escape for data attr
        name_attr = name.replace('"', "&quot;")
        card_html = Template(CARD).substitute(
            icon=icon, name=name_html, name_attr=name_attr, pkg=pkg, ver=ver, arch=arch,
            bundle=bundle, bundle_label=bundle_label, patches_count=patches_count,
            patches_html=patches_html, dl=dl,
        )
        cards.append((bundle, card_html, name.lower(), patches_count))

    # build grouped (by bundle) and flat
    from collections import defaultdict
    by_bundle: dict[str, list] = defaultdict(list)
    for bundle, html, lname, pc in cards:
        by_bundle[bundle].append((html, lname, pc))
    grouped_html = ""
    for bundle in sorted(by_bundle.keys()):
        items = by_bundle[bundle]
        # sort inside bundle by name for initial
        items.sort(key=lambda x: x[1])
        inner = "\n".join(h for h, _, _ in items)
        grouped_html += f'<details class="bundle" open><summary>{bundle} <span class="count">{len(items)}</span></summary><div class="grid">{inner}</div></details>\n'
    # flat (no grouping)
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
