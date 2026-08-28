"""External tools: GitHub release checks/updates for the jars,
morphe-desktop CLI wrappers (list-versions, patch), APKEditor merge,
and git/gh commit+release helpers."""

from __future__ import annotations

import asyncio
import logging
import os
import re
import subprocess
from pathlib import Path

from aiohttp import ClientSession

from .settings import MORPHE_DATA, ROOT, TMP, keystore

log = logging.getLogger("tools")

GH_API = "https://api.github.com"
BLOCK_RE = re.compile(
    r"(?:INFO:\s*)?Package name:\s*(?P<pkg>[\w.]+)\s*\n(?:INFO:\s*)?Most common compatible versions:\s*\n"
    r"(?P<versions>(?:[ \t][^\n]*\n?)+)"
)
# handles "490.0.0.63.82 [versionCodes: ...] (2 patches)", "2.2 build 016 (1 patch)", "477.14 (9 patches)"
VERSION_LINE_RE = re.compile(r"^[ \t]+(?P<ver>\S+(?:\s+build\s+\S+)?)(?:\s*\[versionCodes:[^\]]+\])?\s*\(\d+ patch(?:es)?\)", re.MULTILINE)


def _gh_headers() -> dict[str, str]:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN", "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def gh_latest_prerelease(session: ClientSession, repo: str) -> dict:
    """Newest prerelease, falling back to newest stable — mirrors how
    morphe resolves --prerelease."""
    async with session.get(
        f"{GH_API}/repos/{repo}/releases?per_page=20",
        headers=_gh_headers(), timeout=None,
    ) as resp:
        if resp.status != 200:
            raise RuntimeError(f"github HTTP {resp.status} for {repo}")
        releases = await resp.json()
    if not releases:
        raise RuntimeError(f"no releases for {repo}")
    for release in releases:
        if release.get("prerelease"):
            return release
    return releases[0]

async def gh_latest_release(session: ClientSession, repo: str) -> dict:
    """Newest stable release (prerelease==false), falling back to prerelease."""
    async with session.get(
        f"{GH_API}/repos/{repo}/releases?per_page=20",
        headers=_gh_headers(), timeout=None,
    ) as resp:
        if resp.status != 200:
            raise RuntimeError(f"github HTTP {resp.status} for {repo}")
        releases = await resp.json()
    if not releases:
        raise RuntimeError(f"no releases for {repo}")
    for release in releases:
        if not release.get("prerelease"):
            return release
    return releases[0]



def pick_jar_asset(release: dict) -> str | None:
    jars = [
        a["browser_download_url"]
        for a in release.get("assets", [])
        if a["name"].lower().endswith(".jar")
        and not re.search(r"sources|javadoc", a["name"], re.IGNORECASE)
    ]
    for url in jars:
        if url.rstrip("/").endswith("-all.jar"):
            return url
    return jars[0] if jars else None


async def update_tool(session: ClientSession, name: str, spec: dict, state: dict) -> tuple[bool, str]:
    """Check one tool's upstream release; download and replace its jar on change.
    Returns (changed, tag)."""
    repo, local = spec["repo"], spec["local"]
    release = await gh_latest_prerelease(session, repo)
    tag = release["tag_name"]
    prev = state["tools"].get(name)
    if prev and prev.get("tag") == tag and (ROOT / local).exists():
        return False, tag
    url = pick_jar_asset(release)
    if not url:
        raise RuntimeError(f"no jar asset in {repo} {tag}")
    dest = ROOT / local
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".part")
    async with session.get(url, timeout=None) as resp:
        resp.raise_for_status()
        with open(tmp, "wb") as f:
            async for chunk in resp.content.iter_chunked(1 << 20):
                f.write(chunk)
    tmp.replace(dest)
    state["tools"][name] = {"tag": tag}
    log.info("%s updated to %s (%s)", name, tag, local)
    return True, tag


# ── subprocess helpers ──────────────────────────────────────────────────────

_java_cache: str | None = None


def java_bin() -> str:
    """The JVM to use: MORPHE_JAVA env override, else whatever `java` is on PATH.
    Any JRE 21+ works — keystore handling no longer depends on the JVM because
    signing falls back to apksigner when morphe's BKS path is unavailable."""
    global _java_cache
    if not _java_cache:
        _java_cache = os.environ.get("MORPHE_JAVA") or "java"
    return _java_cache


async def run(cmd: list[str], env: dict | None = None, cwd: Path | None = None, timeout_s: float | None = None) -> tuple[int, str]:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        env=env,
        cwd=cwd,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout_s)
    except TimeoutError:
        proc.kill()
        raise RuntimeError(f"timeout running {' '.join(cmd[:4])}...")
    return proc.returncode or 0, stdout.decode("utf-8", "replace")


def java_env(extra: dict | None = None) -> dict:
    env = os.environ.copy()
    env["MORPHE_DATA_DIR"] = str(MORPHE_DATA)
    if extra:
        env.update(extra)
    return env


APKSIGNER_ZIP = "https://dl.google.com/android/repository/build-tools_r34-linux.zip"
KEYSTORE_ERRORS = (
    "could not use keystore",
    "conversion failed",
    "jce cannot authenticate",
    "bouncycastle",
    "unrecoverablekeyexception",
    "badpaddingexception",
    "couldn't decrypt",
)

BC_PROBE_SRC = """import java.io.*;
import java.security.KeyStore;
import java.security.Security;
public class BCProbe {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        char[] storePw = System.getenv("KS_STORE_PW").toCharArray();
        char[] entryPw = System.getenv("KS_ENTRY_PW").toCharArray();
        KeyStore in = KeyStore.getInstance("PKCS12");
        try (InputStream i = new FileInputStream(args[0])) { in.load(i, storePw); }
        KeyStore bks = KeyStore.getInstance("BKS", "BC");
        bks.load(null, null);
        String alias = args[1];
        var entry = (KeyStore.PrivateKeyEntry) in.getEntry(alias, new KeyStore.PasswordProtection(entryPw));
        bks.setEntry(alias, entry, new KeyStore.PasswordProtection(entryPw));
        System.out.println("PROBE_OK");
    }
}"""


def is_keystore_error(text: str) -> bool:
    low = text.lower()
    return any(k in low for k in KEYSTORE_ERRORS)


def resolve_signing() -> dict:
    store_pw = os.environ.get("KEYSTORE_PASSWORD", "")
    return {
        "path": str((ROOT / keystore()).resolve()),
        "store_pw": store_pw,
        "alias": os.environ.get("KEYSTORE_ENTRY_ALIAS", ""),
        "entry_pw": os.environ.get("KEYSTORE_ENTRY_PASSWORD", "") or store_pw,
        "signer": os.environ.get("SIGNER_NAME", ""),
    }


async def bc_keystore_probe(morphe_jar: Path, creds: dict) -> bool:
    """Replicates morphe's PKCS12->BKS conversion; False where the JVM cannot
    initialize BouncyCastle's password ciphers (e.g. recent JDKs)."""
    probe_dir = TMP / "probe"
    probe_dir.mkdir(parents=True, exist_ok=True)
    src = probe_dir / "BCProbe.java"
    if not src.exists():
        src.write_text(BC_PROBE_SRC)
    env = java_env({"KS_STORE_PW": creds["store_pw"], "KS_ENTRY_PW": creds["entry_pw"]})
    rc, out = await run(
        [java_bin(), "-cp", str(morphe_jar), str(src), creds["path"], creds["alias"]],
        env=env, timeout_s=120,
    )
    ok = rc == 0 and "PROBE_OK" in out
    if ok:
        log.info("native keystore handling: available")
    else:
        reason = next(
            (l.strip() for l in out.splitlines()
             if ("Exception" in l or "error:" in l.lower()) and "at " != l.strip()[:3]),
            out.strip().splitlines()[0] if out.strip() else "unknown error",
        )
        log.info("native keystore handling unavailable (%s)", reason[:160])
    return ok


async def ensure_apksigner(session: ClientSession) -> Path:
    jar = ROOT / "bin" / "apksigner.jar"
    if jar.exists():
        return jar
    log.info("fetching apksigner...")
    zip_path = TMP / "build-tools.zip"
    async with session.get(APKSIGNER_ZIP, timeout=None) as resp:
        resp.raise_for_status()
        with open(zip_path, "wb") as f:
            async for chunk in resp.content.iter_chunked(1 << 20):
                f.write(chunk)
    import zipfile

    with zipfile.ZipFile(zip_path) as zf:
        member = next(n for n in zf.namelist() if n.endswith("/lib/apksigner.jar"))
        jar.parent.mkdir(parents=True, exist_ok=True)
        jar.write_bytes(zf.read(member))
    zip_path.unlink()
    log.info("apksigner ready (%s)", jar)
    return jar


async def sign_apk(apk_in: Path, apk_out: Path, creds: dict) -> None:
    cmd = [
        java_bin(), "--enable-native-access=ALL-UNNAMED",
        "-jar", str(ROOT / "bin" / "apksigner.jar"), "sign",
        "--v4-signing-enabled", "false",
        "--ks", creds["path"],
        "--ks-pass", "env:KS_PASS",
        "--in", str(apk_in), "--out", str(apk_out),
    ]
    if creds["alias"]:
        cmd += ["--ks-key-alias", creds["alias"]]
    if creds["entry_pw"]:
        cmd += ["--key-pass", "env:KEY_PASS"]
    rc, out = await run(
        cmd,
        env={"KS_PASS": creds["store_pw"], "KEY_PASS": creds["entry_pw"]},
        timeout_s=600,
    )
    if rc != 0:
        raise RuntimeError(f"apksigner failed:\n{out[-500:]}")
    log.info("signed %s", apk_out.name)


def apk_info(jar: Path, apk: Path) -> tuple[str, str, int, str] | None:
    """(package, versionName, versionCode, appName) via APKEditor info."""
    try:
        proc = subprocess.run(
            [java_bin(), "-jar", str(jar), "info", "-i", str(apk)],
            capture_output=True, text=True, timeout=300,
        )
        rc, out = proc.returncode or 0, proc.stdout
    except Exception:
        return None
    if rc != 0:
        return None
    pkg = re.search(r'package="([^"]+)"', out)
    ver = re.search(r'VersionName="([^"]+)"', out)
    code = re.search(r'VersionCode="(\d+)"', out)
    name = re.search(r'AppName="([^"]+)"', out)
    if not (pkg and ver and code):
        return None
    return (pkg.group(1), ver.group(1), int(code.group(1)),
            name.group(1) if name else pkg.group(1))


def signing_args() -> list[str]:
    args: list[str] = []
    ks = keystore()
    if ks and Path(ks).exists():
        c = resolve_signing()
        args += ["--keystore", ks]
        if c["store_pw"]:
            args += ["--keystore-password", c["store_pw"]]
        if c["alias"]:
            args += ["--keystore-entry-alias", c["alias"]]
        # PKCS12 keys normally share the store password; morphe would
        # otherwise fall back to its own default ("Morphe") and fail.
        if c["entry_pw"]:
            args += ["--keystore-entry-password", c["entry_pw"]]
        if c["signer"]:
            args += ["--signer", c["signer"]]
    return args


# ── morphe-desktop ──────────────────────────────────────────────────────────


def _version_key(version: str) -> tuple:
    parts = []
    for chunk in re.split(r"[.\-_+]", version):
        digits = re.sub(r"\D", "", chunk)
        parts.append(int(digits) if digits else 0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)


def _bundle_prerelease(cfg: dict, url: str) -> bool:
    # cfg bundles can be str -> prerelease true, or dict {url, prerelease}
    # also handle local MPP paths: map back to bundle
    for name, spec in cfg.get("bundles", {}).items():
        u = spec if isinstance(spec, str) else spec.get("url", "")
        if u == url:
            if isinstance(spec, str):
                return True
            return bool(spec.get("prerelease", True))
        # check if url is a local MPP file for this bundle
        if url.endswith(".mpp") and u and u.split("/")[-1] in url:
            if isinstance(spec, str):
                return True
            return bool(spec.get("prerelease", True))
    # for local files, don't use prerelease (file is already specific)
    if url.endswith(".mpp"):
        return False
    # fallback: if url not found as value, check if url itself is key
    return True


async def recommended_version(jar: Path, urls: list[str], package: str, cfg: dict | None = None) -> str | None:
    use_prerelease = False
    if cfg is not None:
        use_prerelease = any(_bundle_prerelease(cfg, u) for u in urls)
    else:
        use_prerelease = True
    cmd = [java_bin(), "-jar", str(jar), "list-versions"]
    if use_prerelease:
        cmd.append("--prerelease")
    for url in urls:
        cmd += ["--patches", url]
    cmd += ["-f", package]
    rc, out = await run(cmd, env=java_env(), timeout_s=600)
    if rc != 0:
        raise RuntimeError(f"list-versions failed:\n{out[-800:]}")
    highest: str | None = None
    for block in BLOCK_RE.finditer(out):
        if block.group("pkg") != package:
            continue
        versions = [m.group("ver") for m in VERSION_LINE_RE.finditer(block.group("versions"))]
        if versions:
            highest = max(versions, key=_version_key)
    return highest


async def merge_apks(jar: Path, src_dir: Path, out: Path) -> None:
    rc, output = await run(
        [java_bin(), "-jar", str(jar), "merge", "-i", str(src_dir), "-o", str(out)],
        timeout_s=900,
    )
    if rc != 0:
        raise RuntimeError(f"APKEditor merge failed:\n{output[-800:]}")


async def patch(
    jar: Path,
    urls: list[str],
    options_file: Path,
    apk_in: Path,
    apk_out: Path,
    *,
    unsigned: bool,
    force: bool,
    striplibs: list[str],
    bytecode_mode: str,
) -> None:
    cmd = [java_bin(), "-Xmx4g", "-jar", str(jar), "patch"]
    for url in urls:
        cmd += ["-p", url]
    cmd += [
        "--prerelease",
        "--options-file", str(options_file),
        "--options-update",
        "-t", str(TMP / "morphe"),
    ]
    if not unsigned:
        cmd += signing_args()
    if unsigned:
        cmd.append("--unsigned")
    if force:
        cmd.append("--force")
    if striplibs:
        cmd += ["--striplibs", ",".join(striplibs)]
    if bytecode_mode:
        cmd += ["--bytecode-mode", bytecode_mode]
    cmd += ["-o", str(apk_out), str(apk_in)]
    rc, output = await run(cmd, env=java_env(), cwd=ROOT)
    if rc != 0:
        tail = "\n".join(output.splitlines()[-30:])
        raise RuntimeError(f"patch failed ({rc}):\n{tail}")
    log.info("patched -> %s%s", apk_out.name, " (unsigned)" if unsigned else "")


# ── git / gh ────────────────────────────────────────────────────────────────


def _git_env() -> dict:
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", "morpheupdater")
    env.setdefault("GIT_COMMITTER_NAME", "morpheupdater")
    env.setdefault("GIT_AUTHOR_EMAIL", "morpheupdater@users.noreply.github.com")
    env.setdefault("GIT_COMMITTER_EMAIL", "morpheupdater@users.noreply.github.com")
    return env


async def commit_and_push(message: str) -> bool:
    paths = ["state.json", "options", "out/index-v1.json", "out/index-v1.jar", "out/index-v2.json", "out/index-v2.jar", "out/entry.json", "out/entry.jar", "out/icons", "out/index.html"]
    existing = [p for p in paths if (ROOT / p).exists()]
    await run(["git", "add", "--", *existing], cwd=ROOT)
    rc, out = await run(["git", "diff", "--cached", "--quiet"], cwd=ROOT)
    if rc == 0:
        log.info("nothing to commit")
        return False
    rc, out = await run(["git", "commit", "-m", message], env=_git_env(), cwd=ROOT)
    if rc != 0:
        raise RuntimeError(f"git commit failed:\n{out[-500:]}")
    _rc, branch = await run(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=ROOT)
    branch = branch.strip() or "main"
    rc, out = await run(["git", "push", "origin", branch], env=_git_env(), cwd=ROOT)
    if rc != 0:
        raise RuntimeError(f"git push failed:\n{out[-500:]}")
    log.info("committed and pushed: %s", message)
    return True


async def create_release(tag: str, title: str, notes: str, files: list[Path]) -> None:
    cmd = ["gh", "release", "create", tag, "--title", title, "--notes", notes]
    for f in files:
        cmd.append(str(f))
    rc, out = await run(cmd, env=os.environ.copy(), cwd=ROOT, timeout_s=1200)
    if rc != 0:
        raise RuntimeError(f"gh release failed:\n{out[-500:]}")
    log.info("release %s created with %d files", tag, len(files))
