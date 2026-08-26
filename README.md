# morpheupdater

Watches Morphe patch sources, and when any of them publishes a new release it:

1. updates `bin/morphe-desktop.jar` and `bin/apkeditor.jar` from their GitHub releases,
2. resolves the highest recommended app version from the new patches,
3. downloads the needed APK + splits (base, arm64-v8a, xxhdpi, English + Spanish)
   straight from Google Play via the Aurora OSS token dispenser,
4. merges them with APKEditor,
5. patches with morphe-desktop using your per-package options file
   (`--options-file`, always with `--options-update`),
6. commits `out/`, `state.json` and `options/` and, when APKs changed,
   publishes a GitHub release describing which patch versions changed.

Signing: a quick probe checks whether morphe's native keystore path works on
your JVM (some JDKs reject its bundled BouncyCastle). If it does, morphe signs
directly; otherwise builds are patched `--unsigned` and signed afterwards with
Google's `apksigner` (auto-downloaded to `bin/apksigner.jar`). Both paths use
the same keystore from `.env`, so updates stay installable over previous builds.

Runs either as a local loop or as a scheduled GitHub Actions workflow — same code.

## Usage

```bash
uv sync                      # install deps (aiohttp only)
cp .env.example .env         # fill in keystore credentials
uv run main.py               # daemon: check every interval_minutes
uv run main.py once          # single cycle, exit 1 if any build failed
uv run main.py once --commit --release   # what CI runs
```

First run creates `config.json` with defaults. Runtime folders:
`out/` final patched APKs · `tmp/` scratch, wiped on size/age/disk-pressure ·
`options/` per package+bundle-combo options JSONs (morphe creates missing ones
with defaults; edit them freely — e.g. point Custom branding at
`youtube_branding/` / `music_branding/`) · `morphe-data/` morphe's own cache.

## config.json

```jsonc
{
  "interval_minutes": 30,          // daemon poll interval
  "archs": ["arm64"],              // device profiles; one APK per arch is released
  "locales": ["en-US", "es"],      // language splits to bundle
  "force_patch": true,             // --force on every patch run
  "striplibs": [],                 // e.g. ["arm64-v8a"]; empty = keep all
  "bytecode_mode": "",             // FULL | STRIP_SAFE | STRIP_FAST; empty = morphe default
  "bundles": {                     // named patch sources (GitHub repos)
    "morphe": "https://github.com/MorpheApp/morphe-patches"
  },
  "apps": [
    {
      "package": "com.google.android.youtube",
      "combos": [["morphe"]]       // each combo = one patched release;
                                   // a combo may list several bundles, and an
                                   // app may have several combos
    }
  ],
  "tools": {                       // auto-updated jars (only checked when patches change)
    "morphe-desktop": {"repo": "MorpheApp/morphe-desktop", "local": "bin/morphe-desktop.jar"},
    "apkeditor": {"repo": "REAndroid/APKEditor", "local": "bin/apkeditor.jar"}
  },
  "tmp_max_mb": 2048,              // wipe tmp/ above this size...
  "tmp_max_age_days": 7,           // ...or with files older than this...
  "min_free_gb": 10,               // ...or when free disk drops below this
  "commit": false,                 // git commit changes after cycles
  "release": false                 // gh release with rebuilt APKs
}
```

Options files are named `options/<app>.<bundle+bundle...>.json`
(e.g. `options/youtube.morphe.json`) and are created by morphe with defaults on
first patch; CLI flags would override them, so everything is controlled there.

## Environment (.env or real env vars)

| Variable | Meaning |
|---|---|
| `KEYSTORE_PATH` | keystore file used for signing every build |
| `KEYSTORE_PASSWORD` | keystore store password |
| `KEYSTORE_ENTRY_ALIAS` / `KEYSTORE_ENTRY_PASSWORD` | key entry credentials |
| `SIGNER_NAME` | signer name embedded in the APK signature |
| `KEYSTORE_B64` | CI alternative: base64 keystore decoded to `KEYSTORE_PATH` |
| `GITHUB_TOKEN` | optional, raises GitHub API rate limits locally |
| `MORPHE_JAVA` | optional absolute path to a java binary (default: `java` on PATH; any JRE 21+ works) |

## GitHub Actions

`.github/workflows/update.yml` runs every 30 minutes (`workflow_dispatch` to
trigger manually), commits changes and creates a release when APKs changed,
then deploys `out/` to **GitHub Pages**, which doubles as the F-Droid repo.

It needs these repository **secrets** if you don't commit the keystore:
`KEYSTORE_PATH`, `KEYSTORE_PASSWORD`, `KEYSTORE_ENTRY_ALIAS`,
`KEYSTORE_ENTRY_PASSWORD`, `SIGNER_NAME` (or just `KEYSTORE_B64`). The built-in
`GITHUB_TOKEN` is used for API checks, pushing commits and creating releases.
Enable Pages once under *Settings → Pages → Source: GitHub Actions*.

## F-Droid repo (Droidify & co.)

Every cycle regenerates a signed `index-v1.json`/`index-v1.jar` inside `out/`,
with per-APK hashes, sizes, SDK levels, signer digest and icons extracted from
the APKs. After the first CI run, add it to any F-Droid client:

- repo URL: `https://<owner>.github.io/<repo>/`
- fingerprint: the `cert_sha256` from `state.json` (also printed in each
  release's notes, or via `keytool -printcert -jarfile out/index-v1.jar`)

Only rebuilt APKs change; unchanged entries keep their hashes, so clients
download nothing new until an actual update lands.

## Version-code resolution

Google Play has no version-history API, so recommended versions (e.g.
`21.04.223`) are mapped to Play version codes through APKPure's metadata API
(`api.pureapk.com`), which lists recent versions with their real codes. This
was cross-validated against Play itself (same code returned by `/fdfe/details`
for the matching version string).

## Provenance

Device profiles under `morpheupdater/profiles/` come from the Calyx
Institute/Aurora OSS device database (GPL-3.0), as distributed with gplaydl.
