import argparse
import asyncio
import logging

from morpheupdater import daemon
from morpheupdater.settings import load_env


def main() -> None:
    parser = argparse.ArgumentParser(prog="morpheupdater")
    parser.add_argument("mode", nargs="?", choices=["daemon", "once", "build", "clean"], default="daemon",
                        help="run forever (default), single cycle, single-app build, or clean")
    parser.add_argument("target", nargs="?", choices=["tmp", "out", "all"], default="all",
                        help="for clean mode: what to clean (default all)")
    parser.add_argument("--commit", action="store_true",
                        help="commit out/, state.json and options/ changes")
    parser.add_argument("--release", action="store_true",
                        help="create a gh release with rebuilt APKs (implies commit on change)")
    parser.add_argument("--app", dest="app", default=None, help="build only this package (e.g. com.strava) - for 'once' or 'build' mode")
    parser.add_argument("--clean", action="store_true", help="remove tmp/dl, tmp/merged, tmp/build for the built app after success (saves storage)")
    parser.add_argument("--max-size", type=int, default=None, help="for clean: max tmp size in MB (overrides config)")
    parser.add_argument("--old", type=int, default=None, help="for clean: remove tmp files older than N days")
    parser.add_argument("--dupes", action="store_true", help="for clean: remove duplicate old APKs in out, keep only latest per package")
    parser.add_argument("--min-free", type=int, default=None, help="for clean: ensure at least N GB free on disk")
    parser.add_argument("--dry-run", action="store_true", help="for clean: show what would be deleted without deleting")
    parser.add_argument("--full", action="store_true", help="for clean: full clean (tmp + out), like full_clean_out")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    try:
        from pathlib import Path
        import time
        log_dir = Path(__file__).resolve().parent / "tmp" / "logs"
        log_dir.mkdir(parents=True, exist_ok=True)
        dated = log_dir / time.strftime("%Y-%m-%d_%H.log", time.gmtime())
        latest = log_dir / "latest.log"
        class RobustFileHandler(logging.FileHandler):
            def emit(self, record):
                try:
                    p = Path(self.baseFilename)
                    p.parent.mkdir(parents=True, exist_ok=True)
                    if not p.exists():
                        if self.stream:
                            try:
                                self.stream.close()
                            except Exception:
                                pass
                            self.stream = None
                        try:
                            self.stream = self._open()
                        except Exception:
                            pass
                    latest = p.parent / "latest.log"
                    if not latest.exists() and not latest.is_symlink():
                        try:
                            latest.symlink_to(p.name)
                        except Exception:
                            pass
                except Exception:
                    pass
                try:
                    super().emit(record)
                except Exception:
                    try:
                        if self.stream:
                            try:
                                self.stream.close()
                            except Exception:
                                pass
                            self.stream = None
                        self.stream = self._open()
                        super().emit(record)
                    except Exception:
                        pass
        fh = RobustFileHandler(str(dated), encoding="utf-8")
        fh.setLevel(logging.INFO)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
        logging.getLogger().addHandler(fh)
        try:
            if latest.is_symlink() or latest.exists():
                latest.unlink()
            latest.symlink_to(dated.name)
        except Exception:
            pass
    except Exception:
        pass
    load_env()

    commit = True if args.commit else None
    release = True if args.release else None

    if args.mode == "once":
        summary = asyncio.run(daemon.cycle(commit_override=commit, release_override=release, app_filter=args.app, clean_after=args.clean))
        raise SystemExit(1 if summary["failed"] else 0)
    if args.mode == "build":
        if not args.app:
            parser.error("--app is required for 'build' mode")
        summary = asyncio.run(daemon.cycle(commit_override=commit, release_override=release, app_filter=args.app, clean_after=args.clean))
        raise SystemExit(1 if summary["failed"] else 0)
    if args.mode == "clean":
        # clean tmp/out/all with flags
        from morpheupdater.settings import load_config
        cfg = load_config()
        # allow --max-size to override tmp_max_mb, --old to override tmp_max_age_days, --min-free to override
        if args.max_size is not None:
            cfg["tmp_max_mb"] = args.max_size
        if args.old is not None:
            cfg["tmp_max_age_days"] = args.old
        if args.min_free is not None:
            cfg["tmp_min_free_gb"] = args.min_free
        target = args.target
        if args.full:
            target = "all"
        if args.full:
            import shutil
            from pathlib import Path
            from morpheupdater.settings import OUT, TMP
            if not args.dry_run:
                if target in ("tmp", "all") and TMP.exists():
                    shutil.rmtree(TMP)
                    TMP.mkdir(parents=True, exist_ok=True)
                if target in ("out", "all") and OUT.exists():
                    shutil.rmtree(OUT)
                    OUT.mkdir(parents=True, exist_ok=True)
                    (OUT / "icons").mkdir(parents=True, exist_ok=True)
            else:
                for p in ([TMP] if target in ("tmp", "all") else []) + ([OUT] if target in ("out", "all") else []):
                    print(f"[dry-run] would rmtree {p}")
        else:
            if target in ("out", "all"):
                asyncio.run(daemon.prune_out(cfg, dry_run=args.dry_run, remove_dupes=args.dupes))
            if target in ("tmp", "all"):
                asyncio.run(daemon.prune_tmp(cfg, dry_run=args.dry_run, remove_dupes=args.dupes))
        if args.dry_run:
            print("dry-run done")
        raise SystemExit(0)
    try:
        asyncio.run(daemon.loop())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
