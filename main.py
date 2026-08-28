import argparse
import asyncio
import logging

from morpheupdater import daemon
from morpheupdater.settings import load_env


def main() -> None:
    parser = argparse.ArgumentParser(prog="morpheupdater")
    parser.add_argument("mode", nargs="?", choices=["daemon", "once", "build"], default="daemon",
                        help="run forever (default), single cycle, or single-app build")
    parser.add_argument("--commit", action="store_true",
                        help="commit out/, state.json and options/ changes")
    parser.add_argument("--release", action="store_true",
                        help="create a gh release with rebuilt APKs (implies commit on change)")
    parser.add_argument("--app", dest="app", default=None, help="build only this package (e.g. com.strava) - for 'once' or 'build' mode")
    parser.add_argument("--clean", action="store_true", help="remove tmp/dl, tmp/merged, tmp/build for the built app after success (saves storage)")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
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
    try:
        asyncio.run(daemon.loop())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
