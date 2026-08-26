import argparse
import asyncio
import logging

from morpheupdater import daemon
from morpheupdater.settings import load_env


def main() -> None:
    parser = argparse.ArgumentParser(prog="morpheupdater")
    parser.add_argument("mode", nargs="?", choices=["daemon", "once"], default="daemon",
                        help="run forever (default) or a single update cycle")
    parser.add_argument("--commit", action="store_true",
                        help="commit out/, state.json and options/ changes")
    parser.add_argument("--release", action="store_true",
                        help="create a gh release with rebuilt APKs (implies commit on change)")
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
        summary = asyncio.run(daemon.cycle(commit_override=commit, release_override=release))
        raise SystemExit(1 if summary["failed"] else 0)
    try:
        asyncio.run(daemon.loop())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
