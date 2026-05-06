"""
VANGUARD — entry point.

Usage:
  python -m vanguard.main                          # start proxy on 0.0.0.0:8080
  python -m vanguard.main --dojo                   # start proxy + Dojo trainer
  python -m vanguard.main --host 0.0.0.0 --port 8080 --workers 4
"""

from __future__ import annotations

import argparse
import logging
import sys

from vanguard.config import config

logging.basicConfig(
    level=logging.DEBUG if config.debug else logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Project VANGUARD — AI Web Security Shield"
    )
    parser.add_argument("--host", default=config.proxy.host)
    parser.add_argument("--port", type=int, default=config.proxy.port)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument(
        "--dojo",
        action="store_true",
        help="Start the Continuous Dojo adversarial training loop in background",
    )
    args = parser.parse_args(argv)

    logger.info("🛡  Starting Project VANGUARD v%s", "0.1.0")
    logger.info("   Host    : %s", args.host)
    logger.info("   Port    : %s", args.port)
    logger.info("   Origin  : %s", config.proxy.origin_url)
    logger.info("   Workers : %s", args.workers)

    # Optionally start the Dojo trainer in background
    trainer = None
    if args.dojo:
        from vanguard.dojo.trainer import DojoTrainer
        trainer = DojoTrainer()
        trainer.start()
        logger.info("   Dojo    : running (adversarial training active)")

    # Create and serve the Flask app via gunicorn
    from vanguard.proxy.edge_proxy import create_app
    app = create_app()

    try:
        import gunicorn.app.base

        class _StandaloneApp(gunicorn.app.base.BaseApplication):
            def __init__(self, application, options=None):
                self.options = options or {}
                self.application = application
                super().__init__()

            def load_config(self):
                for key, value in self.options.items():
                    self.cfg.set(key.lower(), value)

            def load(self):
                return self.application

        options = {
            "bind": f"{args.host}:{args.port}",
            "workers": args.workers,
            "worker_class": "sync",
            "timeout": 30,
            "loglevel": "info",
        }
        _StandaloneApp(app, options).run()
    except ImportError:
        logger.warning("gunicorn not installed — falling back to Flask dev server")
        app.run(host=args.host, port=args.port, debug=config.debug)
    finally:
        if trainer:
            trainer.stop()

    return 0


if __name__ == "__main__":
    sys.exit(main())
