"""命令行入口：在前台启动独立 worker 进程。

API 进程由 uvicorn 托管（``uvicorn app.main:app``），worker 由本模块独立运行
（``python -m app.cli``），两者通过 SQLite 协作、互不阻塞。

用法：
    python -m app.cli                 # 前台运行 worker
    python -m app.cli --reconcile-once # 仅执行一次启动对账后退出
"""

from __future__ import annotations

import argparse
import logging
import os
import sys

if __package__ in (None, ""):
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.worker import DnsChallengeWorker  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="DNS-01 挑战托管 worker")
    parser.add_argument(
        "--reconcile-once",
        action="store_true",
        help="只执行一次重查续办对账然后退出（排障用）",
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    worker = DnsChallengeWorker()
    if args.reconcile_once:
        worker.reconcile()
        return 0
    worker.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
