"""独立进程版伪权威 DNS：供进程级冒烟测试使用（无需 Docker/BIND）。

用法：
    python -I tests/fake_dns_server.py <tsig_name> <tsig_secret_b64> <port_file>
启动后把实际监听端口写入 port_file，并保持前台运行直到收到 SIGTERM。
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_e2e import FakeAuthoritativeDNS  # noqa: E402


def main() -> int:
    tsig_name = sys.argv[1]
    tsig_secret = sys.argv[2]
    port_file = sys.argv[3]
    server = FakeAuthoritativeDNS(tsig_name, tsig_secret)
    # 固定端口 0 由系统分配；通过文件回传
    port = server.start()
    with open(port_file, "w", encoding="utf-8") as fh:
        fh.write(str(port))

    stop = {"flag": False}

    def _handle(*_args):
        stop["flag"] = True

    signal.signal(signal.SIGTERM, _handle)
    signal.signal(signal.SIGINT, _handle)

    # stdin EOF 也退出（仅测试开关开启时；避免 /dev/null 立即 EOF 误退出）
    if os.environ.get("DNS01_STDIN_SHUTDOWN") == "1":
        def _watch_stdin() -> None:
            try:
                sys.stdin.read()
            except Exception:
                pass
            stop["flag"] = True

        threading.Thread(target=_watch_stdin, daemon=True).start()

    while not stop["flag"]:
        time.sleep(0.2)
    server.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
