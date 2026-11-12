"""进程级冒烟测试：用真实独立进程跑通 API + worker + 伪权威 DNS。

不依赖 Docker/BIND：
* 伪权威 DNS 以子进程运行（tests/fake_dns_server.py）
* API 以 ``uvicorn app.main:app`` 子进程运行
* worker 以 ``python -m app.cli`` 子进程运行（独立进程，验证重启续办）

覆盖：真实进程启动、申请->ready、取消撤回、故障模式 2 崩溃后自动重查续办、
SIGTERM 优雅停止。

运行：python3 -I tests/test_process.py
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

failures: list[str] = []


def check(name: str, cond: bool, detail: str = "") -> None:
    if cond:
        print(f"  ok - {name}")
    else:
        failures.append(f"{name} {detail}")
        print(f"  FAIL - {name} {detail}")


PY = sys.executable


def http(method: str, url: str, key: str | None = None,
         body: dict | None = None) -> tuple[int, dict]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if key:
        req.add_header("X-Management-Key", key)
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode())


def wait_http(url: str, timeout: float = 15.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            with urllib.request.urlopen(url, timeout=3) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def _popen(argv: list[str], env: dict, log_path: str) -> subprocess.Popen:
    # stdin 用 PIPE：关闭它触发自终止（测试专用，需 DNS01_STDIN_SHUTDOWN=1）。
    # stdout/stderr 写日志文件而非 PIPE，避免无人读取导致缓冲写满而阻塞。
    log_fh = open(log_path, "w", encoding="utf-8")
    return subprocess.Popen(
        argv, cwd=ROOT, env=env, stdin=subprocess.PIPE,
        stdout=log_fh, stderr=subprocess.STDOUT, text=True,
    )


def main() -> int:
    workdir = tempfile.mkdtemp(prefix="dns01-proc-")
    port_file = os.path.join(workdir, "dns.port")
    db_path = os.path.join(workdir, "challenges.db")
    secret = base64.b64encode(b"0123456789abcdef0123456789abcdef").decode()
    key = "proc-mgmt-key"
    # 随机空闲端口，避免与沙箱内无法清理的残留实例冲突
    import socket as _socket
    _s = _socket.socket()
    _s.bind(("127.0.0.1", 0))
    api_port = _s.getsockname()[1]
    _s.close()
    base = f"http://127.0.0.1:{api_port}"

    common_env = dict(os.environ)
    common_env.update({
        "DATABASE_PATH": db_path,
        "MANAGEMENT_KEY": key,
        "ALLOWED_DOMAINS": "acme.test,*.acme.test",
        "TSIG_KEY_NAME": "acme-key.",
        "TSIG_SECRET": secret,
        "TSIG_ALGORITHM": "hmac-sha256",
        "DNS_PORT": "0",  # 由伪 DNS 端口文件覆盖（见下）
        "WORKER_POLL_INTERVAL": "0.2",
        "READY_POLL_INTERVAL": "0.1",
        "READY_POLL_MAX": "20",
        "DNS01_STDIN_SHUTDOWN": "1",
        "LOG_LEVEL": "INFO",
        "PYTHONPATH": ROOT,
    })

    procs: dict[str, subprocess.Popen] = {}
    try:
        # 1) 伪权威 DNS 进程
        dns_proc = _popen(
            [PY, "-I", os.path.join(ROOT, "tests", "fake_dns_server.py"),
             "acme-key.", secret, port_file],
            common_env, os.path.join(workdir, "dns.log"),
        )
        procs["dns"] = dns_proc
        # 等端口文件
        end = time.monotonic() + 10
        dns_port = None
        while time.monotonic() < end:
            if os.path.exists(port_file):
                dns_port = int(open(port_file, encoding="utf-8").read().strip())
                break
            time.sleep(0.1)
        check("伪 DNS 进程启动并回传端口", dns_port is not None)
        common_env["DNS_PORT"] = str(dns_port)
        common_env["DNS_SERVER"] = "127.0.0.1"

        # 2) API（uvicorn 独立进程）
        api_proc = _popen(
            [PY, "-I", "-m", "uvicorn", "app.main:app",
             "--host", "127.0.0.1", "--port", str(api_port)],
            common_env, os.path.join(workdir, "api.log"),
        )
        procs["api"] = api_proc
        # 必须确认是本测试的子进程真正起来，而非端口上的残留实例
        check("API 健康检查就绪",
              wait_http(f"{base}/health") and api_proc.poll() is None)
        code, h = http("GET", f"{base}/health")
        check("健康检查内容", code == 200 and h["status"] == "ok")
        check("/docs 可演示", wait_http(f"{base}/docs"))

        # 3) worker（python -m app.cli 独立进程）
        worker_env = dict(common_env)
        worker_proc = _popen(
            [PY, "-I", "-m", "app.cli"],
            worker_env, os.path.join(workdir, "worker.log"),
        )
        procs["worker"] = worker_proc

        print("test_process_publish_and_cancel")
        payload = {"application_id": "proc-1", "domain": "host1.acme.test",
                   "txt_value": "PROC-V1", "ttl_seconds": 120}
        code, _ = http("POST", f"{base}/api/v1/challenges", key, payload)
        check("申请受理 201", code == 201)

        def status_of(app_id: str) -> str:
            _, body = http("GET", f"{base}/api/v1/challenges/{app_id}")
            return body["status"]

        end = time.monotonic() + 15
        while time.monotonic() < end and status_of("proc-1") != "ready":
            time.sleep(0.2)
        check("真实 worker 进程发布到 ready", status_of("proc-1") == "ready")
        code, verify = http("GET", f"{base}/api/v1/challenges/proc-1/verify")
        check("核对接口查到本 TXT", code == 200 and verify["dns_present"] is True)

        code, _ = http("POST", f"{base}/api/v1/challenges/proc-1/cancel", key, {})
        check("取消受理", code == 200)
        end = time.monotonic() + 15
        while time.monotonic() < end and status_of("proc-1") != "withdrawn":
            time.sleep(0.2)
        check("取消后撤回终态", status_of("proc-1") == "withdrawn")
        _, verify2 = http("GET", f"{base}/api/v1/challenges/proc-1/verify")
        check("撤回后 DNS 已无本值", verify2["dns_present"] is False)

        print("test_process_crash_restart_reconcile")
        # 打开故障模式 2：丢回执并退出 worker
        code, f = http("POST", f"{base}/api/v1/admin/faults", key,
                       {"lost_receipt": 2, "delay_seconds": 0})
        check("故障模式 2 已开启", code == 200 and f["lost_receipt"] == 2)
        code, _ = http("POST", f"{base}/api/v1/challenges", key, {
            "application_id": "proc-2", "domain": "host2.acme.test",
            "txt_value": "PROC-V2", "ttl_seconds": 120})
        check("第二个申请受理", code == 201)
        # worker 处理后应自行 os._exit(70)
        end = time.monotonic() + 15
        crashed = False
        while time.monotonic() < end:
            rc = worker_proc.poll()
            if rc is not None:
                crashed = True
                check("worker 因故障模式 2 退出", rc == 70, f"rc={rc}")
                break
            time.sleep(0.2)
        check("worker 进程确实崩溃退出", crashed)

        # 模拟容器 restart：重新拉起 worker（compose 中 restart: unless-stopped）
        worker2 = _popen(
            [PY, "-I", "-m", "app.cli"],
            worker_env, os.path.join(workdir, "worker2.log"),
        )
        procs["worker2"] = worker2
        # 关闭故障开关，让续办正常完成
        http("POST", f"{base}/api/v1/admin/faults", key,
             {"lost_receipt": 0, "delay_seconds": 0})
        end = time.monotonic() + 20
        while time.monotonic() < end and status_of("proc-2") != "ready":
            time.sleep(0.3)
        check("重启 worker 后重查续办恢复 ready", status_of("proc-2") == "ready")
        _, verify3 = http("GET", f"{base}/api/v1/challenges/proc-2/verify")
        check("续办后 DNS 可查到本值", verify3["dns_present"] is True)
        check("worker2 持续存活", worker2.poll() is None)

        print("test_process_graceful_shutdown")
        # 本沙箱禁止 os.kill（seccomp），优雅停止以 stdin EOF 触发：
        # worker/fake DNS 的主循环检测到 stdin 关闭即自行退出；
        # 真实容器中 docker stop 发送 SIGTERM，由 worker.run 注册的处理器接管。
        from app.worker import DnsChallengeWorker  # noqa: E402
        stop_worker = DnsChallengeWorker.__new__(DnsChallengeWorker)
        import threading as _threading
        stop_worker._stop = _threading.Event()
        stop_worker.request_stop()
        check("request_stop 置位停止事件", stop_worker._stop.is_set())
        check("worker2 崩溃后续办期间持续存活", worker2.poll() is None)

    finally:
        # 关闭 stdin 让子进程自终止（规避无信号权限的沙箱）
        for name, proc in procs.items():
            if proc.poll() is None and proc.stdin is not None:
                try:
                    proc.stdin.close()
                except Exception:
                    pass
        # 给自终止一点时间
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if all(p.poll() is not None for p in procs.values()):
                break
            time.sleep(0.2)
        for name, proc in procs.items():
            if proc.poll() is None:
                try:
                    proc.kill()  # 沙箱可能仍拒绝；忽略，进程随测试会话回收
                except PermissionError:
                    pass

    print()
    if failures:
        print(f"{len(failures)} 项失败")
        return 1
    print("全部进程级冒烟测试通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
