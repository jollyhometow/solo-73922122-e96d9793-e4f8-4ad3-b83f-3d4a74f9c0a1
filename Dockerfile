# DNS-01 挑战托管服务：同一镜像支持以不同命令启动 API 或 worker
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /opt/dns01-manager

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# 非 root 运行；数据库目录由 compose 命名卷挂载并 chown 给该 UID
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data \
    && chown -R appuser:appuser /data /opt/dns01-manager
USER appuser

EXPOSE 8080

HEALTHCHECK --interval=15s --timeout=5s --start-period=6s --retries=4 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3).status==200 else 1)"

# 默认启动 API；worker 在 compose 中用 command 覆盖
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
