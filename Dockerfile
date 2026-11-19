# Sentinel-Agent — reproducible dev/CI imajı (takım için aynı ortam)
FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Bağımlılıkları önce kopyala (layer cache)
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Playwright'in kendi node ikilisi libatomic.so.1'e muhtaç; python:3.11-slim bunu içermez,
# bu yüzden `playwright install` daha --with-deps apt adımına gelmeden `libatomic.so.1: cannot
# open shared object file` ile patlar. Tarayıcı bağımlılıklarını kurmadan ÖNCE libatomic1'i kur.
RUN apt-get update && apt-get install -y --no-install-recommends libatomic1 \
    && rm -rf /var/lib/apt/lists/*

# Playwright Chromium + sistem bağımlılıkları (auth/login akışı için — DESIGN.md §10.1)
RUN playwright install --with-deps chromium

# Uygulama kodu (compose'ta bind-mount ile override edilir; imaj tek başına da çalışır)
COPY . .

# Varsayılan: geliştirme kabuğu. run_scan CLI: python -m scripts.run_scan --help
CMD ["bash"]
