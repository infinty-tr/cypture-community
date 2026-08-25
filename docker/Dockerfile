# Cypture engagement engine — one isolated container per engagement.
# Bundles cypture-agent + the agent knowledge base + Cypture's OWN HTTP testing engine
# (cypture-engine: MCP tools with the cyp_ tool names AND a 127.0.0.1:8080
# forward proxy) + a recon toolchain (subfinder, httpx, ffuf, katana, gau, amass,
# nmap, sqlmap, whatweb). No external
# proxy: no external proxy, no license, no account. Internet egress (to reach the target)
# but no published ports. Cypture credentials are mounted read-only at run.

# ── Stage 1: build the recon toolchain ────────────────────────────────────────
FROM golang:1.24-bookworm AS recon
ENV CGO_ENABLED=0 GOBIN=/out GOTOOLCHAIN=auto
# Fast, clean-building tools. katana (JS-crawl → SPA endpoint/route discovery) and
# gau (wayback/historical URLs → deprecated-but-live endpoints) have NO substitute in
# this image: recon-agent.md invokes them but they were missing, so JS routes and
# historical surface were silently never discovered. subfinder/httpx/ffuf as before.
RUN mkdir -p /out \
 && go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest \
 && go install github.com/ffuf/ffuf/v2@latest \
 && go install github.com/projectdiscovery/katana/cmd/katana@latest \
 && go install github.com/lc/gau/v2/cmd/gau@latest \
 && go install github.com/hahwul/dalfox/v2@latest \
 && go install github.com/jaeles-project/gospider@latest \
 && go install github.com/tomnomnom/waybackurls@latest \
 && go install github.com/tomnomnom/gf@latest \
 && go install github.com/tomnomnom/qsreplace@latest
# amass: deeper subdomain enum. Heavy/slow build and overlaps subfinder's passive
# enum — isolated in its own layer so a flaky build is obvious and it can be dropped
# without touching the fast tools above.
RUN go install github.com/owasp-amass/amass/v4/...@v4.2.0
# nuclei: template-based vulnerability scanner. Run as a NON-BLOCKING background worker
# (docker/nuclei_async.sh) so its findings stream in without holding up the agent flow.
RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# ── Stage 2: runtime ──────────────────────────────────────────────────────────
FROM debian:bookworm-slim

# Runtime toolchain. Core (ca-certificates/curl/bash/tar/jq) PLUS the CLI tools the
# expert agents invoke via bash: procps (ps — used by the lcx-doctor skill), dnsutils
# (dig/nslookup/host), python3 (+pip for sqlmap/helper scripts), netcat (nc — SSRF/OOB
# probes), wget, nmap, sqlmap, whatweb (tech fingerprint), git, unzip, openssl. Without
# these the agents hit "command not found" mid-test (the missing-tools symptom).
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl bash tar jq \
        procps dnsutils python3 python3-pip netcat-openbsd wget \
        nmap sqlmap whatweb git unzip openssl \
        chromium fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

# Wordlists: SecLists (git — Debian repo'da YOK, Kali paketi; git zaten kurulu). Full
# shallow clone → pentest-DIŞI ağır klasörleri (Passwords/rockyou, Usernames, IOT...)
# at → ~350-450MB kalır (Discovery/Web-Content dizin+api+param + Fuzzing listeleri).
# Standart yollar: /usr/share/seclists ve /usr/share/wordlists (ffuf/model bunları bilir).
RUN git clone --depth 1 https://github.com/danielmiessler/SecLists.git /usr/share/seclists \
    && rm -rf /usr/share/seclists/.git \
        /usr/share/seclists/Passwords /usr/share/seclists/Usernames \
        /usr/share/seclists/Miscellaneous /usr/share/seclists/IOT \
        /usr/share/seclists/Ai /usr/share/seclists/Pattern-Matching \
    && mkdir -p /usr/share/wordlists \
    && ln -s /usr/share/seclists /usr/share/wordlists/seclists \
    && ln -s /usr/share/seclists/Discovery/Web-Content/common.txt /usr/share/wordlists/common.txt \
    && ls -la /usr/share/wordlists/common.txt

# arjun: parametre keşfi (fuzzing-agent.md çağırıyordu ama YOKtu → param keşfi köreliyordu).
# Python paketi; debian bookworm pip'i --break-system-packages ister.
RUN pip3 install --no-cache-dir --break-system-packages arjun && command -v arjun

# NÖRAL RAG (#23): model2vec statik embeddings + numpy → kb_embed.py'nin NÖRAL yolu (vectors.f32
# cosine benzerlik; "filter evasion"↔"WAF bypass" gibi gerçek anlamsal eşleşme) container'da AKTİF
# olur. HEPSİ NON-FATAL: kurulum/indirme başarısız olsa bile image build olur ve kb_embed.py sessizce
# TF-IDF'e düşer (graceful, mevcut davranış). potion-base-8M (~30MB, torch YOK — saf statik) build-time
# indirilir; runtime egress kapalı olduğundan HF_HUB_OFFLINE ile cache'ten yüklenir.
RUN pip3 install --no-cache-dir --break-system-packages numpy model2vec >/dev/null 2>&1 \
 && python3 -c "from model2vec import StaticModel; StaticModel.from_pretrained('minishlab/potion-base-8M')" >/dev/null 2>&1 \
 && echo "NEURAL_RAG_OK" || echo "NEURAL_RAG_SKIPPED (TF-IDF fallback aktif)"
ENV HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1

# Interactive headless-browser capability (browser_* MCP tools). The engine drives
# this Chromium over CDP (chromedp) to execute JavaScript: real DOM-XSS, JS-heavy
# SPAs, multi-step session flows. Pin the binary path so chromedp finds it without
# probing; --no-sandbox is set in code (the container runs as root).
ENV CYP_CHROME_PATH=/usr/bin/chromium

# Recon + fuzzing toolchain: subdomain enum (subfinder/amass) + liveness/tech probe
# (httpx) + content fuzzing (ffuf) + JS crawl (katana) + historical URLs (gau).
COPY --from=recon /out/subfinder /usr/local/bin/subfinder
COPY --from=recon /out/httpx     /usr/local/bin/httpx
COPY --from=recon /out/ffuf      /usr/local/bin/ffuf
COPY --from=recon /out/katana    /usr/local/bin/katana
COPY --from=recon /out/gau       /usr/local/bin/gau
COPY --from=recon /out/amass     /usr/local/bin/amass
COPY --from=recon /out/nuclei    /usr/local/bin/nuclei
# Extra recon/testing tools the agents reference (dalfox=XSS, gospider=crawl,
# waybackurls=historical, gf/qsreplace=param mutate) — were missing → agents hit
# command-not-found and silently skipped that technique.
COPY --from=recon /out/dalfox      /usr/local/bin/dalfox
COPY --from=recon /out/gospider    /usr/local/bin/gospider
COPY --from=recon /out/waybackurls /usr/local/bin/waybackurls
COPY --from=recon /out/gf          /usr/local/bin/gf
COPY --from=recon /out/qsreplace   /usr/local/bin/qsreplace

# Additional CLI tools the expert agents invoke that had no install (the "missing
# tools" symptom → "command not found"): feroxbuster (content fuzzing), jwt_tool (JWT
# attacks), SSTImap (SSTI; also aliased as `tplmap`, its python2 predecessor). Installed
# from release binary / git so they are on PATH for the agents' bash calls.
RUN set -eux; \
    # feroxbuster — prebuilt linux binary
    curl -sSL https://github.com/epi052/feroxbuster/releases/latest/download/x86_64-linux-feroxbuster.tar.gz -o /tmp/ferox.tgz \
 && tar -xzf /tmp/ferox.tgz -C /usr/local/bin feroxbuster && chmod +x /usr/local/bin/feroxbuster && rm /tmp/ferox.tgz; \
    # jwt_tool — git + python deps, wrapper on PATH
    git clone --depth 1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
 && pip3 install --break-system-packages --no-cache-dir pycryptodomex requests termcolor cprint >/dev/null 2>&1 || true; \
    printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool && chmod +x /usr/local/bin/jwt_tool; \
    # SSTImap — modern python3 SSTI scanner; `tplmap` shim points here (tplmap is py2/EOL)
    git clone --depth 1 https://github.com/vladko312/SSTImap /opt/sstimap \
 && pip3 install --break-system-packages --no-cache-dir -r /opt/sstimap/requirements.txt >/dev/null 2>&1 || true; \
    printf '#!/bin/sh\nexec python3 /opt/sstimap/sstimap.py "$@"\n' > /usr/local/bin/sstimap && chmod +x /usr/local/bin/sstimap \
 && ln -sf /usr/local/bin/sstimap /usr/local/bin/tplmap

# Bundle nuclei templates at build time so the background worker never waits on a
# network template-update at scan time.
RUN nuclei -update-templates -silent >/dev/null 2>&1 || true

# Our own proxy/MCP engine (cypture-engine: MITM proxy on :8080 + cyp_
# MCP tools), built for linux into docker/bin by `make docker-image`.
COPY docker/bin/cypture-engine  /usr/local/bin/cypture-engine

# The REAL scan brain: the Project-Glass cypture binary with its FULL agent roster,
# skills and knowledge/RAG embedded (built via `make build` in Project-Glass). This
# replaces cypture-agent — it drives the whole pentest itself.
COPY docker/bin/cypture  /usr/local/bin/cypture

# Agent knowledge base (scripts + skills + agents) — cypture pentest needs this.
COPY agent /agent

COPY docker/entrypoint.sh /entrypoint.sh
COPY docker/nuclei_async.sh /usr/local/bin/nuclei_async.sh

RUN mkdir -p /root/.local/bin && ln -sf /usr/local/bin/cypture-engine /root/.local/bin/cypture-engine && chmod +x /usr/local/bin/cypture /usr/local/bin/cypture-engine \
        /usr/local/bin/subfinder /usr/local/bin/httpx /usr/local/bin/ffuf \
        /usr/local/bin/katana /usr/local/bin/gau /usr/local/bin/amass \
        /usr/local/bin/dalfox /usr/local/bin/gospider /usr/local/bin/waybackurls \
        /usr/local/bin/gf /usr/local/bin/qsreplace \
        /usr/local/bin/nuclei /usr/local/bin/nuclei_async.sh /entrypoint.sh \
 && mkdir -p /root/.local/share/cypture-agent /root/.config/cypture-agent /work

WORKDIR /work
ENTRYPOINT ["/entrypoint.sh"]
