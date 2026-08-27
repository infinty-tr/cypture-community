#!/usr/bin/env bash
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$APP_DIR"
ENV_FILE="$APP_DIR/.env"
ENV_EXAMPLE="$APP_DIR/.env.example"
BIN="$APP_DIR/bin/cypture"
DOMAIN_DEFAULT="example.com"
KUBECONFIG_DEFAULT="/etc/rancher/k3s/k3s.yaml"
IMAGE_DEFAULT="cypture-engine:latest"
SERVICE="cypture"
RUN_USER="$(id -un)"
RUN_GROUP="$(id -gn)"

c_r=$'\033[31m'; c_g=$'\033[32m'; c_y=$'\033[33m'; c_b=$'\033[36m'; c_0=$'\033[0m'
info()  { printf '%s[*]%s %s\n' "$c_b" "$c_0" "$*"; }
ok()    { printf '%s[+]%s %s\n' "$c_g" "$c_0" "$*"; }
warn()  { printf '%s[!]%s %s\n' "$c_y" "$c_0" "$*"; }
err()   { printf '%s[x]%s %s\n' "$c_r" "$c_0" "$*" >&2; }
hr()    { printf '%s\n' "────────────────────────────────────────────────────────────"; }
section(){ echo; hr; printf '%s## %s%s\n' "$c_b" "$*" "$c_0"; hr; }

confirm() {
  local q="$1" def="${2:-N}" ans
  local hint="[y/N]"; [ "$def" = "Y" ] && hint="[Y/n]"
  read -r -p "$(printf '%s?%s %s %s ' "$c_y" "$c_0" "$q" "$hint")" ans || true
  ans="${ans:-$def}"
  [[ "$ans" =~ ^[Yy]$ ]]
}

ask_value() {
  local prompt="$1" cur="${2:-}" ans shown="$cur"
  read -r -p "$(printf '%s>%s %s [%s]: ' "$c_b" "$c_0" "$prompt" "${shown:-empty}")" ans || true
  printf '%s' "${ans:-$cur}"
}

ask_secret() {
  local prompt="$1" cur="${2:-}" ans state="unset"; [ -n "$cur" ] && state="keep current"
  read -r -s -p "$(printf '%s>%s %s [%s]: ' "$c_b" "$c_0" "$prompt" "$state")" ans || true
  echo >&2
  printf '%s' "${ans:-$cur}"
}

get_env() { # get_env KEY  → prints value from $ENV_FILE (empty if absent)
  [ -f "$ENV_FILE" ] || { printf ''; return; }
  local line; line="$(grep -m1 "^$1=" "$ENV_FILE" || true)"
  printf '%s' "${line#*=}"
}
set_env() { # set_env KEY VALUE  → upsert into $ENV_FILE
  local key="$1" val="$2" tmp
  tmp="$(mktemp)"
  [ -f "$ENV_FILE" ] && grep -v "^${key}=" "$ENV_FILE" > "$tmp" || true
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$ENV_FILE"
}

need_sudo() {
  if ! sudo -n true 2>/dev/null; then
    warn "Some steps need sudo. You may be prompted for your password."
    sudo -v || { err "sudo unavailable — hardening/proxy/systemd steps will be skipped."; return 1; }
  fi
  return 0
}

step_prereqs() {
  section "1) Prerequisites & health"
  local fail=0
  for t in openssl jq curl sqlite3; do
    if command -v "$t" >/dev/null 2>&1; then ok "$t present"
    else err "$t MISSING — install it (e.g. sudo apt-get install -y $t)"; fail=1; fi
  done

  if command -v docker >/dev/null 2>&1; then ok "docker: $(docker --version 2>/dev/null)"
  else err "docker MISSING"; fail=1; fi

  if command -v kubectl >/dev/null 2>&1 || command -v k3s >/dev/null 2>&1; then
    ok "kubectl/k3s present"
    if sudo -n true 2>/dev/null && sudo k3s kubectl --kubeconfig "$KUBECONFIG_DEFAULT" get nodes >/dev/null 2>&1; then
      ok "k3s API reachable"
    else
      warn "k3s API not verified (need sudo / kubeconfig) — will retry during hardening."
    fi
  else
    warn "kubectl/k3s not found — required only for CYPTURE_RUNNER=k8s."
  fi

  if sudo -n iptables -L 2>/dev/null | grep -qi kube-router; then
    ok "kube-router present → NetworkPolicy is ENFORCED"
  else
    warn "Could not confirm a NetworkPolicy controller. The egress backstop (C1) is a"
    warn "no-op without one. On k3s ensure it was NOT started with --disable-network-policy."
  fi

  [ -x "$BIN" ] && ok "backend binary: $BIN" || { err "backend binary missing at $BIN — build it (see BUILD below)"; fail=1; }

  if sudo -n k3s ctr images ls 2>/dev/null | grep -q "cypture-engine"; then
    ok "engine image present in k3s containerd"
  else
    warn "engine image 'cypture-engine' not found in k3s containerd. Import it:"
    warn "   docker save $IMAGE_DEFAULT | sudo k3s ctr images import -"
  fi

  if ss -tlnp 2>/dev/null | grep -q '127.0.0.1:7777'; then warn "port 7777 already in use (existing backend?) — will restart via systemd."; fi
  for p in 80 443; do
    if ss -tlnp 2>/dev/null | grep -qE "[:.]$p\b"; then warn "port $p already bound — Caddy install may conflict (k3s traefik?)."; fi
  done

  df -h / | awk 'NR==2{printf "    disk: %s used of %s (%s free)\n",$3,$2,$4}'
  free -h 2>/dev/null | awk 'NR==2{printf "    mem:  %s used of %s\n",$3,$2}'

  [ "$fail" = 0 ] && ok "Prerequisites OK." || { err "Fix the MISSING items above, then re-run."; exit 1; }
}

step_env() {
  section "2) Secrets & .env"

  if [ ! -f "$ENV_FILE" ]; then
    if [ -f "$ENV_EXAMPLE" ]; then
      info "No .env — seeding from .env.example."
      cp "$ENV_EXAMPLE" "$ENV_FILE"
    else
      : > "$ENV_FILE"
    fi
  else
    info "Existing .env found — current values are the defaults (Enter keeps them)."
    cp "$ENV_FILE" "$ENV_FILE.bak.$(date +%s)"
    ok "Backed up current .env."
  fi

  set_env CYPTURE_ENV prod
  set_env CYPTURE_HOST 127.0.0.1
  set_env CYPTURE_RUNNER_SKIP_PERMS false
  [ -n "$(get_env CYPTURE_PORT)" ] || set_env CYPTURE_PORT 7777

  local domain; domain="$(ask_value 'Public domain' "$DOMAIN_DEFAULT")"
  set_env CYPTURE_BASE_URL "https://$domain"
  echo "$domain" > "$APP_DIR/.setup_domain"   # remembered for the Caddy step

  local sec; sec="$(get_env CYPTURE_SESSION_SECRET)"
  if [ "${#sec}" -lt 32 ]; then
    sec="$(openssl rand -hex 32)"
    set_env CYPTURE_SESSION_SECRET "$sec"
    ok "Generated a strong CYPTURE_SESSION_SECRET."
  else
    ok "Keeping existing CYPTURE_SESSION_SECRET."
  fi

  set_env ADMIN_EMAIL "$(ask_value 'Admin email' "$(get_env ADMIN_EMAIL)")"
  local pw; pw="$(ask_secret 'Admin password (≥12 chars)' "$(get_env ADMIN_PASSWORD)")"
  while [ "${#pw}" -lt 12 ]; do warn "Too short."; pw="$(ask_secret 'Admin password (≥12 chars)' '')"; done
  set_env ADMIN_PASSWORD "$pw"

  local runner; runner="$(ask_value 'Runner (k8s|docker|sim)' "$(get_env CYPTURE_RUNNER)")"
  set_env CYPTURE_RUNNER "${runner:-k8s}"
  if [ "${runner:-k8s}" = "k8s" ]; then
    [ -n "$(get_env CYPTURE_KUBECONFIG)" ] || set_env CYPTURE_KUBECONFIG "$KUBECONFIG_DEFAULT"
    [ -n "$(get_env CYPTURE_K8S_NAMESPACE)" ] || set_env CYPTURE_K8S_NAMESPACE default
  fi
  [ -n "$(get_env CYPTURE_DOCKER_IMAGE)" ] || set_env CYPTURE_DOCKER_IMAGE "$IMAGE_DEFAULT"

  if confirm "Configure the turnkey LLM API key now?" N; then
    set_env CYPTURE_LLM_API_KEY  "$(ask_secret 'CYPTURE_LLM_API_KEY' "$(get_env CYPTURE_LLM_API_KEY)")"
    set_env CYPTURE_LLM_PROVIDER "$(ask_value  'CYPTURE_LLM_PROVIDER (blank = derive from model)' "$(get_env CYPTURE_LLM_PROVIDER)")"
    local rm; rm="$(ask_value 'CYPTURE_RUNNER_MODEL' "$(get_env CYPTURE_RUNNER_MODEL)")"
    [ -n "$rm" ] && set_env CYPTURE_RUNNER_MODEL "$rm"
  else
    info "Skipped — engine will use the host auth.json only if CYP_ALLOW_SHARED_AUTH_JSON=1."
  fi

  if confirm "Configure SMTP so email verification/invites actually send?" Y; then
    local cur_port cur_from
    cur_port="$(get_env CYPTURE_SMTP_PORT)"; cur_port="${cur_port:-587}"
    cur_from="$(get_env CYPTURE_SMTP_FROM)"; cur_from="${cur_from:-no-reply@$domain}"
    set_env CYPTURE_SMTP_HOST "$(ask_value  'SMTP host' "$(get_env CYPTURE_SMTP_HOST)")"
    set_env CYPTURE_SMTP_PORT "$(ask_value  'SMTP port' "$cur_port")"
    set_env CYPTURE_SMTP_USER "$(ask_value  'SMTP user' "$(get_env CYPTURE_SMTP_USER)")"
    set_env CYPTURE_SMTP_PASS "$(ask_secret 'SMTP pass' "$(get_env CYPTURE_SMTP_PASS)")"
    set_env CYPTURE_SMTP_FROM "$(ask_value  'From address' "$cur_from")"
  else
    warn "Email verification will be DISABLED — invited accounts are active without"
    warn "proving email ownership, and invite mails are only logged."
  fi

  chmod 600 "$ENV_FILE"
  chown "$RUN_USER:$RUN_GROUP" "$ENV_FILE" 2>/dev/null || true
  ok ".env written (mode 600)."
}

step_validate() {
  section "3) Config validation"
  [ -x "$BIN" ] || { warn "binary missing — skipping (build first)."; return; }
  if ( set -a; . "$ENV_FILE"; set +a; "$BIN" --check-config ); then
    ok "Config passed the production validation."
  else
    err "Config validation FAILED — fix the reported items above and re-run section 2."
    exit 1
  fi
}

step_harden() {
  section "4) Security hardening"

  local np="$APP_DIR/deploy/networkpolicy-engine.yaml"
  if [ -f "$np" ] && { command -v kubectl >/dev/null 2>&1 || command -v k3s >/dev/null 2>&1; }; then
    if confirm "Apply the engine egress NetworkPolicy (blocks IMDS/RFC1918 from scan pods)?" Y; then
      if sudo k3s kubectl --kubeconfig "$KUBECONFIG_DEFAULT" apply -f "$np" 2>/dev/null \
         || sudo kubectl --kubeconfig "$KUBECONFIG_DEFAULT" apply -f "$np" 2>/dev/null; then
        ok "NetworkPolicy applied."
      else
        warn "NetworkPolicy apply failed — apply it manually and verify NetworkPolicy support."
      fi
    fi
  fi

  chmod 600 "$ENV_FILE" 2>/dev/null || true
  [ -f "$APP_DIR/data/cypture.db" ] && chmod 600 "$APP_DIR/data/cypture.db" 2>/dev/null || true
  local stale; stale=$(ls "$APP_DIR"/.env.bak.pro.* 2>/dev/null || true)
  if [ -n "$stale" ] && confirm "Delete stale secret backup(s) (.env.bak.pro.*)?" Y; then
    rm -f "$APP_DIR"/.env.bak.pro.* && ok "Removed stale .env.bak.pro.* files."
  fi
  ok "File permissions tightened (.env / DB → 600)."

  if ss -tlnp 2>/dev/null | grep -qE '\*:6443|\*:10250'; then
    warn "k3s API (6443) and kubelet (10250) are listening on ALL interfaces."
    warn "Restrict them to trusted sources at the Azure NSG (or bind k3s to a private IP)."
    warn "This script does NOT auto-firewall the node (ufw+kube-router can conflict)."
  fi
}

step_caddy() {
  section "5) Reverse proxy + TLS (Caddy)"
  local domain; domain="$(cat "$APP_DIR/.setup_domain" 2>/dev/null || echo "$DOMAIN_DEFAULT")"

  if ! confirm "Install/configure Caddy as the TLS reverse proxy for $domain?" Y; then
    info "Skipped. If you already terminate TLS upstream (Azure LB/App Gateway), that's fine."
    return
  fi

  warn "PREREQUISITE: DNS A record '$domain' → this server's public IP, and inbound"
  warn "TCP 80 + 443 open at the Azure NSG. Caddy needs both for the ACME challenge."
  confirm "Are DNS + ports 80/443 ready?" N || { warn "Come back and re-run section 5 once DNS/ports are ready."; return; }

  if ! command -v caddy >/dev/null 2>&1; then
    info "Installing Caddy from the official apt repository…"
    sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl >/dev/null 2>&1 || true
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
    curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
    sudo apt-get update -y >/dev/null && sudo apt-get install -y caddy >/dev/null
  fi
  command -v caddy >/dev/null 2>&1 || { err "Caddy install failed — install it manually and re-run."; return; }

  sudo install -d -m 755 /var/log/caddy
  sed "s/example\\.com/$domain/g" "$APP_DIR/deploy/Caddyfile" | sudo tee /etc/caddy/Caddyfile >/dev/null
  sudo caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
    && ok "Caddyfile valid." || warn "caddy validate reported issues — check /etc/caddy/Caddyfile."
  sudo systemctl enable --now caddy
  sudo systemctl reload caddy 2>/dev/null || sudo systemctl restart caddy
  ok "Caddy running — it will obtain a Let's Encrypt cert for $domain on first request."
}

step_service() {
  section "6) systemd service"
  if [ ! -f "/etc/systemd/system/$SERVICE.service" ]; then
    if [ -f "$APP_DIR/deploy/$SERVICE.service" ]; then
      info "Installing $SERVICE.service from deploy/ template."
      sed -e "s#__APP_DIR__#$APP_DIR#g" \
          -e "s#__RUN_USER__#$RUN_USER#g" \
          -e "s#__HOME__#$HOME#g" \
          "$APP_DIR/deploy/$SERVICE.service" | sudo tee "/etc/systemd/system/$SERVICE.service" >/dev/null
    else
      warn "/etc/systemd/system/$SERVICE.service not found and no deploy/ template — create it before enabling."
      return
    fi
  fi
  pkill -x cypture 2>/dev/null && sleep 1 || true
  sudo systemctl daemon-reload
  sudo systemctl enable --now "$SERVICE"
  sleep 2
  if systemctl is-active --quiet "$SERVICE"; then
    ok "$SERVICE is active."
  else
    err "$SERVICE failed to start. Logs:"; sudo journalctl -u "$SERVICE" -n 20 --no-pager; return
  fi
  local port; port="$(get_env CYPTURE_PORT)"; port="${port:-7777}"
  if curl -fsS "http://127.0.0.1:$port/api/health" >/dev/null 2>&1; then
    ok "Health check passed (http://127.0.0.1:$port/api/health)."
  else
    warn "Health check did not pass yet — give it a moment, then: curl -s localhost:$port/api/health"
  fi
}

step_summary() {
  local domain; domain="$(cat "$APP_DIR/.setup_domain" 2>/dev/null || echo "$DOMAIN_DEFAULT")"
  section "Done — manual follow-ups"
  cat <<EOF
  • DNS: ensure $domain (and www) A-records point at this server's public IP.
  • Azure NSG: allow inbound 80 + 443; restrict 6443/10250 (k3s) to trusted sources.
  • First login: admin @ $(get_env ADMIN_EMAIL) — change the password after logging in.
  • Verify end-to-end:
        curl -I https://$domain/api/health        # 200 + valid TLS
        # start a scan against http://169.254.169.254 → must be REJECTED (SSRF guard)
  • Secrets live in $ENV_FILE (mode 600). Do NOT commit it. Rotate if it ever leaks.
EOF
  rm -f "$APP_DIR/.setup_domain"
}

main() {
  section "Cypture production setup — $APP_DIR"
  warn "This configures a PRODUCTION deploy and will collect real secrets."
  confirm "Continue?" Y || { info "Aborted."; exit 0; }
  need_sudo || true

  step_prereqs
  step_env
  step_validate
  step_harden
  step_caddy
  step_service
  step_summary
  echo; ok "Setup complete."
}
main "$@"
