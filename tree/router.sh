#!/usr/bin/env bash
# router.sh — NAT + per-MAC policy chains (DEFAULT / ALL_ALLOW / STUDY / BLOCK)
#             + optional WAN firewall / port-forward refresh.
#
# Author : Kage
# Project: krouter
# Thought: MAC→chain is the enforcement point parents actually feel. Firewall ON
#          means WAN NEW is deny-by-default; OFF keeps the old open-ish behavior.
#
# KROUTER_DRY_RUN=1 → print iptables only (no apply).
set -euo pipefail

# NIC 는 환경변수/Settings 에서만 (코드에 장비명 하드코딩 없음)
INB="${INB:-}"
OUT="${OUT:-}"
SERVER_IP_DEFAULT="${SERVER_IP_DEFAULT:-192.168.0.1}"
ROUTER_DNS_IP="${ROUTER_DNS_IP:-192.168.0.1}"
DRY_RUN="${KROUTER_DRY_RUN:-0}"

ACTION="${1:-}"; ARG1="${2:-}"; ARG2="${3:-}"

msg() { echo "[*] $*"; }
err() { echo "[!] $*" >&2; exit 1; }
need_root() {
  if [[ "$DRY_RUN" == "1" ]]; then return 0; fi
  [[ $EUID -eq 0 ]] || err "root로 실행하세요 (sudo). (또는 KROUTER_DRY_RUN=1)"
}

ipt() {
  if [[ "$DRY_RUN" == "1" ]]; then echo "DRY iptables $*"; return 0; fi
  iptables "$@"
}
iptn() {
  if [[ "$DRY_RUN" == "1" ]]; then echo "DRY iptables -t nat $*"; return 0; fi
  iptables -t nat "$@"
}

flush_ebtables() {
  [[ "$DRY_RUN" == "1" ]] && { msg "DRY ebtables flush"; return 0; }
  if command -v ebtables >/dev/null 2>&1; then
    ebtables -F || true; ebtables -X || true
    ebtables -P INPUT ACCEPT  || true
    ebtables -P OUTPUT ACCEPT || true
    ebtables -P FORWARD ACCEPT|| true
  fi
}

enable_forwarding() {
  [[ "$DRY_RUN" == "1" ]] && { msg "DRY sysctl forward"; return 0; }
  sysctl -w net.ipv4.ip_forward=1 >/dev/null
  sysctl -w net.ipv4.conf.all.proxy_arp=1 >/dev/null
  sysctl -w net.ipv4.conf.all.rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf."${INB}".rp_filter=0 >/dev/null
  sysctl -w net.ipv4.conf."${OUT}".rp_filter=0 >/dev/null
}

base_firewall() {
  ipt -F; ipt -X
  iptn -F; iptn -X
  ipt -P INPUT ACCEPT
  ipt -P OUTPUT ACCEPT
  ipt -P FORWARD DROP

  ipt -I FORWARD 1 -i "${INB}" -o "${INB}" -j ACCEPT
  ipt -I FORWARD 1 -i "tun0" -o "${INB}" -s 10.110.70.0/24 -j ACCEPT 2>/dev/null || true
  ipt -I FORWARD 1 -i "${OUT}" -o "tun0" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

  iptn -A POSTROUTING -o "${OUT}" -j MASQUERADE
  ipt -A FORWARD -i "${INB}" -o "${OUT}" -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  ipt -A FORWARD -i "${OUT}" -o "${INB}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  ipt -I INPUT 1 -i "${INB}" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ipt -I INPUT 1 -i "${INB}" -p tcp -m multiport --dports 22,53,80,443,447,8007,8008,5000,5001,15000,15001 -j ACCEPT
  ipt -I INPUT 1 -i "${INB}" -p udp --dport 53 -j ACCEPT
  ipt -I INPUT 1 -i "${INB}" -p udp --sport 68 --dport 67 -j ACCEPT
  ipt -I INPUT 1 -i "${INB}" -p icmp -j ACCEPT
}

_new_chain() {
  local name="$1"
  iptables -N "$name" 2>/dev/null || iptables -F "$name"
}

define_policy_chains() {
  if [[ "$DRY_RUN" == "1" ]]; then
    msg "DRY define chains DEFAULT ALL_ALLOW STUDY BLOCK"
    return 0
  fi
  modprobe xt_string 2>/dev/null || true
  for c in DEFAULT ALL_ALLOW STUDY BLOCK; do
    _new_chain "$c"
  done

  # ---- ALL_ALLOW ----
  iptables -A ALL_ALLOW -j RETURN

  # ---- DEFAULT (약차단: 유튜브/게임 포트, UDP 전면차단 없음) ----
  for d in youtube.com youtu.be googlevideo.com ytimg.com gvt1.com roblox.com; do
    iptables -A DEFAULT -p tcp --dport 443 -m string --string "$d" --algo bm -j REJECT
    iptables -A DEFAULT -p tcp --dport 80  -m string --string "$d" --algo bm -j REJECT
  done
  iptables -A DEFAULT -p udp --dport 443 -j REJECT
  iptables -A DEFAULT -p udp --dport 27000:27100 -j REJECT
  iptables -A DEFAULT -p tcp --dport 27015:27050 -j REJECT
  iptables -A DEFAULT -p tcp -m multiport --dports 1119,3724,2099,5222,5223,25565,3074 -j REJECT
  iptables -A DEFAULT -p udp -m multiport --dports 19132,19133,3074,3478,3479 -j REJECT
  iptables -A DEFAULT -j RETURN

  # ---- STUDY (강차단) ----
  iptables -A STUDY -p udp --dport 53 -d "${ROUTER_DNS_IP}" -j ACCEPT
  iptables -A STUDY -p tcp --dport 53 -d "${ROUTER_DNS_IP}" -j ACCEPT
  iptables -A STUDY -p udp --dport 53 ! -d "${ROUTER_DNS_IP}" -j REJECT
  iptables -A STUDY -p tcp --dport 53 ! -d "${ROUTER_DNS_IP}" -j REJECT
  for d in youtube.com youtu.be googlevideo.com ytimg.com gvt1.com roblox.com scratch.mit.edu scdn.co comicfury.com; do
    iptables -A STUDY -p tcp --dport 443 -m string --string "$d" --algo bm -j REJECT
    iptables -A STUDY -p tcp --dport 80  -m string --string "$d" --algo bm -j REJECT
  done
  iptables -A STUDY -p udp --dport 443 -j REJECT
  iptables -A STUDY -p udp -m multiport ! --dports 53,67,68,123 -j REJECT
  iptables -A STUDY -p udp --dport 27000:27100 -j REJECT
  iptables -A STUDY -p tcp --dport 27015:27050 -j REJECT
  iptables -A STUDY -p tcp -m multiport --dports 1119,3724,2099,5222,5223,8393:8400,25565,3074 -j REJECT
  iptables -A STUDY -p udp -m multiport --dports 6113,6114,3478,3479,5060,5061,88,500,3074,3544,4500,19132,19133 -j REJECT
  iptables -A STUDY -p udp --dport 7000:7500 -j REJECT
  iptables -A STUDY -p udp --sport 68 --dport 67 -j ACCEPT
  iptables -A STUDY -p udp --sport 67 --dport 68 -j ACCEPT
  iptables -A STUDY -j RETURN

  # BLOCK 본문은 refresh_block 에서 채움 (허용 IP/포트 파일 반영)
  refresh_block
}

# data/block_allow.conf :
#   한 줄에 하나: proto:ip:port
#     proto = tcp | udp | any
#     ip    = IPv4 또는 CIDR (예: 1.2.3.4 / 10.0.0.0/8)
#     port  = 숫자 또는 * (모든 포트)
#   레거시(선택):
#     IPS=1.2.3.4,5.6.7.8
#     PORTS=443,853
BLOCK_ALLOW_FILE="${BLOCK_ALLOW_FILE:-}"
_resolve_allow_file() {
  if [[ -n "${BLOCK_ALLOW_FILE}" && -f "${BLOCK_ALLOW_FILE}" ]]; then
    echo "${BLOCK_ALLOW_FILE}"; return
  fi
  local here
  here="$(cd "$(dirname "$0")" && pwd)"
  if [[ -f "${here}/data/block_allow.conf" ]]; then
    echo "${here}/data/block_allow.conf"; return
  fi
  echo ""
}

_block_allow_rule() {
  # $1=proto $2=ip $3=port(|*)
  local proto="$1" ip="$2" port="$3"
  if [[ ! "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
    msg "skip invalid IP in rule: $proto:$ip:$port"
    return 1
  fi
  if [[ "$port" != "*" ]]; then
    if [[ ! "$port" =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
      msg "skip invalid port in rule: $proto:$ip:$port"
      return 1
    fi
  fi
  case "$proto" in
    tcp|udp)
      if [[ "$port" == "*" ]]; then
        iptables -A BLOCK -p "$proto" -d "$ip" -j ACCEPT
      else
        iptables -A BLOCK -p "$proto" -d "$ip" --dport "$port" -j ACCEPT
      fi
      msg "BLOCK allow $proto:$ip:$port"
      ;;
    any)
      if [[ "$port" == "*" ]]; then
        iptables -A BLOCK -d "$ip" -j ACCEPT
      else
        iptables -A BLOCK -p tcp -d "$ip" --dport "$port" -j ACCEPT
        iptables -A BLOCK -p udp -d "$ip" --dport "$port" -j ACCEPT
      fi
      msg "BLOCK allow any:$ip:$port"
      ;;
    *)
      msg "skip unknown proto: $proto:$ip:$port"
      return 1
      ;;
  esac
}

refresh_block() {
  local allow_file line proto ip port ips_line ports_line
  allow_file="$(_resolve_allow_file)"

  if [[ "$DRY_RUN" == "1" ]]; then
    msg "DRY refresh BLOCK (file=${allow_file:-none})"
    return 0
  fi

  iptables -N BLOCK 2>/dev/null || iptables -F BLOCK

  # 필수: 로컬 DNS / DHCP / NTP
  iptables -A BLOCK -p udp --dport 53 -d "${ROUTER_DNS_IP}" -j ACCEPT
  iptables -A BLOCK -p tcp --dport 53 -d "${ROUTER_DNS_IP}" -j ACCEPT
  iptables -A BLOCK -p udp --sport 68 --dport 67 -j ACCEPT
  iptables -A BLOCK -p udp --sport 67 --dport 68 -j ACCEPT
  iptables -A BLOCK -p udp --dport 123 -j ACCEPT
  iptables -A BLOCK -p udp --sport 123 -j ACCEPT

  if [[ -n "$allow_file" && -f "$allow_file" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(echo "$line" | xargs)"
      [[ -z "$line" ]] && continue
      if [[ "$line" =~ ^IPS= ]]; then
        ips_line="${line#IPS=}"
        IFS=',' read -ra _ips <<< "$ips_line"
        for ip in "${_ips[@]}"; do
          ip="$(echo "$ip" | xargs)"
          [[ -z "$ip" ]] && continue
          _block_allow_rule any "$ip" "*"
        done
        continue
      fi
      if [[ "$line" =~ ^PORTS= ]]; then
        ports_line="${line#PORTS=}"
        IFS=',' read -ra _ports <<< "$ports_line"
        for port in "${_ports[@]}"; do
          port="$(echo "$port" | xargs)"
          [[ -z "$port" ]] && continue
          # 목적지 IP 무관 — 해당 dport 만 통과
          if [[ "$port" =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )); then
            iptables -A BLOCK -p tcp --dport "$port" -j ACCEPT
            iptables -A BLOCK -p udp --dport "$port" -j ACCEPT
            msg "BLOCK allow port $port (any dst)"
          else
            msg "skip invalid port: $port"
          fi
        done
        continue
      fi
      # proto:ip:port
      if [[ "$line" =~ ^(tcp|udp|any):([^:]+):([0-9]+|\*)$ ]]; then
        _block_allow_rule "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}"
      else
        msg "skip invalid allow line: $line"
      fi
    done < "$allow_file"
  fi

  iptables -A BLOCK -j REJECT
  msg "BLOCK chain refreshed"
}

is_mac() { [[ "$1" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; }
is_chain() { [[ "$1" =~ ^(DEFAULT|ALL_ALLOW|STUDY|BLOCK)$ ]]; }

_clear_mac_jumps() {
  local mac="$1"
  if [[ "$DRY_RUN" == "1" ]]; then
    msg "DRY clear jumps for $mac"
    return 0
  fi
  local c
  for c in DEFAULT ALL_ALLOW STUDY BLOCK STUDY; do
    while iptables -C FORWARD -i "${INB}" -o "${OUT}" -m mac --mac-source "${mac}" -j "$c" 2>/dev/null; do
      ipt -D FORWARD -i "${INB}" -o "${OUT}" -m mac --mac-source "${mac}" -j "$c" || true
    done
  done
}

set_mac_chain() {
  local mac="$1" chain="$2"
  is_mac "$mac" || err "MAC 형식 아님: $mac"
  is_chain "$chain" || err "체인 아님: $chain (DEFAULT|ALL_ALLOW|STUDY|BLOCK)"
  _clear_mac_jumps "$mac"
  # IN↔IN 다음, 일반 FORWARD 앞
  ipt -I FORWARD 2 -i "${INB}" -o "${OUT}" -m mac --mac-source "$mac" -j "$chain"
  msg "set $mac -> $chain"
}

# 호환: add = STUDY, del = DEFAULT
register_mac() { set_mac_chain "$1" STUDY; }
unregister_mac() { set_mac_chain "$1" DEFAULT; }

list_registered() {
  if [[ "$DRY_RUN" == "1" ]]; then msg "DRY list"; return 0; fi
  iptables -S FORWARD \
    | grep -E " -i ${INB} -o ${OUT} -m mac --mac-source " \
    | sed -E 's/.*--mac-source ([^ ]+) -j ([^ ]+).*/\1 \2/' \
    | sort -u
}

# data/firewall.conf : ENABLED=0|1
# data/port_forward.conf : proto wan_port dest_ip dest_port   (한 줄에 하나)
FIREWALL_CONF="${FIREWALL_CONF:-}"
PORT_FORWARD_CONF="${PORT_FORWARD_CONF:-}"
_resolve_fw_files() {
  local here
  here="$(cd "$(dirname "$0")" && pwd)"
  if [[ -z "$FIREWALL_CONF" ]]; then
    FIREWALL_CONF="${here}/data/firewall.conf"
  fi
  if [[ -z "$PORT_FORWARD_CONF" ]]; then
    PORT_FORWARD_CONF="${here}/data/port_forward.conf"
  fi
}

_is_local_ip() {
  local ip="$1"
  [[ "$ip" == "$SERVER_IP_DEFAULT" || "$ip" == "$ROUTER_DNS_IP" ]] && return 0
  # 호스트에 붙은 IP 이면 로컬
  ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -qx "$ip"
}

pf_add_rule() {
  local proto="$1" wan_port="$2" dest_ip="$3" dest_port="$4"
  [[ "$proto" =~ ^(tcp|udp)$ ]] || { msg "skip bad proto $proto"; return 1; }
  [[ "$wan_port" =~ ^[0-9]+$ && "$dest_port" =~ ^[0-9]+$ ]] || { msg "skip bad port"; return 1; }
  [[ "$dest_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || { msg "skip bad dest $dest_ip"; return 1; }

  iptn -A KROUTER_DNAT -i "${OUT}" -p "$proto" --dport "$wan_port" \
    -j DNAT --to-destination "${dest_ip}:${dest_port}"

  if _is_local_ip "$dest_ip"; then
    # 라우터 자신 서비스 → INPUT
    ipt -A KROUTER_WANIN -i "${OUT}" -p "$proto" --dport "$dest_port" -j ACCEPT
  else
    # 내부 다른 호스트 → FORWARD
    ipt -A KROUTER_FWDWAN -i "${OUT}" -o "${INB}" -p "$proto" -d "$dest_ip" --dport "$dest_port" \
      -m conntrack --ctstate NEW,ESTABLISHED,RELATED -j ACCEPT
  fi
  msg "PF WAN:${proto}/${wan_port} -> ${dest_ip}:${dest_port}"
}

# 레거시 호환: 동일 포트 tcp DNAT
pf_open() {
  local port="$1"; local dst="${2:-$SERVER_IP_DEFAULT}"
  pf_add_rule tcp "$port" "$dst" "$port"
}

pf_close() {
  msg "pf_close: use refresh-pf (전체 재적용)"
}

refresh_pf() {
  local enabled="0" line proto wan_port dest_ip dest_port
  _resolve_fw_files

  if [[ "$DRY_RUN" == "1" ]]; then
    msg "DRY refresh_pf firewall_conf=${FIREWALL_CONF} pf=${PORT_FORWARD_CONF}"
    return 0
  fi

  iptables -t nat -N KROUTER_DNAT 2>/dev/null || iptables -t nat -F KROUTER_DNAT
  iptables -N KROUTER_FWDWAN 2>/dev/null || iptables -F KROUTER_FWDWAN
  iptables -N KROUTER_WANIN 2>/dev/null || iptables -F KROUTER_WANIN

  # 점프 설치 (없으면)
  iptn -C PREROUTING -i "${OUT}" -j KROUTER_DNAT 2>/dev/null \
    || iptn -I PREROUTING 1 -i "${OUT}" -j KROUTER_DNAT
  ipt -C FORWARD -i "${OUT}" -o "${INB}" -j KROUTER_FWDWAN 2>/dev/null \
    || ipt -I FORWARD 1 -i "${OUT}" -o "${INB}" -j KROUTER_FWDWAN
  ipt -C INPUT -i "${OUT}" -j KROUTER_WANIN 2>/dev/null \
    || ipt -I INPUT 1 -i "${OUT}" -j KROUTER_WANIN

  # WAN 응답은 항상 허용
  ipt -A KROUTER_WANIN -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

  if [[ -f "$FIREWALL_CONF" ]]; then
    enabled="$(grep -E '^ENABLED=' "$FIREWALL_CONF" | head -1 | cut -d= -f2- | tr -d '[:space:]' || true)"
  fi
  [[ "$enabled" == "1" || "$enabled" == "true" || "$enabled" == "ON" ]] && enabled="1" || enabled="0"

  if [[ "$enabled" != "1" ]]; then
    # OFF: 기존과 동일 — 라우터로 22/53/447 오픈 (+ 파일에 있는 추가 PF도 적용)
    msg "Firewall OFF — legacy WAN opens + optional PF list"
    pf_add_rule tcp 53  "${SERVER_IP_DEFAULT}" 53
    pf_add_rule udp 53  "${SERVER_IP_DEFAULT}" 53
    pf_add_rule tcp 447 "${SERVER_IP_DEFAULT}" 447
    pf_add_rule tcp 22  "${SERVER_IP_DEFAULT}" 22
  else
    msg "Firewall ON — only listed port forwards (default deny WAN NEW)"
  fi

  if [[ -f "$PORT_FORWARD_CONF" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      line="${line%%#*}"
      line="$(echo "$line" | xargs)"
      [[ -z "$line" ]] && continue
      # proto wan_port dest_ip dest_port
      read -r proto wan_port dest_ip dest_port _rest <<< "$line" || true
      [[ -n "${proto:-}" && -n "${wan_port:-}" && -n "${dest_ip:-}" && -n "${dest_port:-}" ]] || continue
      pf_add_rule "$proto" "$wan_port" "$dest_ip" "$dest_port"
    done < "$PORT_FORWARD_CONF"
  fi

  if [[ "$enabled" == "1" ]]; then
    ipt -A KROUTER_WANIN -j DROP
  else
    ipt -A KROUTER_WANIN -j RETURN
  fi
  ipt -A KROUTER_FWDWAN -j RETURN
  msg "PF/firewall refreshed (enabled=$enabled)"
}

usage() {
  cat <<EOF
Usage:
  KROUTER_DRY_RUN=1 $0 init|set|add|del|list|...
  sudo $0 init
  sudo $0 set MAC DEFAULT|ALL_ALLOW|STUDY|BLOCK
  sudo $0 add MAC          # STUDY (호환)
  sudo $0 del MAC          # DEFAULT (호환)
  sudo $0 list
Env: INB OUT SERVER_IP_DEFAULT ROUTER_DNS_IP KROUTER_DRY_RUN
EOF
}

need_root

require_ifaces() {
  [[ -n "$INB" && -n "$OUT" ]] || err "INB/OUT unset — set Settings internal/wan device (or env INB OUT)"
  [[ "$INB" != "$OUT" ]] || err "INB and OUT must differ"
}

case "${ACTION}" in
  init)
    require_ifaces
    msg "ebtables"; flush_ebtables
    msg "forwarding"; enable_forwarding
    msg "base firewall"; base_firewall
    msg "policy chains"; define_policy_chains
    msg "port-forward / firewall"; refresh_pf
    msg "완료 (DRY_RUN=$DRY_RUN)"
    ;;
  set|add|del|refresh-block|refresh_block|refresh-pf|refresh_pf|firewall-refresh|open|close)
    require_ifaces
    ;;&
  set)
    [[ -n "${ARG1}" && -n "${ARG2}" ]] || err "set <MAC> <CHAIN>"
    set_mac_chain "${ARG1}" "${ARG2}"
    ;;
  add)
    [[ -n "${ARG1}" ]] || err "add <MAC>"
    register_mac "${ARG1}"
    ;;
  del)
    [[ -n "${ARG1}" ]] || err "del <MAC>"
    unregister_mac "${ARG1}"
    ;;
  list) list_registered ;;
  refresh-block|refresh_block)
    refresh_block
    ;;
  refresh-pf|refresh_pf|firewall-refresh)
    refresh_pf
    ;;
  open|close)
    msg "open/close deprecated — edit Admin Firewall then refresh-pf"
    refresh_pf
    ;;
  *) usage; exit 1 ;;
esac
