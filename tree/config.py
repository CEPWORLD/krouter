# config.py — krouter-work 전용 (운영본과 분리)
# SAFE_MODE=True 이면 DHCP sniff / DNS :53 / 실제 iptables 를 수행하지 않음.
#
# Author : Kage
# Project: krouter — home DHCP/DNS/study-policy router I built and run for years.
# Thought: keep site-specific NICs out of source; live values belong in Settings DB.
#
import os
import ipaddress

try:
    from scapy.all import get_if_hwaddr
except Exception:
    get_if_hwaddr = None

# =========================
# 버전 / 저작
# =========================
def _read_version() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    for path in (
        os.path.join(here, 'VERSION'),
        os.path.join(os.path.dirname(here), 'VERSION'),
    ):
        try:
            with open(path) as f:
                v = f.read().strip()
                if v:
                    return v
        except Exception:
            pass
    return os.environ.get('KROUTER_VERSION', '6.4.136')


VERSION = _read_version()
APP_NAME = 'krouter'
APP_AUTHOR = 'Kage'
# History note (no personal contact data in source):
#   ~2004+ iptables routing / firewall; ~2006 home-router shape;
#   ~2025-07 real home production (old router → AP mode, multi-AP house)
APP_SINCE = '2004'
APP_HOME_PROD_SINCE = '2025-07'

# =========================
# 안전 / 경로
# =========================
# work 트리에서는 기본 True. 운영 이관 시에만 False 로 전환.
SAFE_MODE = os.environ.get('KROUTER_SAFE_MODE', '1') != '0'
KROUTER_ROOT = os.path.dirname(os.path.abspath(__file__))
ROUTER_SCRIPT = os.path.join(KROUTER_ROOT, 'router.sh')

# =========================
# 인터페이스 / 로그
# =========================
# NIC 이름은 코드에 넣지 않음 — Settings DB (또는 env) 에서만.
# 미설정 시 DHCP/iptables 는 실패하는 것이 정상 (공개용 기본값 없음).
INTERFACE = os.environ.get('KROUTER_INTERNAL_IF', '').strip()
WAN_INTERFACE = os.environ.get('KROUTER_WAN_IF', '').strip()
log_size = 5 * 1024 * 1024
log_rotate = 5
log_filename = os.path.join(KROUTER_ROOT, 'logs', 'dhcp.log')
log_filename_interface = os.path.join(KROUTER_ROOT, 'logs', 'dhcp_interface.log')
log_dns_interface = os.path.join(KROUTER_ROOT, 'logs', 'dns_interface.log')
log_dns_server = os.path.join(KROUTER_ROOT, 'logs', 'dns.log')

# =========================
# DB 경로 (work 전용 파일명 — 운영 DB 절대 사용 금지)
# =========================
dhcp_db_file = os.path.join(KROUTER_ROOT, 'data', 'dhcp_leases.db')
dns_db_file = os.path.join(KROUTER_ROOT, 'data', 'dns_records.db')
settings_db_file = os.path.join(KROUTER_ROOT, 'data', 'settings.db')

# =========================
# DNS 동작 기본값
# =========================
dns_local_only = False
upstream_dns = '8.8.8.8'
STUDY_TOKEN = 'study'
fake_ip = '0.0.0.0'

# default 모드 차단 도메인 (약차단)
default_block_domains = [
    'youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'gvt1.com',
    'roblox.com',
]
# study 모드 차단 도메인
block_domains = [
    'youtube.com', 'youtu.be', 'googlevideo.com', 'ytimg.com', 'gvt1.com',
    'roblox.com', 'scratch.mit.edu', 'scdn.co', 'comicfury.com',
]
block_all_subdomains = True

# =========================
# DHCP 설정
# =========================
GATEWAY = '192.168.0.1'
SUBNET_MASK = '255.255.255.0'
SERVER_IP = '192.168.0.1'
IP_NETWORK = ipaddress.IPv4Network(f'{SERVER_IP}/{SUBNET_MASK}', strict=False)
try:
    SERVER_MAC = (get_if_hwaddr(INTERFACE) if (get_if_hwaddr and INTERFACE) else '00:00:00:00:00:00')
except Exception:
    SERVER_MAC = '00:00:00:00:00:00'

DNS_SERVERS = SERVER_IP
DEFAULT_LEASE = 86400
ACTIVE_TIMEOUT = 300
IP_RANGE_START = ipaddress.IPv4Address('192.168.0.2')
IP_RANGE_END = ipaddress.IPv4Address('192.168.0.200')
IP_TEMP_START = ipaddress.IPv4Address('192.168.0.100')
IP_TEMP_END = ipaddress.IPv4Address('192.168.0.200')

# 신규 MAC 기본 모드
NEW_DEVICE_MODE = 'default'  # default | all_allow | study

# study 정규 허용 시간 (로컬 TZ, HH:MM). 이 밖이면 BLOCK (임시해금 없을 때)
STUDY_SCHEDULE_START = '06:00'
STUDY_SCHEDULE_END = '22:00'

# =========================
# UI / 인증
# =========================
# LAN 전체에서 Admin UI 접속 (집 안 기기). SAFE_MODE여도 bind는 0.0.0.0
# DHCP sniff / DNS:53 / iptables 만 SAFE_MODE 에서 막힘.
interface_ip = os.environ.get('KROUTER_BIND', '0.0.0.0')
# 통합 Admin UI (한 로그인) — SAFE 때는 운영 5000 과 안 겹치게 15000
interface_admin_port = int(os.environ.get(
    'KROUTER_ADMIN_PORT', '15000' if SAFE_MODE else '5000'))
# 레거시 분리 UI 포트 (사용 비권장 — admin_app 사용)
interface_dhcp_port = 15000 if SAFE_MODE else 5000
interface_dns_port = 15001 if SAFE_MODE else 5001
trigger = os.path.join(KROUTER_ROOT, 'data', 'update_dhcp_config')

# 기본 admin (최초 기동 시 settings DB 에 hash 저장). Settings 웹에서 변경 가능.
ADMIN_USER = 'admin'
ADMIN_PASSWORD = 'admin'  # 최초 기본값. 이후 settings.db 우선
SECRET_KEY = 'krouter-work-dev-change-me'

# iptables dry-run (SAFE_MODE 이면 강제)
ROUTER_DRY_RUN = SAFE_MODE or os.environ.get('KROUTER_DRY_RUN', '0') == '1'
