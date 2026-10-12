"""
settings_store.py — runtime Settings DB (web-editable), separate from prod DBs.

Author : Kage
Project: krouter
Thought: do not bake my home NIC names into published source. Empty code
         defaults + settings.db keeps each house private when packaging.
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import threading
from typing import Any

import config

_lock = threading.RLock()

# 웹/정책에서 다루는 키와 기본값
DEFAULTS: dict[str, Any] = {
    'admin_user': getattr(config, 'ADMIN_USER', 'admin'),
    'admin_password_hash': '',  # web_auth 가 최초 설정
    'study_schedule_start': getattr(config, 'STUDY_SCHEDULE_START', '06:00'),
    'study_schedule_end': getattr(config, 'STUDY_SCHEDULE_END', '22:00'),
    'new_device_mode': getattr(config, 'NEW_DEVICE_MODE', 'default'),
    'upstream_dns': getattr(config, 'upstream_dns', '8.8.8.8'),
    'dns_local_only': bool(getattr(config, 'dns_local_only', False)),
    'default_block_domains': list(getattr(config, 'default_block_domains', [])),
    'study_block_domains': list(getattr(config, 'block_domains', [])),
    'block_all_subdomains': bool(getattr(config, 'block_all_subdomains', True)),
    'gateway': getattr(config, 'GATEWAY', '192.168.0.1'),
    'dns_servers': getattr(config, 'DNS_SERVERS', '192.168.0.1'),
    # BLOCK(스케줄 밖) 예외: ["tcp:1.2.3.4:443", "udp:8.8.8.8:53", "any:9.9.9.9:*"]
    'block_allow_rules': [],
    # NIC — 코드 기본은 비움. 반드시 settings.db / 설치 시 설정.
    'internal_device': getattr(config, 'INTERFACE', '') or '',
    'wan_device': getattr(config, 'WAN_INTERFACE', '') or '',
    'dhcp_auto_start': str(getattr(config, 'IP_TEMP_START', '192.168.0.100')),
    'dhcp_auto_end': str(getattr(config, 'IP_TEMP_END', '192.168.0.200')),
    # 코드 기본 ON (공개 시 보수적). 로컬 운영 DB 에서 OFF 로 둘 수 있음.
    'firewall_enabled': True,
    # [{proto, wan_port, dest_ip, dest_port, enabled, note}, ...]
    'port_forwards': [],
    # ARP neighbor table size preset key (= gc_thresh1). See ARP_PRESETS.
    'arp_table_size': 100,
}

# Preset key → live sysctl values (no conf file; applied via sysctl -w at start/save).
# thresh ratio 1:4:8; stale/solicit knobs match typical multi-AP home tuning (no IPv6).
ARP_TABLE_CHOICES = (100, 200, 512, 1024, 2048)
ARP_PRESETS: dict[int, dict[str, int]] = {
    n: {
        'gc_thresh1': n,
        'gc_thresh2': n * 4,
        'gc_thresh3': n * 8,
        'gc_stale_time': 300,
        'base_reachable_time_ms': 300000,
        'mcast_solicit': 6,
        'ucast_solicit': 3,
    }
    for n in ARP_TABLE_CHOICES
}


def arp_preset(size: int | None = None) -> dict[str, int]:
    """Resolve Settings arp_table_size → sysctl knobs."""
    if size is None:
        size = get('arp_table_size')
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 100
    if size not in ARP_PRESETS:
        size = min(ARP_TABLE_CHOICES, key=lambda n: abs(n - size))
    return dict(ARP_PRESETS[size])

_IFACE_RE = re.compile(r'^[A-Za-z0-9][A-Za-z0-9_.:-]{0,14}$')


def _db_path() -> str:
    path = getattr(config, 'settings_db_file', 'settings.db')
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    return path


def _connect():
    db = sqlite3.connect(_db_path(), check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


def ensure_tables():
    with _lock, _connect() as db:
        db.execute('''
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            )
        ''')
        db.commit()
        for k, v in DEFAULTS.items():
            row = db.execute('SELECT key FROM settings WHERE key=?', (k,)).fetchone()
            if not row:
                db.execute('INSERT INTO settings (key, value) VALUES (?, ?)',
                           (k, json.dumps(v)))
        db.commit()


def get(key: str, default=None):
    ensure_tables()
    with _lock, _connect() as db:
        row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        if not row:
            return DEFAULTS.get(key, default)
        try:
            return json.loads(row['value'])
        except Exception:
            return row['value']


def get_all() -> dict:
    ensure_tables()
    with _lock, _connect() as db:
        out = dict(DEFAULTS)
        for row in db.execute('SELECT key, value FROM settings'):
            try:
                out[row['key']] = json.loads(row['value'])
            except Exception:
                out[row['key']] = row['value']
        return out


def set_value(key: str, value: Any):
    ensure_tables()
    with _lock, _connect() as db:
        db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                   (key, json.dumps(value)))
        db.commit()


def set_many(mapping: dict):
    ensure_tables()
    with _lock, _connect() as db:
        for k, v in mapping.items():
            db.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)',
                       (k, json.dumps(v)))
        db.commit()


def policy_kwargs() -> dict:
    s = get_all()
    return {
        'study_start': s.get('study_schedule_start') or '06:00',
        'study_end': s.get('study_schedule_end') or '22:00',
    }


def internal_device() -> str:
    """Settings Internal (IN / LAN). DB first, then env, then config."""
    v = get('internal_device')
    if v and str(v).strip():
        return str(v).strip()
    return (os.environ.get('INB')
            or os.environ.get('KROUTER_INTERNAL_IF')
            or getattr(config, 'INTERFACE', '')
            or '').strip()


def wan_device() -> str:
    """Settings WAN (OUT). DB first, then env, then config."""
    v = get('wan_device')
    if v and str(v).strip():
        return str(v).strip()
    return (os.environ.get('OUT')
            or os.environ.get('KROUTER_WAN_IF')
            or getattr(config, 'WAN_INTERFACE', '')
            or '').strip()


def dhcp_auto_range() -> tuple[str, str]:
    start = get('dhcp_auto_start') or str(getattr(config, 'IP_TEMP_START', '192.168.0.100'))
    end = get('dhcp_auto_end') or str(getattr(config, 'IP_TEMP_END', '192.168.0.200'))
    return str(start).strip(), str(end).strip()


def primary_dns_ip() -> str:
    raw = get('dns_servers') or getattr(config, 'DNS_SERVERS', '192.168.0.1')
    return str(raw).split(',')[0].strip()


def gateway_ip() -> str:
    return str(get('gateway') or getattr(config, 'GATEWAY', '192.168.0.1')).strip()


def valid_iface_name(name: str) -> bool:
    return bool(name and _IFACE_RE.match(name))


def iface_exists(name: str) -> bool:
    return valid_iface_name(name) and os.path.exists(f'/sys/class/net/{name}')


def router_env() -> dict[str, str]:
    """router.sh / krouterctl 에 넘길 INB/OUT/DNS/GW — always from Settings."""
    return {
        'INB': internal_device(),
        'OUT': wan_device(),
        'SERVER_IP_DEFAULT': gateway_ip(),
        'ROUTER_DNS_IP': primary_dns_ip(),
    }


def apply_runtime() -> dict[str, str]:
    """
    Push Settings → process env + config so DHCP/DNS/iptables share one view.

    IN  (internal_device) = LAN: DHCP sniff/send, DNS :53, MAC FORWARD rules
    OUT (wan_device)      = WAN: NAT / FORWARD other side
    """
    inb = internal_device()
    out = wan_device()
    gw = gateway_ip()
    dns = str(get('dns_servers') or primary_dns_ip()).strip()

    config.INTERFACE = inb
    config.WAN_INTERFACE = out
    config.GATEWAY = gw
    config.DNS_SERVERS = dns

    os.environ['INB'] = inb
    os.environ['OUT'] = out
    os.environ['KROUTER_INTERNAL_IF'] = inb
    os.environ['KROUTER_WAN_IF'] = out
    os.environ['SERVER_IP_DEFAULT'] = gw
    os.environ['ROUTER_DNS_IP'] = primary_dns_ip()

    mac = '00:00:00:00:00:00'
    sip = gw
    if inb:
        try:
            from scapy.all import get_if_hwaddr
            mac = get_if_hwaddr(inb) or mac
        except Exception:
            pass
        try:
            import netifaces
            addrs = netifaces.ifaddresses(inb)
            for a in addrs.get(netifaces.AF_INET, []) or []:
                if a.get('addr'):
                    sip = a['addr']
                    break
        except Exception:
            pass
    config.SERVER_MAC = mac
    config.SERVER_IP = sip
    return {
        'INB': inb,
        'OUT': out,
        'SERVER_MAC': mac,
        'SERVER_IP': sip,
        'GATEWAY': gw,
        'DNS': dns,
    }
