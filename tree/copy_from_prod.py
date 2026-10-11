#!/usr/bin/env python3
"""
copy_from_prod.py — read-only copy/convert of production DBs into work/data.

Author : Kage
Project: krouter
Thought: never break the live house router while rebuilding. COPY, don't move;
         cut over only after the work tree proves itself.
"""
from __future__ import annotations

import os
import shutil
import sqlite3
import sys
from datetime import datetime

ROOT = os.path.dirname(os.path.abspath(__file__))
DATA = os.path.join(ROOT, 'data')
PROD = os.environ.get('KROUTER_PROD', '/global/bin/krouter')
GATEWAY = '192.168.0.1'


def convert_router(raw) -> str:
    """
    study → study
    default / None / '' / GATEWAY IP → default  (신규 약차단 의미)
    임의 GW IP → 그대로 유지
    all_allow → 자동 생성 안 함 (원본에 없으면 안 생김)
    """
    if raw is None:
        return 'default'
    v = str(raw).strip()
    if not v:
        return 'default'
    low = v.lower()
    if low == 'study':
        return 'study'
    if low == 'all_allow':
        return 'all_allow'
    if low in ('default', 'gateway'):
        return 'default'
    if v == GATEWAY:
        return 'default'
    # 임의 IP 등
    return v


def open_ro(path: str) -> sqlite3.Connection:
    uri = f'file:{path}?mode=ro'
    conn = sqlite3.connect(uri, uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def ensure_dhcp_schema(db: sqlite3.Connection):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS leases (
        mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
        lease_start INTEGER, lease_time INTEGER, last_seen INTEGER,
        router TEXT, allow_until INTEGER
    );
    CREATE TABLE IF NOT EXISTS reservations (
        mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
        lease_time INTEGER, router TEXT, desc TEXT, allow_until INTEGER
    );
    CREATE TABLE IF NOT EXISTS history (
        mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
        last_seen INTEGER, router TEXT
    );
    CREATE TABLE IF NOT EXISTS routers (
        ip TEXT PRIMARY KEY, desc TEXT
    );
    ''')
    db.commit()


def ensure_dns_schema(db: sqlite3.Connection):
    db.executescript('''
    CREATE TABLE IF NOT EXISTS dns_mappings (
        ip TEXT, domain TEXT, PRIMARY KEY (ip, domain)
    );
    CREATE TABLE IF NOT EXISTS block_rules (
        domain TEXT PRIMARY KEY,
        enabled INTEGER DEFAULT 1,
        block_all_sub INTEGER DEFAULT 1,
        note TEXT
    );
    ''')
    db.commit()


def copy_dhcp(src_path: str, dst_path: str) -> dict:
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    if os.path.exists(dst_path):
        bak = dst_path + '.bak-' + datetime.now().strftime('%Y%m%d%H%M%S')
        shutil.copy2(dst_path, bak)
        print(f'[bak] {dst_path} -> {bak}')
    # 새 파일로 재생성
    if os.path.exists(dst_path):
        os.remove(dst_path)

    src = open_ro(src_path)
    dst = sqlite3.connect(dst_path)
    ensure_dhcp_schema(dst)
    stats = {'reservations': 0, 'leases': 0, 'history': 0, 'routers': 0,
             'router_converted': {}}

    def bump(key, old, new):
        k = f'{old!r}->{new!r}'
        stats['router_converted'][k] = stats['router_converted'].get(k, 0) + 1

    # reservations
    cols = [r[1] for r in src.execute('PRAGMA table_info(reservations)')]
    has_desc = 'desc' in cols
    for r in src.execute('SELECT * FROM reservations'):
        d = dict(r)
        old = d.get('router')
        new = convert_router(old)
        bump('res', old, new)
        dst.execute(
            'INSERT OR REPLACE INTO reservations '
            '(mac,ip,hostname,lease_time,router,desc,allow_until) VALUES (?,?,?,?,?,?,NULL)',
            (d.get('mac'), d.get('ip'), d.get('hostname'), d.get('lease_time'),
             new, d.get('desc') if has_desc else '',))
        stats['reservations'] += 1

    # leases
    for r in src.execute('SELECT * FROM leases'):
        d = dict(r)
        old = d.get('router')
        new = convert_router(old)
        bump('lea', old, new)
        dst.execute(
            'INSERT OR REPLACE INTO leases '
            '(mac,ip,hostname,lease_start,lease_time,last_seen,router,allow_until) '
            'VALUES (?,?,?,?,?,?,?,NULL)',
            (d.get('mac'), d.get('ip'), d.get('hostname'), d.get('lease_start'),
             d.get('lease_time'), d.get('last_seen'), new))
        stats['leases'] += 1

    # history
    try:
        for r in src.execute('SELECT * FROM history'):
            d = dict(r)
            old = d.get('router')
            new = convert_router(old) if old is not None else None
            dst.execute(
                'INSERT OR REPLACE INTO history (mac,ip,hostname,last_seen,router) VALUES (?,?,?,?,?)',
                (d.get('mac'), d.get('ip'), d.get('hostname'), d.get('last_seen'), new))
            stats['history'] += 1
    except sqlite3.Error as e:
        print(f'[warn] history: {e}')

    # routers
    try:
        for r in src.execute('SELECT * FROM routers'):
            d = dict(r)
            dst.execute('INSERT OR REPLACE INTO routers (ip, desc) VALUES (?,?)',
                        (d.get('ip'), d.get('desc')))
            stats['routers'] += 1
    except sqlite3.Error as e:
        print(f'[warn] routers: {e}')

    if not dst.execute('SELECT 1 FROM routers WHERE ip=?', (GATEWAY,)).fetchone():
        dst.execute('INSERT INTO routers (ip, desc) VALUES (?,?)',
                    (GATEWAY, 'default gateway'))

    dst.commit()
    src.close()
    dst.close()
    return stats


def copy_dns(src_path: str, dst_path: str) -> dict:
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    if os.path.exists(dst_path):
        bak = dst_path + '.bak-' + datetime.now().strftime('%Y%m%d%H%M%S')
        shutil.copy2(dst_path, bak)
        print(f'[bak] {dst_path} -> {bak}')
    if os.path.exists(dst_path):
        os.remove(dst_path)

    src = open_ro(src_path)
    dst = sqlite3.connect(dst_path)
    ensure_dns_schema(dst)
    stats = {'dns_mappings': 0, 'block_rules': 0}

    for r in src.execute('SELECT ip, domain FROM dns_mappings'):
        dst.execute('INSERT OR IGNORE INTO dns_mappings (ip, domain) VALUES (?,?)',
                    (r['ip'], r['domain']))
        stats['dns_mappings'] += 1

    # block_rules (있으면)
    tables = {r[0] for r in src.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'block_rules' in tables:
        cols = [c[1] for c in src.execute('PRAGMA table_info(block_rules)')]
        for r in src.execute('SELECT * FROM block_rules'):
            d = dict(r)
            domain = d.get('domain')
            if not domain:
                continue
            enabled = int(d.get('enabled', 1) or 0)
            bas = int(d.get('block_all_sub', 1) or 0) if 'block_all_sub' in cols else 1
            note = d.get('note') or ''
            dst.execute(
                'INSERT OR REPLACE INTO block_rules (domain, enabled, block_all_sub, note) VALUES (?,?,?,?)',
                (domain.lower(), enabled, bas, note))
            stats['block_rules'] += 1

    dst.commit()
    src.close()
    dst.close()
    return stats


def main():
    prod_dhcp = os.path.join(PROD, 'dhcp_leases.db')
    prod_dns = os.path.join(PROD, 'dns_records.db')
    dst_dhcp = os.path.join(DATA, 'dhcp_leases.db')
    dst_dns = os.path.join(DATA, 'dns_records.db')

    if not os.path.isfile(prod_dhcp):
        print(f'FAIL: missing {prod_dhcp}', file=sys.stderr)
        sys.exit(1)

    print(f'[copy] READ-ONLY from {PROD}')
    print(f'[copy] WRITE only under {DATA}')

    # 운영 파일이 쓰기로 열리지 않게 mode=ro 만 사용
    s1 = copy_dhcp(prod_dhcp, dst_dhcp)
    print('[dhcp]', s1)
    if os.path.isfile(prod_dns):
        s2 = copy_dns(prod_dns, dst_dns)
        print('[dns]', s2)
    else:
        print('[dns] skip (no prod dns db)')

    # 검증
    d = sqlite3.connect(dst_dhcp)
    d.row_factory = sqlite3.Row
    print('--- work reservations by router ---')
    for r in d.execute('SELECT router, COUNT(*) c FROM reservations GROUP BY router ORDER BY c DESC'):
        print(dict(r))
    print('--- work leases by router ---')
    for r in d.execute('SELECT router, COUNT(*) c FROM leases GROUP BY router ORDER BY c DESC'):
        print(dict(r))
    print('study sample:')
    for r in d.execute("SELECT mac,ip,hostname,router,allow_until FROM reservations WHERE router='study'"):
        print(dict(r))
    print('custom GW sample:')
    for r in d.execute(
            "SELECT mac,ip,hostname,router FROM reservations "
            "WHERE router NOT IN ('default','study','all_allow')"):
        print(dict(r))
    d.close()

    if os.path.isfile(dst_dns):
        n = sqlite3.connect(dst_dns)
        print('dns_mappings', n.execute('SELECT COUNT(*) FROM dns_mappings').fetchone()[0])
        print('block_rules', n.execute('SELECT COUNT(*) FROM block_rules').fetchone()[0])
        n.close()

    print('\nDONE: production untouched; work/data filled by COPY.')


if __name__ == '__main__':
    main()
