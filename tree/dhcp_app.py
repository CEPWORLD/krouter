#!/usr/bin/env python3
# dhcp_app.py — DHCP service + MemDB + policy hooks (default / all_allow / study).
#
# Author : Kage
# Project: krouter
# Thought: reservations hold the "truth" for kids' devices; new MACs land in a
#          predictable auto pool so servers can keep fixed IPs outside that range.
#
import os
import ipaddress
import sqlite3
import time
import threading
import logging
from logging.handlers import RotatingFileHandler
from flask import Flask, render_template_string, request, redirect, url_for, jsonify, session

from scapy.all import sniff, sendp, BOOTP, DHCP, Ether, IP, UDP, get_if_hwaddr
import config
import common
import policy
import settings_store
import web_auth
import router_ctl

os.makedirs(os.path.join(config.KROUTER_ROOT, 'logs'), exist_ok=True)
os.makedirs(os.path.join(config.KROUTER_ROOT, 'data'), exist_ok=True)

handler = RotatingFileHandler(config.log_filename, maxBytes=config.log_size, backupCount=config.log_rotate)
handler.setLevel(logging.DEBUG)
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
app_log = logging.getLogger('dhcp_app')
app_log.setLevel(logging.INFO)
app_log.addHandler(handler)
app_log.addHandler(logging.StreamHandler())

web_auth.ensure_admin_password(config.ADMIN_USER, config.ADMIN_PASSWORD)
settings_store.ensure_tables()
settings_store.apply_runtime()  # Settings IN/OUT/GW/DNS → config + env


def decode_hostname(raw):
    try:
        if isinstance(raw, bytes):
            return raw.decode('utf-8', errors='ignore')
        if isinstance(raw, str):
            return raw
    except Exception:
        pass
    return None


def validate_ip(ip):
    try:
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def lan_iface() -> str:
    """Settings Internal device (DHCP sniff / sendp)."""
    return settings_store.internal_device()


def _sched():
    return settings_store.policy_kwargs()


def apply_mac_policy(mac: str, mode: str, allow_until=None, study_until=None):
    kw = _sched()
    row = MEMDB.get_reservation(mac) or MEMDB.get_lease(mac) or {}
    if allow_until is None:
        allow_until = row.get('allow_until')
    if study_until is None:
        study_until = row.get('study_until')
    return router_ctl.apply_effective(
        mac, mode, allow_until, study_until=study_until, **kw)


class MemDB:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.leases_by_mac: dict[str, dict] = {}
        self.res_by_mac: dict[str, dict] = {}
        self.history_by_mac: dict[str, dict] = {}
        self.routers: list[dict] = []
        self.lock = threading.RLock()
        self._ensure_tables()
        self._load_all()

    def _ensure_tables(self):
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        with sqlite3.connect(self.db_path) as db:
            c = db.cursor()
            c.execute('''
              CREATE TABLE IF NOT EXISTS leases (
                  mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
                  lease_start INTEGER, lease_time INTEGER, last_seen INTEGER,
                  router TEXT, allow_until INTEGER
              )''')
            c.execute('''
              CREATE TABLE IF NOT EXISTS reservations (
                  mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
                  lease_time INTEGER, router TEXT, desc TEXT,
                  allow_until INTEGER
              )''')
            c.execute('''
              CREATE TABLE IF NOT EXISTS history (
                  mac TEXT PRIMARY KEY, ip TEXT, hostname TEXT,
                  last_seen INTEGER, router TEXT
              )''')
            c.execute('''
              CREATE TABLE IF NOT EXISTS routers (
                  ip TEXT PRIMARY KEY, desc TEXT
              )''')
            # 마이그레이션: allow_until / study_until
            for table in ('leases', 'reservations'):
                cols = [r[1] for r in c.execute(f'PRAGMA table_info({table})')]
                if 'allow_until' not in cols:
                    c.execute(f'ALTER TABLE {table} ADD COLUMN allow_until INTEGER')
                if 'study_until' not in cols:
                    c.execute(f'ALTER TABLE {table} ADD COLUMN study_until INTEGER')
            db.commit()
            row = c.execute('SELECT ip FROM routers WHERE ip=?', (config.GATEWAY,)).fetchone()
            if not row:
                c.execute('INSERT OR REPLACE INTO routers (ip, desc) VALUES (?, ?)',
                          (config.GATEWAY, 'default gateway'))
                db.commit()

    def _load_all(self):
        with self.lock, sqlite3.connect(self.db_path) as db:
            db.row_factory = sqlite3.Row
            self.leases_by_mac = {r['mac']: dict(r) for r in db.execute('SELECT * FROM leases')}
            self.res_by_mac = {r['mac']: dict(r) for r in db.execute('SELECT * FROM reservations')}
            self.history_by_mac = {r['mac']: dict(r) for r in db.execute('SELECT * FROM history')}
            self.routers = [dict(r) for r in db.execute('SELECT * FROM routers ORDER BY ip')]
        self._policy_mtime = self._trigger_mtime()
        app_log.info(f"[MEMDB] Loaded leases={len(self.leases_by_mac)} res={len(self.res_by_mac)}")

    def _trigger_mtime(self) -> float:
        try:
            return os.path.getmtime(config.trigger)
        except Exception:
            return 0.0

    def _touch_trigger(self):
        """Notify peer processes (DHCP/DNS) that sqlite policy data changed."""
        path = config.trigger
        try:
            os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
            with open(path, 'a'):
                pass
            os.utime(path, None)
            try:
                os.chmod(path, 0o666)
            except Exception:
                pass
        except Exception as e:
            app_log.warning(f"[MEMDB] trigger touch failed {path}: {e}")
        self._policy_mtime = self._trigger_mtime()

    def _db(self):
        db = sqlite3.connect(self.db_path, timeout=30)
        db.row_factory = sqlite3.Row
        return db

    def sync_reservations_from_disk(self) -> bool:
        """
        Read-only refresh of reservations into MemDB (other process wrote sqlite).
        Never writes sqlite from this path — avoids dual-writer clobber.
        """
        changed = False
        with self.lock, self._db() as db:
            disk_res = {r['mac']: dict(r) for r in db.execute('SELECT * FROM reservations')}
            if disk_res != self.res_by_mac:
                changed = True
            self.res_by_mac = disk_res
            for mac, d in disk_res.items():
                lr = self.leases_by_mac.get(mac)
                if not lr:
                    continue
                for k in ('router', 'allow_until', 'study_until', 'ip', 'hostname', 'lease_time'):
                    if lr.get(k) != d.get(k):
                        lr[k] = d.get(k)
                        changed = True
        self._policy_mtime = self._trigger_mtime()
        if changed:
            app_log.info(f"[MEMDB] synced reservations from disk res={len(self.res_by_mac)}")
        return changed

    def sync_leases_from_disk(self) -> bool:
        """Read-only refresh of leases (DHCP process is lease writer)."""
        changed = False
        with self.lock, self._db() as db:
            disk = {r['mac']: dict(r) for r in db.execute('SELECT * FROM leases')}
            if disk != self.leases_by_mac:
                changed = True
            self.leases_by_mac = disk
            disk_hist = {r['mac']: dict(r) for r in db.execute('SELECT * FROM history')}
            self.history_by_mac = disk_hist
        return changed

    def maybe_sync_reservations(self, force: bool = False) -> bool:
        if force or self._trigger_mtime() != getattr(self, '_policy_mtime', None):
            return self.sync_reservations_from_disk()
        return False

    # --- write-through APIs: always MemDB + sqlite together; no full-table rewrite ---

    def upsert_reservation(self, row: dict):
        mac = str(row['mac']).strip().lower()
        data = {
            'mac': mac,
            'ip': row.get('ip'),
            'hostname': row.get('hostname'),
            'lease_time': row.get('lease_time') or config.DEFAULT_LEASE,
            'router': row.get('router') or 'default',
            'desc': row.get('desc') or '',
            'allow_until': row.get('allow_until'),
            'study_until': row.get('study_until'),
        }
        with self.lock:
            self.res_by_mac[mac] = data
            if mac in self.leases_by_mac:
                lr = self.leases_by_mac[mac]
                lr['router'] = data['router']
                lr['allow_until'] = data['allow_until']
                lr['study_until'] = data['study_until']
                if data.get('ip'):
                    lr['ip'] = data['ip']
                if data.get('hostname'):
                    lr['hostname'] = data['hostname']
                if data.get('lease_time'):
                    lr['lease_time'] = data['lease_time']
            with self._db() as db:
                db.execute(
                    'INSERT OR REPLACE INTO reservations '
                    '(mac,ip,hostname,lease_time,router,desc,allow_until,study_until) '
                    'VALUES (?,?,?,?,?,?,?,?)',
                    (mac, data['ip'], data['hostname'], data['lease_time'],
                     data['router'], data['desc'], data['allow_until'], data['study_until']))
                if mac in self.leases_by_mac:
                    db.execute(
                        'UPDATE leases SET ip=?, hostname=?, lease_time=?, router=?, '
                        'allow_until=?, study_until=? WHERE mac=?',
                        (self.leases_by_mac[mac].get('ip'), self.leases_by_mac[mac].get('hostname'),
                         self.leases_by_mac[mac].get('lease_time'), data['router'],
                         data['allow_until'], data['study_until'], mac))
                db.commit()
        self._touch_trigger()
        return data

    def delete_reservation(self, mac: str):
        mac = mac.strip().lower()
        with self.lock:
            self.res_by_mac.pop(mac, None)
            with self._db() as db:
                db.execute('DELETE FROM reservations WHERE mac=?', (mac,))
                db.commit()
        self._touch_trigger()

    def upsert_lease(self, row: dict):
        """DHCP lease write-through. Policy fields follow reservation when present."""
        mac = str(row['mac']).strip().lower()
        with self.lock:
            res = self.res_by_mac.get(mac)
            data = dict(row)
            data['mac'] = mac
            if res:
                data['router'] = res.get('router') or data.get('router') or 'default'
                data['allow_until'] = res.get('allow_until')
                data['study_until'] = res.get('study_until')
                if res.get('ip'):
                    data['ip'] = res.get('ip')
                if res.get('hostname'):
                    data['hostname'] = res.get('hostname')
                if res.get('lease_time'):
                    data['lease_time'] = res.get('lease_time')
            self.leases_by_mac[mac] = data
            with self._db() as db:
                db.execute(
                    'INSERT OR REPLACE INTO leases '
                    '(mac,ip,hostname,lease_start,lease_time,last_seen,router,'
                    'allow_until,study_until) VALUES (?,?,?,?,?,?,?,?,?)',
                    (mac, data.get('ip'), data.get('hostname'), data.get('lease_start'),
                     data.get('lease_time'), data.get('last_seen'), data.get('router'),
                     data.get('allow_until'), data.get('study_until')))
                db.commit()
        return data

    def save_lease(self, mac, ip, hostname, lease_time=None, router=None, allow_until=None,
                   study_until=None):
        lease_time = lease_time or config.DEFAULT_LEASE
        router = router or settings_store.get('new_device_mode') or config.NEW_DEVICE_MODE
        now = int(time.time())
        with self.lock:
            prev = self.leases_by_mac.get(mac) or {}
            if allow_until is None:
                allow_until = prev.get('allow_until')
            if study_until is None:
                study_until = prev.get('study_until')
        return self.upsert_lease({
            'mac': mac, 'ip': ip, 'hostname': hostname,
            'lease_start': now, 'lease_time': lease_time,
            'last_seen': now, 'router': router,
            'allow_until': allow_until,
            'study_until': study_until,
        })

    def update_last_seen(self, mac):
        now = int(time.time())
        with self.lock:
            r = self.leases_by_mac.get(mac)
            if not r:
                return
            r['last_seen'] = now
            with self._db() as db:
                db.execute('UPDATE leases SET last_seen=? WHERE mac=?', (now, mac))
                db.commit()

    def del_lease_by_mac(self, mac):
        mac = mac.strip().lower()
        with self.lock:
            self.leases_by_mac.pop(mac, None)
            with self._db() as db:
                db.execute('DELETE FROM leases WHERE mac=?', (mac,))
                db.commit()

    def move_to_history(self, mac):
        mac = mac.strip().lower()
        with self.lock:
            r = self.leases_by_mac.get(mac)
            if not r:
                return
            hist = {
                'mac': mac, 'ip': r.get('ip'), 'hostname': r.get('hostname'),
                'last_seen': r.get('last_seen') or int(time.time()),
                'router': r.get('router'),
            }
            self.history_by_mac[mac] = hist
            self.leases_by_mac.pop(mac, None)
            with self._db() as db:
                db.execute(
                    'INSERT OR REPLACE INTO history (mac,ip,hostname,last_seen,router) VALUES (?,?,?,?,?)',
                    (mac, hist['ip'], hist['hostname'], hist['last_seen'], hist['router']))
                db.execute('DELETE FROM leases WHERE mac=?', (mac,))
                db.commit()

    def get_all_assigned_ips(self):
        with self.lock:
            ips = set()
            for r in self.leases_by_mac.values():
                if r.get('ip'):
                    ips.add(r['ip'])
            for r in self.res_by_mac.values():
                if r.get('ip'):
                    ips.add(r['ip'])
            return ips

    def list_routers(self):
        with self.lock:
            return list(self.routers)

    def add_router(self, ip, desc):
        with self.lock:
            found = False
            for r in self.routers:
                if r['ip'] == ip:
                    r['desc'] = desc
                    found = True
                    break
            if not found:
                self.routers.append({'ip': ip, 'desc': desc})
            with self._db() as db:
                db.execute('INSERT OR REPLACE INTO routers (ip, desc) VALUES (?, ?)', (ip, desc))
                db.commit()

    def del_router(self, ip):
        with self.lock:
            self.routers = [r for r in self.routers if r['ip'] != ip]
            with self._db() as db:
                db.execute('DELETE FROM routers WHERE ip=?', (ip,))
                db.commit()

    def get_reservation(self, mac):
        mac = (mac or '').strip().lower()
        with self.lock:
            return self.res_by_mac.get(mac)

    def get_lease(self, mac):
        mac = (mac or '').strip().lower()
        with self.lock:
            return self.leases_by_mac.get(mac)

    def device_row(self, mac):
        """reservation 우선, 없으면 lease. Always from MemDB."""
        mac = (mac or '').strip().lower()
        with self.lock:
            return self.res_by_mac.get(mac) or self.leases_by_mac.get(mac)

    def reservation_owner_of_ip(self, ip: str):
        """Return MAC that has this IP reserved, or None."""
        if not ip:
            return None
        with self.lock:
            for m, r in self.res_by_mac.items():
                if r.get('ip') == ip:
                    return m
        return None

    def set_allow_until(self, mac, until_ts):
        """Write-through Free time (allow_until → ALL_ALLOW)."""
        mac = mac.strip().lower()
        with self.lock:
            if mac in self.res_by_mac:
                self.res_by_mac[mac]['allow_until'] = until_ts
            if mac in self.leases_by_mac:
                self.leases_by_mac[mac]['allow_until'] = until_ts
            with self._db() as db:
                if mac in self.res_by_mac:
                    db.execute('UPDATE reservations SET allow_until=? WHERE mac=?', (until_ts, mac))
                if mac in self.leases_by_mac:
                    db.execute('UPDATE leases SET allow_until=? WHERE mac=?', (until_ts, mac))
                db.commit()
        self._touch_trigger()

    def set_study_until(self, mac, until_ts):
        """Write-through Extend study (study_until → STUDY outside schedule)."""
        mac = mac.strip().lower()
        with self.lock:
            if mac in self.res_by_mac:
                self.res_by_mac[mac]['study_until'] = until_ts
            if mac in self.leases_by_mac:
                self.leases_by_mac[mac]['study_until'] = until_ts
            with self._db() as db:
                if mac in self.res_by_mac:
                    db.execute('UPDATE reservations SET study_until=? WHERE mac=?', (until_ts, mac))
                if mac in self.leases_by_mac:
                    db.execute('UPDATE leases SET study_until=? WHERE mac=?', (until_ts, mac))
                db.commit()
        self._touch_trigger()

    @staticmethod
    def _ts_expired(ts, now: int) -> bool:
        """True if grant timestamp is set and already past (one-shot instance gone)."""
        if ts is None or ts == '':
            return False
        try:
            return int(ts) <= now
        except (TypeError, ValueError):
            return True  # garbage → clear

    def clear_expired_allows(self):
        """
        Free time / Extend study are one-shot: when the instant ends, wipe the
        column to NULL (do not leave a stale 'until' that looks like a schedule).
        """
        now = int(time.time())
        changed = []
        with self.lock:
            macs = set(self.res_by_mac) | set(self.leases_by_mac)
        for mac in macs:
            with self.lock:
                r = self.res_by_mac.get(mac) or self.leases_by_mac.get(mac) or {}
                au = r.get('allow_until')
                su = r.get('study_until')
            if self._ts_expired(au, now):
                self.set_allow_until(mac, None)
                app_log.info(f"[GRANT-EXPIRE] {mac} clear allow_until (was {au})")
                changed.append(mac)
            if self._ts_expired(su, now):
                self.set_study_until(mac, None)
                app_log.info(f"[GRANT-EXPIRE] {mac} clear study_until (was {su})")
                if mac not in changed:
                    changed.append(mac)
        return changed

    # Back-compat names used by older call sites / peer sync
    def pull_admin_writes(self) -> bool:
        return self.sync_reservations_from_disk()

    def maybe_pull_admin(self, force: bool = False) -> bool:
        return self.maybe_sync_reservations(force=force)

    def flush_all(self):
        """Deprecated no-op: writes are write-through. Kept so old callers do not wipe DB."""
        app_log.warning("[MEMDB] flush_all() is a no-op — use upsert_*/set_allow_until write-through")


MEMDB = MemDB(config.dhcp_db_file)


def get_offer_info(mac, opts):
    mac = (mac or '').strip().lower()
    MEMDB.maybe_pull_admin()
    reservation = MEMDB.get_reservation(mac)
    if reservation:
        # Reservation always wins — even if MemDB lease still has an old IP (.152 etc).
        return (reservation.get('ip'),
                reservation.get('hostname'),
                reservation.get('router') or 'default',
                reservation.get('lease_time') or config.DEFAULT_LEASE,
                'RES',
                reservation.get('allow_until'))
    lease = MEMDB.get_lease(mac)
    if lease:
        lip = lease.get('ip')
        owner = MEMDB.reservation_owner_of_ip(lip)
        if owner and owner != mac:
            # Stale lease on an IP reserved for someone else — drop and reassign.
            app_log.info(f"[DHCP] drop lease {mac} {lip}: reserved for {owner}")
            MEMDB.del_lease_by_mac(mac)
        else:
            now = int(time.time())
            if int(lease.get('last_seen', 0)) + int(lease.get('lease_time', 0)) >= now:
                MEMDB.update_last_seen(mac)
                return (lease.get('ip'), lease.get('hostname'),
                        lease.get('router') or 'default',
                        lease.get('lease_time') or config.DEFAULT_LEASE,
                        'LEA', lease.get('allow_until'))
            MEMDB.del_lease_by_mac(mac)
            return (lease.get('ip'), lease.get('hostname'),
                    lease.get('router') or 'default',
                    lease.get('lease_time') or config.DEFAULT_LEASE,
                    'NEW', None)
    assigned = MEMDB.get_all_assigned_ips()
    ip = common.find_free_ip(assigned, log=app_log)
    if not ip:
        return (False, None, None, None, 'NEW', None)
    hostname = decode_hostname(opts.get('hostname')) or f"host-{ip.split('.')[-1]}"
    new_mode = settings_store.get('new_device_mode') or config.NEW_DEVICE_MODE
    return (ip, hostname, new_mode, config.DEFAULT_LEASE, 'NEW', None)


def handle_dhcp(pkt):
    try:
        if not (pkt.haslayer(Ether) and pkt.haslayer(IP) and pkt.haslayer(UDP)
                and pkt.haslayer(BOOTP) and pkt.haslayer(DHCP)):
            return
        bootp = pkt[BOOTP]
        dhcp = pkt[DHCP]
        if not dhcp.options:
            return
        mac = (pkt[Ether].src or '').lower()
        xid = bootp.xid
        opts = {}
        for opt in dhcp.options:
            if opt == 'end':
                break
            if isinstance(opt, tuple) and len(opt) == 2:
                opts[opt[0]] = opt[1]
        raw_mt = opts.get('message-type')
        # scapy may give int (1/3/6) or name ('discover'/'request'/…)
        _mt_map = {1: 1, 2: 2, 3: 3, 6: 6,
                   'discover': 1, 'offer': 2, 'request': 3, 'nak': 6, 'release': 7}
        msg_type = _mt_map.get(raw_mt, raw_mt)
        if msg_type not in (1, 3) or xid == 0:
            return
        gw = settings_store.get('gateway') or config.GATEWAY
        dns = settings_store.get('dns_servers') or config.DNS_SERVERS

        iface = lan_iface()
        if msg_type == 1:
            offered_ip, hostname, router_field, lease_time, info, allow_until = get_offer_info(mac, opts)
            if not offered_ip:
                sendp(common.make_dhcp_nak(xid, pkt[BOOTP].chaddr, iface=iface),
                      iface=iface, verbose=False)
                return
            # Keep lease row in sync for RES/LEA/NEW (policy + Admin UI)
            MEMDB.save_lease(mac, offered_ip, hostname, lease_time, router_field, allow_until)
            apply_mac_policy(mac, router_field, allow_until)
            offer = common.make_dhcp_offer(
                offered_ip, xid, pkt[BOOTP].chaddr, dns,
                policy.pick_offer_gateway(router_field, gw), lease_time,
                hostname=hostname, iface=iface)
            sendp(offer, iface=iface, verbose=False)
            smac, sip = common.dhcp_server_identity(iface)
            app_log.info(
                f"[DHCPOFFER] {mac} {offered_ip} mode={router_field} ({info}) "
                f"via {iface} src={smac}/{sip}")

        elif msg_type == 3:
            req_ip = opts.get('requested_addr')
            if isinstance(req_ip, bytes):
                try:
                    req_ip = '.'.join(str(b) for b in req_ip)
                except Exception:
                    req_ip = None
            # Renew path: some clients put current IP in ciaddr and omit requested_addr
            if not req_ip and getattr(bootp, 'ciaddr', None) and bootp.ciaddr != '0.0.0.0':
                req_ip = str(bootp.ciaddr)
            offered_ip, hostname, router_field, lease_time, info, allow_until = get_offer_info(mac, opts)
            if not offered_ip:
                sendp(common.make_dhcp_nak(xid, pkt[BOOTP].chaddr, iface=iface),
                      iface=iface, verbose=False)
                app_log.info(f"[DHCPNAK] {mac} no offer available")
                return
            # Client asking for wrong IP (e.g. old .152 while reserved .145) → NAK so it rediscovers.
            if req_ip and str(req_ip) != str(offered_ip):
                app_log.info(
                    f"[DHCPNAK] {mac} requested {req_ip} but must use {offered_ip} ({info})")
                sendp(common.make_dhcp_nak(xid, pkt[BOOTP].chaddr, iface=iface),
                      iface=iface, verbose=False)
                return
            if req_ip and not common.ip_in_network(req_ip):
                sendp(common.make_dhcp_nak(xid, pkt[BOOTP].chaddr, iface=iface),
                      iface=iface, verbose=False)
                return
            ack_ip = str(offered_ip)
            MEMDB.save_lease(mac, ack_ip, hostname, lease_time, router_field, allow_until)
            apply_mac_policy(mac, router_field, allow_until)
            ack = common.make_dhcp_ack(
                ack_ip, xid, pkt[BOOTP].chaddr, dns,
                policy.pick_offer_gateway(router_field, gw), lease_time,
                hostname=hostname, iface=iface)
            sendp(ack, iface=iface, verbose=False)
            app_log.info(f"[DHCPACK] {mac} {ack_ip} mode={router_field} ({info})")
    except Exception as e:
        app_log.error(f"[ERROR] DHCP handler: {e}", exc_info=True)

def periodic_cleanup():
    while True:
        try:
            now = int(time.time())
            with MEMDB.lock:
                for mac, r in list(MEMDB.leases_by_mac.items()):
                    lease_end = int(r.get('lease_start', 0)) + int(r.get('lease_time', 0))
                    if lease_end < now:
                        if not config.SAFE_MODE and common.is_ip_alive(r.get('ip')):
                            MEMDB.update_last_seen(mac)
                        else:
                            MEMDB.move_to_history(mac)
        except Exception as e:
            app_log.error(f"[CLEANUP] {e}")
        time.sleep(60)


def allow_expiry_watcher():
    """
    Sync Admin writes, expire allows, re-apply iptables only when effective chain changes.
    Do NOT re-apply every study device every 30s — that raced and stomped ALL_ALLOW grants.
    """
    prev_eff: dict[str, str] = {}
    while True:
        try:
            MEMDB.sync_reservations_from_disk()
            expired = MEMDB.clear_expired_allows()
            kw = settings_store.policy_kwargs()
            with MEMDB.lock:
                items = list(MEMDB.res_by_mac.items())
                for mac, r in MEMDB.leases_by_mac.items():
                    if mac not in MEMDB.res_by_mac:
                        items.append((mac, r))
            for mac, r in items:
                mode = r.get('router') or 'default'
                au = r.get('allow_until')
                su = r.get('study_until')
                eff = policy.effective_mode(mode, au, study_until=su, **kw)
                if prev_eff.get(mac) == eff and mac not in expired:
                    continue
                got, ok, msg = apply_mac_policy(mac, mode, au, su)
                app_log.info(
                    f"[POLICY] {mac} mode={policy.normalize_mode(mode)} -> {got} "
                    f"ok={ok}{' (expire)' if mac in expired else ''}")
                prev_eff[mac] = got
        except Exception as e:
            app_log.error(f"[ALLOW-WATCH] {e}")
        time.sleep(15)


def run_dhcp():
    rt = settings_store.apply_runtime()
    iface = lan_iface()  # Settings Internal (IN) only
    auto_s, auto_e = settings_store.dhcp_auto_range()
    smac, sip = rt.get('SERVER_MAC'), rt.get('SERVER_IP')
    app_log.info(
        f"[INFO] DHCP sniff on IN={iface} OUT={rt.get('OUT')} "
        f"server={sip} mac={smac} auto_pool={auto_s}-{auto_e}")
    if not iface:
        app_log.error("[ERROR] Settings internal_device (IN) empty — cannot sniff")
        return
    if not smac or smac == '00:00:00:00:00:00':
        app_log.error(
            "[ERROR] SERVER_MAC is 00:00:00:00:00:00 on IN=%s — clients will ignore OFFER",
            iface)
    sniff(filter="udp and (port 67 or 68)", iface=iface, prn=handle_dhcp)


# ===============================
# Flask UI
# ===============================
app = Flask(__name__)
app.secret_key = config.SECRET_KEY

MENU = '''
<div style="margin:8px 0">
  [<a href="/">Devices</a>]
  [<a href="/dhcp_leases">Leases</a>]
  [<a href="/settings">Settings</a>]
  [<a href="/dhcp_history">History</a>]
  [<a href="/logout">Logout</a>]
  <span style="color:#888;margin-left:12px">SAFE_MODE={{ safe }}</span>
</div>
'''

TPL_LOGIN = '''
<!doctype html><title>Login</title>
<h2>krouter Admin Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  User: <input name="username" required autofocus>
  Password: <input name="password" type="password" required>
  <button type="submit">Login</button>
</form>
<p style="color:#888;font-size:12px">기본 계정: admin / admin (Settings 에서 변경)</p>
'''

TPL_MAIN = '''
<!doctype html><title>DHCP Admin</title>
''' + MENU + '''
<hr>
<h2>Add Reservation</h2>
<form action="{{ url_for('add_reservation') }}" method="post">
  MAC <input name="mac" required>
  IP <input name="ip" required>
  Hostname <input name="hostname" required>
  Lease <input name="lease_time" value="86400" size="7">
  Mode
  <select name="router">
    <option value="default">default (약차단)</option>
    <option value="all_allow">all_allow (무제한)</option>
    <option value="study">study</option>
  </select>
  Desc <input name="desc" size="40">
  <button type="submit">Add</button>
</form>
<h2>Reservations</h2>
<table border="1" cellpadding="4">
<tr><th>#</th><th>MAC</th><th>Host</th><th>IP</th><th>Mode</th><th>Effective</th><th>Allow until</th><th>Desc</th><th>Action</th></tr>
{% for r in reservations %}
<tr>
  <td>{{ loop.index }}</td>
  <td>{{ r.mac }}</td><td>{{ r.hostname }}</td><td>{{ r.ip }}</td>
  <td>{{ r.mode }}</td><td><b>{{ r.effective }}</b></td>
  <td>{{ r.allow_until_fmt }}</td>
  <td>{{ r.desc or '' }}</td>
  <td><a href="{{ url_for('edit_reservation', mac=r.mac) }}">Edit</a></td>
</tr>
{% endfor %}
</table>
'''

TPL_EDIT = '''
<!doctype html><title>Edit</title>
''' + MENU + '''
<hr>
<h2>Edit {{ reservation.mac }}</h2>
<p>Effective now: <b>{{ effective }}</b></p>
<form method="post">
  IP <input name="ip" value="{{ reservation.ip }}" required><br>
  Hostname <input name="hostname" value="{{ reservation.hostname }}" required><br>
  Lease <input name="lease_time" value="{{ reservation.lease_time or 86400 }}"><br>
  Mode
  <select name="router">
    <option value="default" {% if mode=='default' %}selected{% endif %}>default</option>
    <option value="all_allow" {% if mode=='all_allow' %}selected{% endif %}>all_allow</option>
    <option value="study" {% if mode=='study' %}selected{% endif %}>study</option>
  </select><br>
  Desc <input name="desc" value="{{ reservation.desc or '' }}" size="60"><br>
  <button type="submit">Update</button>
</form>
{% if mode=='study' %}
<hr>
<h3>1. Extend study</h3>
<p>STUDY kept (blocks stay). Study until: {{ reservation.study_until_fmt or '—' }}</p>
<form action="{{ url_for('grant_study', mac=reservation.mac) }}" method="post">
  <button name="kind" value="30m">+30m</button>
  <button name="kind" value="1h">+1h</button>
  <button name="kind" value="4h">+4h</button>
  <button name="kind" value="1d">until midnight</button>
</form>
<form action="{{ url_for('clear_study', mac=reservation.mac) }}" method="post" style="margin-top:8px">
  <button type="submit">Clear study extend</button>
</form>
<hr>
<h3>2. Free time (all_allow)</h3>
<p>Free until: {{ reservation.allow_until_fmt or '—' }}</p>
<form action="{{ url_for('grant_allow', mac=reservation.mac) }}" method="post">
  <button name="kind" value="30m">+30m</button>
  <button name="kind" value="1h">+1h</button>
  <button name="kind" value="4h">+4h</button>
  <button name="kind" value="1d">until midnight</button>
</form>
<form action="{{ url_for('clear_allow', mac=reservation.mac) }}" method="post" style="margin-top:8px">
  <button type="submit">Clear free time</button>
</form>
{% endif %}
<p><a href="{{ url_for('delete_reservation_route', mac=reservation.mac) }}">Delete reservation</a></p>
'''

TPL_SETTINGS = '''
<!doctype html><title>Settings</title>
''' + MENU + '''
<hr>
<h2>Settings</h2>
<form method="post">
  <h3>Default schedule (local)</h3>
  Start <input name="default_schedule_start" value="{{ s.default_schedule_start }}">
  End <input name="default_schedule_end" value="{{ s.default_schedule_end }}">
  <h3>Study schedule (local)</h3>
  Start <input name="study_schedule_start" value="{{ s.study_schedule_start }}">
  End <input name="study_schedule_end" value="{{ s.study_schedule_end }}">
  <h3>New device mode</h3>
  <select name="new_device_mode">
    <option value="default" {% if s.new_device_mode=='default' %}selected{% endif %}>default</option>
    <option value="all_allow" {% if s.new_device_mode=='all_allow' %}selected{% endif %}>all_allow</option>
    <option value="study" {% if s.new_device_mode=='study' %}selected{% endif %}>study</option>
  </select>
  <h3>DNS</h3>
  Upstream <input name="upstream_dns" value="{{ s.upstream_dns }}">
  Local only <input type="checkbox" name="dns_local_only" {% if s.dns_local_only %}checked{% endif %}>
  <h3>Gateway / DNS servers pushed by DHCP</h3>
  Gateway <input name="gateway" value="{{ s.gateway }}">
  DNS servers <input name="dns_servers" value="{{ s.dns_servers }}">
  <h3>Default block domains (comma)</h3>
  <textarea name="default_block_domains" rows="3" cols="60">{{ default_domains }}</textarea>
  <h3>Study block domains (comma)</h3>
  <textarea name="study_block_domains" rows="3" cols="60">{{ study_domains }}</textarea>
  <h3>Login account</h3>
  Current user: <b>{{ s.admin_user }}</b><br>
  New username <input name="admin_user" value="{{ s.admin_user }}" required><br>
  New password <input name="new_password" type="password" placeholder="(leave blank to keep password)">
  Confirm password <input name="new_password2" type="password" placeholder="(same as above)">
  <br><br><button type="submit">Save</button>
</form>
'''

TPL_LEASES = '''
<!doctype html><title>Leases</title>
''' + MENU + '''
<hr><table border="1" cellpadding="4">
<tr><th>MAC</th><th>IP</th><th>Host</th><th>Mode</th><th>Effective</th><th>Last seen</th></tr>
{% for l in leases %}
<tr>
  <td>{{ l.mac }}</td><td>{{ l.ip }}</td><td>{{ l.hostname }}</td>
  <td>{{ l.mode }}</td><td>{{ l.effective }}</td><td>{{ l.last_seen }}</td>
</tr>
{% endfor %}
</table>
'''

TPL_HISTORY = '''
<!doctype html><title>History</title>
''' + MENU + '''
<hr><table border="1" cellpadding="4">
<tr><th>MAC</th><th>IP</th><th>Host</th><th>Mode</th><th>Last seen</th></tr>
{% for h in histories %}
<tr><td>{{ h.mac }}</td><td>{{ h.ip }}</td><td>{{ h.hostname }}</td><td>{{ h.router }}</td><td>{{ h.last_seen }}</td></tr>
{% endfor %}
</table>
'''


def _fmt_ts(ts):
    if not ts:
        return ''
    try:
        return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(int(ts)))
    except Exception:
        return str(ts)


def _enrich(row):
    """UI row: drop expired one-shot grants from display; persist clear if still set."""
    gw = settings_store.get('gateway') or config.GATEWAY
    mode = policy.normalize_mode(row.get('router'), gw)
    au = row.get('allow_until')
    su = row.get('study_until')
    now = int(time.time())
    mac = (row.get('mac') or '').strip().lower()
    if mac and MemDB._ts_expired(au, now):
        MEMDB.set_allow_until(mac, None)
        au = None
        row = {**row, 'allow_until': None}
    if mac and MemDB._ts_expired(su, now):
        MEMDB.set_study_until(mac, None)
        su = None
        row = {**row, 'study_until': None}
    kw = _sched()
    eff = policy.effective_mode(
        row.get('router') or mode, au,
        gateway=gw, study_until=su, **kw)
    return {
        **row, 'mode': mode, 'effective': eff,
        'allow_until_fmt': _fmt_ts(au),
        'study_until_fmt': _fmt_ts(su),
    }


@app.route('/login', methods=['GET', 'POST'])
def login():
    err = None
    if request.method == 'POST':
        if web_auth.check_login(request.form.get('username', ''), request.form.get('password', '')):
            web_auth.login_user(request.form['username'])
            return redirect(request.args.get('next') or url_for('index_list'))
        err = 'Invalid credentials'
    return render_template_string(TPL_LOGIN, error=err)


@app.route('/logout')
def logout():
    web_auth.logout_user()
    return redirect(url_for('login'))


@app.route('/')
@app.route('/index/<sort>')
@web_auth.login_required
def index_list(sort='mac'):
    with MEMDB.lock:
        reservations = [_enrich(r) for r in MEMDB.res_by_mac.values()]
    if sort in ('mac', 'hostname', 'ip'):
        reservations.sort(key=lambda r: (r.get(sort) or ''))
    return render_template_string(TPL_MAIN, reservations=reservations, safe=config.SAFE_MODE)


@app.route('/add_reservation', methods=['POST'])
@web_auth.login_required
def add_reservation():
    mac = request.form['mac'].strip().lower()
    ip = request.form['ip'].strip()
    hostname = request.form['hostname'].strip()
    lease_time = int(request.form.get('lease_time') or config.DEFAULT_LEASE)
    router = policy.normalize_mode(request.form.get('router', 'default'))
    if not validate_ip(ip) or not common.ip_in_network(ip):
        return "<script>alert('Invalid IP');history.back();</script>"
    with MEMDB.lock:
        if mac in MEMDB.res_by_mac:
            return f"<script>alert('Duplicate MAC');history.back();</script>"
    MEMDB.upsert_reservation({
        'mac': mac, 'ip': ip, 'hostname': hostname,
        'lease_time': lease_time, 'router': router,
        'desc': request.form.get('desc', '').strip(),
        'allow_until': None,
    })
    apply_mac_policy(mac, router, None)
    return redirect(url_for('index_list'))


@app.route('/edit_reservation/<mac>', methods=['GET', 'POST'])
@web_auth.login_required
def edit_reservation(mac):
    mac = mac.strip().lower()
    if request.method == 'POST':
        ip = request.form['ip'].strip()
        hostname = request.form['hostname'].strip()
        lease_time = int(request.form.get('lease_time') or config.DEFAULT_LEASE)
        router = policy.normalize_mode(request.form.get('router', 'default'))
        desc = request.form.get('desc', '').strip()
        if not validate_ip(ip) or not common.ip_in_network(ip):
            return "<script>alert('Invalid IP');history.back();</script>"
        with MEMDB.lock:
            prev = MEMDB.res_by_mac.get(mac) or {}
            au = prev.get('allow_until') if router == 'study' else None
        MEMDB.upsert_reservation({
            'mac': mac, 'ip': ip, 'hostname': hostname,
            'lease_time': lease_time, 'router': router, 'desc': desc,
            'allow_until': au,
        })
        apply_mac_policy(mac, router, au)
        return redirect(url_for('index_list'))
    with MEMDB.lock:
        r = MEMDB.res_by_mac.get(mac) or MEMDB.leases_by_mac.get(mac)
        if not r:
            return "<script>alert('not found');history.back();</script>"
        # lease only → promote shell for edit
        if mac not in MEMDB.res_by_mac:
            r = MEMDB.upsert_reservation({
                'mac': mac, 'ip': r.get('ip'), 'hostname': r.get('hostname'),
                'lease_time': r.get('lease_time') or config.DEFAULT_LEASE,
                'router': r.get('router') or 'default',
                'desc': '', 'allow_until': r.get('allow_until'),
            })
    en = _enrich(r)
    return render_template_string(
        TPL_EDIT, reservation=en, mode=en['mode'], effective=en['effective'], safe=config.SAFE_MODE)


@app.route('/grant_study/<mac>', methods=['POST'])
@web_auth.login_required
def grant_study(mac):
    mac = mac.strip().lower()
    kind = request.form.get('kind', '30m')
    row = MEMDB.device_row(mac)
    if not row or policy.normalize_mode(row.get('router')) != 'study':
        return "<script>alert('study device only');history.back();</script>"
    until = policy.compute_study_until(kind)
    MEMDB.set_study_until(mac, until)
    apply_mac_policy(mac, 'study', study_until=until)
    app_log.info(f"[STUDY-EXTEND] {mac} kind={kind} until={until}")
    return redirect(url_for('edit_reservation', mac=mac))


@app.route('/clear_study/<mac>', methods=['POST'])
@web_auth.login_required
def clear_study(mac):
    mac = mac.strip().lower()
    MEMDB.set_study_until(mac, None)
    apply_mac_policy(mac, 'study', study_until=None)
    return redirect(url_for('edit_reservation', mac=mac))


@app.route('/grant_allow/<mac>', methods=['POST'])
@web_auth.login_required
def grant_allow(mac):
    mac = mac.strip().lower()
    kind = request.form.get('kind', '30m')
    row = MEMDB.device_row(mac)
    if not row or policy.normalize_mode(row.get('router')) != 'study':
        return "<script>alert('study device only');history.back();</script>"
    until = policy.compute_allow_until(kind)
    MEMDB.set_allow_until(mac, until)
    apply_mac_policy(mac, 'study', allow_until=until)
    app_log.info(f"[ALLOW-GRANT] {mac} kind={kind} until={until}")
    return redirect(url_for('edit_reservation', mac=mac))


@app.route('/clear_allow/<mac>', methods=['POST'])
@web_auth.login_required
def clear_allow(mac):
    mac = mac.strip().lower()
    MEMDB.set_allow_until(mac, None)
    apply_mac_policy(mac, 'study', allow_until=None)
    return redirect(url_for('edit_reservation', mac=mac))


@app.route('/delete_reservation/<mac>')
@web_auth.login_required
def delete_reservation_route(mac):
    MEMDB.delete_reservation(mac.strip().lower())
    return redirect(url_for('index_list'))


@app.route('/settings', methods=['GET', 'POST'])
@web_auth.login_required
def settings_page():
    if request.method == 'POST':
        def domains(s):
            return [x.strip().lower() for x in s.replace('\n', ',').split(',') if x.strip()]
        new_user = (request.form.get('admin_user') or '').strip()
        npw = request.form.get('new_password', '')
        npw2 = request.form.get('new_password2', '')
        if not new_user:
            return "<script>alert('username required');history.back();</script>"
        if npw or npw2:
            if npw != npw2:
                return "<script>alert('password confirm mismatch');history.back();</script>"
            if len(npw) < 4:
                return "<script>alert('password too short (min 4)');history.back();</script>"
        settings_store.set_many({
            'default_schedule_start': request.form.get('default_schedule_start', '00:00').strip(),
            'default_schedule_end': request.form.get('default_schedule_end', '00:00').strip(),
            'study_schedule_start': request.form.get('study_schedule_start', '06:00').strip(),
            'study_schedule_end': request.form.get('study_schedule_end', '22:00').strip(),
            'new_device_mode': policy.normalize_mode(request.form.get('new_device_mode', 'default')),
            'upstream_dns': request.form.get('upstream_dns', '8.8.8.8').strip(),
            'dns_local_only': bool(request.form.get('dns_local_only')),
            'gateway': request.form.get('gateway', config.GATEWAY).strip(),
            'dns_servers': request.form.get('dns_servers', config.DNS_SERVERS).strip(),
            'default_block_domains': domains(request.form.get('default_block_domains', '')),
            'study_block_domains': domains(request.form.get('study_block_domains', '')),
            'admin_user': new_user,
        })
        if npw:
            settings_store.set_value('admin_password_hash', web_auth.hash_password(npw))
        return redirect(url_for('settings_page'))
    s = settings_store.get_all()
    return render_template_string(
        TPL_SETTINGS, s=s, safe=config.SAFE_MODE,
        default_domains=', '.join(s.get('default_block_domains') or []),
        study_domains=', '.join(s.get('study_block_domains') or []))


@app.route('/dhcp_leases')
@web_auth.login_required
def dhcp_leases():
    with MEMDB.lock:
        leases = [_enrich(r) for r in MEMDB.leases_by_mac.values()]
    return render_template_string(TPL_LEASES, leases=leases, safe=config.SAFE_MODE)


@app.route('/dhcp_history')
@web_auth.login_required
def dhcp_history():
    with MEMDB.lock:
        histories = list(MEMDB.history_by_mac.values())
    return render_template_string(TPL_HISTORY, histories=histories, safe=config.SAFE_MODE)


@app.route('/api/policy/<mac>')
@web_auth.login_required
def api_policy(mac):
    row = MEMDB.device_row(mac.strip().lower())
    if not row:
        return jsonify({'error': 'not found'}), 404
    en = _enrich(row)
    return jsonify({
        'mac': mac, 'mode': en['mode'], 'effective': en['effective'],
        'allow_until': en.get('allow_until'), 'safe_mode': config.SAFE_MODE,
    })


def reapply_all_policies():
    with MEMDB.lock:
        items = list(MEMDB.res_by_mac.items())
        for mac, r in MEMDB.leases_by_mac.items():
            if mac not in MEMDB.res_by_mac:
                items.append((mac, r))
    for mac, r in items:
        apply_mac_policy(mac, r.get('router') or 'default', r.get('allow_until'))


def main():
    """DHCP 서비스 전용. 웹 UI 는 admin_app.py 사용."""
    app_log.info(
        f"[INFO] DHCP service SAFE_MODE={config.SAFE_MODE} db={config.dhcp_db_file} "
        f"(UI → admin_app.py :{getattr(config, 'interface_admin_port', 15000)})")
    # no periodic full-DB flush — MemDB changes are write-through to sqlite
    threading.Thread(target=allow_expiry_watcher, daemon=True).start()
    threading.Thread(target=periodic_cleanup, daemon=True).start()
    if config.SAFE_MODE:
        app_log.warning("[SAFE_MODE] DHCP sniff DISABLED — idle service (use admin_app for UI)")
        while True:
            time.sleep(3600)
    else:
        reapply_all_policies()
        run_dhcp()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        app_log.info("[INFO] Stopped.")
