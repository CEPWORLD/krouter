#!/usr/bin/env python3
# dns_app.py — DNS service (policy-aware). SAFE_MODE skips :53 bind.
#
# Author : Kage
# Project: krouter
# Thought: DNS is where study/default blocking feels immediate — fake A answers
#          for blocked names, quiet success path (log BLOCK/FAIL, not every hit).
#
"""DNS Server + effective policy (login UI mostly via admin_app)."""
import os
import time
import threading
import sqlite3
import socket
import logging
from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler
from dnslib import DNSRecord, RR, QTYPE, A, RCODE
from flask import Flask, request, redirect, render_template_string, url_for, jsonify
import concurrent.futures

import config
import common
import policy
import settings_store
import web_auth

# Upstream / flood protection — one noisy client must not stall house DNS.
UPSTREAM_TIMEOUT_SEC = float(getattr(config, 'dns_upstream_timeout', 1.0))
THROTTLE_WINDOW_SEC = 15.0
THROTTLE_FAIL_LIMIT = 20          # FAILs in window → quarantine
THROTTLE_QUERY_LIMIT = 80         # queries in window → quarantine
QUARANTINE_SEC = 300              # 5 minutes
DNS_MAX_INFLIGHT = 40             # recv fail-fast when saturated

os.makedirs(os.path.join(config.KROUTER_ROOT, 'logs'), exist_ok=True)
os.makedirs(os.path.join(config.KROUTER_ROOT, 'data'), exist_ok=True)

BYPASS_FILE = os.path.join(config.KROUTER_ROOT, 'data', 'dns_bypass')

handler = RotatingFileHandler(config.log_dns_server, maxBytes=config.log_size, backupCount=config.log_rotate)
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
app_log = logging.getLogger('dns_app')
app_log.setLevel(logging.INFO)
if not app_log.handlers:
    app_log.addHandler(handler)
    app_log.addHandler(logging.StreamHandler())

web_auth.ensure_admin_password(config.ADMIN_USER, config.ADMIN_PASSWORD)
settings_store.ensure_tables()
settings_store.apply_runtime()  # Settings IN/OUT/GW/DNS → config + env

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
app.jinja_env.filters['human_time'] = common.seconds_to_human
app.jinja_env.filters['format_date'] = common.seconds_to_date


def ensure_dns_tables():
    with sqlite3.connect(config.dns_db_file) as db:
        db.execute('''CREATE TABLE IF NOT EXISTS dns_mappings (
            ip TEXT, domain TEXT, PRIMARY KEY (ip, domain))''')
        db.execute('''CREATE TABLE IF NOT EXISTS block_rules (
            domain TEXT PRIMARY KEY, enabled INTEGER DEFAULT 1,
            block_all_sub INTEGER DEFAULT 1, note TEXT)''')
        db.commit()


ensure_dns_tables()


def _match_domain(qname: str, domains, all_sub: bool) -> bool:
    q = (qname or '').rstrip('.').lower()
    for dom in domains or []:
        d = str(dom).lower().strip()
        if not d:
            continue
        if all_sub and (q == d or q.endswith('.' + d)):
            return True
        if not all_sub and q == d:
            return True
    return False


class ClientThrottle:
    """
    Per-client flood guard. A laptop dumping ads/trackers (or WAN blip + retries)
    used to fill all DNS workers with 5s upstream waits and make Deco APs go red.
    Quarantine that IP only for QUARANTINE_SEC — rest of the house stays up.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._fails: dict[str, deque] = defaultdict(deque)
        self._queries: dict[str, deque] = defaultdict(deque)
        self._until: dict[str, float] = {}
        self._last_log: dict[str, float] = {}

    def _prune(self, dq: deque, now: float) -> None:
        cut = now - THROTTLE_WINDOW_SEC
        while dq and dq[0] < cut:
            dq.popleft()

    def is_quarantined(self, ip: str) -> bool:
        now = time.time()
        with self._lock:
            until = self._until.get(ip)
            if until is None:
                return False
            if now < until:
                return True
            self._until.pop(ip, None)
            self._fails.pop(ip, None)
            self._queries.pop(ip, None)
            return False

    def remaining_sec(self, ip: str) -> int:
        with self._lock:
            until = self._until.get(ip)
        if not until:
            return 0
        return max(0, int(until - time.time()))

    def should_log_quiet(self, ip: str, every_sec: float = 30.0) -> bool:
        """True at most once per every_sec while quarantined (avoid QUIET spam)."""
        now = time.time()
        with self._lock:
            last = self._last_log.get(ip, 0.0)
            if now - last < every_sec:
                return False
            self._last_log[ip] = now
            return True

    def _enter(self, ip: str, reason: str, now: float) -> bool:
        """Return True if newly quarantined (for one-shot log)."""
        prev = self._until.get(ip)
        if prev and prev > now:
            return False
        self._until[ip] = now + QUARANTINE_SEC
        self._fails[ip].clear()
        self._queries[ip].clear()
        self._last_log[ip] = now
        app_log.info(
            f"[QUARANTINE] {ip} {reason} — mute upstream {QUARANTINE_SEC}s "
            f"(window={THROTTLE_WINDOW_SEC}s fail>={THROTTLE_FAIL_LIMIT} "
            f"q>={THROTTLE_QUERY_LIMIT})")
        return True

    def note_query(self, ip: str) -> bool:
        """Record a query. Returns True if client is (now) quarantined."""
        now = time.time()
        with self._lock:
            until = self._until.get(ip)
            if until and now < until:
                return True
            dq = self._queries[ip]
            dq.append(now)
            self._prune(dq, now)
            if len(dq) >= THROTTLE_QUERY_LIMIT:
                self._enter(ip, f'query_flood n={len(dq)}', now)
                return True
        return False

    def note_fail(self, ip: str) -> bool:
        """Record upstream FAIL. Returns True if client is (now) quarantined."""
        now = time.time()
        with self._lock:
            until = self._until.get(ip)
            if until and now < until:
                return True
            dq = self._fails[ip]
            dq.append(now)
            self._prune(dq, now)
            if len(dq) >= THROTTLE_FAIL_LIMIT:
                self._enter(ip, f'upstream_fail n={len(dq)}', now)
                return True
        return False


THROTTLE = ClientThrottle()


class MemDB:
    def __init__(self):
        self.lock = threading.RLock()
        self.dns_mappings = []
        self.block_rules = {}
        self.leases_by_ip = {}
        self.reservations_by_ip = {}
        self.last_refresh_dhcp = 0
        self._trigger_mtime = 0
        self.bypass = False
        self.query_count = 0
        self.blocked_count = 0

    def load_bypass_state(self):
        if os.path.exists(BYPASS_FILE):
            try:
                with open(BYPASS_FILE) as f:
                    self.bypass = f.read().strip() == '1'
            except Exception:
                pass

    def set_bypass(self, enabled: bool):
        with self.lock:
            self.bypass = bool(enabled)
            with open(BYPASS_FILE, 'w') as f:
                f.write('1' if self.bypass else '0')

    def get_bypass(self):
        with self.lock:
            return self.bypass

    def load_dns_from_disk(self):
        with self.lock, sqlite3.connect(config.dns_db_file) as db:
            db.row_factory = sqlite3.Row
            self.dns_mappings = [dict(r) for r in db.execute('SELECT ip, domain FROM dns_mappings')]
            self.block_rules = {}
            for r in db.execute('SELECT domain, enabled, block_all_sub, note FROM block_rules'):
                self.block_rules[r['domain'].lower()] = {
                    'enabled': int(r['enabled'] or 0),
                    'block_all_sub': int(r['block_all_sub'] or 0),
                    'note': r['note'] or '',
                }

    def sync_dns_to_disk(self):
        with self.lock, sqlite3.connect(config.dns_db_file) as db:
            db.execute('DELETE FROM dns_mappings')
            for m in self.dns_mappings:
                db.execute('INSERT OR IGNORE INTO dns_mappings (ip, domain) VALUES (?,?)',
                           (m['ip'], m['domain']))
            db.execute('DELETE FROM block_rules')
            for d, r in self.block_rules.items():
                db.execute(
                    'INSERT OR REPLACE INTO block_rules (domain, enabled, block_all_sub, note) VALUES (?,?,?,?)',
                    (d, r.get('enabled', 1), r.get('block_all_sub', 1), r.get('note', '')))
            db.commit()

    def refresh_dhcp_cache(self, force=False):
        now = time.time()
        try:
            trig_mtime = os.path.getmtime(config.trigger) if os.path.exists(config.trigger) else 0
        except Exception:
            trig_mtime = 0
        # Reload when trigger moves, or at least every 2s (allow_until grants must be fast).
        if (not force
                and now - self.last_refresh_dhcp < 2
                and trig_mtime == self._trigger_mtime):
            return
        if not os.path.exists(config.dhcp_db_file):
            return
        with self.lock, sqlite3.connect(config.dhcp_db_file) as db:
            db.row_factory = sqlite3.Row
            self.reservations_by_ip = {}
            self.reservations_by_mac = {}
            cols = [r[1] for r in db.execute('PRAGMA table_info(reservations)')]
            extra = ''
            if 'allow_until' in cols:
                extra += ', allow_until'
            if 'study_until' in cols:
                extra += ', study_until'
            for r in db.execute(
                    f'SELECT mac,ip,hostname,lease_time,router,desc{extra} FROM reservations'):
                d = dict(r)
                if r['ip']:
                    self.reservations_by_ip[r['ip']] = d
                if r['mac']:
                    self.reservations_by_mac[str(r['mac']).lower()] = d
            self.leases_by_ip = {}
            self.leases_by_mac = {}
            cols = [r[1] for r in db.execute('PRAGMA table_info(leases)')]
            extra = ''
            if 'allow_until' in cols:
                extra += ', allow_until'
            if 'study_until' in cols:
                extra += ', study_until'
            for r in db.execute(
                    f'SELECT mac,ip,hostname,lease_start,lease_time,last_seen,router{extra} '
                    f'FROM leases'):
                d = dict(r)
                if r['ip']:
                    self.leases_by_ip[r['ip']] = d
                if r['mac']:
                    self.leases_by_mac[str(r['mac']).lower()] = d
        self._trigger_mtime = trig_mtime
        self.last_refresh_dhcp = now

    @staticmethod
    def _arp_mac(ip: str):
        """Resolve client IP → MAC via kernel neigh table."""
        try:
            with open('/proc/net/arp') as f:
                next(f, None)
                for line in f:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        mac = parts[3].lower()
                        if mac != '00:00:00:00:00:00':
                            return mac
        except Exception:
            pass
        return None

    def client_row(self, client_ip: str):
        """Reservation/lease for client — by IP, else ARP→MAC (APIPA / IP churn)."""
        self.refresh_dhcp_cache()
        with self.lock:
            row = self.reservations_by_ip.get(client_ip) or self.leases_by_ip.get(client_ip)
            if row:
                return row
            by_mac_r = self.reservations_by_mac
            by_mac_l = self.leases_by_mac
        mac = self._arp_mac(client_ip)
        if not mac:
            return None
        return by_mac_r.get(mac) or by_mac_l.get(mac)

    def client_effective(self, client_ip: str) -> str:
        row = self.client_row(client_ip)
        kw = settings_store.policy_kwargs()
        if not row:
            return policy.effective_mode('default', None, **kw)
        return policy.effective_mode(
            policy.normalize_mode(row.get('router')), row.get('allow_until'),
            study_until=row.get('study_until'), **kw)
    @staticmethod
    def normalize(name: str) -> str:
        return (name or '').rstrip('.').lower()

    def is_blocked_for_client(self, qname: str, client_ip: str) -> bool:
        eff = self.client_effective(client_ip)
        dns_pol = policy.dns_policy_for_effective(eff)
        if dns_pol == 'none':
            return False
        if dns_pol == 'block_all':
            return True
        s = settings_store.get_all()
        all_sub = bool(s.get('block_all_subdomains', True))
        q = self.normalize(qname)
        if dns_pol == 'default_block':
            return _match_domain(q, s.get('default_block_domains') or [], all_sub)
        if dns_pol == 'iot_block':
            return _match_domain(q, s.get('iot_block_domains') or [], all_sub)
        if dns_pol == 'study_block':
            if _match_domain(q, s.get('study_block_domains') or [], all_sub):
                return True
            with self.lock:
                for dom, rule in self.block_rules.items():
                    if not rule.get('enabled'):
                        continue
                    if rule.get('block_all_sub', 1) and (q == dom or q.endswith('.' + dom)):
                        return True
                    if not rule.get('block_all_sub', 1) and q == dom:
                        return True
        return False

    def find_local_ip_for_domain(self, qname: str):
        q = self.normalize(qname)
        with self.lock:
            for m in self.dns_mappings:
                if self.normalize(m.get('domain')) == q:
                    return m.get('ip')
        return None

    def client_label(self, client_ip: str) -> str:
        """로그용: IP + hostname/mac (있으면)."""
        row = self.client_row(client_ip)
        if not row:
            return client_ip
        host = (row.get('hostname') or '').strip() or '-'
        mac = (row.get('mac') or '').strip() or '-'
        return f"{client_ip}({host}/{mac})"


MEMDB = MemDB()
MEMDB.load_dns_from_disk()
MEMDB.refresh_dhcp_cache(force=True)
MEMDB.load_bypass_state()


class DNSServer:
    def __init__(self, host, port=53):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.settimeout(5.0)
        self.sock.bind((self.host, self.port))
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=20)
        # Cap in-flight work so a flood cannot grow an unbounded queue.
        self._inflight = threading.Semaphore(DNS_MAX_INFLIGHT)

    def forward_request(self, data):
        upstream = (settings_store.get('upstream_dns') or config.upstream_dns, 53)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(UPSTREAM_TIMEOUT_SEC)
        try:
            s.sendto(data, upstream)
            resp, _ = s.recvfrom(4096)
            return resp, None
        except Exception as e:
            return None, e
        finally:
            s.close()

    def _reply_a(self, req, ip_str):
        reply = req.reply()
        # Short TTL on FAKE blocks so a later allow_until grant is picked up quickly
        # (phones otherwise cache 0.0.0.0 for youtube for many minutes).
        ttl = 30 if ip_str == getattr(config, 'fake_ip', '0.0.0.0') else 300
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.A, rclass=1, ttl=ttl, rdata=A(ip_str)))
        reply.header.rcode = RCODE.NOERROR
        return reply

    def _reply_nx(self, req):
        reply = req.reply()
        reply.header.rcode = RCODE.NXDOMAIN
        return reply

    def _log_deny(self, kind: str, client_ip: str, qnorm: str, qtype, extra: str = ''):
        who = MEMDB.client_label(client_ip)
        eff = MEMDB.client_effective(client_ip)
        msg = f"[{kind}] {who} {qnorm} type={qtype} eff={eff}"
        if extra:
            msg += f" {extra}"
        app_log.info(msg)

    def _send_nx_raw(self, data, addr, why: str):
        """Best-effort NXDOMAIN without occupying an upstream slot."""
        try:
            req = DNSRecord.parse(data)
            self.sock.sendto(self._reply_nx(req).pack(), addr)
        except Exception:
            return
        # rare log — only when recv-loop drops (saturation)
        if why == 'saturated':
            app_log.info(f"[DROP] {addr[0]} DNS saturated (inflight>={DNS_MAX_INFLIGHT})")

    def handle_query(self, data, addr):
        try:
            MEMDB.refresh_dhcp_cache()
            req = DNSRecord.parse(data)
            qname = str(req.q.qname).rstrip('.')
            client_ip, _ = addr
            qnorm = MEMDB.normalize(qname)
            try:
                qtype = QTYPE[req.q.qtype]
            except Exception:
                qtype = str(req.q.qtype)
            with MEMDB.lock:
                MEMDB.query_count += 1

            quarantined = THROTTLE.note_query(client_ip) or THROTTLE.is_quarantined(client_ip)

            def _quiet_nx(tag=''):
                if THROTTLE.should_log_quiet(client_ip):
                    self._log_deny(
                        'QUIET', client_ip, qnorm, qtype,
                        f"quarantine {THROTTLE.remaining_sec(client_ip)}s left{tag}")
                self.sock.sendto(self._reply_nx(req).pack(), addr)

            if MEMDB.get_bypass():
                if quarantined:
                    _quiet_nx(' (bypass)')
                    return
                fwd, err = self.forward_request(data)
                if fwd:
                    self.sock.sendto(fwd, addr)
                else:
                    THROTTLE.note_fail(client_ip)
                    self._log_deny('FAIL', client_ip, qnorm, qtype,
                                   f"upstream err={err!r} (bypass)")
                return
            blocked = MEMDB.is_blocked_for_client(qnorm, client_ip)
            fake = getattr(config, 'fake_ip', '0.0.0.0')
            local_only = bool(settings_store.get('dns_local_only'))
            if req.q.qtype == QTYPE.A:
                local_ip = MEMDB.find_local_ip_for_domain(qnorm)
                if local_ip and local_ip != '0.0.0.0':
                    self.sock.sendto(self._reply_a(req, local_ip).pack(), addr)
                    return
                if blocked:
                    with MEMDB.lock:
                        MEMDB.blocked_count += 1
                    self._log_deny('BLOCK', client_ip, qnorm, qtype, f"-> FAKE {fake}")
                    self.sock.sendto(self._reply_a(req, fake).pack(), addr)
                    return
                if local_only:
                    self._log_deny('DENY', client_ip, qnorm, qtype, 'local_only NXDOMAIN')
                    self.sock.sendto(self._reply_nx(req).pack(), addr)
                    return
                if quarantined:
                    # No upstream — free workers for everyone else.
                    _quiet_nx()
                    return
                fwd, err = self.forward_request(data)
                if fwd:
                    self.sock.sendto(fwd, addr)
                    return
                THROTTLE.note_fail(client_ip)
                self._log_deny('FAIL', client_ip, qnorm, qtype, f"upstream err={err!r}")
                self.sock.sendto(self._reply_nx(req).pack(), addr)
                return
            if blocked:
                with MEMDB.lock:
                    MEMDB.blocked_count += 1
                self._log_deny('BLOCK', client_ip, qnorm, qtype, 'NXDOMAIN')
                self.sock.sendto(self._reply_nx(req).pack(), addr)
                return
            if quarantined:
                _quiet_nx()
                return
            fwd, err = self.forward_request(data)
            if fwd:
                self.sock.sendto(fwd, addr)
            else:
                THROTTLE.note_fail(client_ip)
                self._log_deny('FAIL', client_ip, qnorm, qtype, f"upstream err={err!r}")
                self.sock.sendto(self._reply_nx(req).pack(), addr)
        except Exception as e:
            app_log.error(f"DNS handle error: {e}")

    def _run_query(self, data, addr):
        try:
            self.handle_query(data, addr)
        finally:
            self._inflight.release()

    def serve_forever(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(2048)
                if not self._inflight.acquire(blocking=False):
                    # House stays up: drop overflow with fast NX, do not queue forever.
                    self._send_nx_raw(data, addr, 'saturated')
                    continue
                self.executor.submit(self._run_query, data, addr)
            except socket.timeout:
                continue
            except Exception as e:
                app_log.error(f"DNS recv: {e}")


def dns_server_thread():
    rt = settings_store.apply_runtime()
    iface = rt.get('INB') or settings_store.internal_device()
    host_ip = rt.get('SERVER_IP') or common.get_interface_ip(iface) or '127.0.0.1'
    app_log.info(
        f"[INFO] DNS bind {host_ip}:53 on IN={iface} OUT={rt.get('OUT')}")
    if not iface:
        app_log.error("[ERROR] Settings internal_device (IN) empty — DNS not binding")
        return
    DNSServer(host=host_ip, port=53).serve_forever()


def periodic_dns_sync():
    while True:
        try:
            MEMDB.sync_dns_to_disk()
        except Exception as e:
            app_log.error(f"sync: {e}")
        time.sleep(30)


MENU = '''
[<a href="/">DNS</a>] [<a href="/blocks">Blocks</a>] [<a href="/logout">Logout</a>]
<span style="color:#888">SAFE={{ safe }}</span>
'''

TPL_LOGIN = '''
<!doctype html><title>DNS Login</title>
<h2>DNS Admin Login</h2>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">User <input name="username"> Pass <input name="password" type="password">
<button>Login</button></form>
'''

TPL_MAIN = '''
<!doctype html><title>DNS Admin</title>
''' + MENU + '''
<hr>
<p>Bypass: <b>{{ 'ON' if bypass else 'OFF' }}</b>
 <a href="{{ url_for('toggle_bypass') }}">Toggle</a></p>
<form method="post" action="{{ url_for('add_mapping') }}">
  <input name="ip" placeholder="IP" required>
  <input name="domain" placeholder="domain" required>
  <button>Add mapping</button>
</form>
<table border="1" cellpadding="4">
<tr><th>IP</th><th>Domain</th><th></th></tr>
{% for m in mappings %}
<tr>
  <td>{{ m.ip }}</td><td>{{ m.domain }}</td>
  <td><a href="{{ url_for('delete_mapping', ip=m.ip, domain=m.domain) }}">Del</a></td>
</tr>
{% endfor %}
</table>
'''

TPL_BLOCKS = '''
<!doctype html><title>Blocks</title>
''' + MENU + '''
<hr>
<form method="post" action="{{ url_for('add_block') }}">
  Domain <input name="domain" required>
  <button>Add block rule</button>
</form>
<table border="1" cellpadding="4">
<tr><th>Domain</th><th>On</th><th>Sub</th><th></th></tr>
{% for d,r in rules %}
<tr>
  <td>{{ d }}</td>
  <td><a href="{{ url_for('toggle_block', domain=d) }}">{{ r.enabled }}</a></td>
  <td>{{ r.block_all_sub }}</td>
  <td><a href="{{ url_for('delete_block', domain=d) }}">Del</a></td>
</tr>
{% endfor %}
</table>
'''


@app.route('/login', methods=['GET', 'POST'])
def login():
    err = None
    if request.method == 'POST':
        if web_auth.check_login(request.form.get('username', ''), request.form.get('password', '')):
            web_auth.login_user(request.form['username'])
            return redirect(url_for('main'))
        err = 'Invalid'
    return render_template_string(TPL_LOGIN, error=err)


@app.route('/logout')
def logout():
    web_auth.logout_user()
    return redirect(url_for('login'))


@app.route('/')
@web_auth.login_required
def main():
    with MEMDB.lock:
        mappings = list(MEMDB.dns_mappings)
    return render_template_string(
        TPL_MAIN, mappings=mappings, bypass=MEMDB.get_bypass(), safe=config.SAFE_MODE)


@app.route('/add_mapping', methods=['POST'])
@web_auth.login_required
def add_mapping():
    ip = request.form['ip'].strip()
    domain = request.form['domain'].strip().lower()
    with MEMDB.lock:
        MEMDB.dns_mappings.append({'ip': ip, 'domain': domain})
    MEMDB.sync_dns_to_disk()
    return redirect(url_for('main'))


@app.route('/delete/<ip>/<domain>')
@web_auth.login_required
def delete_mapping(ip, domain):
    with MEMDB.lock:
        MEMDB.dns_mappings = [m for m in MEMDB.dns_mappings
                              if not (m['ip'] == ip and m['domain'] == domain)]
    MEMDB.sync_dns_to_disk()
    return redirect(url_for('main'))


@app.route('/blocks')
@web_auth.login_required
def blocks_page():
    with MEMDB.lock:
        rules = sorted(MEMDB.block_rules.items())
    return render_template_string(TPL_BLOCKS, rules=rules, safe=config.SAFE_MODE)


@app.route('/blocks/add', methods=['POST'])
@web_auth.login_required
def add_block():
    d = request.form['domain'].strip().lower()
    with MEMDB.lock:
        MEMDB.block_rules[d] = {'enabled': 1, 'block_all_sub': 1, 'note': ''}
    MEMDB.sync_dns_to_disk()
    return redirect(url_for('blocks_page'))


@app.route('/blocks/toggle/<domain>')
@web_auth.login_required
def toggle_block(domain):
    with MEMDB.lock:
        r = MEMDB.block_rules.get(domain)
        if r:
            r['enabled'] = 0 if r.get('enabled') else 1
    MEMDB.sync_dns_to_disk()
    return redirect(url_for('blocks_page'))


@app.route('/blocks/delete/<domain>')
@web_auth.login_required
def delete_block(domain):
    with MEMDB.lock:
        MEMDB.block_rules.pop(domain, None)
    MEMDB.sync_dns_to_disk()
    return redirect(url_for('blocks_page'))


@app.route('/bypass/toggle')
@web_auth.login_required
def toggle_bypass():
    MEMDB.set_bypass(not MEMDB.get_bypass())
    return redirect(url_for('main'))


@app.route('/api/client_policy')
@web_auth.login_required
def api_client_policy():
    ip = request.args.get('ip', '')
    MEMDB.refresh_dhcp_cache(force=True)
    eff = MEMDB.client_effective(ip)
    return jsonify({'ip': ip, 'effective': eff, 'dns': policy.dns_policy_for_effective(eff)})


def main():
    """DNS 서비스 전용. 웹 UI 는 admin_app.py 사용."""
    app_log.info(
        f"[INFO] DNS service SAFE_MODE={config.SAFE_MODE} "
        f"(UI → admin_app.py :{getattr(config, 'interface_admin_port', 15000)}) "
        f"log={config.log_dns_server} rotate={config.log_size}B x{config.log_rotate} "
        f"(BLOCK/DENY/FAIL only)")
    threading.Thread(target=periodic_dns_sync, daemon=True).start()
    if config.SAFE_MODE:
        app_log.warning("[SAFE_MODE] DNS :53 DISABLED — idle service (use admin_app for UI)")
        while True:
            time.sleep(3600)
    else:
        dns_server_thread()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        app_log.info('stopped')
