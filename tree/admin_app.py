#!/usr/bin/env python3
"""
admin_app.py — unified Admin UI (Devices / DNS / Firewall / Settings).

Author : Kage
Project: krouter
Why    : One login for the whole house router — parents should not juggle
         three admin ports just to change a study device or open a port.

SAFE_MODE: may bind UI only; DHCP sniff / DNS :53 / live iptables stay off.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time

from flask import Flask, redirect, render_template_string, request, url_for, jsonify

import config
import policy
import settings_store
import web_auth
import router_ctl

# 서비스 모듈의 MemDB / 헬퍼 재사용 (UI만 이 프로세스에서 제공)
import dhcp_app as dhc
import dns_app as dns

from logging.handlers import RotatingFileHandler

os.makedirs(os.path.join(config.KROUTER_ROOT, 'logs'), exist_ok=True)
os.makedirs(os.path.join(config.KROUTER_ROOT, 'data'), exist_ok=True)

# 기본 admin/admin (settings.db 에 이미 hash 있으면 유지 — 아래에서 강제 리셋 옵션 없음)
web_auth.ensure_admin_password(config.ADMIN_USER, config.ADMIN_PASSWORD)
settings_store.ensure_tables()
settings_store.apply_runtime()  # Settings IN/OUT/GW/DNS → config + env

app = Flask(__name__)
app.secret_key = config.SECRET_KEY
log = logging.getLogger('admin_app')
log.setLevel(logging.INFO)
# router_ctl apply success is INFO — ensure it reaches admin.ctl.log (nohup stderr)
logging.getLogger('router_ctl').setLevel(logging.INFO)
if not logging.getLogger('router_ctl').handlers:
    logging.getLogger('router_ctl').addHandler(logging.StreamHandler())
if not log.handlers:
    _ah = RotatingFileHandler(
        os.path.join(config.KROUTER_ROOT, 'logs', 'admin.log'),
        maxBytes=config.log_size, backupCount=config.log_rotate)
    _ah.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    log.addHandler(_ah)
    log.addHandler(logging.StreamHandler())

ADMIN_PORT = getattr(config, 'interface_admin_port', None) or (
    15000 if config.SAFE_MODE else 5000
)

MENU = '''
<div style="margin:8px 0;font-family:sans-serif">
  <b>krouter</b>
  <span style="color:#666;font-size:12px">v{{ version }}</span>
  [<a href="{{ url_for('devices') }}">Devices</a>]
  [<a href="{{ url_for('leases') }}">Leases</a>]
  [<a href="{{ url_for('dns_page') }}">DNS</a>]
  [<a href="{{ url_for('blocks_page') }}">Blocks</a>]
  [<a href="{{ url_for('firewall_page') }}">Firewall</a>]
  [<a href="{{ url_for('settings_page') }}">Settings</a>]
  [<a href="{{ url_for('history') }}">History</a>]
  [<a href="{{ url_for('about_page') }}">About</a>]
  [<a href="{{ url_for('logout') }}">Logout</a>]
  <span style="color:#888;margin-left:12px">user={{ user }} · SAFE={{ safe }} · by {{ author }}</span>
</div>
'''


def _ctx(**extra):
    base = {
        'safe': config.SAFE_MODE,
        'version': getattr(config, 'VERSION', '0'),
        'author': getattr(config, 'APP_AUTHOR', 'Kage'),
        'user': (request and hasattr(request, 'environ') and None) or '',
    }
    try:
        from flask import session
        base['user'] = session.get('user') or ''
    except Exception:
        pass
    base.update(extra)
    return base


def _ip_sort_key(val):
    try:
        return (0, int(ipaddress.IPv4Address(str(val))))
    except Exception:
        return (1, str(val or '').lower())


def _parse_sort(allowed: tuple[str, ...], default: str):
    col = (request.args.get('sort') or default).strip()
    if col not in allowed:
        col = default
    direction = (request.args.get('dir') or 'asc').strip().lower()
    if direction not in ('asc', 'desc'):
        direction = 'asc'
    return col, direction


def _sort_urls(endpoint: str, cols: tuple[str, ...], sort: str, direction: str, **extra):
    """Build header links: first click asc, same column toggles."""
    out = {}
    marks = {}
    for c in cols:
        if c == sort:
            nxt = 'desc' if direction == 'asc' else 'asc'
            marks[c] = '▲' if direction == 'asc' else '▼'
        else:
            nxt = 'asc'
            marks[c] = ''
        out[c] = url_for(endpoint, sort=c, dir=nxt, **extra)
    return out, marks


def _sort_rows(rows: list, sort: str, direction: str, getters: dict):
    g = getters.get(sort) or (lambda r: '')
    rev = direction == 'desc'

    def key(r):
        v = g(r)
        if isinstance(v, tuple):
            return v
        if isinstance(v, (int, float)):
            return v
        return str(v or '').lower()

    try:
        return sorted(rows, key=key, reverse=rev)
    except TypeError:
        return sorted(rows, key=lambda r: str(g(r) or '').lower(), reverse=rev)


def _read_arp_live() -> str:
    """Read live gc_thresh1/2/3 for Settings display."""
    vals = []
    for name in ('gc_thresh1', 'gc_thresh2', 'gc_thresh3'):
        path = f'/proc/sys/net/ipv4/neigh/default/{name}'
        try:
            with open(path) as f:
                vals.append(f.read().strip())
        except Exception:
            vals.append('?')
    return '/'.join(vals)


TPL_LOGIN = '''
<!doctype html><title>krouter Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>body{font-family:sans-serif;max-width:420px;margin:40px auto}</style>
<h2>krouter Admin</h2>
<p>DHCP · DNS · Policy · <span style="color:#666">v{{ version }}</span></p>
{% if error %}<p style="color:red">{{ error }}</p>{% endif %}
<form method="post">
  <p>User <input name="username" required autofocus value="admin"></p>
  <p>Password <input name="password" type="password" required></p>
  <button type="submit">Login</button>
</form>
<p style="color:#888;font-size:12px">Default: admin / admin — change under Settings</p>
'''

TPL_ABOUT = MENU + '''
<hr>
<h2>About krouter</h2>
<p><b>Version {{ version }}</b> · Author <b>{{ author }}</b> · License <b>Apache-2.0</b></p>
<p>A small home router stack: DHCP, DNS policy, study-mode scheduling,
firewall / port forwarding, and one admin UI.</p>
<h3>History</h3>
<p style="max-width:720px;line-height:1.45">
From about <b>2004</b>, {{ author }} kept expanding firewall and iptables-based
routing (home use and many other setups). A home-router shape grew around
<b>2006</b>. Those lines of work kept being upgraded until they became this
packaged <b>krouter</b>.
</p>
<p style="max-width:720px;line-height:1.45">
Real home production use (not just lab experiments) started around
<b>July 2025</b>: this box became the main router, the previous router was
switched to <b>AP mode</b>, and several AP-mode routers were placed around
the house — still in daily use.
</p>
<h3>Why it exists</h3>
<p style="max-width:720px;line-height:1.45">
Commercial home routers often feel short-lived and overly complex — many features,
limited practical device capacity, and security options that are hard to use for
everyday needs. {{ author }} built krouter to keep useful household policies
simple and under control. After years of real home use and ongoing upgrades,
it became stable enough to package.
</p>
<p style="max-width:720px;line-height:1.45">
With students at home, internet access can turn into a daily fight. During agreed
study hours, what is needed for school stays open while distractions stay blocked.
Outside those hours the policy tightens, and an adult can still grant extra time
or a short temporary free window when needed.
</p>
<p style="color:#888;font-size:13px">
Published source carries the author name and intent — not private contact details
or host NIC names (those live in Settings DB).
</p>
'''

TPL_DEVICES = MENU + '''
<hr>
<h2>Add Reservation</h2>
<form action="{{ url_for('add_reservation') }}" method="post">
  MAC <input name="mac" required>
  IP <input name="ip" required>
  Hostname <input name="hostname" required>
  Lease <input name="lease_time" value="86400" size="7">
  Mode
  <select name="router">
    <option value="default">default (light block)</option>
    <option value="all_allow">all_allow (unrestricted)</option>
    <option value="study">study</option>
  </select>
  Desc <input name="desc" size="40">
  <button type="submit">Add</button>
</form>
<h2>Reservations</h2>
<table border="1" cellpadding="4" cellspacing="0">
<tr>
  <th>#</th>
  <th><a href="{{ sort_urls.mac }}">MAC {{ sort_marks.mac }}</a></th>
  <th><a href="{{ sort_urls.hostname }}">Host {{ sort_marks.hostname }}</a></th>
  <th><a href="{{ sort_urls.ip }}">IP {{ sort_marks.ip }}</a></th>
  <th><a href="{{ sort_urls.mode }}">Mode {{ sort_marks.mode }}</a></th>
  <th><a href="{{ sort_urls.effective }}">Effective {{ sort_marks.effective }}</a></th>
  <th><a href="{{ sort_urls.study_until }}">Study until {{ sort_marks.study_until }}</a></th>
  <th><a href="{{ sort_urls.allow_until }}">Free until {{ sort_marks.allow_until }}</a></th>
  <th><a href="{{ sort_urls.desc }}">Desc {{ sort_marks.desc }}</a></th>
  <th></th>
</tr>
{% for r in reservations %}
<tr>
  <td>{{ loop.index }}</td>
  <td>{{ r.mac }}</td><td>{{ r.hostname }}</td><td>{{ r.ip }}</td>
  <td>{{ r.mode }}</td><td><b>{{ r.effective }}</b></td>
  <td>{{ r.study_until_fmt }}</td>
  <td>{{ r.allow_until_fmt }}</td>
  <td>{{ r.desc or '' }}</td>
  <td><a href="{{ url_for('edit_device', mac=r.mac) }}">Edit</a></td>
</tr>
{% endfor %}
</table>
'''

TPL_EDIT = MENU + '''
<hr>
<h2>Edit {{ reservation.mac }}</h2>
<p>Base mode: <b>{{ mode }}</b> · Effective now: <b>{{ effective }}</b></p>
<form method="post">
  IP <input name="ip" value="{{ reservation.ip }}" required><br>
  Hostname <input name="hostname" value="{{ reservation.hostname }}" required><br>
  Lease <input name="lease_time" value="{{ reservation.lease_time or 86400 }}"><br>
  Mode
  <select name="router">
    <option value="default" {% if mode=='default' %}selected{% endif %}>default</option>
    <option value="all_allow" {% if mode=='all_allow' %}selected{% endif %}>all_allow</option>
    <option value="study" {% if mode=='study' %}selected{% endif %}>study</option>
    {% if mode=='custom' %}
    <option value="{{ reservation.router }}" selected>custom {{ reservation.router }}</option>
    {% endif %}
  </select><br>
  Desc <input name="desc" value="{{ reservation.desc or '' }}" size="60"><br>
  <button type="submit">Update (change base group)</button>
</form>
{% if mode=='study' %}
<hr>
<h3>1. Extend study</h3>
<p>Stay on <b>STUDY</b> (blocks stay). Only lifts schedule BLOCK → STUDY until expiry.
  Current: {{ reservation.study_until_fmt or '—' }}</p>
<form action="{{ url_for('grant_study', mac=reservation.mac) }}" method="post">
  <button name="kind" value="30m">+30m</button>
  <button name="kind" value="1h">+1h</button>
  <button name="kind" value="4h">+4h</button>
  <button name="kind" value="1d">until midnight</button>
</form>
<form action="{{ url_for('grant_study', mac=reservation.mac) }}" method="post" style="margin-top:6px">
  Hours
  <select name="hours"><option value="0">0h</option><option value="1">1h</option><option value="2">2h</option><option value="3">3h</option><option value="4">4h</option><option value="5">5h</option><option value="6">6h</option><option value="7">7h</option><option value="8">8h</option></select>
  Minutes
  <select name="minutes"><option value="0">0m</option><option value="15">15m</option><option value="30" selected>30m</option><option value="45">45m</option></select>
  <input type="hidden" name="kind" value="custom">
  <button type="submit">Grant extend</button>
</form>
<form action="{{ url_for('clear_study', mac=reservation.mac) }}" method="post" style="margin-top:8px">
  <button type="submit">Clear study extend</button>
</form>
{% endif %}
{% if mode in ('study', 'default') %}
<hr>
<h3>{% if mode=='study' %}2. {% endif %}Free time (all_allow)</h3>
<p>Temporary <b>ALL_ALLOW</b> — YouTube/games open. When it expires, back to <b>{{ mode }}</b>.
  Current: {{ reservation.allow_until_fmt or '—' }}</p>
<form action="{{ url_for('grant_allow', mac=reservation.mac) }}" method="post">
  <button name="kind" value="30m">+30m</button>
  <button name="kind" value="1h">+1h</button>
  <button name="kind" value="4h">+4h</button>
  <button name="kind" value="1d">until midnight</button>
</form>
<form action="{{ url_for('grant_allow', mac=reservation.mac) }}" method="post" style="margin-top:6px">
  Hours
  <select name="hours"><option value="0">0h</option><option value="1">1h</option><option value="2">2h</option><option value="3">3h</option><option value="4">4h</option><option value="5">5h</option><option value="6">6h</option><option value="7">7h</option><option value="8">8h</option></select>
  Minutes
  <select name="minutes"><option value="0">0m</option><option value="15">15m</option><option value="30" selected>30m</option><option value="45">45m</option></select>
  <input type="hidden" name="kind" value="custom">
  <button type="submit">Grant free time</button>
</form>
<form action="{{ url_for('clear_allow', mac=reservation.mac) }}" method="post" style="margin-top:8px">
  <button type="submit">Clear free time → back to {{ mode }}</button>
</form>
{% endif %}
<p><a href="{{ url_for('delete_device', mac=reservation.mac) }}">Delete reservation</a></p>
'''

TPL_LEASES = MENU + '''
<hr><h2>Leases</h2>
<table border="1" cellpadding="4">
<tr>
  <th><a href="{{ sort_urls.mac }}">MAC {{ sort_marks.mac }}</a></th>
  <th><a href="{{ sort_urls.ip }}">IP {{ sort_marks.ip }}</a></th>
  <th><a href="{{ sort_urls.hostname }}">Host {{ sort_marks.hostname }}</a></th>
  <th><a href="{{ sort_urls.mode }}">Mode {{ sort_marks.mode }}</a></th>
  <th><a href="{{ sort_urls.effective }}">Effective {{ sort_marks.effective }}</a></th>
  <th><a href="{{ sort_urls.last_seen }}">Last seen {{ sort_marks.last_seen }}</a></th>
  <th></th>
</tr>
{% for l in leases %}
<tr>
  <td>{{ l.mac }}</td><td>{{ l.ip }}</td><td>{{ l.hostname }}</td>
  <td>{{ l.mode }}</td><td>{{ l.effective }}</td><td>{{ l.last_seen }}</td>
  <td><a href="{{ url_for('edit_device', mac=l.mac) }}">Edit</a></td>
</tr>
{% endfor %}
</table>
'''

TPL_HISTORY = MENU + '''
<hr><h2>History</h2>
<table border="1" cellpadding="4">
<tr>
  <th><a href="{{ sort_urls.mac }}">MAC {{ sort_marks.mac }}</a></th>
  <th><a href="{{ sort_urls.ip }}">IP {{ sort_marks.ip }}</a></th>
  <th><a href="{{ sort_urls.hostname }}">Host {{ sort_marks.hostname }}</a></th>
  <th><a href="{{ sort_urls.mode }}">Mode {{ sort_marks.mode }}</a></th>
  <th><a href="{{ sort_urls.last_seen }}">Last seen {{ sort_marks.last_seen }}</a></th>
</tr>
{% for h in histories %}
<tr><td>{{ h.mac }}</td><td>{{ h.ip }}</td><td>{{ h.hostname }}</td>
<td>{{ h.router }}</td><td>{{ h.last_seen }}</td></tr>
{% endfor %}
</table>
'''

TPL_DNS = MENU + '''
<hr>
<h2>DNS</h2>
<p>Bypass: <b>{{ 'ON' if bypass else 'OFF' }}</b>
  <a href="{{ url_for('toggle_bypass') }}">Toggle</a>
  <span style="color:#888">(ON = no DNS policy control)</span>
</p>
<form method="post" action="{{ url_for('add_mapping') }}">
  IP <input name="ip" required>
  Domain <input name="domain" required>
  <button>Add mapping</button>
</form>
<table border="1" cellpadding="4">
<tr>
  <th><a href="{{ sort_urls.ip }}">IP {{ sort_marks.ip }}</a></th>
  <th><a href="{{ sort_urls.domain }}">Domain {{ sort_marks.domain }}</a></th>
  <th></th>
</tr>
{% for m in mappings %}
<tr>
  <td>{{ m.ip }}</td><td>{{ m.domain }}</td>
  <td><a href="{{ url_for('delete_mapping', ip=m.ip, domain=m.domain) }}">Del</a></td>
</tr>
{% endfor %}
</table>
'''

TPL_BLOCKS = MENU + '''
<hr>
<h2>DNS Block Rules (extra)</h2>
<p>Edit default/study domain lists in Settings. Rules here are added for study mode.</p>
<form method="post" action="{{ url_for('add_block') }}">
  Domain <input name="domain" required>
  <button>Add</button>
</form>
<table border="1" cellpadding="4">
<tr>
  <th><a href="{{ sort_urls.domain }}">Domain {{ sort_marks.domain }}</a></th>
  <th><a href="{{ sort_urls.enabled }}">On {{ sort_marks.enabled }}</a></th>
  <th><a href="{{ sort_urls.sub }}">Sub {{ sort_marks.sub }}</a></th>
  <th></th>
</tr>
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

TPL_SETTINGS = MENU + '''
<hr>
<h2>Settings</h2>
<form method="post">
  <h3>Study schedule (local)</h3>
  Start <input name="study_schedule_start" value="{{ s.study_schedule_start }}">
  End <input name="study_schedule_end" value="{{ s.study_schedule_end }}">
  <small>If start==end, study window is 24h</small>
  <h3>New device mode</h3>
  <select name="new_device_mode">
    <option value="default" {% if s.new_device_mode=='default' %}selected{% endif %}>default</option>
    <option value="all_allow" {% if s.new_device_mode=='all_allow' %}selected{% endif %}>all_allow</option>
    <option value="study" {% if s.new_device_mode=='study' %}selected{% endif %}>study</option>
  </select>
  <h3>DNS</h3>
  Upstream <input name="upstream_dns" value="{{ s.upstream_dns }}">
  Local only <input type="checkbox" name="dns_local_only" {% if s.dns_local_only %}checked{% endif %}>
  <h3>DHCP options</h3>
  Gateway <input name="gateway" value="{{ s.gateway }}">
  DNS servers <input name="dns_servers" value="{{ s.dns_servers }}"><br>
  Internal device (LAN) <input name="internal_device" value="{{ s.internal_device }}" size="12" required>
  WAN device <input name="wan_device" value="{{ s.wan_device }}" size="12" required><br>
  DHCP auto IP range
  <input name="dhcp_auto_start" value="{{ s.dhcp_auto_start }}" size="14">
  –
  <input name="dhcp_auto_end" value="{{ s.dhcp_auto_end }}" size="14">
  <p style="color:#555;font-size:13px;max-width:640px">
    New devices get a free IP only inside this auto range.
    Manual reservations may use any address in the subnet (occupied IPs are skipped by auto-assign).
    After changing NIC names, use <b>Restart stack</b> below.
  </p>
  <h3>Default block domains</h3>
  <textarea name="default_block_domains" rows="3" cols="70">{{ default_domains }}</textarea>
  <h3>Study block domains</h3>
  <textarea name="study_block_domains" rows="3" cols="70">{{ study_domains }}</textarea>
  <h3>BLOCK allow (outside study schedule) — proto:ip:port</h3>
  <p style="color:#555;font-size:13px">
    Extra allow while effective mode is BLOCK. One rule per line.<br>
    Format: <code>tcp|udp|any</code>:<code>IP[/CIDR]</code>:<code>port|*</code><br>
    Examples: <code>tcp:1.2.3.4:443</code> / <code>udp:8.8.8.8:53</code> / <code>any:9.9.9.9:*</code><br>
    (DNS/DHCP/NTP remain allowed. Saving refreshes the BLOCK chain.)
  </p>
  <textarea name="block_allow_rules" rows="6" cols="70" placeholder="tcp:1.2.3.4:443">{{ block_allow_text }}</textarea>
  <h3>ARP table size (neighbor cache)</h3>
  <p style="color:#555;font-size:13px;max-width:640px">
    Preset for how many ARP/neighbor entries the kernel keeps
    (<code>gc_thresh1</code>; thresh2/3 = ×4 / ×8). Also applies stale-time,
    reachable-time, and solicit limits. Applied live via <code>sysctl -w</code>
    on Save and stack start — no conf file is written.<br>
    Larger values help networks with many devices or Wi‑Fi APs, but
    <b>raising this too high can slow the server and increase load</b>.
    Match the level to your hardware and device count.
  </p>
  Size
  <select name="arp_table_size">
    {% for n in arp_choices %}
    <option value="{{ n }}" {% if (s.arp_table_size|int) == n %}selected{% endif %}>{{ n }}{% if n == 100 %} (default){% endif %} → {{ n }}/{{ n*4 }}/{{ n*8 }}</option>
    {% endfor %}
  </select>
  <small>Current live: gc_thresh1/2/3 = {{ arp_live }}</small>
  <h3>Login account</h3>
  Username <input name="admin_user" value="{{ s.admin_user }}" required><br>
  New password <input name="new_password" type="password" placeholder="(blank = keep)"><br>
  Confirm <input name="new_password2" type="password"><br>
  <br><button type="submit">Save</button>
</form>
<hr>
<h3>Restart stack</h3>
<p style="color:#555;font-size:13px">
  Restart to apply NIC / iptables / DHCP / DNS with saved Settings.
  UI and DHCP/DNS will drop for a few seconds.
</p>
<form method="post" action="{{ url_for('restart_stack') }}"
      onsubmit="return confirm('Restart krouter stack now?');">
  <button type="submit" style="background:#c44;color:#fff;padding:6px 14px">Restart stack</button>
</form>
{% if restart_msg %}<p style="color:green">{{ restart_msg }}</p>{% endif %}
'''

TPL_FIREWALL = MENU + '''
<hr>
<h2>Firewall &amp; Port Forward</h2>
<p style="color:#555;font-size:13px;max-width:720px">
  <b>OFF</b>: legacy behavior (WAN→router 22/53/447 open by default; PF list still applied).<br>
  <b>ON</b>: deny new WAN inbound by default; only Port Forward rules below are allowed.<br>
  For a web server on this router, set dest IP to Gateway ({{ gw }}).
</p>
<form method="post" action="{{ url_for('firewall_save') }}">
  Firewall
  <select name="firewall_enabled">
    <option value="0" {% if not fw_on %}selected{% endif %}>OFF (legacy)</option>
    <option value="1" {% if fw_on %}selected{% endif %}>ON (PF + deny WAN NEW)</option>
  </select>
  <button type="submit">Save &amp; Apply</button>
</form>
{% if msg %}<p style="color:green">{{ msg }}</p>{% endif %}
<hr>
<h3>Port forwards</h3>
<form method="post" action="{{ url_for('firewall_add') }}">
  proto
  <select name="proto"><option value="tcp">tcp</option><option value="udp">udp</option></select>
  WAN port <input name="wan_port" size="5" required>
  → dest IP <input name="dest_ip" size="14" placeholder="{{ gw }}" required>
  dest port <input name="dest_port" size="5" required>
  note <input name="note" size="20">
  <button type="submit">Add</button>
</form>
<table border="1" cellpadding="4" cellspacing="0" style="margin-top:10px">
<tr><th>On</th><th>Proto</th><th>WAN</th><th>Dest</th><th>Note</th><th></th></tr>
{% for r in forwards %}
<tr>
  <td>{{ 'Y' if r.enabled else 'N' }}</td>
  <td>{{ r.proto }}</td>
  <td>{{ r.wan_port }}</td>
  <td>{{ r.dest_ip }}:{{ r.dest_port }}</td>
  <td>{{ r.note or '' }}</td>
  <td>
    <a href="{{ url_for('firewall_toggle', idx=loop.index0) }}">Toggle</a>
    <a href="{{ url_for('firewall_del', idx=loop.index0) }}">Del</a>
  </td>
</tr>
{% else %}
<tr><td colspan="6">(no rules)</td></tr>
{% endfor %}
</table>
'''


# ---------- auth ----------
@app.route('/login', methods=['GET', 'POST'])
def login():
    err = None
    if request.method == 'POST':
        u = request.form.get('username', '')
        p = request.form.get('password', '')
        if web_auth.check_login(u, p):
            web_auth.login_user(u)
            return redirect(request.args.get('next') or url_for('devices'))
        err = 'Invalid username or password'
    return render_template_string(
        TPL_LOGIN, error=err, version=getattr(config, 'VERSION', '0'))


@app.route('/logout')
def logout():
    web_auth.logout_user()
    return redirect(url_for('login'))


@app.route('/about')
@web_auth.login_required
def about_page():
    return render_template_string(TPL_ABOUT, **_ctx())


@app.route('/')
@web_auth.login_required
def devices():
    cols = ('mac', 'hostname', 'ip', 'mode', 'effective', 'study_until', 'allow_until', 'desc')
    sort, direction = _parse_sort(cols, 'hostname')
    # Peer DHCP may have updated leases; reservations are Admin-written (already in mem)
    dhc.MEMDB.sync_leases_from_disk()
    with dhc.MEMDB.lock:
        reservations = [dhc._enrich(r) for r in dhc.MEMDB.res_by_mac.values()]
    reservations = _sort_rows(reservations, sort, direction, {
        'mac': lambda r: r.get('mac') or '',
        'hostname': lambda r: r.get('hostname') or '',
        'ip': lambda r: _ip_sort_key(r.get('ip')),
        'mode': lambda r: r.get('mode') or '',
        'effective': lambda r: r.get('effective') or '',
        'study_until': lambda r: r.get('study_until') or 0,
        'allow_until': lambda r: r.get('allow_until') or 0,
        'desc': lambda r: r.get('desc') or '',
    })
    sort_urls, sort_marks = _sort_urls('devices', cols, sort, direction)
    return render_template_string(
        TPL_DEVICES, reservations=reservations,
        sort_urls=sort_urls, sort_marks=sort_marks, **_ctx())


@app.route('/leases')
@web_auth.login_required
def leases():
    cols = ('mac', 'ip', 'hostname', 'mode', 'effective', 'last_seen')
    sort, direction = _parse_sort(cols, 'ip')
    dhc.MEMDB.sync_leases_from_disk()
    dhc.MEMDB.maybe_sync_reservations()
    with dhc.MEMDB.lock:
        rows = [dhc._enrich(r) for r in dhc.MEMDB.leases_by_mac.values()]
    rows = _sort_rows(rows, sort, direction, {
        'mac': lambda r: r.get('mac') or '',
        'ip': lambda r: _ip_sort_key(r.get('ip')),
        'hostname': lambda r: r.get('hostname') or '',
        'mode': lambda r: r.get('mode') or '',
        'effective': lambda r: r.get('effective') or '',
        'last_seen': lambda r: r.get('last_seen') or 0,
    })
    sort_urls, sort_marks = _sort_urls('leases', cols, sort, direction)
    return render_template_string(
        TPL_LEASES, leases=rows, sort_urls=sort_urls, sort_marks=sort_marks, **_ctx())


@app.route('/history')
@web_auth.login_required
def history():
    cols = ('mac', 'ip', 'hostname', 'mode', 'last_seen')
    sort, direction = _parse_sort(cols, 'last_seen')
    dhc.MEMDB.sync_leases_from_disk()
    with dhc.MEMDB.lock:
        histories = list(dhc.MEMDB.history_by_mac.values())
    histories = _sort_rows(histories, sort, direction, {
        'mac': lambda r: r.get('mac') or '',
        'ip': lambda r: _ip_sort_key(r.get('ip')),
        'hostname': lambda r: r.get('hostname') or '',
        'mode': lambda r: r.get('router') or '',
        'last_seen': lambda r: r.get('last_seen') or 0,
    })
    sort_urls, sort_marks = _sort_urls('history', cols, sort, direction)
    return render_template_string(
        TPL_HISTORY, histories=histories,
        sort_urls=sort_urls, sort_marks=sort_marks, **_ctx())


@app.route('/add_reservation', methods=['POST'])
@web_auth.login_required
def add_reservation():
    mac = request.form['mac'].strip().lower()
    ip = request.form['ip'].strip()
    hostname = request.form['hostname'].strip()
    lease_time = int(request.form.get('lease_time') or config.DEFAULT_LEASE)
    raw = request.form.get('router', 'default').strip()
    if raw in ('default', 'all_allow', 'study'):
        router = raw
    elif dhc.validate_ip(raw):
        router = raw
    else:
        router = 'default'
    if not dhc.validate_ip(ip) or not __import__('common').ip_in_network(ip):
        return "<script>alert('Invalid IP');history.back();</script>"
    with dhc.MEMDB.lock:
        if mac in dhc.MEMDB.res_by_mac:
            return "<script>alert('Duplicate MAC');history.back();</script>"
    dhc.MEMDB.upsert_reservation({
        'mac': mac, 'ip': ip, 'hostname': hostname,
        'lease_time': lease_time, 'router': router,
        'desc': request.form.get('desc', '').strip(),
        'allow_until': None,
        'study_until': None,
    })
    _eff, ok, msg = dhc.apply_mac_policy(mac, router, None)
    if not ok:
        return (
            f"<script>alert({json.dumps('Saved, but iptables apply failed: ' + (msg or '')[:200])});"
            f"location.href={json.dumps(url_for('devices'))}</script>")
    return redirect(url_for('devices'))


@app.route('/device/<mac>', methods=['GET', 'POST'])
@web_auth.login_required
def edit_device(mac):
    mac = mac.strip().lower()
    gw = settings_store.get('gateway') or config.GATEWAY
    if request.method == 'POST':
        ip = request.form['ip'].strip()
        hostname = request.form['hostname'].strip()
        lease_time = int(request.form.get('lease_time') or config.DEFAULT_LEASE)
        raw = request.form.get('router', 'default').strip()
        if raw in ('default', 'all_allow', 'study'):
            router = raw
        elif dhc.validate_ip(raw):
            router = raw
        else:
            router = 'default'
        desc = request.form.get('desc', '').strip()
        if not dhc.validate_ip(ip) or not __import__('common').ip_in_network(ip):
            return "<script>alert('Invalid IP');history.back();</script>"
        with dhc.MEMDB.lock:
            prev = dhc.MEMDB.res_by_mac.get(mac) or {}
            # Free time survives edits for study/default; Extend study only for study
            au = prev.get('allow_until') if router in ('study', 'default') else None
            su = prev.get('study_until') if router == 'study' else None
        dhc.MEMDB.upsert_reservation({
            'mac': mac, 'ip': ip, 'hostname': hostname,
            'lease_time': lease_time, 'router': router, 'desc': desc,
            'allow_until': au, 'study_until': su,
        })
        _eff, ok, msg = dhc.apply_mac_policy(mac, router, au, su)
        if not ok:
            return (
                f"<script>alert({json.dumps('Saved, but iptables apply failed: ' + (msg or '')[:200])});"
                f"location.href={json.dumps(url_for('devices'))}</script>")
        return redirect(url_for('devices'))

    dhc.MEMDB.sync_leases_from_disk()
    with dhc.MEMDB.lock:
        r = dhc.MEMDB.res_by_mac.get(mac) or dhc.MEMDB.leases_by_mac.get(mac)
        if not r:
            return "<script>alert('not found');history.back();</script>"
    if mac not in dhc.MEMDB.res_by_mac:
        r = dhc.MEMDB.upsert_reservation({
            'mac': mac, 'ip': r.get('ip'), 'hostname': r.get('hostname'),
            'lease_time': r.get('lease_time') or config.DEFAULT_LEASE,
            'router': r.get('router') or 'default',
            'desc': '', 'allow_until': r.get('allow_until'),
            'study_until': r.get('study_until'),
        })
    en = dhc._enrich(r)
    return render_template_string(
        TPL_EDIT, reservation=en, mode=en['mode'], effective=en['effective'], **_ctx())


def _grant_until_from_form():
    """Preset kind=30m|1h|4h|1d, or kind=custom with hours 0..8 + minutes 0/15/30/45."""
    kind = (request.form.get('kind') or '30m').strip().lower()
    if kind == 'custom':
        try:
            h = int(request.form.get('hours') or 0)
            m = int(request.form.get('minutes') or 0)
            return policy.compute_allow_hm(h, m)
        except (TypeError, ValueError) as e:
            raise ValueError(str(e)) from e
    return policy.compute_allow_until(kind)


@app.route('/grant_study/<mac>', methods=['POST'])
@web_auth.login_required
def grant_study(mac):
    """Extend study hours only — effective STUDY (blocks stay)."""
    mac = mac.strip().lower()
    row = dhc.MEMDB.device_row(mac)
    if not row or policy.normalize_mode(row.get('router')) != 'study':
        return "<script>alert('study device only');history.back();</script>"
    try:
        until = _grant_until_from_form()
    except ValueError as e:
        return f"<script>alert({json.dumps(str(e))});history.back();</script>"
    dhc.MEMDB.set_study_until(mac, until)
    _eff, ok, msg = dhc.apply_mac_policy(mac, 'study', study_until=until)
    if not ok:
        return (
            f"<script>alert({json.dumps('Study extend saved, but iptables apply failed: ' + (msg or '')[:200])});"
            f"location.href={json.dumps(url_for('edit_device', mac=mac))}</script>")
    return redirect(url_for('edit_device', mac=mac))


@app.route('/clear_study/<mac>', methods=['POST'])
@web_auth.login_required
def clear_study(mac):
    mac = mac.strip().lower()
    row = dhc.MEMDB.device_row(mac) or {}
    mode = policy.normalize_mode(row.get('router'))
    dhc.MEMDB.set_study_until(mac, None)
    _eff, ok, msg = dhc.apply_mac_policy(mac, mode or 'study', study_until=None)
    if not ok:
        return (
            f"<script>alert({json.dumps('Cleared in DB, but iptables apply failed: ' + (msg or '')[:200])});"
            f"location.href={json.dumps(url_for('edit_device', mac=mac))}</script>")
    return redirect(url_for('edit_device', mac=mac))


@app.route('/grant_allow/<mac>', methods=['POST'])
@web_auth.login_required
def grant_allow(mac):
    """Free time for study or default → temporary ALL_ALLOW."""
    mac = mac.strip().lower()
    row = dhc.MEMDB.device_row(mac)
    mode = policy.normalize_mode(row.get('router') if row else None)
    if not row or mode not in ('study', 'default'):
        return "<script>alert('study or default device only');history.back();</script>"
    try:
        until = _grant_until_from_form()
    except ValueError as e:
        return f"<script>alert({json.dumps(str(e))});history.back();</script>"
    dhc.MEMDB.set_allow_until(mac, until)
    _eff, ok, msg = dhc.apply_mac_policy(mac, mode, allow_until=until)
    if not ok:
        return (
            f"<script>alert({json.dumps('Allow saved, but iptables apply failed: ' + (msg or '')[:200])});"
            f"location.href={json.dumps(url_for('edit_device', mac=mac))}</script>")
    return redirect(url_for('edit_device', mac=mac))


@app.route('/clear_allow/<mac>', methods=['POST'])
@web_auth.login_required
def clear_allow(mac):
    mac = mac.strip().lower()
    row = dhc.MEMDB.device_row(mac) or {}
    mode = policy.normalize_mode(row.get('router')) or 'default'
    dhc.MEMDB.set_allow_until(mac, None)
    _eff, ok, msg = dhc.apply_mac_policy(mac, mode, allow_until=None)
    if not ok:
        return (
            f"<script>alert({json.dumps('Cleared in DB, but iptables apply failed: ' + (msg or '')[:200])});"
            f"location.href={json.dumps(url_for('edit_device', mac=mac))}</script>")
    return redirect(url_for('edit_device', mac=mac))

@app.route('/delete/<mac>')
@web_auth.login_required
def delete_device(mac):
    dhc.MEMDB.delete_reservation(mac.strip().lower())
    return redirect(url_for('devices'))


# ---------- DNS ----------
@app.route('/dns')
@web_auth.login_required
def dns_page():
    cols = ('ip', 'domain')
    sort, direction = _parse_sort(cols, 'domain')
    dns.MEMDB.load_dns_from_disk()
    with dns.MEMDB.lock:
        mappings = list(dns.MEMDB.dns_mappings)
    mappings = _sort_rows(mappings, sort, direction, {
        'ip': lambda m: _ip_sort_key(m.get('ip')),
        'domain': lambda m: m.get('domain') or '',
    })
    sort_urls, sort_marks = _sort_urls('dns_page', cols, sort, direction)
    return render_template_string(
        TPL_DNS, mappings=mappings, bypass=dns.MEMDB.get_bypass(),
        sort_urls=sort_urls, sort_marks=sort_marks, **_ctx())


@app.route('/dns/add', methods=['POST'])
@web_auth.login_required
def add_mapping():
    ip = request.form['ip'].strip()
    domain = request.form['domain'].strip().lower()
    with dns.MEMDB.lock:
        dns.MEMDB.dns_mappings.append({'ip': ip, 'domain': domain})
    dns.MEMDB.sync_dns_to_disk()
    return redirect(url_for('dns_page'))


@app.route('/dns/delete/<ip>/<domain>')
@web_auth.login_required
def delete_mapping(ip, domain):
    with dns.MEMDB.lock:
        dns.MEMDB.dns_mappings = [
            m for m in dns.MEMDB.dns_mappings
            if not (m['ip'] == ip and m['domain'] == domain)
        ]
    dns.MEMDB.sync_dns_to_disk()
    return redirect(url_for('dns_page'))


@app.route('/blocks')
@web_auth.login_required
def blocks_page():
    cols = ('domain', 'enabled', 'sub')
    sort, direction = _parse_sort(cols, 'domain')
    dns.MEMDB.load_dns_from_disk()
    with dns.MEMDB.lock:
        rules = list(dns.MEMDB.block_rules.items())
    rules = _sort_rows(rules, sort, direction, {
        'domain': lambda t: t[0] or '',
        'enabled': lambda t: (t[1] or {}).get('enabled', 0),
        'sub': lambda t: (t[1] or {}).get('block_all_sub', 0),
    })
    sort_urls, sort_marks = _sort_urls('blocks_page', cols, sort, direction)
    return render_template_string(
        TPL_BLOCKS, rules=rules, sort_urls=sort_urls, sort_marks=sort_marks, **_ctx())


@app.route('/blocks/add', methods=['POST'])
@web_auth.login_required
def add_block():
    d = request.form['domain'].strip().lower()
    with dns.MEMDB.lock:
        dns.MEMDB.block_rules[d] = {'enabled': 1, 'block_all_sub': 1, 'note': ''}
    dns.MEMDB.sync_dns_to_disk()
    return redirect(url_for('blocks_page'))


@app.route('/blocks/toggle/<domain>')
@web_auth.login_required
def toggle_block(domain):
    with dns.MEMDB.lock:
        r = dns.MEMDB.block_rules.get(domain)
        if r:
            r['enabled'] = 0 if r.get('enabled') else 1
    dns.MEMDB.sync_dns_to_disk()
    return redirect(url_for('blocks_page'))


@app.route('/blocks/delete/<domain>')
@web_auth.login_required
def delete_block(domain):
    with dns.MEMDB.lock:
        dns.MEMDB.block_rules.pop(domain, None)
    dns.MEMDB.sync_dns_to_disk()
    return redirect(url_for('blocks_page'))


@app.route('/bypass/toggle')
@web_auth.login_required
def toggle_bypass():
    dns.MEMDB.set_bypass(not dns.MEMDB.get_bypass())
    return redirect(url_for('dns_page'))


def _normalize_port_forwards(raw) -> list:
    out = []
    for r in raw or []:
        if not isinstance(r, dict):
            continue
        try:
            out.append({
                'proto': str(r.get('proto', 'tcp')).lower(),
                'wan_port': int(r['wan_port']),
                'dest_ip': str(r.get('dest_ip', '')).strip(),
                'dest_port': int(r['dest_port']),
                'enabled': bool(r.get('enabled', True)),
                'note': str(r.get('note') or ''),
            })
        except (KeyError, TypeError, ValueError):
            continue
    return out


def _apply_firewall():
    return router_ctl.apply_firewall_settings()


@app.route('/firewall', methods=['GET'])
@web_auth.login_required
def firewall_page():
    s = settings_store.get_all()
    return render_template_string(
        TPL_FIREWALL,
        fw_on=bool(s.get('firewall_enabled')),
        forwards=_normalize_port_forwards(s.get('port_forwards')),
        gw=settings_store.gateway_ip(),
        msg=request.args.get('msg'),
        **_ctx())


@app.route('/firewall/save', methods=['POST'])
@web_auth.login_required
def firewall_save():
    on = request.form.get('firewall_enabled', '0') in ('1', 'on', 'true', 'ON')
    settings_store.set_value('firewall_enabled', on)
    ok, out = _apply_firewall()
    log.info(f"[FIREWALL] enabled={on} ok={ok} {out.strip()}")
    return redirect(url_for('firewall_page', msg='Applied' if ok else f'Apply failed: {out[:120]}'))


@app.route('/firewall/add', methods=['POST'])
@web_auth.login_required
def firewall_add():
    proto = (request.form.get('proto') or 'tcp').lower().strip()
    note = (request.form.get('note') or '').strip()
    dest_ip = (request.form.get('dest_ip') or '').strip()
    try:
        wan_port = int(request.form.get('wan_port'))
        dest_port = int(request.form.get('dest_port'))
    except (TypeError, ValueError):
        return "<script>alert('invalid port');history.back();</script>"
    if proto not in ('tcp', 'udp'):
        return "<script>alert('proto tcp|udp');history.back();</script>"
    if not common_ip_ok(dest_ip) or not (1 <= wan_port <= 65535 and 1 <= dest_port <= 65535):
        return "<script>alert('invalid dest/port');history.back();</script>"
    rules = _normalize_port_forwards(settings_store.get('port_forwards'))
    rules.append({
        'proto': proto, 'wan_port': wan_port, 'dest_ip': dest_ip,
        'dest_port': dest_port, 'enabled': True, 'note': note,
    })
    settings_store.set_value('port_forwards', rules)
    ok, out = _apply_firewall()
    return redirect(url_for('firewall_page', msg='Added' if ok else f'Added but apply: {out[:80]}'))


@app.route('/firewall/toggle/<int:idx>')
@web_auth.login_required
def firewall_toggle(idx: int):
    rules = _normalize_port_forwards(settings_store.get('port_forwards'))
    if 0 <= idx < len(rules):
        rules[idx]['enabled'] = not rules[idx].get('enabled', True)
        settings_store.set_value('port_forwards', rules)
        _apply_firewall()
    return redirect(url_for('firewall_page'))


@app.route('/firewall/del/<int:idx>')
@web_auth.login_required
def firewall_del(idx: int):
    rules = _normalize_port_forwards(settings_store.get('port_forwards'))
    if 0 <= idx < len(rules):
        rules.pop(idx)
        settings_store.set_value('port_forwards', rules)
        _apply_firewall()
    return redirect(url_for('firewall_page'))


def common_ip_ok(ip: str) -> bool:
    try:
        import ipaddress
        ipaddress.IPv4Address(ip)
        return True
    except Exception:
        return False


def _parse_block_allow_rules(raw: str) -> tuple[list, str | None]:
    """한 줄/쉼표 구분 proto:ip:port. 성공 시 (rules, None), 실패 시 ([], err)."""
    pat = re.compile(r'^(tcp|udp|any):([0-9.]+(?:/[0-9]+)?):([0-9]+|\*)$', re.I)
    out = []
    for part in (raw or '').replace(',', '\n').splitlines():
        line = part.strip()
        if not line or line.startswith('#'):
            continue
        m = pat.match(line)
        if not m:
            return [], f'invalid rule: {line} (want proto:ip:port)'
        proto, ip, port = m.group(1).lower(), m.group(2), m.group(3)
        if port != '*' and not (1 <= int(port) <= 65535):
            return [], f'invalid port: {line}'
        out.append(f'{proto}:{ip}:{port}')
    return out, None


# ---------- settings ----------
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
                return "<script>alert('password min 4 chars');history.back();</script>"
        allow_rules, allow_err = _parse_block_allow_rules(
            request.form.get('block_allow_rules', ''))
        if allow_err:
            return f"<script>alert({json.dumps(allow_err)});history.back();</script>"
        internal = (request.form.get('internal_device') or '').strip()
        wan = (request.form.get('wan_device') or '').strip()
        auto_s = (request.form.get('dhcp_auto_start') or '').strip()
        auto_e = (request.form.get('dhcp_auto_end') or '').strip()
        if not settings_store.valid_iface_name(internal):
            return "<script>alert('invalid Internal device name');history.back();</script>"
        if not settings_store.valid_iface_name(wan):
            return "<script>alert('invalid WAN device name');history.back();</script>"
        if internal == wan:
            return "<script>alert('Internal and WAN must differ');history.back();</script>"
        try:
            import ipaddress as _ip
            a = _ip.IPv4Address(auto_s)
            b = _ip.IPv4Address(auto_e)
            if int(a) > int(b):
                raise ValueError('range order')
            if a not in config.IP_NETWORK or b not in config.IP_NETWORK:
                raise ValueError('range outside subnet')
        except Exception:
            return "<script>alert('invalid DHCP auto IP range');history.back();</script>"
        try:
            arp_size = int(request.form.get('arp_table_size') or 100)
        except (TypeError, ValueError):
            arp_size = 100
        if arp_size not in settings_store.ARP_TABLE_CHOICES:
            return "<script>alert('invalid ARP table size');history.back();</script>"
        settings_store.set_many({
            'study_schedule_start': request.form.get('study_schedule_start', '00:00').strip(),
            'study_schedule_end': request.form.get('study_schedule_end', '00:00').strip(),
            'new_device_mode': request.form.get('new_device_mode', 'default').strip() or 'default',
            'upstream_dns': request.form.get('upstream_dns', '8.8.8.8').strip(),
            'dns_local_only': bool(request.form.get('dns_local_only')),
            'gateway': request.form.get('gateway', config.GATEWAY).strip(),
            'dns_servers': request.form.get('dns_servers', config.DNS_SERVERS).strip(),
            'internal_device': internal,
            'wan_device': wan,
            'dhcp_auto_start': auto_s,
            'dhcp_auto_end': auto_e,
            'default_block_domains': domains(request.form.get('default_block_domains', '')),
            'study_block_domains': domains(request.form.get('study_block_domains', '')),
            'block_allow_rules': allow_rules,
            'arp_table_size': arp_size,
            'admin_user': new_user,
        })
        if npw:
            settings_store.set_value('admin_password_hash', web_auth.hash_password(npw))
        rt = settings_store.apply_runtime()
        path = router_ctl.write_block_allow_conf(allow_rules)
        ok, msg = router_ctl.refresh_block()
        arp_ok, arp_msg = router_ctl.apply_arp_table_size(arp_size)
        log.info(
            f"[SETTINGS] saved ifaces IN={rt.get('INB')} OUT={rt.get('OUT')} "
            f"mac={rt.get('SERVER_MAC')} ip={rt.get('SERVER_IP')} "
            f"auto={auto_s}-{auto_e} arp={arp_size} ok={arp_ok} "
            f"block_allow -> {path} refresh_ok={ok} {msg.strip()} "
            f"arp_msg={arp_msg.strip()}")
        return redirect(url_for('settings_page'))
    s = settings_store.get_all()
    arp_live = _read_arp_live()
    return render_template_string(
        TPL_SETTINGS, s=s,
        default_domains=', '.join(s.get('default_block_domains') or []),
        study_domains=', '.join(s.get('study_block_domains') or []),
        block_allow_text='\n'.join(s.get('block_allow_rules') or []),
        arp_choices=settings_store.ARP_TABLE_CHOICES,
        arp_live=arp_live,
        restart_msg=request.args.get('restart_msg'),
        **_ctx())


@app.route('/settings/restart', methods=['POST'])
@web_auth.login_required
def restart_stack():
    """Settings NIC 등 반영을 위해 krouterctl restart (detached)."""
    log.info(
        f"[RESTART] requested by UI IN={settings_store.internal_device()} "
        f"WAN={settings_store.wan_device()}")
    router_ctl.schedule_stack_restart(1.0)
    return (
        '<!doctype html><title>Restarting</title>'
        '<p>Restarting stack… wait ~5s then <a href="/login">reload</a>.</p>'
        '<script>setTimeout(function(){location.href="/login"}, 5000)</script>'
    )


@app.route('/api/policy/<mac>')
@web_auth.login_required
def api_policy(mac):
    row = dhc.MEMDB.device_row(mac.strip().lower())
    if not row:
        return jsonify({'error': 'not found'}), 404
    en = dhc._enrich(row)
    return jsonify({
        'mac': mac, 'mode': en['mode'], 'effective': en['effective'],
        'allow_until': en.get('allow_until'),
    })


def main():
    # 통합 UI 전용. DHCP/DNS 패킷 서비스는 dhcp_app / dns_app 을 따로 실행.
    dhc.MEMDB._load_all()
    dns.MEMDB.load_dns_from_disk()
    dns.MEMDB.refresh_dhcp_cache(force=True)
    log.info(
        f"[ADMIN] unified UI http://{config.interface_ip}:{ADMIN_PORT}/ "
        f"SAFE_MODE={config.SAFE_MODE} user/pass default admin/admin")
    app.run(host=config.interface_ip, port=ADMIN_PORT, debug=False, threaded=True)


if __name__ == '__main__':
    main()
