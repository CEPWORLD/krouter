# common.py — shared DHCP/IP helpers for krouter.
#
# Author : Kage
# Project: krouter
# Thought: auto-assign only from the Settings auto pool; reserved IPs anywhere
#          in the subnet stay sticky until a human deletes them.
#
import ipaddress
import sqlite3
import time
import threading
from scapy.all import sniff, sendp, BOOTP, DHCP, Ether, IP, UDP, raw, get_if_hwaddr
import netifaces
import subprocess
import config
from kmport import *

def ip_addr(ip):
    return IpV4(ip)

def mac_addr(mac):
    return MacV4(mac)

def is_ip_alive(ip,log=None):
    try:
        if ip:
            # -c 1 = send 1 ping, -W 1 = 1 second timeout (Linux)
            output = subprocess.run(["ping", "-c", "1", "-W", "3", ip],stdout=subprocess.DEVNULL, timeout=5)
            return output.returncode == 0
        else:
            return False
    except Exception as e:
        if log:
            log.debug(f'[ERROR] Failed Ping : {str(e)}')
        return False

# Dynamic SERVER_IP retrieval
def get_interface_mac(interface,log=None):
    try:
        return get_if_hwaddr(interface)
    except Exception as e:
        if log:
            log.debug(f"[ERROR] Failed to get IP for {interface}: {str(e)}")
        return None

def get_interface_ip(interface,netmask='255.255.255.0',network=None,log=None):
    try:
        if interface not in netifaces.interfaces():
            raise Exception(f"Interface {interface} does not exist")
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET not in addrs:
            raise Exception(f"No IPv4 address found for {interface}")
        ip = addrs[netifaces.AF_INET][0]['addr']
        if network:
            IP_NETWORK = ipaddress.IPv4Network(f'{network}/{netmask}',strict=False)
        else:
            IP_NETWORK = ipaddress.IPv4Network(f'{ip}/{netmask}',strict=False)
        if not ipaddress.IPv4Address(ip) in IP_NETWORK:
            raise Exception(f"IP {ip} for {interface} is not in {IP_NETWORK}")
        if log:
            log.debug(f"[DEBUG] Retrieved IP for {interface}: {ip}")
        return ip
    except Exception as e:
        if log:
            log.debug(f"[ERROR] Failed to get IP for {interface}: {str(e)}")
        return None

# ===============================
# DB Handler
# ===============================
def get_db():
    db = sqlite3.connect(config.dhcp_db_file, check_same_thread=True)
    db.row_factory = sqlite3.Row
    return db

def close_db(db,log=None):
    try:
        if db is not None:
            db.close()
            if log:
                log.debug(f"[DEBUG] Database connection closed")
    except Exception as e:
        if log:
            log.debug(f"[ERROR] Failed to close database: {str(e)}")

def ip_to_int(ip):
    if isinstance(ip,str):
        return int(ipaddress.IPv4Address(ip))
    return int(ip)

def ip_to_str(int_ip):
    if isinstance(int_ip,int):
        return str(ipaddress.IPv4Address(int_ip))
    return str(int_ip)

def ip_range(start=config.IP_RANGE_START,end=config.IP_RANGE_END):
    return ip_to_int(start),ip_to_int(end)

def ip_in_range(ip):
    try:
        start,end=ip_range(config.IP_RANGE_START,config.IP_RANGE_END)
        return start <= ip_to_int(ip) <= end
    except:
        return False

def ip_in_temp(ip):
    try:
        start,end=ip_range(config.IP_TEMP_START,config.IP_TEMP_END)
        return start <= ip_to_int(ip) <= end
    except:
        return False

def ip_in_network(ip):
    try:
        return ipaddress.IPv4Address(ip) in config.IP_NETWORK
    except ValueError:
        print(f"[ERROR] Invalid IP address: {ip}")
        return False

def find_free_ip(pool,log=None):
    """신규 장비용: Settings dhcp_auto_start~end (없으면 IP_TEMP_*) 안에서만 빈 IP 선택.
    reservation/lease 로 이미 잡힌 IP 는 pool 에 있어 건너뜀."""
    try:
        import settings_store
        a_start, a_end = settings_store.dhcp_auto_range()
    except Exception:
        a_start, a_end = str(config.IP_TEMP_START), str(config.IP_TEMP_END)
    try:
        start,end=ip_range(a_start, a_end)
        for ip in range(start,end+1):
            ip_s=ip_to_str(ip)
            if ip_s not in pool:
                if log:
                    log.info(f"[INFO] Found free new available IP {ip_s} (auto {a_start}-{a_end})")
                return ip_s
    except Exception:
        pass
    if log:
        log.debug("[WARN] No free IP available in auto range")
    return False

def get_all_assigned_ips(db):
    try:
        rows = db.execute('SELECT ip FROM leases').fetchall()
        leased = {row['ip'] for row in rows}
        rows = db.execute('SELECT ip FROM reservations').fetchall()
        reserved = {row['ip'] for row in rows}
        return leased | reserved
    except Exception as e:
        app_log.debug(f"[ERROR] get_all_assigned_ips failed: {str(e)}")
        return set()

def free_ip_num(*pools,db=None):
    cnt=0
    pool=set()
    start,end=ip_range(config.IP_RANGE_START,config.IP_RANGE_END)
    if pools:
        for p in pools:
            pool = pool | {row['ip'] for row in p}
    elif db:
        pool=get_all_assigned_ips(db)
    if pool:
        for ip in range(start,end+1):
            ip_s=ip_to_str(ip)
            if ip_s not in pool:
                cnt+=1
    return cnt

def is_router(db,ip=None):
    if ip:
        row = db.execute('SELECT ip FROM routers WHERE ip = ?',(ip,)).fetchone()
        if row:
            return True
        return False
    else:
        rows = db.execute('SELECT ip FROM routers').fetchall()
        out=[]
        if rows:
            for r in rows:
                i=r[0]
                if i: out.append(i)
            return out
        else:
            return [config.GATEWAY]



# ===============================
# DHCP Handler
# ===============================
#DHCP_DISCOVER = 1
#DHCP_OFFER = 2
#DHCP_REQUEST = 3
#DHCP_DECLINE = 4
#DHCP_ACK = 5
#DHCP_NAK = 6
#DHCP_RELEASE = 7
#DHCP_INFORM = 8

def make_dhcp_nak(xid, chaddr):
    return Ether(src=config.SERVER_MAC, dst="ff:ff:ff:ff:ff:ff") / \
           IP(src=config.SERVER_IP, dst="255.255.255.255") / \
           UDP(sport=67, dport=68) / \
           BOOTP(op=2, siaddr=config.SERVER_IP, chaddr=chaddr, xid=xid) / \
           DHCP(options=[
               ("message-type", "nak"),
               ("server_id", config.SERVER_IP),
               "end"
           ])

def make_dhcp_offer(yiaddr, xid, chaddr, dns, gateway, lease_time, hostname=None):
    options=[
            ("message-type", "offer"),
            ("server_id", config.SERVER_IP),
            ("subnet_mask", config.SUBNET_MASK),
            ("router", gateway),
            ("lease_time", lease_time),
            ("name_server", dns)
            ]
    if hostname:
        options.append(("hostname",hostname))
    options.append("end")

    return Ether(src=config.SERVER_MAC, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src=config.SERVER_IP, dst="255.255.255.255") / \
        UDP(sport=67, dport=68) / \
        BOOTP(op=2, yiaddr=yiaddr, siaddr=config.SERVER_IP, chaddr=chaddr, xid=xid) / \
        DHCP(options=options)

def make_dhcp_ack(yiaddr, xid, chaddr, dns, gateway, lease_time,hostname=None):
    options=[
            ("message-type", "ack"),
            ("server_id", config.SERVER_IP),
            ("subnet_mask", config.SUBNET_MASK),
            ("router", gateway),
            ("lease_time", lease_time),
            ("name_server", dns)
            ]
    if hostname:
        options.append(("hostname",hostname))
    options.append("end")

    return Ether(src=config.SERVER_MAC, dst="ff:ff:ff:ff:ff:ff") / \
        IP(src=config.SERVER_IP, dst="255.255.255.255") / \
        UDP(sport=67, dport=68) / \
        BOOTP(op=2, yiaddr=yiaddr, siaddr=config.SERVER_IP, chaddr=chaddr, xid=xid) / \
        DHCP(options=options)

def seconds_to_human(seconds):
    if isinstance(seconds,int):
        seconds = int(seconds)
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)

        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0 or days > 0:
            parts.append(f"{hours}h")
        if minutes > 0 or hours > 0 or days > 0:
            parts.append(f"{minutes}m")
        parts.append(f"{seconds}s")

        return ' '.join(parts)
    return '0'

def seconds_to_date(seconds, fmt="%Y-%m-%d %H:%M:%S"):
    if isinstance(seconds,int):
        return TIME().Format(tformat="%Y-%m-%d %H:%M:%S",time=seconds)
    return ''

# Validate domain name (basic regex for DNS names)
def is_valid_domain(domain):
    pattern = r'^[a-zA-Z0-9][a-zA-Z0-9-\.]*[a-zA-Z0-9]$'
    return bool(re.match(pattern, domain)) and len(domain) <= 255
