"""
policy.py — mode / allow_until / study schedule → effective chain + DNS label.

Author : Kage
Project: krouter
Thought: the hard part is not "block YouTube" — it is agreeing on study hours,
         then still being able to grant homework time or a short free window
         without rewriting the whole router config.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, time as dtime, timedelta
from typing import Optional

MODES = ('default', 'all_allow', 'study', 'iot')
CHAINS = ('DEFAULT', 'ALL_ALLOW', 'STUDY', 'BLOCK', 'IOT')


@dataclass
class PolicySettings:
    study_start: str = '06:00'   # HH:MM local
    study_end: str = '22:00'     # HH:MM local
    new_device_mode: str = 'default'


def _parse_hhmm(s: str) -> dtime:
    hh, mm = s.strip().split(':')
    return dtime(int(hh), int(mm))


def _is_ipv4(value: str) -> bool:
    try:
        ipaddress.IPv4Address(value)
        return True
    except Exception:
        return False


def normalize_mode(raw: Optional[str], gateway: str = '192.168.0.1') -> str:
    """표시용 모드: default|all_allow|study|iot|custom."""
    if not raw:
        return 'default'
    v = str(raw).strip()
    low = v.lower()
    if low in MODES:
        return low
    if low in ('', 'gateway') or v == gateway:
        return 'default'
    if _is_ipv4(v):
        return 'custom'
    return 'default'


def compute_allow_until(kind: str, now: Optional[datetime] = None) -> int:
    """
    kind: '30m' | '1h' | '4h' | '1d' | 또는 '<N>m' / '<N>h'
    1d → 다음 로컬 자정(오늘 남은 구간 → 내일 00:00)
    """
    now = now or datetime.now()
    k = kind.strip().lower()
    if k in ('1d', 'day', '1day'):
        end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        if end <= now:
            end = end + timedelta(days=1)
        return int(end.timestamp())
    if k.endswith('m') and k[:-1].isdigit():
        return int((now + timedelta(minutes=int(k[:-1]))).timestamp())
    if k.endswith('h') and k[:-1].isdigit():
        return int((now + timedelta(hours=int(k[:-1]))).timestamp())
    raise ValueError(f'unsupported allow kind: {kind}')


def compute_allow_hm(hours: int, minutes: int, now: Optional[datetime] = None) -> int:
    """Custom Free time: hours 0..8, minutes in {0,15,30,45}. At least 15m total."""
    now = now or datetime.now()
    h = int(hours)
    m = int(minutes)
    if h < 0 or h > 8:
        raise ValueError('hours must be 0..8')
    if m not in (0, 15, 30, 45):
        raise ValueError('minutes must be 0, 15, 30, or 45')
    total_m = h * 60 + m
    if total_m < 15:
        raise ValueError('duration must be at least 15 minutes')
    return int((now + timedelta(minutes=total_m)).timestamp())


def in_schedule(now: Optional[datetime] = None,
                start: str = '06:00',
                end: str = '22:00') -> bool:
    """로컬 시각이 [start, end) 이면 True. start==end 이면 24h 허용."""
    now = now or datetime.now()
    t = now.time().replace(second=0, microsecond=0)
    s = _parse_hhmm(start)
    e = _parse_hhmm(end)
    if s == e:
        return True
    if s < e:
        return s <= t < e
    # 자정 넘어가는 허용 구간 (예: 22:00~06:00)
    return t >= s or t < e


# back-compat name
in_study_schedule = in_schedule


def _ts_active(ts: Optional[int], now_ts: int) -> bool:
    if ts is None:
        return False
    try:
        return int(ts) > now_ts
    except (TypeError, ValueError):
        return False


def effective_mode(mode: str,
                   allow_until: Optional[int] = None,
                   now_ts: Optional[int] = None,
                   study_start: str = '06:00',
                   study_end: str = '22:00',
                   gateway: str = '192.168.0.1',
                   study_until: Optional[int] = None,
                   default_start: str = '00:00',
                   default_end: str = '00:00') -> str:
    """
    반환: ALL_ALLOW | DEFAULT | STUDY | BLOCK | IOT

    allow_until 유효 → ALL_ALLOW (Free time) for study *and* default.
    iot: always IOT (no schedule; IoT plugs/cams — open + light entertainment block).
    study: in schedule or study_until → STUDY, else BLOCK.
    default: in schedule → DEFAULT, else BLOCK (start==end → 24h DEFAULT).
    custom GW → ALL_ALLOW.
    """
    kind = normalize_mode(mode, gateway)
    now_ts = int(now_ts if now_ts is not None else datetime.now().timestamp())

    if kind in ('all_allow', 'custom'):
        return 'ALL_ALLOW'
    # Free time (YouTube/games) — temporary ALL_ALLOW, then back to base mode
    if _ts_active(allow_until, now_ts):
        return 'ALL_ALLOW'
    if kind == 'iot':
        return 'IOT'
    now_dt = datetime.fromtimestamp(now_ts)
    if kind == 'default':
        if in_schedule(now_dt, default_start, default_end):
            return 'DEFAULT'
        return 'BLOCK'
    # study
    if in_schedule(now_dt, study_start, study_end) or _ts_active(study_until, now_ts):
        return 'STUDY'
    return 'BLOCK'


# alias — same duration helper for Free time / Extend study buttons
compute_study_until = compute_allow_until


def dns_policy_for_effective(effective: str) -> str:
    """DNS 측 정책 라벨: none | default_block | study_block | iot_block | block_all"""
    return {
        'ALL_ALLOW': 'none',
        'DEFAULT': 'default_block',
        'STUDY': 'study_block',
        'IOT': 'iot_block',
        'BLOCK': 'block_all',
    }.get(effective, 'none')


def pick_offer_gateway(mode_field: Optional[str], gateway: str) -> str:
    """DHCP 옵션으로 내려줄 gateway IP. custom 은 해당 IP 유지."""
    kind = normalize_mode(mode_field, gateway)
    if kind == 'custom':
        return str(mode_field).strip()
    return gateway
