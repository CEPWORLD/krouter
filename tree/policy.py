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

MODES = ('default', 'all_allow', 'study')
CHAINS = ('DEFAULT', 'ALL_ALLOW', 'STUDY', 'BLOCK')


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
    """표시용 모드: default|all_allow|study|custom."""
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
    1d → 다음 로컬 자정(오늘이 아직이면 오늘 24:00 = 내일 00:00)
    """
    now = now or datetime.now()
    k = kind.strip().lower()
    if k in ('1d', 'day', '1day'):
        tomorrow = (now + timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
        # 이미 자정이면 바로 만료 방지: 다음 자정
        if tomorrow <= now:
            tomorrow = tomorrow + timedelta(days=1)
        # 오늘 남은 구간: 다음날 00:00
        end = now.replace(hour=0, minute=0, second=0, microsecond=0) + timedelta(days=1)
        return int(end.timestamp())
    if k.endswith('m') and k[:-1].isdigit():
        return int((now + timedelta(minutes=int(k[:-1]))).timestamp())
    if k.endswith('h') and k[:-1].isdigit():
        return int((now + timedelta(hours=int(k[:-1]))).timestamp())
    raise ValueError(f'unsupported allow kind: {kind}')


def in_study_schedule(now: Optional[datetime] = None,
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
                   study_until: Optional[int] = None) -> str:
    """
    반환: ALL_ALLOW | DEFAULT | STUDY | BLOCK

    study 장비:
      allow_until 유효 → ALL_ALLOW (Free time)
      정규 스케줄 안이거나 study_until 유효 → STUDY (Extend study: 차단 유지, BLOCK만 해제)
      그 외 → BLOCK
    custom GW → ALL_ALLOW.
    """
    kind = normalize_mode(mode, gateway)
    now_ts = int(now_ts if now_ts is not None else datetime.now().timestamp())

    if kind in ('all_allow', 'custom'):
        return 'ALL_ALLOW'
    if kind == 'default':
        return 'DEFAULT'
    # Free time first (full unblock)
    if _ts_active(allow_until, now_ts):
        return 'ALL_ALLOW'
    now_dt = datetime.fromtimestamp(now_ts)
    if in_study_schedule(now_dt, study_start, study_end) or _ts_active(study_until, now_ts):
        return 'STUDY'
    return 'BLOCK'


# alias — same duration helper for Free time / Extend study buttons
compute_study_until = compute_allow_until


def dns_policy_for_effective(effective: str) -> str:
    """DNS 측 정책 라벨: none | default_block | study_block | block_all"""
    return {
        'ALL_ALLOW': 'none',
        'DEFAULT': 'default_block',
        'STUDY': 'study_block',
        'BLOCK': 'block_all',
    }.get(effective, 'none')


def pick_offer_gateway(mode_field: Optional[str], gateway: str) -> str:
    """DHCP 옵션으로 내려줄 gateway IP. custom 은 해당 IP 유지."""
    kind = normalize_mode(mode_field, gateway)
    if kind == 'custom':
        return str(mode_field).strip()
    return gateway
