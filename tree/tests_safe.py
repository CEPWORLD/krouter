#!/usr/bin/env python3
"""
tests_safe.py — SAFE unit tests (no DHCP sniff / DNS :53 / live iptables).

Author : Kage
Project: krouter
"""
import os
import subprocess
import sys
from datetime import datetime, timedelta

ROOT = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, ROOT)
os.environ['KROUTER_SAFE_MODE'] = '1'
os.chdir(ROOT)

import policy
import web_auth
import config
import router_ctl
import settings_store


def test_normalize_mode():
    assert policy.normalize_mode(None) == 'default'
    assert policy.normalize_mode('study') == 'study'
    assert policy.normalize_mode('all_allow') == 'all_allow'
    assert policy.normalize_mode('DEFAULT') == 'default'
    print('OK normalize_mode')


def test_allow_until_duration():
    now = datetime(2026, 9, 28, 22, 0, 0)
    until = policy.compute_allow_until('4h', now=now)
    assert until == int((now + timedelta(hours=4)).timestamp())
    until30 = policy.compute_allow_until('30m', now=now)
    assert until30 == int((now + timedelta(minutes=30)).timestamp())
    print('OK allow duration (22:00 + 4h)')


def test_allow_until_1d_midnight():
    now = datetime(2026, 9, 28, 11, 0, 0)
    until = policy.compute_allow_until('1d', now=now)
    end = datetime(2026, 9, 29, 0, 0, 0)
    assert until == int(end.timestamp())
    print('OK allow 1d until local midnight')


def test_effective_modes():
    assert policy.effective_mode('all_allow') == 'ALL_ALLOW'
    assert policy.effective_mode('default') == 'DEFAULT'
    noon = int(datetime(2026, 9, 28, 12, 0).timestamp())
    night = int(datetime(2026, 9, 28, 23, 0).timestamp())
    assert policy.effective_mode('study', None, now_ts=noon,
                                 study_start='06:00', study_end='22:00') == 'STUDY'
    assert policy.effective_mode('study', None, now_ts=night,
                                 study_start='06:00', study_end='22:00') == 'BLOCK'
    future = night + 3600
    assert policy.effective_mode('study', allow_until=future, now_ts=night,
                                 study_start='06:00', study_end='22:00') == 'ALL_ALLOW'
    past = night - 10
    assert policy.effective_mode('study', allow_until=past, now_ts=night,
                                 study_start='06:00', study_end='22:00') == 'BLOCK'
    print('OK effective modes')


def test_dns_policy_labels():
    assert policy.dns_policy_for_effective('ALL_ALLOW') == 'none'
    assert policy.dns_policy_for_effective('DEFAULT') == 'default_block'
    assert policy.dns_policy_for_effective('STUDY') == 'study_block'
    assert policy.dns_policy_for_effective('BLOCK') == 'block_all'
    print('OK dns policy labels')


def test_password_and_settings():
    h = web_auth.hash_password('secret')
    assert web_auth.verify_password('secret', h)
    assert not web_auth.verify_password('wrong', h)
    settings_store.set_value('study_schedule_start', '07:00')
    assert settings_store.get('study_schedule_start') == '07:00'
    settings_store.set_value('study_schedule_start', '06:00')
    print('OK password + settings store')


def test_router_dry_run():
    assert config.SAFE_MODE is True
    ok, msg = router_ctl.apply_chain('aa:bb:cc:dd:ee:ff', 'STUDY')
    assert ok and 'DRY_RUN' in msg
    print('OK router_ctl dry-run')


def test_router_sh_syntax_and_dry():
    script = os.path.join(ROOT, 'router.sh')
    syn = subprocess.run(['bash', '-n', script], capture_output=True, text=True)
    assert syn.returncode == 0, syn.stderr
    env = os.environ.copy()
    env['KROUTER_DRY_RUN'] = '1'
    r = subprocess.run(['bash', script, 'set', 'aa:bb:cc:dd:ee:ff', 'DEFAULT'],
                       env=env, capture_output=True, text=True)
    assert r.returncode == 0, r.stderr + r.stdout
    assert 'aa:bb:cc:dd:ee:ff' in r.stdout and 'DEFAULT' in r.stdout
    print('OK router.sh bash -n and dry set')


def test_dns_block_decision_without_socket():
    """MemDB 판정만. 소켓 bind / 업스트림 질의 없음."""
    import dns_app
    s = settings_store.get_all()
    # 미등록 IP → default → youtube 차단
    assert dns_app.MEMDB.is_blocked_for_client('www.youtube.com', '192.168.0.50') is True
    assert dns_app.MEMDB.is_blocked_for_client('example.com', '192.168.0.50') is False
    print('OK dns block decision (no socket), domains=', len(s.get('default_block_domains') or []))


def test_flask_login_no_listen():
    """test_client 는 포트를 열지 않는다."""
    settings_store.set_value('admin_user', config.ADMIN_USER)
    settings_store.set_value('admin_password_hash', web_auth.hash_password(config.ADMIN_PASSWORD))
    import dhcp_app
    c = dhcp_app.app.test_client()
    r = c.get('/')
    assert r.status_code in (302, 303)
    assert '/login' in (r.headers.get('Location') or '')
    bad = c.post('/login', data={'username': 'admin', 'password': 'nope'})
    assert b'Invalid' in bad.data
    ok = c.post('/login', data={'username': config.ADMIN_USER, 'password': config.ADMIN_PASSWORD},
                follow_redirects=True)
    assert ok.status_code == 200
    assert b'Add Reservation' in ok.data
    print('OK flask login via test_client (no bind)')


if __name__ == '__main__':
    test_normalize_mode()
    test_allow_until_duration()
    test_allow_until_1d_midnight()
    test_effective_modes()
    test_dns_policy_labels()
    test_password_and_settings()
    test_router_dry_run()
    test_router_sh_syntax_and_dry()
    test_dns_block_decision_without_socket()
    test_flask_login_no_listen()
    print('\nALL SAFE TESTS PASSED')
