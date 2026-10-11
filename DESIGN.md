# krouter 정책 3모드 + study 임시해금 + 웹 로그인 — 설계서

상태: **work 트리에 구현됨** (`tree/`, SAFE_MODE). 운영본(`/global/bin/krouter`)은 수정하지 않음.  
작성: 2026-09-28  
운영 경로: `/global/bin/krouter` (`~/project/krouter` 심볼릭 링크)  
작업 경로: `/home/kage/project/krouter-work` (여기만 수정·테스트)

---

## 0. 절대 제약

- 현재 라우터는 **가정의 실제 인터넷**이다. 장애 시 숙제·전 집안망이 멈춘다.
- **운영 코드(`/global/bin/krouter`)를 직접 고치지 않는다.**
- 작업은 반드시:
  1. `krouter-work`에 소스 복사
  2. 다른 포트/인터페이스 또는 별도 테스트 환경에서 검증
  3. 문제 없을 때만 운영본에 **교체(복사)**  
- 한 번에 전부 넣지 말고 **단계(phase)별**로 넣고, 각 단계마다 롤백 가능하게 한다.

---

## 1. 목표 요약 (합의된 동작)

### 1.1 장비 모드 3종

| 모드 | 누가 | 동작 |
|------|------|------|
| `default` | **처음 들어온 모르는 MAC** 자동 배정 | 게임·YouTube 등 **기본 차단**, 나머지 통과, 시간 제한 없음 |
| `all_allow` | 관리자가 지정 (내 컴퓨터 등) | **항상** 제약 없음 |
| `study` | 관리자가 지정 (아이들 장비) | **항상** study 제약 (현재 study 수준: DNS 강제, 유튜브/게임 등). 정규 시간대 밖이면 **네트워크 차단**(기존 설계 의도 유지) |

### 1.2 study 임시 해금 (`allow_time`)

- `all_allow` 장비는 임시 해금 개념 없음. **항상 all_allow.**
- `study` 장비만, 필요 시(숙제·늦게까지) **잠시 all_allow처럼** 연다.
- 만료되면 **자동으로 다시 study.**

| 부여 종류 | 예 | 만료 |
|-----------|----|------|
| 기간(분/시간) | 밤 10시에 4시간 | 다음날 새벽 2시까지 all_allow 취급 후 study 복귀 |
| 1일 | 오전 11시에 1일 | **그날 로컬 00:00** 까지 all_allow 취급 후 study 복귀 (24시간 롤링 아님) |

임시 해금 중에는 YouTube 등도 가능해야 함 (= 실효 모드가 all_allow).

### 1.3 웹 UI 보호

- DHCP/DNS 관리 웹에 **user id / password 로그인** 필수.
- 로그인 전에는 설정·해금·모드 변경 불가.

---

## 2. 현재 구조 (기준점)

운영본 요약:

- `dhcp_app.py`: DHCP + Flask UI(:5000) + MemDB ↔ `dhcp_leases.db`
- `dns_app.py`: DNS(:53) + Flask UI(:5001) + MemDB ↔ `dns_records.db` + DHCP DB 읽기
- `router.sh`: NAT/FORWARD + MAC → `STUDY` 체인 (`add`/`del`)
- reservation `router=study` → 부팅/UI에서 `router.sh add <mac>`
- DNS는 `router=study` IP만 도메인 차단

사실상 지금: **study vs 무제한(미등록)** 2모드.  
`DEFAULTFREE` 체인은 있으나 실질 미사용.

---

## 3. 목표 아키텍처

```
[장비 MAC]
    │
    ▼
DHCP reservation.mode  = default | all_allow | study
DHCP reservation.allow_until = NULL | unix timestamp   (study만 의미 있음)
    │
    ▼
effective_mode() 계산
    │
    ├── iptables: MAC → DEFAULT | ALL_ALLOW | STUDY | BLOCK 체인
    └── DNS:      normal / light-block / study-block / (offhours면 전면 거부 보조)
```

### 3.1 실효 모드

```
if mode == all_allow:
    effective = ALL_ALLOW
elif mode == default:
    effective = DEFAULT
elif mode == study:
    if allow_until is set and now < allow_until:
        effective = ALL_ALLOW          # 임시 해금
    elif now outside study_schedule:
        effective = BLOCK              # 정규 시간 외 전면 차단
    else:
        effective = STUDY
```

참고: 임시 해금 중에는 **정규 시간 외 BLOCK도 덮어씀** (늦게까지 열어주는 목적과 일치).

### 3.2 iptables 체인 (4개)

| 체인 | 내용 |
|------|------|
| `ALL_ALLOW` | RETURN만 (무제한) |
| `DEFAULT` | 게임 대표 포트 + YouTube/관련 문자열·QUIC 등 **가벼운** 차단. UDP 전면 차단은 넣지 않음(신규 장비 과도 차단 방지) |
| `STUDY` | 현 `router.sh` STUDY 수준 (DNS 강제, 유튜브, UDP 광역, 게임 포트 등) |
| `BLOCK` | 필수(DHCP/로컬 DNS/로컬망)만 허용, 그 외 REJECT — study 시간 외 |

`router.sh` API 방향:

- `init` — 베이스 NAT + 4 체인 정의
- `set <mac> <ALL_ALLOW|DEFAULT|STUDY|BLOCK>` — MAC당 점프 1개만 유지
- (호환) `add`/`del`은 내부적으로 `set` 래핑 가능

### 3.3 신규 MAC → default

- DHCP DISCOVER/REQUEST로 **처음 리스 생성** 시 `router='default'` 로 저장.
- 동시에 `router.sh set <mac> DEFAULT` (또는 워처가 동기화).
- 관리자가 UI에서 `all_allow` / `study` 로만 승격.

### 3.4 allow_until 저장·만료

- DB 컬럼(또는 동등 필드): `allow_until INTEGER NULL`
- 부여:
  - N분/N시간: `allow_until = now + duration`
  - 1일: `allow_until = 오늘 로컬 자정(다음 00:00:00)`  
    - 예: 11:00에 1일 → 당일 24:00(다음날 0시)까지
- **재부여**: 새 값으로 덮어쓰기 (남은 시간 가산 없음 — 단순·예측 가능)
- **만료 워처** (dhcp 쪽 백그라운드, 30~60초):
  - `allow_until <= now` → NULL로 클리어 → `effective` 재계산 → iptables `set` → DNS 캐시 갱신 트리거
- 프로세스 재시작/재부팅: DB의 `allow_until`·`mode`로 iptables 일괄 재적용

iptables `-m time`만으로는 “지금+4시간”을 표현하기 어려우므로 **워처 필수**.

### 3.5 DNS 정책

| effective | DNS |
|-----------|-----|
| ALL_ALLOW | 차단 없음 (업스트림/로컬 매핑만) |
| DEFAULT | 짧은 차단 리스트 (youtube/게임 관련) |
| STUDY | 현 study 차단 리스트 |
| BLOCK | 전면 NXDOMAIN/센티넬(보조). 본차단은 iptables |

`client_policy`는 reservation/lease의 `mode`+`allow_until`+스케줄로 effective 계산.

### 3.6 웹 로그인

- Flask: 세션 기반 로그인 (dhcp UI, dns UI 각각 또는 공통 시크릿)
- 계정: 설정 파일 또는 DB에 **password hash** (평문 금지)
- 모든 변경 API·폼에 로그인 필수
- 초기 비밀번호는 설치/문서에만, 첫 로그인 후 변경 권장
- (선택) 내부 LAN에서만 UI 포트 노출 — 이미 INPUT 제한과 맞춤

---

## 4. 데이터 모델 (최소 변경)

`reservations` (및 필요 시 leases와 동기 정책 명시):

| 필드 | 의미 |
|------|------|
| `mac` | PK |
| `ip`, `hostname`, … | 기존 |
| `router` → 의미 확장 | `default` \| `all_allow` \| `study` (기존 `default`/`study` 마이그레이션 필요) |
| `allow_until` | NULL 또는 unix ts (study 임시해금) |

기존에 `router=default`가 “게이트웨이 기본/사실상 자유”였다면:

- 마이그레이션: **기존 default → `all_allow`** 로 옮길지, **default(약차단)로 둘지** 운영 전에 한 번 결정.
- 권장: “내 PC로 쓰던 것”은 `all_allow`로 명시 이관, 나머지 미지정·신규만 새 `default`.

`configs` 또는 별도 파일:

- study 허용 시간대 (예: 시작/종료, TZ=local)
- 웹 계정 hash
- DEFAULT/STUDY 차단 도메인 리스트 (DNS와 iptables 문자열 목록의 단일 소스 이상적)

---

## 5. 동기화 (장애 포인트 1순위)

모드 변경·해금·만료·부팅 경로를 **하나의 `apply_policy(mac)`** 로 통일:

1. DB에서 mode/allow_until 읽기  
2. effective 계산  
3. `router.sh set`  
4. DNS MemDB 갱신(트리거 파일 또는 공유 DB 필드)

불일치 시 증상: “DNS만 막힘 / 패킷만 막힘”.  
모니터링: UI에 장비별 **DB mode / allow_until / effective / iptables 체인** 표시(읽기 전용) 권장.

---

## 6. 작업·배포 방식 (필수)

### 6.1 디렉터리

| 경로 | 역할 |
|------|------|
| `/global/bin/krouter` | **운영 — 읽기만, 평소 수정 금지** |
| `/home/kage/project/krouter-work` | 설계 문서 + **복사본 개발·테스트** |

### 6.2 개발 절차

1. 운영본을 `krouter-work/tree/` 등으로 **복사** (db·로그는 복사하지 않거나 마스킹).
2. 복사본에서만 코드 수정.
3. 테스트 시:
   - UI 포트를 **5000/5001이 아닌 다른 포트**로 띄우거나
   - 가능하면 별도 NIC/VM/미러 환경
   - DNS(:53)·DHCP(:67)는 **운영과 동시에 띄우지 않음** (포트 충돌·이중 DHCP 위험)
4. 단위적으로 검증 가능한 것부터: 정책 계산 함수 → router.sh set 시뮬 → UI 로그인 → (마지막) 실기 전환.

### 6.3 운영 전환

1. 짧은 점검 창 (가능하면 아이들 비사용 시간)
2. 설정·DB 백업
3. 복사본에서 검증된 파일만 운영 경로로 교체
4. `router.sh init` + 예약 MAC 일괄 `set` + 서비스 재시작
5. 스모크: all_allow PC / default 신규 / study / 임시해금·만료
6. 문제 시 **백업본 즉시 롤백**

### 6.4 Phase (제안)

| Phase | 내용 | 운영 리스크 |
|-------|------|-------------|
| P0 | 문서·work 복사·백업 스크립트 | 없음 |
| P1 | 웹 로그인만 (동작 동일) | 낮음 |
| P2 | 체인 4개 + `set` API, 기존 study/자유 동등 동작 유지 | 중 (신중 테스트) |
| P3 | `default` 약차단 + 신규 MAC default | 중 |
| P4 | DNS effective 연동 | 중 |
| P5 | study 스케줄 → BLOCK | 중 |
| P6 | allow_until + 워처 + UI 해금 | 중 |
| P7 | 정리·모니터링·문서 확정 | 낮음 |

**한 번에 P1~P6을 운영에 넣지 않는다.**

---

## 7. 테스트 체크리스트 (요지)

- [ ] 신규 MAC → reservation `default` + DEFAULT 체인
- [ ] all_allow MAC → 유튜브/게임 가능, 재부팅 후에도 유지
- [ ] study MAC → 현 수준 차단, 로컬 DNS만
- [ ] study 시간 외 → BLOCK (임시해금 없을 때)
- [ ] study + 4시간 해금 → 만료 시각까지 유튜브 가능 → 자동 study 복귀
- [ ] study + 1일 해금 → 자정 지나면 study (23:50 부여 시 약 10분만 — 의도 확인됨)
- [ ] 해금 중 재부팅 → 남은 시간이 있으면 계속 ALL_ALLOW
- [ ] UI 비로그인 시 설정 불가
- [ ] dhcp/dns 프로세스 재시작 후 iptables와 DB 일치
- [ ] 롤백 절차 1회 실습

---

## 8. 의도적으로 넣지 않는 것 (이번 범위 밖)

- “느린망(이메일만)” — 요청은 **시간 외 차단**이므로 tc 쉐이핑은 제외
- DoH/VPN 완전 차단 고도화 — 기존 한계 유지, 필요 시 후속
- `router_bak/` 정리 — 운영과 무관, 건드리지 않음

---

## 9. 확정된 이해 (한 줄씩)

1. 모르는 MAC이 처음 오면 → **default** (약차단).
2. 내 PC 등은 → **all_allow** (항상 무제한).
3. 애들 장비 → **study** (항상 study 제약 + 스케줄 외 차단).
4. study만 → 시간/1일 **임시 all_allow**, 만료 시 **자동 study 복귀**.
5. 관리 웹 → **로그인 필수**.
6. 구현은 **work 디렉터리 복사본**에서, 충분히 테스트 후만 운영 교체.
7. **지금은 설계만. 운영 코드 수정 없음.**

---

## 10. 구현 착수 전 확인 사항 (소수)

설계는 위 mid로 진행 가능. 착수 직전에만 확인:

1. study **정규 허용 시간대** 기본값 (예: 매일 HH:MM–HH:MM, 로컬 TZ).
2. 기존 DB에서 `router=default`/빈 값/`study`를 새 의미로 **어떻게 이관**할지.
3. 로그인 계정 개수 (단일 admin이면 충분할지).
4. dhcp UI / dns UI 비밀번호를 **공유할지 분리할지**.

---

## 11. 다음 액션 (코드 없음)

- [ ] 이 문서 검토·수정 의견 반영
- [ ] 확인 사항 4가지 답변
- [ ] 동의 후: `krouter-work/tree/`에 운영 소스 **복사만** (실행·교체 없음)
- [ ] Phase P1부터 작업
