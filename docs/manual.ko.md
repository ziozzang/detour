# detour — 한국어 사용 설명서

> `detour`는 iptables DNAT과 `/etc/hosts` 임시 항목을 사용해 **트래픽을
> 실시간으로 우회**시키는 리눅스용 데몬과 CLI 도구입니다. 데몬은
> JSON HTTP API를 Unix-domain socket으로 노출하며, 선택적으로 TCP
> 포트로도 열 수 있습니다. 별도의 외부 의존성 없이 Go 표준 라이브러리만
> 사용해 빌드됩니다.

본 문서는 `README.md`의 보조 자료가 아닌, 한국어 사용자에게 깊이 있는
운영 정보를 제공할 목적으로 작성되었습니다. 영어 README와 중복되는
부분도 일부 있지만, 한국어 매뉴얼만 읽어도 운영이 가능하도록 모든
주요 항목을 포함했습니다.

---

## 목차

1. [빠른 시작](#1-빠른-시작)
2. [설계 개요](#2-설계-개요)
3. [`detourd` (데몬) 옵션 상세](#3-detourd-데몬-옵션-상세)
4. [`detour` (CLI) 사용법](#4-detour-cli-사용법)
5. [토큰 기반 인증](#5-토큰-기반-인증)
6. [systemd 서비스 등록](#6-systemd-서비스-등록)
7. [웹 UI 사용법](#7-웹-ui-사용법)
8. [내부 동작 — iptables와 /etc/hosts](#8-내부-동작--iptables와-etchosts)
9. [보안 모델과 위협 모델](#9-보안-모델과-위협-모델)
10. [트러블슈팅](#10-트러블슈팅)
11. [자주 묻는 질문 (FAQ)](#11-자주-묻는-질문-faq)
12. [HTTP API 레퍼런스](#12-http-api-레퍼런스)

---

## 1. 빠른 시작

### 1.1. 빌드

Go 1.23 이상이 필요합니다. 외부 모듈 의존성은 전혀 없으며 모든 코드가
Go 표준 라이브러리로 작성되어 있습니다.

```sh
git clone https://github.com/ziozzang/detour.git
cd detour
go build -o detourd ./cmd/detourd
go build -o detour  ./cmd/detour
```

이 두 바이너리만 배포하면 됩니다. 웹 UI(HTML/JS/CSS)는 Go의
`embed.FS`로 `detourd` 바이너리에 포함되어 별도 파일을 함께
배포할 필요가 없습니다.

### 1.2. 권한 그룹 생성

CLI를 일반 사용자도 실행할 수 있도록, Docker가 `docker` 그룹을 쓰는
방식과 동일하게 `detour` 그룹을 만듭니다.

```sh
sudo groupadd --system detour
sudo usermod -aG detour "$USER"
# 로그아웃/로그인 또는 newgrp detour 로 그룹 적용
```

### 1.3. 데몬 실행

```sh
sudo ./detourd \
    --socket /run/detour.sock \
    --socket-group detour \
    --socket-mode 0660
```

기본 동작:

- iptables의 `nat` 테이블에 `DETOUR` 체인을 만들고 `OUTPUT`과
  `PREROUTING`에 연결합니다.
- `/etc/hosts`에 detour 전용 sentinel 블록을 만들 준비를 합니다(실제
  쓰기는 호스트 항목을 추가할 때 발생).
- Unix socket `/run/detour.sock`을 그룹 `detour`, 권한 `0660`으로
  생성합니다.

### 1.4. 기본 동작 확인

```sh
detour status
# ADDRESS    unix:///run/detour.sock
# HEALTHY    true
# VERSION    1.0.0
# CHAIN      DETOUR
# HOSTS-FILE /etc/hosts
# AUTH-MODE  none
# UPTIME     12s
# RULES      0
# HOSTS      0
```

### 1.5. 첫 번째 규칙

```sh
# 0.0.0.0:1234 로 들어오거나 나가는 TCP 트래픽을 127.0.0.1:2234 로
detour rule add --from 0.0.0.0:1234 --to 127.0.0.1:2234 --proto tcp

# foo.com 도메인 lookup 을 10.2.3.4 로 강제
detour host add --hostname foo.com --ip 10.2.3.4
```

데몬을 종료하면 iptables 체인은 flush되고 삭제되며, `/etc/hosts`의
detour 블록도 정리됩니다. 호스트는 시작 전 상태로 돌아갑니다.

---

## 2. 설계 개요

```
                   ┌────────────────────────────────────┐
   detour CLI  ───►│      /run/detour.sock (0660)       │
   브라우저   ───►│      (Unix-domain socket)           │
   curl/jq    ───►│                                     │
                   │  ┌───────────────────────────────┐  │
                   │  │     detourd (HTTP API)        │  │
                   │  │  /healthz /version            │  │
                   │  │  /rules /hosts                │  │
                   │  │  /  /static/* (web UI)        │  │
                   │  └────────┬──────────┬───────────┘  │
                   │           │          │              │
                   │  ┌────────▼──┐  ┌────▼──────────┐   │
                   │  │ linuxnat  │  │  hostsfile     │   │
                   │  │ iptables  │  │  /etc/hosts    │   │
                   │  └───────────┘  └────────────────┘   │
                   └────────────────────────────────────┘
```

설계 원칙:

- **단일 책임의 패키지 분할**: `cmd/detourd`(부팅·플래그·종료)와
  `cmd/detour`(CLI), 그리고 `internal/api`·`internal/auth`·
  `internal/client`·`internal/linuxnat`·`internal/hostsfile`·
  `internal/socket`의 6개 내부 패키지로 분리되어 있습니다.
- **외부 의존성 0개**: `go.mod`에 어떠한 모듈도 없습니다. 공급망
  위험과 보안 패치 의존을 최소화하기 위함입니다.
- **테스트 가능성**: iptables 호출은 `linuxnat.Runner` 인터페이스를
  통해 가짜로 교체할 수 있고, systemctl 호출도 `serviceEnv`로 교체
  가능해 root 권한 없이 종단 간 테스트가 돌아갑니다.
- **종료 시 깨끗한 정리**: SIGTERM/SIGINT 수신 시 체인 flush·삭제와
  `/etc/hosts` 블록 제거를 보장합니다. 비정상 종료에서도 다음 부팅
  때 stale entry가 정리됩니다.

더 깊은 설계 문서는 [`architecture.md`](architecture.md)를 참고하세요.

---

## 3. `detourd` (데몬) 옵션 상세

```
Usage of detourd:
  --socket           string  Unix socket 경로 (기본 /run/detour.sock)
  --socket-group     string  socket을 소유할 Unix 그룹 (기본 "detour", 빈 문자열이면 변경 안함)
  --socket-mode      string  socket 파일 모드, 8진수 (기본 "0660")
  --http             string  추가로 노출할 TCP 주소 (예: 127.0.0.1:8080). 기본 비활성
  --hosts-file       string  관리할 hosts 파일 경로 (기본 /etc/hosts)
  --chain            string  iptables nat 테이블 안에 사용할 체인 이름 (기본 DETOUR)
  --iptables         string  iptables 바이너리 경로 또는 $PATH 에서 찾을 이름 (기본 iptables)
  --no-hosts         bool    /etc/hosts 관리 기능 비활성화. /hosts 엔드포인트는 503 반환
  --auth-token       string  TCP 에서 사용할 단일 베어러 토큰 (운영 환경에서는 --auth-token-file 권장)
  --auth-token-file  string  한 줄당 토큰 하나가 들어 있는 파일 경로. 모드 0600 필수
  --auth-required    bool    Unix socket 에서도 Authorization 헤더 요구 (기본은 socket peer 는 신뢰)
  --auth-state-dir   string  --http 가 켜져 있는데 토큰이 없으면 자동 생성한 토큰을 이 디렉터리에 저장 (기본 /var/lib/detour)
  --version          bool    버전 출력 후 종료
```

### 3.1. 환경 변수

| 변수 | 효과 |
|---|---|
| `DETOURD_AUTH_TOKEN` | `--auth-token` 과 동일한 효과로 토큰 한 개를 주입 |

### 3.2. 권한 요구사항

- 루트 권한 **또는** `CAP_NET_ADMIN` 권한이 필요합니다 (iptables 조작).
- `/etc/hosts`에 쓰기 권한이 필요합니다.
- `--socket` 경로의 부모 디렉터리에 쓰기 권한이 필요합니다.

systemd 유닛 템플릿(아래 6장 참조)은 `AmbientCapabilities=CAP_NET_ADMIN`,
`CapabilityBoundingSet=CAP_NET_ADMIN`, `NoNewPrivileges=true`로
하드닝되어 있어 권한 상승 경로를 차단합니다.

### 3.3. 동시성과 종료

- 신호 처리는 `signal.Notify`로 SIGINT/SIGTERM 두 가지를 잡습니다.
- 종료 시 5초 안에 `http.Server.Shutdown`이 완료되어야 하며, 이후
  iptables 체인 제거와 `/etc/hosts` 블록 제거가 무조건 수행됩니다.
- iptables 정리는 etag 기반 atomic 갱신을 사용하지 않으므로, 데몬이
  비정상 종료하더라도 다음 부팅 때 같은 이름의 체인을 재사용해 정상
  복구됩니다.

---

## 4. `detour` (CLI) 사용법

### 4.1. 전역 플래그

| 플래그 | 환경 변수 | 기본값 | 설명 |
|---|---|---|---|
| `--host` | `DETOUR_HOST` | `unix:///run/detour.sock` | 데몬 주소 |
| `--token` | `DETOUR_TOKEN` | (없음) | TCP 인증용 베어러 토큰 |
| `--token-file` | `DETOUR_TOKEN_FILE` | (없음) | 베어러 토큰 파일 경로 |
| `--json` | — | false | 표 대신 JSON 출력 |
| `--timeout` | — | 10s | 호출당 타임아웃 |

`--host` 의 지원 형식:

- `unix:///path/to.sock`
- `/path/to.sock` (자동으로 unix:// 처리)
- `http://host:port`
- `https://host:port`

### 4.2. 종료 코드

| 코드 | 의미 |
|---|---|
| 0 | 성공 |
| 1 | 데몬에 도달했으나 작업 실패 (예: 404, 400, 500) |
| 2 | 사용자 오류 (잘못된 플래그, 알 수 없는 명령, 데몬 도달 실패) |

### 4.3. 명령 일람

```
version                          클라이언트 버전 표시
ping                             간단 헬스 체크. 정상시 "pong" 출력
info                             상태/카운트 표 (간단)
status                           verbose 상태 (버전, 체인, 인증 모드, 업타임 포함)
rule list                        규칙 목록    (alias: rule ls)
rule add --from --to [--proto] [--dry-run]
                                 DNAT 규칙 추가
rule rm <id>                     규칙 삭제    (alias: rule remove, rule delete)
host list                        호스트 항목 목록
host add --hostname --ip         호스트 항목 추가
host rm <id>                     호스트 항목 삭제
service install [...]            systemd 유닛 생성/등록
service uninstall [--purge]      systemd 유닛 제거
service status                   systemctl 상태 표시
service logs [--tail N] [--follow]
                                 journalctl -u detourd 호출
completion {bash|zsh|fish}       셸 자동완성 스크립트 출력
```

### 4.4. 예시 시나리오

#### 4.4.1. 임시 디버깅 — 외부 API를 로컬 mock 으로

```sh
# 외부 https://api.example.com 호출을 로컬 mock(127.0.0.1:8443)으로
detour host add --hostname api.example.com --ip 127.0.0.1
detour rule add --from 127.0.0.1:443 --to 127.0.0.1:8443 --proto tcp
# … 디버그 작업 …
detour rule list
detour host list
# 정리:
detour host rm <id>
detour rule rm <id>
# 또는 데몬 재시작이면 자동으로 정리됨
```

#### 4.4.2. CI에서 사용

```sh
DETOUR_TOKEN="$(cat /etc/detour/ci.token)" \
  detour --host http://10.0.0.5:8080 --json status \
  | jq '.healthy'
```

#### 4.4.3. dry-run 으로 명령 검증

```sh
detour rule add --from 0.0.0.0:80 --to 127.0.0.1:8080 --dry-run
# dry-run ok: from=0.0.0.0:80 to=127.0.0.1:8080 proto=both
```

데몬에 어떤 변경도 가하지 않습니다. CI 파이프라인의 단순 검증용입니다.

### 4.5. 자동완성 설치

#### bash

```sh
# 일회성
source <(detour completion bash)

# 영구
sudo detour completion bash > /etc/bash_completion.d/detour
```

#### zsh

```sh
# fpath 에 추가
detour completion zsh > "${fpath[1]}/_detour"

# 또는 .zshrc 에서
eval "$(detour completion zsh)"
```

#### fish

```sh
detour completion fish > ~/.config/fish/completions/detour.fish
```

---

## 5. 토큰 기반 인증

### 5.1. 인증 모델

detour는 두 가지 채널을 가집니다:

1. **Unix socket** (`/run/detour.sock`) — POSIX 그룹 권한으로 접근을
   제한합니다. 기본 정책은 `root:detour 0660` 으로, `detour` 그룹에
   속한 사용자만 접근할 수 있습니다. 토큰은 기본적으로 검사하지
   않습니다 (Docker와 동일한 모델).
2. **TCP HTTP** (`--http ADDR`) — 네트워크에 노출되는 채널이므로
   **반드시 베어러 토큰**이 필요합니다. 토큰이 없으면 `detourd`가
   자동으로 하나를 생성해 `/var/lib/detour/auth.token`(모드 0600)에
   저장하고 그 토큰을 사용합니다. 즉 "토큰 없이 네트워크에 노출"되는
   상태는 발생하지 않습니다.

`--auth-required` 옵션을 주면 Unix socket에서도 토큰을 요구합니다.
여러 사용자가 같은 호스트를 공유하는 환경에서 권장합니다.

`GET /healthz` 는 모니터링 시스템의 외부 헬스 체크가 토큰 없이도
동작하도록 인증을 우회합니다. 그 외 모든 엔드포인트(`GET /version`
포함)는 TCP에서 토큰이 필요합니다.

### 5.2. 토큰 공급 방법

여러 방법을 동시에 사용 가능합니다. 모두 합쳐서 토큰 집합을 만듭니다.

```sh
# 1) 단일 토큰 (테스트용)
detourd --http :8080 --auth-token "my-secret"

# 2) 환경 변수 — systemd EnvironmentFile= 와 잘 어울림
DETOURD_AUTH_TOKEN=my-secret detourd --http :8080

# 3) 토큰 파일 (운영 권장)
sudo install -m 0600 /dev/null /etc/detour/tokens
sudo tee -a /etc/detour/tokens > /dev/null <<'EOF'
# 운영자 토큰
e7a4c1b2...64hex
# CI 봇 토큰
9f2bd31a...64hex
EOF
detourd --http :8080 --auth-token-file /etc/detour/tokens
```

토큰 파일은 한 줄에 하나의 토큰입니다. 빈 줄과 `#` 으로 시작하는 줄은
주석으로 처리되어 무시됩니다. 파일 모드는 **0600 또는 더 엄격**해야
합니다. 0640/0644 등으로 두면 `detourd`가 시작을 거부합니다 (실수로
토큰이 유출되는 것을 막기 위함).

### 5.3. 자동 생성 토큰

`--http`를 켰지만 어떤 토큰도 설정하지 않은 경우, 데몬은:

1. crypto/rand 로 32 바이트 (256 비트) 난수 생성
2. 16진수 64자 토큰으로 인코딩
3. `/var/lib/detour/auth.token` 에 모드 0600 으로 atomic write
4. 로그에 경로를 출력
5. 그 토큰만 허용

```
2026-05-15T22:30:00Z auto-generated bearer token written to /var/lib/detour/auth.token (mode 0600); use it as Authorization: Bearer <token>
```

토큰을 회수하려면 그 파일을 `cat`하면 됩니다:

```sh
sudo cat /var/lib/detour/auth.token
```

### 5.4. 토큰 회전

토큰 파일을 교체하고 데몬에 SIGHUP을 보내…는 **현재 지원하지 않습니다**.
회전은 다음 절차로 수행합니다:

1. 새 토큰을 `--auth-token-file` 에 **추가** (기존 토큰 옆에 한 줄
   더 작성). 데몬은 둘 다 받아들이는 상태로 동작 가능.
2. 데몬 재시작 (`sudo systemctl restart detourd`).
3. 모든 클라이언트가 새 토큰으로 전환되었는지 확인.
4. 기존 토큰을 파일에서 제거하고 다시 재시작.

이 절차는 무중단으로 가능합니다 (재시작 사이에 잠시 connection refused가
발생할 수 있지만 클라이언트의 재시도가 흡수합니다).

### 5.5. 토큰을 CLI에 전달하는 방법

```sh
# 환경 변수
export DETOUR_TOKEN="$(sudo cat /var/lib/detour/auth.token)"
detour --host http://10.0.0.5:8080 rule list

# 파일
detour --host http://10.0.0.5:8080 \
       --token-file ~/.config/detour/token \
       rule list

# 직접
detour --host http://10.0.0.5:8080 --token "$T" rule list
```

세 가지가 모두 주어졌다면 우선순위는 **--token > --token-file > 환경 변수**입니다.

---

## 6. systemd 서비스 등록

### 6.1. install 서브커맨드

```sh
sudo detour service install \
    --binary /usr/local/bin/detourd \
    --user root --group root \
    --socket /run/detour.sock \
    --socket-group detour \
    --socket-mode 0660 \
    --http 127.0.0.1:8080 \
    --auth-token-file /etc/detour/tokens \
    --chain DETOUR \
    --hosts-file /etc/hosts \
    --enable
```

수행 내용:

1. `/etc/systemd/system/detourd.service` 에 유닛 작성 (모드 0644)
2. `systemctl daemon-reload`
3. `--enable` 플래그가 있으면 `systemctl enable --now detourd`

### 6.2. 생성되는 유닛 예시

```ini
[Unit]
Description=detour iptables/hosts daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
ExecStart=/usr/local/bin/detourd --socket=/run/detour.sock --socket-group=detour --socket-mode=0660 --http=127.0.0.1:8080 --chain=DETOUR --hosts-file=/etc/hosts --auth-token-file=/etc/detour/tokens
Restart=on-failure
RestartSec=2
StateDirectory=detour
StateDirectoryMode=0700
RuntimeDirectory=detour

[Install]
WantedBy=multi-user.target
```

- `StateDirectory=detour` — systemd 가 `/var/lib/detour` 를 자동으로
  생성하고 권한을 0700 으로 맞춥니다. 자동 생성된 토큰 파일이 이
  위치에 저장됩니다.
- `RuntimeDirectory=detour` — `/run/detour` 가 자동 생성됩니다 (소켓
  부모 디렉터리가 필요한 경우 활용).
- `NoNewPrivileges=true`, `CapabilityBoundingSet=CAP_NET_ADMIN` —
  권한 상승 경로를 차단하고 데몬이 필요로 하는 최소 권한만 부여.

### 6.3. dry-run

설치 전에 무엇을 할지 미리 확인할 수 있습니다.

```sh
detour service install --dry-run --http :8080
```

systemd가 없는 시스템에서도 dry-run은 동작합니다 (유닛 내용을 출력하기만
하기 때문).

### 6.4. status 와 logs

```sh
detour service status
# UNIT     detourd.service
# LOADED   loaded
# ACTIVE   active (running)
# ENABLED  enabled
# PID      4242
# SINCE    Sat 2026-05-15 22:30:00 UTC

detour service status --json | jq .
# {"systemd_detected":true,"load_state":"loaded","active_state":"active",...}

detour service logs --tail 50
detour service logs --follow      # journalctl -u detourd -f 와 동치
```

내부적으로 `systemctl show -p ...` 의 key=value 출력 형식을 파싱하므로
systemd 버전 차이에 영향이 적습니다.

### 6.5. uninstall

```sh
# 유닛만 제거
sudo detour service uninstall

# /var/lib/detour 까지 삭제 (자동 생성된 토큰도 함께)
sudo detour service uninstall --purge

# 미리보기
sudo detour service uninstall --dry-run --purge
```

---

## 7. 웹 UI 사용법

`--http` 옵션이 켜진 데몬에 브라우저로 접속하면 임베디드 웹 UI가
표시됩니다. 외부 자바스크립트나 CSS 의존성이 전혀 없습니다.

- **상단 상태 표시**: 데몬 헬스 (초록/빨강 원), 토큰 입력 필드 (선택),
  Save 버튼.
- **Port redirects 테이블**: 현재 설치된 DNAT 규칙. 추가/삭제 가능.
- **Host overrides 테이블**: 현재 관리 중인 `/etc/hosts` 항목.
  추가/삭제 가능.
- 데이터는 4초 간격으로 자동 갱신 (Polling).

토큰은 `localStorage` 에 저장되며, 매 요청에 `Authorization: Bearer ...`
헤더로 첨부됩니다. 토큰을 지우려면 입력 필드를 비우고 Save를 누르면
됩니다.

---

## 8. 내부 동작 — iptables와 /etc/hosts

### 8.1. iptables

- detourd 시작 시 nat 테이블에 `DETOUR` 체인이 없으면 생성하고,
  있으면 flush하여 깨끗한 상태로 만듭니다.
- `OUTPUT`과 `PREROUTING`에서 `DETOUR` 체인으로 jump하는 룰이 한 번씩
  설치됩니다 (중복 방지).
- 규칙 추가 시 `iptables -t nat -A DETOUR ... -j DNAT --to-destination` 호출.
- 규칙 삭제 시 동일 사양으로 `-D` 호출.
- `proto=both` 인 경우 TCP와 UDP 룰을 같은 ID로 묶어 관리합니다.
- 로컬 트래픽이 `127.0.0.0/8` 으로 향하도록 허용하기 위해
  `/proc/sys/net/ipv4/conf/all/route_localnet` 을 `1` 로 설정 시도합니다
  (실패는 경고로만 처리).

### 8.2. /etc/hosts

- detour 가 관리하는 영역은 다음 sentinel 사이에만 존재합니다:

  ```
  # >>> detour managed entries (do not edit manually) >>>
  10.2.3.4    foo.com
  # <<< detour managed entries <<<
  ```
- 사용자가 수동으로 추가한 다른 줄은 절대 건드리지 않습니다.
- 파일은 atomic rename (`os.Rename`) 으로 갱신되어 부분 쓰기 상태가
  관찰되지 않습니다.
- 데몬 종료 시 sentinel 블록 전체가 제거됩니다.

### 8.3. ID 체계

- 규칙과 호스트 항목 모두 6자리 16진수 ID 를 가집니다 (`a1b2c3`).
- 데몬을 재시작하면 ID는 재발급됩니다 (영속적이지 않음). 스크립트에서
  안정적으로 참조하려면 `from`/`to` 등 식별자를 직접 사용하거나
  `--json` 출력을 가공하세요.

---

## 9. 보안 모델과 위협 모델

### 9.1. detour가 보호하는 것

- **로컬 권한 분리**: Unix socket 의 POSIX 권한으로 비특권 사용자가
  데몬을 조작하지 못하도록 막습니다.
- **네트워크 노출 시 인증**: `--http` 가 켜진 채로 토큰 없이
  무인증으로 노출되는 상태는 절대 발생하지 않습니다 (자동 토큰
  생성).
- **상수 시간 비교**: 토큰 검증은 `crypto/subtle.ConstantTimeCompare`
  로 수행해 타이밍 사이드채널을 방지합니다.
- **종료 시 깨끗한 정리**: SIGTERM 으로 종료하면 iptables 룰과 hosts
  엔트리가 모두 제거되어 호스트가 원래 상태로 돌아갑니다.

### 9.2. detour가 보호하지 못하는 것

- **per-user 인증**: 모든 토큰은 동일한 권한을 가집니다. 누가 어떤
  토큰으로 어떤 작업을 했는지 구분되지 않습니다.
- **mTLS / TLS 종단**: detour 자체는 TLS를 종단하지 않습니다. 인증서
  관리가 필요하면 nginx/traefik 등 리버스 프록시 뒤에 두세요.
- **감사 로그**: 누가 무엇을 했는지의 감사 로그는 없습니다 (단순
  stderr 로그만 존재).
- **레이트 리미트 / IP 화이트리스트**: 없습니다. 프록시에서 처리하세요.

### 9.3. 권장 운영 자세

| 시나리오 | 권장 |
|---|---|
| 단일 호스트, 운영자 1명 | Unix socket + `detour` 그룹 |
| 단일 호스트, 여러 사용자 | `--auth-required` 추가, 사용자별 토큰 |
| 원격 호스트 관리 | `--http 127.0.0.1:PORT` + SSH 터널 (직접 노출 금지) |
| 멀티 호스트 자동화 | 리버스 프록시 + mTLS, 그 뒤에 detour 배치 |

---

## 10. 트러블슈팅

### 10.1. "permission denied" 가 떨어진다

- 데몬이 root 또는 `CAP_NET_ADMIN` 권한으로 실행되고 있는지 확인:
  `ps -o user,cmd -p $(pidof detourd)`
- `/etc/hosts` 쓰기 권한이 있는지: `ls -la /etc/hosts`
- 데몬 로그를 보세요: `detour service logs --tail 100`

### 10.2. "connection refused" 또는 "no such file"

CLI 가 다음과 같은 메시지를 출력한다면:

```
detour: ... dial unix /run/detour.sock: connect: no such file or directory
  hint: is detourd running at unix:///run/detour.sock? Try: sudo systemctl status detourd
```

데몬이 떠 있지 않거나 다른 경로를 보고 있는 것입니다. `detour service status`
나 `ps -ef | grep detourd` 로 확인하세요.

### 10.3. "operation not permitted" — iptables 호출 실패

- `iptables` 바이너리가 PATH에 있는지 (`which iptables`)
- 컨테이너 환경이라면 `--cap-add=NET_ADMIN` 이 부여되어 있는지
- nftables 백엔드 환경에서 `iptables-legacy` 가 필요할 수도 있음:
  `--iptables /sbin/iptables-legacy`

### 10.4. 401 Unauthorized

TCP 로 접속하는데 토큰을 보내지 않았거나 잘못된 토큰입니다.
`5장`을 다시 보세요. 토큰을 잃어버렸다면:

```sh
sudo cat /var/lib/detour/auth.token
```

가 자동 생성된 토큰을 보여줍니다.

### 10.5. 데몬이 죽고 나서 iptables 가 남아있다

비정상 종료일 가능성이 있습니다. 데몬을 다시 시작하면 같은 이름의
체인을 flush 해 깨끗한 상태로 만듭니다. 수동 정리가 필요하면:

```sh
sudo iptables -t nat -F DETOUR
sudo iptables -t nat -X DETOUR
sudo iptables -t nat -D OUTPUT     -j DETOUR
sudo iptables -t nat -D PREROUTING -j DETOUR
```

### 10.6. /etc/hosts 가 망가졌다

detour 가 관리하는 블록만 손대므로 다른 내용은 안전합니다. 만약
sentinel 블록이 손상되었다면 직접 텍스트로 정리하세요. 다음 시작
시점부터 detour 는 sentinel 을 새로 만듭니다.

---

## 11. 자주 묻는 질문 (FAQ)

**Q1. IPv6는 지원하나요?**
A. 현재 IPv4 만 지원합니다. `from`/`to` 가 IPv6 면 `400 Bad Request`
를 반환합니다.

**Q2. 한 포트를 여러 곳으로 분기할 수 있나요?**
A. iptables DNAT 의 특성상 한 (from, proto) 조합에는 한 destination
만 가능합니다. 같은 from 으로 두 번 add 하면 두 번째 규칙이 우선합니다.

**Q3. 데몬을 재시작하면 규칙이 보존되나요?**
A. 아니요. detour 는 의도적으로 모든 상태를 휘발성으로 둡니다.
영속화가 필요하면 (1) 시작 스크립트에서 `detour rule add` 를 반복
호출하거나 (2) JSON 출력을 저장했다가 복원하는 헬퍼 스크립트를
쓰세요.

**Q4. Docker 컨테이너 안에서 동작하나요?**
A. `--cap-add=NET_ADMIN --network=host` 와 `/etc/hosts` 마운트가
필요합니다. 다만 컨테이너 내부의 iptables 가 호스트 네임스페이스로
번지므로 보안상 매우 주의해야 합니다.

**Q5. NFTables 환경에서도 동작하나요?**
A. iptables 호환 shim (`iptables-nft`) 이 있는 배포판에서는 동작합니다.
순수 nft 환경의 직접 지원은 로드맵입니다.

**Q6. 토큰을 변경하면 기존 클라이언트 연결이 끊어지나요?**
A. detour 의 HTTP 호출은 단발성이라 "연결을 유지"하지 않습니다. 다음
호출부터 새 토큰이 필요합니다.

**Q7. 데몬 로그 레벨을 조절할 수 있나요?**
A. 현재 단일 레벨 (`info`) 만 출력합니다. 로그 라이브러리는 표준
`log` 패키지를 그대로 사용합니다.

---

## 12. HTTP API 레퍼런스

모든 엔드포인트는 JSON으로 요청과 응답을 처리합니다. 오류는

```json
{"error": "사람이 읽을 수 있는 메시지"}
```

형식으로 응답하며, HTTP 상태 코드가 함께 의미를 전달합니다.

TCP 로 접근할 때는 `Authorization: Bearer <token>` 헤더가 필요합니다
(단, `/healthz` 는 인증 우회). Unix socket 으로 접근할 때는 기본적으로
인증을 요구하지 않습니다 (단, `--auth-required` 가 있으면 동일하게
요구).

### 12.1. `GET /healthz`

```http
HTTP/1.1 200 OK
Content-Type: application/json

{"status": "ok", "uptime_sec": 3600}
```

인증 불필요. 외부 모니터링 시스템 헬스 체크에 사용하세요.

### 12.2. `GET /version`

```http
GET /version HTTP/1.1
Authorization: Bearer <token>

HTTP/1.1 200 OK
{
  "version":    "1.2.3",
  "commit":     "abcdef0",
  "date":       "2026-05-15T00:00:00Z",
  "chain":      "DETOUR",
  "hosts_file": "/etc/hosts",
  "auth_mode":  "tcp",
  "uptime_sec": 3600
}
```

`auth_mode` 값:

| 값 | 의미 |
|---|---|
| `none` | 어떤 채널에서도 토큰을 요구하지 않음 |
| `tcp`  | TCP 채널에서만 토큰을 요구 (Unix 는 우회) |
| `all`  | 모든 채널에서 토큰 요구 (`--auth-required`) |

### 12.3. `GET /rules`

```json
[
  {"id": "a1b2c3", "from": "0.0.0.0:1234", "to": "127.0.0.1:2234", "proto": "tcp"}
]
```

### 12.4. `POST /rules`

요청:

```json
{"from": "0.0.0.0:1234", "to": "127.0.0.1:2234", "proto": "tcp"}
```

응답: `201 Created`

```json
{"id": "a1b2c3", "from": "0.0.0.0:1234", "to": "127.0.0.1:2234", "proto": "tcp"}
```

- `proto`: `tcp` | `udp` | `both` (기본값 `both`).
- `from` 의 IP가 `0.0.0.0` 이면 모든 로컬 destination IP에 매치.
- 잘못된 형식이면 `400 Bad Request`.

### 12.5. `DELETE /rules/{id}`

성공 시 `204 No Content`. 없는 ID 이면 `404 Not Found`.

### 12.6. `GET /hosts`

```json
[
  {"id": "9f8e7d", "hostname": "foo.com", "ip": "10.2.3.4"}
]
```

`--no-hosts` 로 시작한 데몬이면 `503 Service Unavailable`.

### 12.7. `POST /hosts`

```json
{"hostname": "foo.com", "ip": "10.2.3.4"}
```

응답: `201 Created`. `hostname` 은 소문자로 정규화되고, `ip` 는 표준화된
표현으로 반환됩니다.

### 12.8. `DELETE /hosts/{id}`

성공 시 `204 No Content`. 없는 ID 이면 `404 Not Found`.

### 12.9. 인증 헤더 예시

```sh
curl -sS \
  -H "Authorization: Bearer $(cat /etc/detour/tokens | head -n1)" \
  http://10.0.0.5:8080/version
```

Unix socket 으로 접근:

```sh
curl --unix-socket /run/detour.sock \
     -H 'Content-Type: application/json' \
     -d '{"from":"0.0.0.0:1234","to":"127.0.0.1:2234","proto":"tcp"}' \
     http://detour/rules
```

---

## 부록 A. 빌드 정보 주입

릴리스 빌드는 다음과 같이 빌드 메타데이터를 ldflags 로 주입합니다.

```sh
LDFLAGS=$(printf -- "-X main.version=%s -X main.commit=%s -X main.date=%s" \
  "$(git describe --tags --always)" \
  "$(git rev-parse --short HEAD)" \
  "$(date -u +%Y-%m-%dT%H:%M:%SZ)")

go build -ldflags "$LDFLAGS" -o detourd ./cmd/detourd
go build -ldflags "$LDFLAGS" -o detour  ./cmd/detour
```

`detour version` 과 `GET /version` 양쪽에서 같은 정보가 노출됩니다.

## 부록 B. 외부 도구와의 연동 팁

- **Prometheus 모니터링**: `/healthz` 와 `/version` 의 `uptime_sec`
  을 blackbox_exporter 로 수집하면 데몬 가용성을 추적할 수 있습니다.
- **Ansible**: `detour rule add --dry-run` 으로 차이 없음(idempotency)
  을 검증한 다음, changed_when 으로 실제 적용 여부를 판단하세요.
- **Vault / SOPS**: 토큰 파일은 SOPS 등으로 암호화해 저장소에 보관하고,
  배포 시점에 평문으로 복호화하여 0600 으로 배치하는 방식을 권장합니다.

---

문서 끝.
