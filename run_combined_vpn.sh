#!/usr/bin/env bash

# Единый launcher для AmneziaWG/AmneziaVPN и Check Point bridge.
# Модули AmneziaWG, bridge и Python UAPI-helper встроены ниже,
# поэтому отдельные launcher-файлы больше не требуются.

set -Eeuo pipefail

embed_awg_helper() {
	local helper="$AWG_STATE_DIR/amneziawg_terminal.py"
	mkdir -p "$AWG_STATE_DIR"
	chmod 700 "$AWG_STATE_DIR" 2>/dev/null || true
	cat >"$helper" <<'__AWG_HELPER_PY__'
#!/usr/bin/env python3
"""Private helper for the AmneziaWG module of run_combined_vpn.sh.

It imports the Qt/QSettings profile format used by AmneziaVPN and talks to the
userspace AmneziaWG daemon over its UAPI socket. It never prints private keys.
"""

from __future__ import annotations

import base64
import json
import re
import socket
import sys
import time
from pathlib import Path


def decode_qsettings(raw: str) -> str:
    result: list[str] = []
    pos = 0
    escapes = {"n": "\n", "r": "\r", "t": "\t"}
    while pos < len(raw):
        if raw[pos] != "\\" or pos + 1 >= len(raw):
            result.append(raw[pos])
            pos += 1
            continue
        code = raw[pos + 1]
        if code == "x" and pos + 3 < len(raw):
            result.append(chr(int(raw[pos + 2 : pos + 4], 16)))
            pos += 4
        else:
            result.append(escapes.get(code, code))
            pos += 2
    return "".join(result)


def read_servers(path: str) -> tuple[str, list[dict], int]:
    source = Path(path).read_text(encoding="utf-8")
    match = re.search(r'^serversList="@ByteArray\((.*)\)"\s*$', source, re.MULTILINE)
    if not match:
        raise ValueError("serversList в формате AmneziaVPN не найден")
    try:
        servers = json.loads(decode_qsettings(match.group(1)))
    except json.JSONDecodeError as exc:
        raise ValueError(f"Не удалось разобрать serversList: {exc}") from exc
    default = re.search(r"^defaultServerIndex=(\d+)\s*$", source, re.MULTILINE)
    return source, servers, int(default.group(1)) if default else 0


def server_name(server: dict, index: int) -> str:
    return str(server.get("description") or server.get("name") or f"profile-{index}")


def select_server(source: str, servers: list[dict], default: int, index: str, name: str) -> tuple[int, dict]:
    if index:
        try:
            selected = int(index)
        except ValueError as exc:
            raise ValueError("Индекс профиля должен быть числом") from exc
    elif name:
        matches = [i for i, server in enumerate(servers) if server_name(server, i) == name]
        if len(matches) != 1:
            raise ValueError(f"Профиль с названием {name!r} не найден однозначно")
        selected = matches[0]
    else:
        selected = default
    if selected < 0 or selected >= len(servers):
        raise ValueError(f"Индекс профиля вне диапазона: {selected}")
    return selected, servers[selected]


def section_values(config: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    section = ""
    for line in config.splitlines():
        line = line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].lower()
            sections.setdefault(section, {})
        elif section and "=" in line:
            key, value = line.split("=", 1)
            sections[section][key.strip().lower()] = value.strip()
    return sections


def get_awg(server: dict, container_selector: str) -> tuple[dict, str]:
    container_name = container_selector or server.get("defaultContainer")
    for container in server.get("containers", []):
        if "awg" in container and (not container_name or container.get("container") == container_name):
            return container["awg"], str(container.get("container") or container_name or "")
    raise ValueError("AWG-контейнер для выбранного профиля не найден")


def build_config(source: str, server: dict, awg: dict) -> tuple[str, dict]:
    metadata: dict = {}
    last_config = awg.get("last_config")
    if last_config:
        try:
            metadata = json.loads(last_config)
        except json.JSONDecodeError:
            pass
    config = metadata.get("config")
    if not config:
        metadata = awg
        client_ip = metadata.get("client_ip")
        private_key = metadata.get("client_priv_key")
        server_key = metadata.get("server_pub_key")
        endpoint = f"{metadata.get('hostName') or server.get('hostName')}:{metadata.get('port') or server.get('port')}"
        if not all((client_ip, private_key, server_key, endpoint)):
            raise ValueError("В выбранном профиле отсутствует готовая AWG-конфигурация")
        lines = ["[Interface]", f"Address = {client_ip}", f"PrivateKey = {private_key}"]
        for key in ("Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"):
            if metadata.get(key) not in (None, ""):
                lines.append(f"{key} = {metadata[key]}")
        lines.extend(["", "[Peer]", f"PublicKey = {server_key}"])
        if metadata.get("psk_key"):
            lines.append(f"PresharedKey = {metadata['psk_key']}")
        allowed = metadata.get("allowed_ips") or ["0.0.0.0/0"]
        lines.extend([
            f"AllowedIPs = {', '.join(allowed)}",
            f"Endpoint = {endpoint}",
            f"PersistentKeepalive = {metadata.get('persistent_keep_alive') or 25}",
        ])
        config = "\n".join(lines)

    primary = re.search(r"^primaryDns=([^\s]+)\s*$", source, re.MULTILINE)
    secondary = re.search(r"^secondaryDns=([^\s]+)\s*$", source, re.MULTILINE)
    config = config.replace("$PRIMARY_DNS", primary.group(1) if primary else "")
    config = config.replace("$SECONDARY_DNS", secondary.group(1) if secondary else "")
    config = config.strip() + "\n"
    values = section_values(config)
    if not values.get("interface") or not values.get("peer"):
        raise ValueError("В выбранном профиле нет секций Interface и Peer")

    peer = values["peer"]
    endpoint = peer.get("endpoint") or f"{metadata.get('hostName') or server.get('hostName')}:{metadata.get('port') or server.get('port')}"
    meta = {
        "endpoint": endpoint,
        "address": values["interface"].get("address", ""),
        "dns": values["interface"].get("dns", ""),
        "mtu": str(metadata.get("mtu") or awg.get("mtu") or ""),
        "allowed": peer.get("allowedips", ""),
    }
    return config, meta


def extract(argv: list[str]) -> None:
    source_path, config_path, meta_path, index, name, container = argv
    source, servers, default = read_servers(source_path)
    selected, server = select_server(source, servers, default, index, name)
    awg, container_name = get_awg(server, container)
    config, meta = build_config(source, server, awg)
    Path(config_path).write_text(config, encoding="utf-8")
    Path(config_path).chmod(0o600)
    fields = [str(selected), server_name(server, selected), meta["endpoint"], meta["address"], meta["dns"], meta["mtu"], container_name, meta["allowed"]]
    Path(meta_path).write_text("\t".join(fields) + "\n", encoding="utf-8")
    Path(meta_path).chmod(0o600)


def profiles(path: str) -> None:
    source, servers, default = read_servers(path)
    for index, server in enumerate(servers):
        marker = "*" if index == default else " "
        print(f"{marker} {index}: {server_name(server, index)} ({server.get('hostName', '')})")


def parse_key(value: str) -> str:
    if re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value.lower()
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ValueError("Некорректный ключ в конфигурации") from exc
    if len(decoded) != 32:
        raise ValueError("Ключ в конфигурации имеет неправильную длину")
    return decoded.hex()


def uapi_request(path: str, payload: bytes) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(10)
        connection.connect(path)
        connection.sendall(payload)
        response = b""
        while b"\n\n" not in response:
            chunk = connection.recv(4096)
            if not chunk:
                break
            response += chunk
    return response.decode(errors="replace")


def configure(socket_path: str, config_path: str, firewall_mark: str) -> None:
    values = section_values(Path(config_path).read_text(encoding="utf-8"))
    interface = values.get("interface", {})
    peer = values.get("peer", {})
    if not all((interface.get("privatekey"), peer.get("publickey"), peer.get("endpoint"))):
        raise ValueError("В конфигурации отсутствует PrivateKey, PublicKey или Endpoint")

    lines = ["set=1", "replace_peers=true", f"private_key={parse_key(interface['privatekey'])}", f"fwmark={firewall_mark}"]
    mapping = {
        "contentpaddingaddition": "content_padding_addition",
        "rekeyaftertime": "rekey_after_time",
        "rekeytimeout": "rekey_timeout",
        "rejectaftertime": "reject_after_time",
        "keepalivetimeout": "keepalive_timeout",
        "maxhandshakeattempts": "max_handshake_attempts",
    }
    for key in ("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4", "i1", "i2", "i3", "i4", "i5", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout", "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts"):
        if interface.get(key):
            lines.append(f"{mapping.get(key, key)}={interface[key]}")
    if interface.get("headerprotectionkey"):
        lines.append(f"header_protection_key={parse_key(interface['headerprotectionkey'])}")
    for key, uapi_key in (("randomtrailers", "random_trailers"), ("disablecookies", "disable_cookies")):
        value = interface.get(key)
        if not value:
            continue
        if value.lower() in ("on", "yes", "true", "1"):
            lines.append(f"{uapi_key}=true")
        elif value.lower() in ("off", "no", "false", "0"):
            lines.append(f"{uapi_key}=false")
        else:
            raise ValueError(f"Некорректное значение {key}: {value}")
    lines.extend([f"public_key={parse_key(peer['publickey'])}", "replace_allowed_ips=true"])
    if peer.get("presharedkey"):
        lines.append(f"preshared_key={parse_key(peer['presharedkey'])}")
    lines.append(f"endpoint={peer['endpoint']}")
    if peer.get("persistentkeepalive"):
        lines.append(f"persistent_keepalive_interval={peer['persistentkeepalive']}")
    for allowed in peer.get("allowedips", "").split(","):
        allowed = allowed.strip()
        if allowed:
            lines.append(f"allowed_ip={allowed}")
    lines.extend(["protocol_version=1", ""])
    response = uapi_request(socket_path, ("\n".join(lines) + "\n").encode())
    errno = next((int(line.split("=", 1)[1]) for line in response.splitlines() if line.startswith("errno=")), 1)
    if errno:
        raise ValueError(f"UAPI отклонил конфигурацию (errno={errno})")


def status(socket_path: str) -> None:
    response = uapi_request(socket_path, b"get=1\n\n")
    peers: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for line in response.splitlines():
        key, _, value = line.partition("=")
        if key == "public_key":
            if current:
                peers.append(current)
            current = {}
        elif key in {"last_handshake_time_sec", "rx_bytes", "tx_bytes", "endpoint", "persistent_keepalive_interval", "errno"}:
            current[key] = value
    if current:
        peers.append(current)
    for number, peer in enumerate(peers, 1):
        handshake = int(peer.get("last_handshake_time_sec", "0"))
        age = "never" if not handshake else f"{max(0, int(time.time()) - handshake)}s ago"
        print(f"peer[{number}]: endpoint={peer.get('endpoint', 'unknown')} handshake={age} rx={peer.get('rx_bytes', '0')} tx={peer.get('tx_bytes', '0')}")


def main() -> None:
    command = sys.argv[1]
    try:
        if command == "extract":
            extract(sys.argv[2:])
        elif command == "profiles":
            profiles(sys.argv[2])
        elif command == "configure":
            configure(sys.argv[2], sys.argv[3], sys.argv[4])
        elif command == "status":
            status(sys.argv[2])
        else:
            raise ValueError(f"Неизвестная команда helper: {command}")
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()
__AWG_HELPER_PY__
	chmod 700 "$helper"
	AWG_HELPER_FILE="$helper"
	export AWG_HELPER_FILE
}

awg_module() (
#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$AWG_HELPER_FILE"
AMNEZIA_CONFIG_FILE="${AMNEZIA_CONFIG_FILE:-${HOME:-}/.config/AmneziaVPN.ORG/AmneziaVPN.conf}"
AWG_SOURCE_DIR="${AWG_SOURCE_DIR:-${HOME:-}/src/github.com/amnezia-vpn/amneziawg-go}"
AWG_BIN="${AWG_BIN:-$AWG_SOURCE_DIR/amneziawg-go}"
AWG_IF_NAME="${AWG_IF_NAME:-amneziawg0}"
AWG_ROUTE_TABLE="${AWG_ROUTE_TABLE:-51821}"
AWG_RULE_PRIORITY="${AWG_RULE_PRIORITY:-1000}"
AWG_FIREWALL_MARK="${AWG_FIREWALL_MARK:-51821}"
AWG_LOG_LEVEL="${AWG_LOG_LEVEL:-error}"
AWG_CONTAINER="${AWG_CONTAINER:-}"
AWG_PROFILE_INDEX="${AWG_PROFILE_INDEX:-}"
AWG_PROFILE_NAME="${AWG_PROFILE_NAME:-}"
AWG_SET_DNS="${AWG_SET_DNS:-true}"
AWG_FALLBACK_DNS="${AWG_FALLBACK_DNS:-1.1.1.1,1.0.0.1}"
AWG_ENABLE_IPV6="${AWG_ENABLE_IPV6:-auto}"
AWG_START_TIMEOUT="${AWG_START_TIMEOUT:-10}"
RUN_UID="${SUDO_UID:-${UID:-$(id -u)}}"
AWG_STATE_DIR="${AWG_STATE_DIR:-${XDG_RUNTIME_DIR:-/tmp}/amneziawg-terminal-${RUN_UID}}"
AWG_LOG_FILE="${AWG_LOG_FILE:-$AWG_STATE_DIR/amneziawg.log}"
SOCKET_DIR="/var/run/amneziawg"
SOCKET_PATH="$SOCKET_DIR/$AWG_IF_NAME.sock"
STATE_FILE="$AWG_STATE_DIR/state"
PID_FILE="$AWG_STATE_DIR/engine.pid"
CONFIG_PATH_FILE="$AWG_STATE_DIR/config.path"
PROFILE_META_FILE="$AWG_STATE_DIR/profile.meta"
LOCK_FILE="$AWG_STATE_DIR/lock"
ENGINE_PID=""
CONFIG_FILE=""
MANAGED_STATE=false
START_IN_PROGRESS=false
LOCK_FD=""

RED='\033[0;31m'; GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; NC='\033[0m'

usage() {
	cat <<EOF
Использование: $(basename "$0") <команда> [опции]

Команды:
  start       Запустить AmneziaWG с профилем из AmneziaVPN.conf
  stop        Остановить запущенное этим скриптом соединение
  restart     Перезапустить соединение
  status      Показать интерфейс, маршруты и состояние handshake
  logs        Показать лог amneziawg-go
  profiles    Показать профили из AmneziaVPN.conf без секретов
  config      Показать выбранный профиль без секретов

Опции:
  --profile VALUE       Индекс профиля или его название
  --config PATH         Путь к AmneziaVPN.conf
  --interface NAME      Имя интерфейса (до 15 символов)
  --engine PATH         Путь к бинарнику amneziawg-go
  --no-dns              Не менять настройки systemd-resolved
  -h, --help            Показать эту справку

Переменные окружения:
  AWG_FALLBACK_DNS      Резервные DNS через запятую, если в профиле их нет или они некорректны (по умолчанию 1.1.1.1,1.0.0.1)
EOF
}

log() {
	local log_dir
	log_dir=$(dirname -- "$AWG_LOG_FILE")
	mkdir -p "$log_dir" 2>/dev/null || true
	printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$2" >>"$AWG_LOG_FILE" 2>/dev/null || true
}
info() { printf '%b[INFO]%b %s\n' "$BLUE" "$NC" "$1"; log INFO "$1"; }
success() { printf '%b[SUCCESS]%b %s\n' "$GREEN" "$NC" "$1"; log SUCCESS "$1"; }
warn() { printf '%b[WARNING]%b %s\n' "$YELLOW" "$NC" "$1" >&2; log WARNING "$1"; }
error() { printf '%b[ERROR]%b %s\n' "$RED" "$NC" "$1" >&2; log ERROR "$1"; }
run_root() { if [ "$EUID" -eq 0 ]; then "$@"; else sudo "$@"; fi; }

init_state() {
	mkdir -p "$AWG_STATE_DIR"; chmod 700 "$AWG_STATE_DIR"
	if [ ! -O "$AWG_STATE_DIR" ]; then error "Каталог состояния не принадлежит текущему пользователю: $AWG_STATE_DIR"; exit 1; fi
}
acquire_lock() {
	exec {LOCK_FD}>"$LOCK_FILE"
	flock -n "$LOCK_FD" || { error "Другой экземпляр скрипта уже выполняет операцию."; exit 1; }
}
release_lock_for_children() {
	[ -n "$LOCK_FD" ] && eval "exec ${LOCK_FD}>&-"
	LOCK_FD=""
}
check_dependencies() {
	local command_name
	for command_name in ip python3 flock ps; do
		command -v "$command_name" >/dev/null 2>&1 || { error "Отсутствует необходимая утилита: $command_name"; exit 1; }
	done
	[ -r "$HELPER" ] || { error "Не найден helper: $HELPER"; exit 1; }
	case "$ACTION" in
		start|stop|restart|status)
			if [ "$EUID" -ne 0 ]; then
				command -v sudo >/dev/null 2>&1 || { error "Для сетевых операций нужен sudo."; exit 1; }
				sudo -v || { error "Не удалось получить права sudo."; exit 1; }
			fi
			;;
	esac
	case "$ACTION" in
		start|restart|profiles|config)
			[ -r "$AMNEZIA_CONFIG_FILE" ] || { error "Файл конфигурации не найден: $AMNEZIA_CONFIG_FILE"; exit 1; }
			;;
	esac
	[[ "$AWG_IF_NAME" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || { error "Некорректное имя интерфейса: $AWG_IF_NAME"; exit 1; }
	[[ "$AWG_ROUTE_TABLE" =~ ^[0-9]+$ && "$AWG_RULE_PRIORITY" =~ ^[0-9]+$ && "$AWG_FIREWALL_MARK" =~ ^[0-9]+$ ]] || { error "Параметры маршрутизации должны быть числами."; exit 1; }
}

load_profile() {
	CONFIG_FILE=$(mktemp "$AWG_STATE_DIR/config.XXXXXX")
	if ! python3 "$HELPER" extract "$AMNEZIA_CONFIG_FILE" "$CONFIG_FILE" "$PROFILE_META_FILE" "$AWG_PROFILE_INDEX" "$AWG_PROFILE_NAME" "$AWG_CONTAINER"; then
		rm -f "$CONFIG_FILE"; CONFIG_FILE=""; return 1
	fi
	IFS=$'\t' read -r PROFILE_INDEX PROFILE_NAME PROFILE_ENDPOINT PROFILE_ADDRESS PROFILE_DNS PROFILE_MTU PROFILE_CONTAINER PROFILE_ALLOWED_IPS <"$PROFILE_META_FILE"
	printf '%s\n' "$CONFIG_FILE" >"$CONFIG_PATH_FILE"; chmod 600 "$CONFIG_PATH_FILE"
}

load_state() {
	MANAGED_STATE=false
	[ -r "$STATE_FILE" ] || return 1
	local key value
	while IFS='=' read -r key value; do
		case "$key" in
			interface) AWG_IF_NAME="$value";; route_table) AWG_ROUTE_TABLE="$value";;
			rule_priority) AWG_RULE_PRIORITY="$value";; firewall_mark) AWG_FIREWALL_MARK="$value";; pid) ENGINE_PID="$value";;
		esac
	done <"$STATE_FILE"
	SOCKET_PATH="$SOCKET_DIR/$AWG_IF_NAME.sock"; MANAGED_STATE=true
}

write_state() {
	local temporary="$AWG_STATE_DIR/state.tmp"
	{
		printf 'interface=%s\nroute_table=%s\nrule_priority=%s\nfirewall_mark=%s\npid=%s\n' "$AWG_IF_NAME" "$AWG_ROUTE_TABLE" "$AWG_RULE_PRIORITY" "$AWG_FIREWALL_MARK" "$ENGINE_PID"
	} >"$temporary"
	chmod 600 "$temporary"; mv -f "$temporary" "$STATE_FILE"; MANAGED_STATE=true
}

ensure_engine() {
	if [ -x "$AWG_BIN" ]; then return 0; fi
	if [ "$AWG_BIN" = "$AWG_SOURCE_DIR/amneziawg-go" ] && [ -d "$AWG_SOURCE_DIR" ]; then
		command -v make >/dev/null 2>&1 && command -v go >/dev/null 2>&1 || { error "Для сборки нужны make и go."; return 1; }
		info "Сборка amneziawg-go из $AWG_SOURCE_DIR..."
		make -C "$AWG_SOURCE_DIR" amneziawg-go >>"$AWG_LOG_FILE" 2>&1 || { error "Сборка не удалась; подробности в $AWG_LOG_FILE"; return 1; }
		return 0
	fi
	if command -v amneziawg-go >/dev/null 2>&1; then AWG_BIN="$(command -v amneziawg-go)"; return 0; fi
	error "Бинарник amneziawg-go не найден: $AWG_BIN"; return 1
}

interface_exists() { ip link show dev "$AWG_IF_NAME" >/dev/null 2>&1; }
managed_process_alive() {
	[ -n "$ENGINE_PID" ] && kill -0 "$ENGINE_PID" 2>/dev/null || return 1
	local args; args=$(ps -p "$ENGINE_PID" -o args= 2>/dev/null || true)
	[[ "$args" == *"-f $AWG_IF_NAME"* ]]
}

remove_routes() {
	local next=$((AWG_RULE_PRIORITY + 1)) family
	for family in -4 -6; do
		run_root ip "$family" rule del pref "$AWG_RULE_PRIORITY" not fwmark "$AWG_FIREWALL_MARK" table "$AWG_ROUTE_TABLE" >/dev/null 2>&1 || true
		run_root ip "$family" rule del pref "$next" table main suppress_prefixlength 0 >/dev/null 2>&1 || true
		run_root ip "$family" route flush table "$AWG_ROUTE_TABLE" >/dev/null 2>&1 || true
	done
}
remove_dns() { command -v resolvectl >/dev/null 2>&1 && run_root resolvectl revert "$AWG_IF_NAME" >/dev/null 2>&1 || true; }
stop_engine() {
	managed_process_alive || return 0
	info "Остановка amneziawg-go (PID $ENGINE_PID)..."; run_root kill -TERM "$ENGINE_PID" >/dev/null 2>&1 || true
	local attempt
	for ((attempt=0; attempt<50; attempt++)); do kill -0 "$ENGINE_PID" 2>/dev/null || return 0; sleep 0.1; done
	warn "Процесс не завершился по SIGTERM; используется SIGKILL."; run_root kill -KILL "$ENGINE_PID" >/dev/null 2>&1 || true
}
stop_internal() {
	"$MANAGED_STATE" || return 0
	remove_dns; remove_routes; stop_engine
	interface_exists && run_root ip link del dev "$AWG_IF_NAME" >/dev/null 2>&1 || true
	[ -S "$SOCKET_PATH" ] && run_root rm -f "$SOCKET_PATH" >/dev/null 2>&1 || true
	local old_config=""; [ -r "$CONFIG_PATH_FILE" ] && old_config=$(<"$CONFIG_PATH_FILE")
	rm -f "$old_config" "$CONFIG_PATH_FILE" "$PROFILE_META_FILE" "$PID_FILE" "$STATE_FILE"
	MANAGED_STATE=false; ENGINE_PID=""; CONFIG_FILE=""
}
cleanup_failed_start() {
	if "$START_IN_PROGRESS"; then
		stop_internal
		[ -z "$CONFIG_FILE" ] || rm -f "$CONFIG_FILE"
		[ -z "$CONFIG_PATH_FILE" ] || rm -f "$CONFIG_PATH_FILE"
	fi
}
wait_for_socket() {
	local attempt
	for ((attempt=0; attempt<AWG_START_TIMEOUT*10; attempt++)); do
		[ -S "$SOCKET_PATH" ] && return 0
		[ -n "$ENGINE_PID" ] && kill -0 "$ENGINE_PID" 2>/dev/null || return 1
		sleep 0.1
	done
	return 1
}

configure_device() { run_root python3 "$HELPER" configure "$SOCKET_PATH" "$CONFIG_FILE" "$AWG_FIREWALL_MARK"; }
configure_interface() {
	local address
	for address in ${PROFILE_ADDRESS//,/ }; do [ -n "$address" ] && run_root ip address replace "$address" dev "$AWG_IF_NAME"; done
	if [ -n "$PROFILE_MTU" ]; then
		[[ "$PROFILE_MTU" =~ ^[0-9]+$ ]] || { error "Некорректный MTU в профиле: $PROFILE_MTU"; return 1; }
		run_root ip link set dev "$AWG_IF_NAME" mtu "$PROFILE_MTU"
	fi
	run_root ip link set dev "$AWG_IF_NAME" up
}
configure_routes() {
	case "$AWG_ENABLE_IPV6" in true|yes|1|false|no|0|auto) ;; *) error "AWG_ENABLE_IPV6 должен быть auto, true или false."; return 1;; esac
	remove_routes
	local prefix family has_v4=false has_v6=false
	for prefix in ${PROFILE_ALLOWED_IPS//,/ }; do
		[ -n "$prefix" ] || continue
		case "$prefix" in
			*:*)
				case "$AWG_ENABLE_IPV6" in false|no|0) continue;; esac
				family=-6; has_v6=true;;
			*) family=-4; has_v4=true;;
		esac
		if [ "$prefix" = "0.0.0.0/0" ] || [ "$prefix" = "::/0" ]; then
			run_root ip "$family" route replace default dev "$AWG_IF_NAME" table "$AWG_ROUTE_TABLE"
		else
			run_root ip "$family" route replace "$prefix" dev "$AWG_IF_NAME" table "$AWG_ROUTE_TABLE"
		fi
	done
	if [ "$has_v4" = true ]; then
		run_root ip -4 rule add pref "$AWG_RULE_PRIORITY" not fwmark "$AWG_FIREWALL_MARK" table "$AWG_ROUTE_TABLE"
		run_root ip -4 rule add pref $((AWG_RULE_PRIORITY+1)) table main suppress_prefixlength 0
	fi
	if [ "$has_v6" = true ]; then
		run_root ip -6 rule add pref "$AWG_RULE_PRIORITY" not fwmark "$AWG_FIREWALL_MARK" table "$AWG_ROUTE_TABLE"
		run_root ip -6 rule add pref $((AWG_RULE_PRIORITY+1)) table main suppress_prefixlength 0
	fi
	if [ "$has_v4" = false ] && [ "$has_v6" = false ]; then
		warn "В профиле пустой список AllowedIPs; маршруты не установлены."
		return 1
	fi
}
configure_dns() {
	case "$AWG_SET_DNS" in false|no|0) return 0;; true|yes|1);; *) error "AWG_SET_DNS должен быть true или false."; return 1;; esac
	command -v resolvectl >/dev/null 2>&1 || { warn "resolvectl не найден; настройки DNS не меняются."; return 0; }
	local dns_source="$PROFILE_DNS" dns_server
	local -a dns_servers=()
	for dns_server in ${dns_source//,/ }; do [[ "$dns_server" =~ ^[0-9a-fA-F:.]+$ ]] && dns_servers+=("$dns_server"); done
	if [ "${#dns_servers[@]}" -eq 0 ]; then
		[ -n "$AWG_FALLBACK_DNS" ] || { warn "DNS-серверы не заданы ни в профиле, ни в AWG_FALLBACK_DNS; настройки DNS не меняются."; return 0; }
		warn "В профиле нет корректных DNS-серверов; используются резервные: $AWG_FALLBACK_DNS."
		for dns_server in ${AWG_FALLBACK_DNS//,/ }; do [[ "$dns_server" =~ ^[0-9a-fA-F:.]+$ ]] && dns_servers+=("$dns_server"); done
		[ "${#dns_servers[@]}" -gt 0 ] || { warn "Резервные DNS-серверы (AWG_FALLBACK_DNS) некорректны; настройки DNS не меняются."; return 0; }
	fi
	run_root resolvectl dns "$AWG_IF_NAME" "${dns_servers[@]}"; run_root resolvectl domain "$AWG_IF_NAME" '~.'
	run_root resolvectl flush-caches >/dev/null 2>&1 || true
}

restore_ownership() {
	if [ -n "${SUDO_UID:-}" ] && [ -n "${SUDO_GID:-}" ]; then
		chown -R "$SUDO_UID:$SUDO_GID" "$AWG_STATE_DIR" >/dev/null 2>&1 || true
	fi
}

start_action() {
	if load_state && managed_process_alive; then info "AmneziaWG уже запущен на интерфейсе $AWG_IF_NAME (PID $ENGINE_PID)."; return 0; fi
	if "$MANAGED_STATE"; then warn "Очищается состояние предыдущего запуска."; stop_internal; fi
	if interface_exists || [ -S "$SOCKET_PATH" ]; then error "Интерфейс или UAPI-сокет уже существует и не принадлежит этому скрипту: $AWG_IF_NAME"; return 1; fi
	START_IN_PROGRESS=true; trap cleanup_failed_start EXIT; : >>"$AWG_LOG_FILE"
	load_profile || return 1
	info "Профиль: $PROFILE_NAME; endpoint: $PROFILE_ENDPOINT"
	ensure_engine || return 1
	release_lock_for_children
	info "Запуск $AWG_BIN на интерфейсе $AWG_IF_NAME..."
	if [ "$EUID" -eq 0 ]; then LOG_LEVEL="$AWG_LOG_LEVEL" "$AWG_BIN" -f "$AWG_IF_NAME" >>"$AWG_LOG_FILE" 2>&1 & else sudo env LOG_LEVEL="$AWG_LOG_LEVEL" "$AWG_BIN" -f "$AWG_IF_NAME" >>"$AWG_LOG_FILE" 2>&1 & fi
	ENGINE_PID=$!; printf '%s\n' "$ENGINE_PID" >"$PID_FILE"; chmod 600 "$PID_FILE"; write_state
	if ! wait_for_socket; then error "amneziawg-go не создал UAPI-сокет за ${AWG_START_TIMEOUT} секунд."; tail -n 30 "$AWG_LOG_FILE" >&2 || true; return 1; fi
	configure_device; configure_interface; configure_routes; configure_dns
	restore_ownership
	START_IN_PROGRESS=false; trap - EXIT
	success "AmneziaWG запущен: $AWG_IF_NAME, профиль $PROFILE_NAME."
	info "Управление: $0 status | $0 stop | $0 logs"
}
stop_action() {
	if ! load_state; then
		if interface_exists || [ -S "$SOCKET_PATH" ]; then
			warn "Состояние запуска не найдено, но интерфейс $AWG_IF_NAME существует; возможно, он был запущен вне этого скрипта."
		else
			info "У этого скрипта нет сохраненного состояния запуска."
		fi
		return 0
	fi
	stop_internal
	restore_ownership
	success "AmneziaWG остановлен и сетевые настройки очищены."
}

status_action() {
	if load_state; then printf 'Интерфейс: %s\nPID: %s (%s)\n' "$AWG_IF_NAME" "${ENGINE_PID:-unknown}" "$(managed_process_alive && echo running || echo stopped)"; else printf 'Состояние: не запущен этим скриптом\n'; fi
	if ! interface_exists; then printf 'Интерфейс: отсутствует\n'; return 0; fi
	run_root ip -brief address show dev "$AWG_IF_NAME"
	printf '\nМаршруты таблицы %s:\n' "$AWG_ROUTE_TABLE"
	run_root ip -4 route show table "$AWG_ROUTE_TABLE" || true
	run_root ip -6 route show table "$AWG_ROUTE_TABLE" 2>/dev/null || true
	if [ -S "$SOCKET_PATH" ]; then printf '\nUAPI:\n'; run_root python3 "$HELPER" status "$SOCKET_PATH" || true; fi
}
config_action() {
	local config meta; config=$(mktemp "$AWG_STATE_DIR/config.XXXXXX"); meta="$AWG_STATE_DIR/config-meta"
	if ! python3 "$HELPER" extract "$AMNEZIA_CONFIG_FILE" "$config" "$meta" "$AWG_PROFILE_INDEX" "$AWG_PROFILE_NAME" "$AWG_CONTAINER"; then
		rm -f "$config" "$meta"
		return 1
	fi
	IFS=$'\t' read -r PROFILE_INDEX PROFILE_NAME PROFILE_ENDPOINT PROFILE_ADDRESS PROFILE_DNS PROFILE_MTU PROFILE_CONTAINER <"$meta"
	printf 'Профиль: %s (%s)\nEndpoint: %s\nAddress: %s\nMTU: %s\nDNS: %s\n' "$PROFILE_INDEX" "$PROFILE_NAME" "$PROFILE_ENDPOINT" "$PROFILE_ADDRESS" "${PROFILE_MTU:-default}" "${PROFILE_DNS:-not set}"
	rm -f "$config" "$meta"
}

parse_args() {
	if [ "${1:-}" = "-h" ] || [ "${1:-}" = "--help" ]; then usage; exit 0; fi
	ACTION="${1:-start}"; [ "$ACTION" = "start" ] || [ "$ACTION" = "stop" ] || [ "$ACTION" = "restart" ] || [ "$ACTION" = "status" ] || [ "$ACTION" = "logs" ] || [ "$ACTION" = "profiles" ] || [ "$ACTION" = "config" ] || { usage; exit 2; }; shift || true
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--profile) [ "$#" -ge 2 ] || { error "--profile требует значение"; exit 2; }; if [[ "$2" =~ ^[0-9]+$ ]]; then AWG_PROFILE_INDEX="$2"; AWG_PROFILE_NAME=""; else AWG_PROFILE_NAME="$2"; AWG_PROFILE_INDEX=""; fi; shift 2;;
			--config) [ "$#" -ge 2 ] || { error "--config требует путь"; exit 2; }; AMNEZIA_CONFIG_FILE="$2"; shift 2;;
			--interface) [ "$#" -ge 2 ] || { error "--interface требует имя"; exit 2; }; AWG_IF_NAME="$2"; SOCKET_PATH="$SOCKET_DIR/$AWG_IF_NAME.sock"; shift 2;;
			--engine) [ "$#" -ge 2 ] || { error "--engine требует путь"; exit 2; }; AWG_BIN="$2"; shift 2;;
			--no-dns) AWG_SET_DNS=false; shift;; -h|--help) usage; exit 0;; *) error "Неизвестная опция: $1"; usage; exit 2;;
		esac
	done
}

main() {
	parse_args "$@"
	init_state
	case "$ACTION" in
		profiles) check_dependencies; python3 "$HELPER" profiles "$AMNEZIA_CONFIG_FILE";;
		config) check_dependencies; config_action;;
		logs) [ -f "$AWG_LOG_FILE" ] || { error "Лог не найден: $AWG_LOG_FILE"; exit 1; }; tail -f "$AWG_LOG_FILE";;
		*) check_dependencies; acquire_lock; case "$ACTION" in start) start_action;; stop) stop_action;; restart) stop_action; start_action;; status) status_action;; esac;;
	esac
}

main "$@"

)

bridge_module() (
#!/usr/bin/env bash

# The bridge was originally a standalone script without errexit/nounset.
# Keep those semantics when embedding it into the stricter combined launcher.
set +Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
if [ -f "$ENV_FILE" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$ENV_FILE"
	set +a
fi

SERVER_NAME="${SERVER_NAME:-achird.emergingtravel.com}"
IF_NAME="${IF_NAME:-etg_vpn}"
LOGIN_TYPE="${LOGIN_TYPE:-vpn_etg_google_ravpn}"
LOG_FILE="${LOG_FILE:-snx_bridge_vpn.log}"
CONTAINER_NAME="${CONTAINER_NAME:-snx-rs-vpn}"
TIMEOUT_DOCKER_BOOT="${TIMEOUT_DOCKER_BOOT:-10}"
HEALTHCHECK_URL="${HEALTHCHECK_URL:-https://llmgate.etg.team}"
HEALTHCHECK_INTERVAL="${HEALTHCHECK_INTERVAL:-20}"
HEALTHCHECK_TIMEOUT="${HEALTHCHECK_TIMEOUT:-8}"
HEALTHCHECK_FAILURE_THRESHOLD="${HEALTHCHECK_FAILURE_THRESHOLD:-3}"
HEALTHCHECK_WAKE_ATTEMPTS="${HEALTHCHECK_WAKE_ATTEMPTS:-2}"
HEALTHCHECK_WAKE_DELAY="${HEALTHCHECK_WAKE_DELAY:-2}"
RECONNECT_COOLDOWN="${RECONNECT_COOLDOWN:-30}"
DISABLE_IPSEC_KEEPALIVE="${DISABLE_IPSEC_KEEPALIVE:-false}"
ROUTES_TMP_FILE="${ROUTES_TMP_FILE:-/tmp/snx_added_routes.txt}"
HOST_ROUTE_TABLE="${HOST_ROUTE_TABLE:-18001}"
HOST_ROUTE_RULE_PRIORITY="${HOST_ROUTE_RULE_PRIORITY:-50}"
HOST_ACCESS_NETWORKS="${HOST_ACCESS_NETWORKS:-}"
AMNEZIA_CONFIG_FILE="${AMNEZIA_CONFIG_FILE:-${HOME:-/root}/.config/AmneziaVPN.ORG/AmneziaVPN.conf}"
AMNEZIA_ENDPOINTS="${AMNEZIA_ENDPOINTS:-}"
PLAYWRIGHT_ENABLED="${PLAYWRIGHT_ENABLED:-true}"
PLAYWRIGHT_IMAGE="${PLAYWRIGHT_IMAGE:-snx-rs-playwright:local}"
PLAYWRIGHT_BASE_IMAGE="${PLAYWRIGHT_BASE_IMAGE:-mcr.microsoft.com/playwright:v1.52.0-noble}"
PLAYWRIGHT_VERSION="${PLAYWRIGHT_VERSION:-1.52.0}"
PLAYWRIGHT_TIMEOUT="${PLAYWRIGHT_TIMEOUT:-110}"
PLAYWRIGHT_USERNAME="${PLAYWRIGHT_USERNAME:-}"
PLAYWRIGHT_PASSWORD="${PLAYWRIGHT_PASSWORD:-}"
PLAYWRIGHT_OTP="${PLAYWRIGHT_OTP:-}"
PLAYWRIGHT_DEBUG="${PLAYWRIGHT_DEBUG:-false}"
PLAYWRIGHT_PROFILE_VOLUME="${PLAYWRIGHT_PROFILE_VOLUME-snx-rs-playwright-profile}"
PLAYWRIGHT_CONTEXT="${PLAYWRIGHT_CONTEXT:-$SCRIPT_DIR/docker/playwright}"
SNX_SESSIONS_VOLUME="${SNX_SESSIONS_VOLUME:-snx-rs-sessions}"
DOCKER_USE_SUDO="${DOCKER_USE_SUDO:-auto}"
DOCKER_SUDO=false

GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

BRIDGE_NAME=""
GATEWAY_IP=""
UPLINK_INTERFACE="${UPLINK_INTERFACE:-}"
UPLINK_GATEWAY=""
UPLINK_SOURCE=""
LOGS_PID=""
AUTH_WATCHER_PID=""
AUTH_CONTAINER_NAME="${CONTAINER_NAME}-playwright"
PLAYWRIGHT_ENV_FILE=""
HEALTHCHECK_FAILURE_COUNT=0
CLEANUP_DONE=false

log() {
	local level="$1"
	local message="$2"
	local time_str
	time_str=$(date '+%Y-%m-%d %H:%M:%S')
	echo "[$time_str] [$level] $message" >>"$LOG_FILE"
}

info() {
	echo -e "${BLUE}[INFO]${NC} $1"
	log "INFO" "$1"
}

success() {
	echo -e "${GREEN}[SUCCESS]${NC} $1"
	log "SUCCESS" "$1"
}

warn() {
	echo -e "${YELLOW}[WARNING]${NC} $1"
	log "WARNING" "$1"
}

error() {
	echo -e "${RED}[ERROR]${NC} $1" >&2
	log "ERROR" "$1"
}

docker() {
	if [ "$DOCKER_SUDO" = true ]; then
		sudo -n docker --context default "$@"
	else
		command docker "$@"
	fi
}

configure_docker() {
	case "$DOCKER_USE_SUDO" in
		true|false|auto) ;;
		*)
			error "DOCKER_USE_SUDO должен быть auto, true или false."
			return 1
			;;
	esac

	local security_options=""
	if [ "$DOCKER_USE_SUDO" != true ]; then
		security_options=$(command docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true)
	fi

	if [ "$DOCKER_USE_SUDO" = true ]; then
		if ! sudo -n docker --context default info >/dev/null 2>&1; then
			error "Для Check Point bridge нужен rootful Docker. Запустите системный Docker и убедитесь, что sudo доступен."
			return 1
		fi
		DOCKER_SUDO=true
		export DOCKER_USE_SUDO
		return 0
	fi

	if [ "$DOCKER_USE_SUDO" = auto ] && [ -z "$security_options" ]; then
		if sudo -n docker --context default info >/dev/null 2>&1; then
			info "Текущий Docker daemon недоступен пользователю; для Check Point bridge используется системный Docker через sudo."
			DOCKER_SUDO=true
			DOCKER_USE_SUDO=true
			export DOCKER_USE_SUDO
			return 0
		fi
	fi

	if [[ "$security_options" == *rootless* ]]; then
		if [ "$DOCKER_USE_SUDO" = false ]; then
			error "Rootless Docker не подходит для Check Point bridge; используйте rootful Docker или DOCKER_USE_SUDO=auto."
			return 1
		fi
		info "Обнаружен rootless Docker; для Check Point bridge используется системный Docker через sudo."
		if ! sudo -n docker --context default info >/dev/null 2>&1; then
			error "Для Check Point bridge нужен rootful Docker. Запустите системный Docker и убедитесь, что sudo доступен."
			return 1
		fi
		DOCKER_SUDO=true
		DOCKER_USE_SUDO=true
		export DOCKER_USE_SUDO
		return 0
	fi

	if [ -z "$security_options" ] || ! command docker info >/dev/null 2>&1; then
		error "Не удалось проверить Docker daemon."
		return 1
	fi

	DOCKER_SUDO=false
	DOCKER_USE_SUDO=false
	export DOCKER_USE_SUDO
}

container_is_running() {
	[ "$(docker inspect -f '{{.State.Running}}' "$CONTAINER_NAME" 2>/dev/null)" = "true" ]
}

container_ip() {
	docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CONTAINER_NAME" 2>/dev/null
}

is_route_prefix() {
	[[ "$1" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || return 1
	[[ "$1" != 0.0.0.0 && "$1" != 0.0.0.0/* ]]
}

clear_host_policy_routes() {
	local priority
	local destination

	while read -r priority destination; do
		[ -n "$priority" ] || continue
		if [ "$destination" = all ]; then
			sudo ip rule del pref "$priority" lookup "$HOST_ROUTE_TABLE" 2>/dev/null || true
		else
			sudo ip rule del pref "$priority" to "$destination" lookup "$HOST_ROUTE_TABLE" 2>/dev/null || true
		fi
	done < <(
		ip -4 -o rule show 2>/dev/null | awk -v table="$HOST_ROUTE_TABLE" '
			$NF == table {
				priority = $1
				sub(/:$/, "", priority)
				destination = "all"
				for (i = 1; i < NF; i++) {
					if ($i == "to") {
						destination = $(i + 1)
						break
					}
				}
				print priority, destination
			}
		'
	)

	sudo ip route flush table "$HOST_ROUTE_TABLE" 2>/dev/null || true
}

find_uplink_route() {
	local route=""
	local candidate
	local candidate_interface
	local candidate_source

	while IFS= read -r candidate; do
		candidate_interface=$(awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$candidate")
		if [ -n "$UPLINK_INTERFACE" ]; then
			[ "$candidate_interface" = "$UPLINK_INTERFACE" ] || continue
			route="$candidate"
			break
		fi
		if ! is_host_access_interface "$candidate_interface"; then
			continue
		fi
		candidate_source=$(awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}' <<<"$candidate")
		if [ -z "$candidate_source" ]; then
			candidate_source=$(ip -4 -o addr show dev "$candidate_interface" scope global 2>/dev/null | awk 'NR == 1 {split($4, address, "/"); print address[1]}')
		fi
		if [ -n "$candidate_source" ]; then
			route="$candidate"
			break
		fi
	done < <(ip -4 route show table main default 2>/dev/null)

	if [ -z "$route" ]; then
		error "В основной таблице маршрутизации не найден IPv4 default route."
		return 1
	fi

	UPLINK_INTERFACE=$(awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$route")
	UPLINK_GATEWAY=$(awk '{for (i = 1; i <= NF; i++) if ($i == "via") {print $(i + 1); exit}}' <<<"$route")
	UPLINK_SOURCE=$(awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}' <<<"$route")

	if [ -z "$UPLINK_SOURCE" ] && [ -n "$UPLINK_INTERFACE" ]; then
		UPLINK_SOURCE=$(ip -4 -o addr show dev "$UPLINK_INTERFACE" scope global 2>/dev/null | awk 'NR == 1 {split($4, address, "/"); print address[1]}')
	fi

	if [ -z "$UPLINK_INTERFACE" ] || [ -z "$UPLINK_SOURCE" ]; then
		error "Не удалось определить физический интерфейс и адрес для обхода AmneziaVPN."
		return 1
	fi
}

amnezia_endpoint_addresses() {
	local configured_endpoints="${AMNEZIA_ENDPOINTS//,/ }"
	local endpoint

	for endpoint in $configured_endpoints; do
		endpoint="${endpoint%%:*}"
		if is_route_prefix "$endpoint"; then
			printf '%s\n' "$endpoint"
		fi
	done

	if [ -r "$AMNEZIA_CONFIG_FILE" ]; then
		grep -oE 'Endpoint = [0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?' "$AMNEZIA_CONFIG_FILE" 2>/dev/null |
			awk '{endpoint = $3; sub(/:.*/, "", endpoint); if (!seen[endpoint]++) print endpoint}'
	fi
}

install_amnezia_endpoint_route() {
	local endpoint="$1"

	if [ "$endpoint" = "$GATEWAY_IP" ]; then
		return 0
	fi
	if [ -n "$UPLINK_GATEWAY" ]; then
		if ! sudo ip route replace "$endpoint/32" via "$UPLINK_GATEWAY" dev "$UPLINK_INTERFACE" src "$UPLINK_SOURCE" table "$HOST_ROUTE_TABLE"; then
			return 1
		fi
	else
		if ! sudo ip route replace "$endpoint/32" dev "$UPLINK_INTERFACE" src "$UPLINK_SOURCE" table "$HOST_ROUTE_TABLE"; then
			return 1
		fi
	fi
	sudo ip rule add pref "$HOST_ROUTE_RULE_PRIORITY" to "$endpoint/32" lookup "$HOST_ROUTE_TABLE"
}

install_amnezia_endpoint_routes() {
	local endpoint

	while read -r endpoint; do
		[ -n "$endpoint" ] || continue
		if ! install_amnezia_endpoint_route "$endpoint"; then
			return 1
		fi
	done < <(amnezia_endpoint_addresses | awk '!seen[$0]++')
}

install_host_access_route() {
	local destination="$1"
	local interface="$2"
	local gateway="$3"
	local source="$4"
	local -a route_args=("$destination")

	if [ -n "$gateway" ]; then
		route_args+=(via "$gateway")
	fi
	route_args+=(dev "$interface")
	if [ -n "$source" ]; then
		route_args+=(src "$source")
	fi

	if ! sudo ip route replace "${route_args[@]}" table "$HOST_ROUTE_TABLE"; then
		return 1
	fi

	if ! ip -4 -o rule show 2>/dev/null | grep -Fq "to $destination lookup $HOST_ROUTE_TABLE"; then
		if ! sudo ip rule add pref "$HOST_ROUTE_RULE_PRIORITY" to "$destination" lookup "$HOST_ROUTE_TABLE"; then
			return 1
		fi
	fi
}

is_host_access_interface() {
	local interface="$1"
	[ "$interface" != "$BRIDGE_NAME" ] || return 1
	[[ "$interface" != tun* && "$interface" != wg* && "$interface" != awg* && "$interface" != amn* ]]
}

install_connected_host_access_routes() {
	local line
	local destination
	local interface
	local source

	while IFS= read -r line; do
		destination=$(awk '{print $1}' <<<"$line")
		interface=$(awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$line")
		source=$(awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}' <<<"$line")

		is_route_prefix "$destination" || continue
		[ -n "$interface" ] || continue
		is_host_access_interface "$interface" || continue
		if ! install_host_access_route "$destination" "$interface" "" "$source"; then
			return 1
		fi
	done < <(ip -4 route show table main scope link 2>/dev/null)
}

install_configured_host_access_routes() {
	local network

	for network in ${HOST_ACCESS_NETWORKS//,/ }; do
		is_route_prefix "$network" || {
			error "Некорректная сеть HOST_ACCESS_NETWORKS: $network"
			return 1
		}

		if [ -z "$UPLINK_INTERFACE" ] || ! is_host_access_interface "$UPLINK_INTERFACE"; then
			error "Не удалось определить uplink для HOST_ACCESS_NETWORKS=$network"
			return 1
		fi
		if ! install_host_access_route "$network" "$UPLINK_INTERFACE" "$UPLINK_GATEWAY" "$UPLINK_SOURCE"; then
			return 1
		fi
	done
}

install_bridge_policy_route() {
	local bridge_ip
	local bridge_subnet

	bridge_ip=$(ip -4 -o addr show dev "$BRIDGE_NAME" scope global 2>/dev/null | awk 'NR == 1 {split($4, address, "/"); print address[1]}')
	bridge_subnet=$(ip -4 route show dev "$BRIDGE_NAME" scope link 2>/dev/null | awk 'NR == 1 {print $1}')
	if [ -z "$bridge_ip" ] || [ -z "$bridge_subnet" ]; then
		error "Не удалось определить IPv4-сеть Docker bridge $BRIDGE_NAME."
		return 1
	fi

	if ! sudo ip route replace "$bridge_subnet" dev "$BRIDGE_NAME" src "$bridge_ip" table "$HOST_ROUTE_TABLE"; then
		return 1
	fi
	if ! sudo ip rule add pref "$HOST_ROUTE_RULE_PRIORITY" to "$bridge_subnet" lookup "$HOST_ROUTE_TABLE"; then
		return 1
	fi
}

install_gateway_policy_route() {
	if [ -n "$UPLINK_GATEWAY" ]; then
		if ! sudo ip route replace "$UPLINK_GATEWAY/32" dev "$UPLINK_INTERFACE" src "$UPLINK_SOURCE" scope link table "$HOST_ROUTE_TABLE"; then
			return 1
		fi
		if ! sudo ip route replace "$GATEWAY_IP/32" via "$UPLINK_GATEWAY" dev "$UPLINK_INTERFACE" src "$UPLINK_SOURCE" table "$HOST_ROUTE_TABLE"; then
			return 1
		fi
	else
		if ! sudo ip route replace "$GATEWAY_IP/32" dev "$UPLINK_INTERFACE" src "$UPLINK_SOURCE" table "$HOST_ROUTE_TABLE"; then
			return 1
		fi
	fi

	sudo ip rule add pref "$HOST_ROUTE_RULE_PRIORITY" to "$GATEWAY_IP/32" lookup "$HOST_ROUTE_TABLE"
}

configure_gateway_policy_route() {
	if ! find_uplink_route; then
		return 1
	fi

	clear_host_policy_routes
	if ! install_connected_host_access_routes; then
		return 1
	fi
	if ! install_configured_host_access_routes; then
		return 1
	fi
	if ! install_bridge_policy_route; then
		return 1
	fi
	if ! install_gateway_policy_route; then
		return 1
	fi
	install_amnezia_endpoint_routes
}

configure_host_policy_routes() {
	local route_list="$1"
	local container_ip="$2"
	local subnet
	local line

	if ! find_uplink_route; then
		return 1
	fi

	clear_host_policy_routes

	if ! install_connected_host_access_routes; then
		return 1
	fi
	if ! install_configured_host_access_routes; then
		return 1
	fi
	if ! install_bridge_policy_route; then
		return 1
	fi
	if ! install_gateway_policy_route; then
		return 1
	fi
	if ! install_amnezia_endpoint_routes; then
		return 1
	fi

	while read -r line; do
		subnet=$(awk '{print $1}' <<<"$line")
		if ! is_route_prefix "$subnet" || [[ "$subnet" == "$GATEWAY_IP"* ]]; then
			continue
		fi
		if ! sudo ip route replace "$subnet" via "$container_ip" dev "$BRIDGE_NAME" table "$HOST_ROUTE_TABLE"; then
			return 1
		fi
		if ! sudo ip rule add pref "$HOST_ROUTE_RULE_PRIORITY" to "$subnet" lookup "$HOST_ROUTE_TABLE"; then
			return 1
		fi
	done <<<"$route_list"
}

trim_line() {
	local line="$1"
	line="${line#"${line%%[![:space:]]*}"}"
	line="${line%"${line##*[![:space:]]}"}"
	printf '%s' "$line"
}

is_identity_challenge_marker() {
	local line="$1"
	[[ "$line" == *identity* || "$line" == *Identity* || "$line" == *identit* || "$line" == *провайдер* || "$line" == *идентификац* ]]
}

ensure_playwright_image() {
	if docker image inspect "$PLAYWRIGHT_IMAGE" >/dev/null 2>&1; then
		return 0
	fi

	info "Сборка Docker-образа Playwright для IdP-аутентификации..."
	if ! docker build \
		--build-arg "PLAYWRIGHT_BASE_IMAGE=$PLAYWRIGHT_BASE_IMAGE" \
		--build-arg "PLAYWRIGHT_VERSION=$PLAYWRIGHT_VERSION" \
		--tag "$PLAYWRIGHT_IMAGE" \
		"$PLAYWRIGHT_CONTEXT" >>"$LOG_FILE" 2>&1; then
		error "Не удалось собрать Docker-образ Playwright."
		return 1
	fi
}

run_playwright_auth() {
	local url="$1"
	local -a volume_args=()

	if ! ensure_playwright_image; then
		return 1
	fi

	if [[ "$PLAYWRIGHT_PASSWORD" == *$'\n'* || "$PLAYWRIGHT_PASSWORD" == *$'\r'* ]]; then
		error "PLAYWRIGHT_PASSWORD не должен содержать переводы строк."
		return 1
	fi

	PLAYWRIGHT_ENV_FILE=$(mktemp)
	chmod 600 "$PLAYWRIGHT_ENV_FILE"
	printf 'PLAYWRIGHT_TIMEOUT=%s\nPLAYWRIGHT_CALLBACK_PORT=7779\nPLAYWRIGHT_USERNAME=%s\nPLAYWRIGHT_PASSWORD=%s\nPLAYWRIGHT_OTP=%s\nPLAYWRIGHT_DEBUG=%s\n' \
		"$PLAYWRIGHT_TIMEOUT" "$PLAYWRIGHT_USERNAME" "$PLAYWRIGHT_PASSWORD" "$PLAYWRIGHT_OTP" "$PLAYWRIGHT_DEBUG" \
		>"$PLAYWRIGHT_ENV_FILE"

	docker rm -f "$AUTH_CONTAINER_NAME" >/dev/null 2>&1 || true
	if [ -n "$PLAYWRIGHT_PROFILE_VOLUME" ]; then
		volume_args+=("--volume=$PLAYWRIGHT_PROFILE_VOLUME:/tmp/playwright-profile")
	fi

	info "Получена ссылка IdP; запускается Playwright-аутентификация. Если Google запросит подтверждение, нажмите кнопку в Google Prompt на телефоне."
	if ! printf '%s\n' "$url" | docker run \
		--rm \
		--interactive \
		--init \
		--ipc=host \
		--network=host \
		--name "$AUTH_CONTAINER_NAME" \
		--env-file "$PLAYWRIGHT_ENV_FILE" \
		"${volume_args[@]}" \
		"$PLAYWRIGHT_IMAGE" >>"$LOG_FILE" 2>&1; then
		rm -f "$PLAYWRIGHT_ENV_FILE"
		PLAYWRIGHT_ENV_FILE=""
		warn "Playwright не завершил IdP-аутентификацию. Проверьте учетные данные и MFA."
		return 1
	fi

	rm -f "$PLAYWRIGHT_ENV_FILE"
	PLAYWRIGHT_ENV_FILE=""
	success "IdP-аутентификация через Playwright завершена."
}

auth_watcher() {
	local challenge_pending=false
	local last_url=""
	local line
	local url

	while docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; do
		local since
		since=$(docker inspect -f '{{.State.StartedAt}}' "$CONTAINER_NAME" 2>/dev/null || true)
		[ -n "$since" ] || since=$(date -u '+%Y-%m-%dT%H:%M:%S')
		while IFS= read -r line; do
			line="$(trim_line "${line%$'\r'}")"

			if is_identity_challenge_marker "$line"; then
				challenge_pending=true
				continue
			fi

			if [ "$challenge_pending" = true ] && [[ "$line" =~ ^https?://[^[:space:]]+$ ]]; then
				url="${BASH_REMATCH[0]}"
				challenge_pending=false
				if [ "$url" != "$last_url" ]; then
					last_url="$url"
					run_playwright_auth "$url" || true
				fi
			fi
		done < <(docker logs --since "$since" -f "$CONTAINER_NAME" 2>&1 || true)

		if docker inspect "$CONTAINER_NAME" >/dev/null 2>&1; then
			sleep 1
		fi
	done
}

start_auth_watcher() {
	if [ "$PLAYWRIGHT_ENABLED" != true ]; then
		return 0
	fi

	if [ -z "$PLAYWRIGHT_USERNAME" ] || [ -z "$PLAYWRIGHT_PASSWORD" ]; then
		warn "PLAYWRIGHT_USERNAME/PLAYWRIGHT_PASSWORD не заданы; будет использован сохраненный профиль Playwright."
	fi

	auth_watcher &
	AUTH_WATCHER_PID=$!
}

check_dependencies() {
	info "Проверка зависимостей хост-системы..."

	if [ "$EUID" -eq 0 ]; then
		error "Запуск напрямую от root запрещен. Скрипт запросит sudo самостоятельно."
		exit 1
	fi

	local cmd
	for cmd in resolvectl awk getent ip curl sudo grep; do
		if ! command -v "$cmd" &>/dev/null; then
			error "Отсутствует необходимая утилита: '$cmd'."
			exit 1
		fi
	done
	if ! type -P docker >/dev/null 2>&1; then
		error "Отсутствует необходимая утилита: 'docker'."
		exit 1
	fi

	if ! sudo -v; then
		error "Не удалось получить права sudo для настройки сети."
		exit 1
	fi
	if ! configure_docker; then
		exit 1
	fi
	if ! docker info &>/dev/null; then
		error "Docker не запущен либо текущий пользователь не имеет к нему доступа."
		exit 1
	fi

	success "Все необходимые утилиты доступны."
}

remove_host_routes() {
	local gateway_ip="${1:-}"

	clear_host_policy_routes

	if [ -z "$gateway_ip" ]; then
		gateway_ip=$(container_ip)
	fi

	if [ -n "$gateway_ip" ] && [ -f "$ROUTES_TMP_FILE" ]; then
		while read -r route; do
			if [ -n "$route" ]; then
				sudo ip route del "$route" via "$gateway_ip" dev "$BRIDGE_NAME" 2>/dev/null || true
			fi
		done <"$ROUTES_TMP_FILE"
	fi
	rm -f "$ROUTES_TMP_FILE"
}

cleanup() {
	if [ "$CLEANUP_DONE" = true ]; then
		return
	fi
	CLEANUP_DONE=true
	trap - EXIT INT TERM

	echo -e "\n${YELLOW}Запущена очистка сетевых ресурсов...${NC}"
	log "CLEANUP" "Starting network resources cleanup"

	if [ -n "$LOGS_PID" ]; then
		kill "$LOGS_PID" 2>/dev/null || true
	fi

	if [ -n "$AUTH_WATCHER_PID" ]; then
		kill "$AUTH_WATCHER_PID" 2>/dev/null || true
	fi
	if [ -n "$PLAYWRIGHT_ENV_FILE" ]; then
		rm -f "$PLAYWRIGHT_ENV_FILE"
	fi
	docker rm -f "$AUTH_CONTAINER_NAME" >/dev/null 2>&1 || true

	if [ -n "$BRIDGE_NAME" ]; then
		info "Сброс настроек Split DNS на интерфейсе $BRIDGE_NAME..."
		sudo resolvectl revert "$BRIDGE_NAME" 2>/dev/null || true
	fi

	remove_host_routes

	if docker ps -a --format '{{.Names}}' | grep -Fqx "$CONTAINER_NAME"; then
		info "Остановка и удаление контейнера $CONTAINER_NAME..."
		docker rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
	fi

	success "Система успешно очищена."
	log "CLEANUP" "Cleanup finished successfully"
}

wait_for_container_network() {
	local counter=0
	while ! docker exec "$CONTAINER_NAME" iptables -t nat -L &>/dev/null; do
		if ! container_is_running; then
			return 1
		fi
		sleep 0.5
		counter=$((counter + 1))
		if [ "$counter" -ge $((TIMEOUT_DOCKER_BOOT * 2)) ]; then
			return 1
		fi
	done
}

configure_container_network() {
	if ! wait_for_container_network; then
		error "Контейнер не смог загрузить сетевую подсистему за ${TIMEOUT_DOCKER_BOOT} секунд."
		return 1
	fi

	docker exec "$CONTAINER_NAME" sysctl -w net.ipv4.conf.all.route_localnet=1 >>"$LOG_FILE" 2>&1 || return 1
	docker exec "$CONTAINER_NAME" sysctl -w net.ipv4.conf.default.route_localnet=1 >>"$LOG_FILE" 2>&1 || return 1
	docker exec "$CONTAINER_NAME" iptables -t nat -A PREROUTING -p tcp --dport 7779 \
		-j DNAT --to-destination 127.0.0.1:7779 >>"$LOG_FILE" 2>&1 || return 1
}

host_policy_routes_ready() {
	local route_list
	local line
	local subnet
	local endpoint
	local bridge_subnet

	[ -n "$GATEWAY_IP" ] || return 1
	if ! docker exec "$CONTAINER_NAME" ip link show "$IF_NAME" &>/dev/null; then
		return 1
	fi
	if ip -4 route show table "$HOST_ROUTE_TABLE" 2>/dev/null | grep -Eq '^(default|0\.0\.0\.0/[0-9]+)([[:space:]]|$)'; then
		return 1
	fi
	if ! ip -4 route show table "$HOST_ROUTE_TABLE" 2>/dev/null | grep -Fq "$GATEWAY_IP/32"; then
		return 1
	fi
	if ! ip -4 -o rule show 2>/dev/null | grep -Fq "to $GATEWAY_IP/32 lookup $HOST_ROUTE_TABLE"; then
		return 1
	fi
	bridge_subnet=$(ip -4 route show dev "$BRIDGE_NAME" scope link 2>/dev/null | awk 'NR == 1 {print $1}')
	if [ -z "$bridge_subnet" ] || ! ip -4 -o rule show 2>/dev/null | grep -Fq "to $bridge_subnet lookup $HOST_ROUTE_TABLE"; then
		return 1
	fi
	while read -r endpoint; do
		[ -n "$endpoint" ] || continue
		if [ "$endpoint" != "$GATEWAY_IP" ]; then
			if ! ip -4 route show table "$HOST_ROUTE_TABLE" 2>/dev/null | grep -Fq "$endpoint/32"; then
				return 1
			fi
			if ! ip -4 -o rule show 2>/dev/null | grep -Fq "to $endpoint/32 lookup $HOST_ROUTE_TABLE"; then
				return 1
			fi
		fi
	done < <(amnezia_endpoint_addresses | awk '!seen[$0]++')

	route_list=$(docker exec "$CONTAINER_NAME" ip route show table 18000 2>/dev/null) || return 1
	while read -r line; do
		subnet=$(awk '{print $1}' <<<"$line")
		if is_route_prefix "$subnet" && [[ "$subnet" != "$GATEWAY_IP"* ]]; then
			if ! ip -4 route show table "$HOST_ROUTE_TABLE" 2>/dev/null | grep -Fq "$subnet"; then
				return 1
			fi
			if ! ip -4 -o rule show 2>/dev/null | grep -Fq "to $subnet lookup $HOST_ROUTE_TABLE"; then
				return 1
			fi
		fi
	done <<<"$route_list"
}

setup_host_network() {
	local quiet="${1:-false}"

	while ! docker exec "$CONTAINER_NAME" ip link show "$IF_NAME" &>/dev/null; do
		if ! container_is_running; then
			return 1
		fi
		sleep 0.5
	done

	if [ "$quiet" != true ]; then
		docker exec "$CONTAINER_NAME" sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || return 1
		docker exec "$CONTAINER_NAME" iptables -t nat -A POSTROUTING -o "$IF_NAME" -j MASQUERADE \
			>/dev/null 2>&1 || return 1
	fi

	local gateway_ip
	gateway_ip=$(container_ip)
	if [ -z "$gateway_ip" ] || [ -z "$GATEWAY_IP" ]; then
		return 1
	fi

	local route_list
	route_list=$(docker exec "$CONTAINER_NAME" ip route show table 18000 2>/dev/null)
	if ! configure_host_policy_routes "$route_list" "$gateway_ip"; then
		error "Не удалось установить policy-маршруты Check Point."
		return 1
	fi

	: >"$ROUTES_TMP_FILE"
	while read -r line; do
		local subnet
		subnet=$(awk '{print $1}' <<<"$line")
		if is_route_prefix "$subnet" && [[ "$subnet" != "$GATEWAY_IP"* ]]; then
			echo "$subnet" >>"$ROUTES_TMP_FILE"
		fi
	done <<<"$route_list"

	sudo resolvectl dns "$BRIDGE_NAME" 10.40.22.100 10.40.22.101 >/dev/null 2>&1
	sudo resolvectl domain "$BRIDGE_NAME" \
		"~ostrovok-team.ru" "~ostrovok.in" "~ostrovok.ru" "~emergingtravel.in" \
		"~etg.team" "~srv.team" "~trv.team" "~ostrovok.team" "~ozon.ru" "~wb.ru" \
		>/dev/null 2>&1

	if [ "$quiet" != true ]; then
		success "Сеть настроена: маршруты Check Point и Split DNS активированы на хосте."
	fi
}

start_log_stream() {
	if [ -n "$LOGS_PID" ]; then
		kill "$LOGS_PID" 2>/dev/null || true
	fi
	docker logs -f "$CONTAINER_NAME" &
	LOGS_PID=$!
}

probe_vpn() {
	curl --silent --show-error --location --output /dev/null \
		--connect-timeout "$HEALTHCHECK_TIMEOUT" \
		--max-time "$HEALTHCHECK_TIMEOUT" \
		"$HEALTHCHECK_URL"
}

restart_vpn_container() {
	warn "Перезапуск VPN-контейнера и повторная настройка сети..."

	local old_ip
	old_ip=$(container_ip)
	remove_host_routes "$old_ip"

	local attempt
	local configured=false
	for ((attempt = 1; attempt <= 3; attempt++)); do
		if configure_gateway_policy_route; then
			configured=true
			break
		fi
		warn "Не удалось закрепить маршрут до Check Point (попытка $attempt/3); повтор через 2 секунды."
		sleep 2
	done
	if [ "$configured" != true ]; then
		error "Не удалось закрепить маршрут до Check Point через физический интерфейс."
		return 1
	fi

	if ! docker restart "$CONTAINER_NAME" >/dev/null; then
		error "Не удалось перезапустить контейнер $CONTAINER_NAME."
		return 1
	fi

	if ! configure_container_network; then
		return 1
	fi
	start_log_stream

	if ! setup_host_network; then
		error "Туннель не поднялся после перезапуска контейнера."
		return 1
	fi

	success "VPN автоматически переподключен."
}

check_vpn_health() {
	if ! container_is_running; then
		warn "VPN-контейнер остановлен."
		if restart_vpn_container; then
			HEALTHCHECK_FAILURE_COUNT=0
		fi
		return
	fi

	if ! host_policy_routes_ready && ! setup_host_network true; then
		warn "Не удалось повторно применить маршруты Check Point; следующая проверка повторит настройку."
	fi

	if probe_vpn; then
		if [ "$HEALTHCHECK_FAILURE_COUNT" -gt 0 ]; then
			success "Доступ к $HEALTHCHECK_URL восстановлен без переподключения."
		fi
		HEALTHCHECK_FAILURE_COUNT=0
		return
	fi

	HEALTHCHECK_FAILURE_COUNT=$((HEALTHCHECK_FAILURE_COUNT + 1))
	warn "Health-check $HEALTHCHECK_URL не прошел ($HEALTHCHECK_FAILURE_COUNT/$HEALTHCHECK_FAILURE_THRESHOLD)."

	if [ "$HEALTHCHECK_FAILURE_COUNT" -lt "$HEALTHCHECK_FAILURE_THRESHOLD" ]; then
		return
	fi

	local attempt
	for ((attempt = 1; attempt <= HEALTHCHECK_WAKE_ATTEMPTS; attempt++)); do
		info "Попытка оживить туннель дополнительным запросом ($attempt/$HEALTHCHECK_WAKE_ATTEMPTS)..."
		sleep "$HEALTHCHECK_WAKE_DELAY"
		if probe_vpn; then
			success "Туннель ответил после дополнительного трафика, переподключение не требуется."
			HEALTHCHECK_FAILURE_COUNT=0
			return
		fi
	done

	if restart_vpn_container; then
		HEALTHCHECK_FAILURE_COUNT=0
	else
		error "Автоматическое переподключение не удалось; следующая попытка через $RECONNECT_COOLDOWN секунд."
		sleep "$RECONNECT_COOLDOWN"
	fi
}

monitor_vpn() {
	info "Мониторинг VPN включен: $HEALTHCHECK_URL каждые $HEALTHCHECK_INTERVAL секунд."
	while true; do
		sleep "$HEALTHCHECK_INTERVAL"
		check_vpn_health
	done
}

start_container() {
	info "Запуск Docker-контейнера..."
	docker run -d \
		--privileged \
		--device=/dev/net/tun \
		--cap-add=NET_ADMIN \
		--cap-add=SYS_ADMIN \
		-p 7779:7779 \
		--name "$CONTAINER_NAME" \
		--volume="$SNX_SESSIONS_VOLUME:/var/cache/snx-rs" \
		-v /lib/modules:/lib/modules:ro \
		ghcr.io/leleobhz/snx-rs-docker:latest \
		/usr/bin/snx-rs \
		--mode standalone \
		--login-type "$LOGIN_TYPE" \
		--tunnel-type ipsec \
		--ike-persist true \
		--default-route false \
		--no-dns true \
		--no-keepalive "$DISABLE_IPSEC_KEEPALIVE" \
		--allow-forwarding true \
		--if-name "$IF_NAME" \
		--server-name "$SERVER_NAME" \
		--log-level debug \
		--client-mode endpoint_security >>"$LOG_FILE" 2>&1
}

cleanup_action() {
	check_dependencies
	BRIDGE_NAME=$(docker network inspect bridge -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null || true)
	BRIDGE_NAME="${BRIDGE_NAME:-docker0}"
	cleanup
}

start_action() {
	echo "Новый запуск SNX-RS VPN" >"$LOG_FILE"

	check_dependencies
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	info "Разрешение IP-адреса для $SERVER_NAME..."
	GATEWAY_IP=$(getent ahostsv4 "$SERVER_NAME" | head -n 1 | awk '{print $1}' || true)
	if [ -z "$GATEWAY_IP" ]; then
		warn "Не удалось разрешить $SERVER_NAME. Используется резервный IP 87.228.66.146."
		GATEWAY_IP="87.228.66.146"
	fi

	BRIDGE_NAME=$(docker network inspect bridge -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null || true)
	BRIDGE_NAME="${BRIDGE_NAME:-docker0}"

	remove_host_routes "$(container_ip)"
	rm -f "$ROUTES_TMP_FILE"
	if ! configure_gateway_policy_route; then
		error "Не удалось закрепить маршрут до Check Point через физический интерфейс."
		exit 1
	fi

	docker rm -f "$CONTAINER_NAME" &>/dev/null || true
	if ! start_container; then
		error "Не удалось запустить контейнер $CONTAINER_NAME."
		exit 1
	fi

	info "Настройка локального проброса портов..."
	if ! configure_container_network; then
		exit 1
	fi
	start_log_stream
	start_auth_watcher

	if ! setup_host_network; then
		warn "Первичная настройка туннеля не завершена; монитор попробует восстановить соединение."
	fi

	monitor_vpn
}

main() {
	case "${1:-start}" in
		start)
			start_action
			;;
		cleanup)
			cleanup_action
			;;
		*)
			error "Неизвестная команда: ${1:-}"
			return 2
			;;
	esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
	main "$@"
fi

)


set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
if [ -f "$ENV_FILE" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$ENV_FILE"
	set +a
fi

AWG_PROFILE_NAME="${AWG_PROFILE_NAME:-Denmark6}"
AWG_IF_NAME="${AWG_IF_NAME:-amneziawg0}"
IF_NAME="${IF_NAME:-etg_vpn}"
BRIDGE_CONTAINER_NAME="${BRIDGE_CONTAINER_NAME:-${CONTAINER_NAME:-snx-rs-vpn}}"
AMNEZIA_SERVICE_NAME="${AMNEZIA_SERVICE_NAME:-AmneziaVPN.service}"
AMNEZIA_MODE="${AMNEZIA_MODE:-auto}"
AMNEZIA_INTERFACE="${AMNEZIA_INTERFACE:-amn0}"
STOP_CONFLICTING_AMNEZIA="${STOP_CONFLICTING_AMNEZIA:-true}"
AMNEZIA_STOP_TIMEOUT="${AMNEZIA_STOP_TIMEOUT:-10}"
CONTAINER_NAME="${CONTAINER_NAME:-$BRIDGE_CONTAINER_NAME}"
AWG_ROUTE_TABLE="${AWG_ROUTE_TABLE:-51821}"
AWG_RULE_PRIORITY="${AWG_RULE_PRIORITY:-1000}"
HOST_ROUTE_TABLE="${HOST_ROUTE_TABLE:-18001}"
HOST_ROUTE_RULE_PRIORITY="${HOST_ROUTE_RULE_PRIORITY:-50}"
HOST_ACCESS_NETWORKS="${HOST_ACCESS_NETWORKS:-}"
BRIDGE_START_CHECK_SECONDS="${BRIDGE_START_CHECK_SECONDS:-5}"
RUN_UID="${SUDO_UID:-${UID:-$(id -u)}}"
STATE_DIR="${COMBINED_STATE_DIR:-${XDG_RUNTIME_DIR:-/tmp}/snx-both-vpn-${RUN_UID}}"
STATE_FILE="$STATE_DIR/state"
LOCK_FILE="$STATE_DIR/lock"
AWG_STATE_DIR="${AWG_STATE_DIR:-${XDG_RUNTIME_DIR:-/tmp}/amneziawg-terminal-${RUN_UID}}"
AWG_LOG_FILE="${AWG_LOG_FILE:-$AWG_STATE_DIR/amneziawg.log}"
LOG_FILE="${LOG_FILE:-$SCRIPT_DIR/snx_bridge_vpn.log}"
BRIDGE_LOG_FILE="$LOG_FILE"
COMBINED_LOG_FILE="${COMBINED_LOG_FILE:-$STATE_DIR/combined.log}"
DOCKER_USE_SUDO="${DOCKER_USE_SUDO:-auto}"
DOCKER_SUDO=false
export CONTAINER_NAME AWG_IF_NAME IF_NAME AWG_ROUTE_TABLE AWG_RULE_PRIORITY HOST_ROUTE_TABLE HOST_ROUTE_RULE_PRIORITY HOST_ACCESS_NETWORKS LOG_FILE DOCKER_USE_SUDO AWG_PROFILE_NAME

BRIDGE_PID=""
LOCK_FD=""
AWG_STARTED=false
AMNEZIA_START_EXISTING=false
CLEANUP_DONE=false

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

usage() {
	cat <<EOF
Использование: $(basename "$0") <команда> [опции]

Команды:
  start [опции]  Поднять Amnezia (или использовать AmneziaVPN), затем Check Point bridge
  stop           Остановить bridge и запущенный скриптом AmneziaWG
  restart        Перезапустить объединённый VPN
  status         Показать состояние Amnezia и Check Point bridge
  logs [какой]   Показать логи: both, amnezia или bridge
  amnezia ...    Управление только AmneziaWG (start, stop, status, logs, profiles, config)
  bridge ...     Управление только Check Point bridge (start, cleanup)

Опции после start/restart передаются встроенному модулю AmneziaWG:
  --profile VALUE       Индекс или название профиля AmneziaWG (по умолчанию Denmark6)
  --config PATH         Путь к AmneziaVPN.conf
  --interface NAME      Имя интерфейса AmneziaWG
  --engine PATH         Путь к amneziawg-go
  --no-dns              Не менять DNS в скрипте AmneziaWG

Порядок запуска важен: AmneziaWG устанавливает default route, а bridge
после него добавляет корпоративные маршруты с более высоким приоритетом.
Локальные подключённые сети автоматически обходят AmneziaWG, чтобы сохранять
доступ к компьютеру по SSH. Дополнительные сети можно задать через
HOST_ACCESS_NETWORKS=сеть1,сеть2 в .env.

Режим AmneziaWG задаётся через AMNEZIA_MODE:
  auto      Использовать уже подключённый AmneziaVPN, если он активен и есть amn0;
            иначе запустить amneziawg-go (по умолчанию)
  existing  Обязательно использовать уже подключённый AmneziaVPN и не останавливать его
  script    Всегда останавливать AmneziaVPN.service и запускать amneziawg-go

Перед запуском в режиме script скрипт останавливает активный AmneziaVPN.service,
который создаёт конфликтующий интерфейс amn0. Отключить остановку можно через
STOP_CONFLICTING_AMNEZIA=false, но тогда конфликт нужно устранить вручную.

Для Check Point bridge нужен rootful Docker. Если выбран rootless Docker,
скрипт автоматически использует системный Docker через sudo. Поведение можно
настроить через DOCKER_USE_SUDO=auto|true|false.
EOF
}

log() {
	local level="$1"
	local message="$2"
	local log_dir
	log_dir=$(dirname -- "$COMBINED_LOG_FILE")
	mkdir -p "$log_dir" 2>/dev/null || true
	printf '[%s] [%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$level" "$message" >>"$COMBINED_LOG_FILE" 2>/dev/null || true
}

info() {
	printf '%b[INFO]%b %s\n' "$BLUE" "$NC" "$1"
	log INFO "$1"
}

success() {
	printf '%b[SUCCESS]%b %s\n' "$GREEN" "$NC" "$1"
	log SUCCESS "$1"
}

warn() {
	printf '%b[WARNING]%b %s\n' "$YELLOW" "$NC" "$1" >&2
	log WARNING "$1"
}

error() {
	printf '%b[ERROR]%b %s\n' "$RED" "$NC" "$1" >&2
	log ERROR "$1"
}

docker() {
	if [ "$DOCKER_SUDO" = true ]; then
		sudo -n docker --context default "$@"
	else
		command docker "$@"
	fi
}

configure_docker() {
	case "$DOCKER_USE_SUDO" in
		true|false|auto) ;;
		*)
			error "DOCKER_USE_SUDO должен быть auto, true или false."
			return 1
			;;
	esac

	local security_options=""
	if [ "$DOCKER_USE_SUDO" != true ]; then
		security_options=$(command docker info --format '{{json .SecurityOptions}}' 2>/dev/null || true)
	fi

	if [ "$DOCKER_USE_SUDO" = true ]; then
		if ! sudo -n docker --context default info >/dev/null 2>&1; then
			error "Для Check Point bridge нужен rootful Docker. Запустите системный Docker и убедитесь, что sudo доступен."
			return 1
		fi
		DOCKER_SUDO=true
		export DOCKER_USE_SUDO
		return 0
	fi

	if [ "$DOCKER_USE_SUDO" = auto ] && [ -z "$security_options" ]; then
		if sudo -n docker --context default info >/dev/null 2>&1; then
			info "Текущий Docker daemon недоступен пользователю; для Check Point bridge используется системный Docker через sudo."
			DOCKER_SUDO=true
			DOCKER_USE_SUDO=true
			export DOCKER_USE_SUDO
			return 0
		fi
	fi

	if [[ "$security_options" == *rootless* ]]; then
		if [ "$DOCKER_USE_SUDO" = false ]; then
			error "Rootless Docker не подходит для Check Point bridge; используйте rootful Docker или DOCKER_USE_SUDO=auto."
			return 1
		fi
		info "Обнаружен rootless Docker; для Check Point bridge используется системный Docker через sudo."
		if ! sudo -n docker --context default info >/dev/null 2>&1; then
			error "Для Check Point bridge нужен rootful Docker. Запустите системный Docker и убедитесь, что sudo доступен."
			return 1
		fi
		DOCKER_SUDO=true
		DOCKER_USE_SUDO=true
		export DOCKER_USE_SUDO
		return 0
	fi

	if [ -z "$security_options" ] || ! command docker info >/dev/null 2>&1; then
		error "Не удалось проверить Docker daemon."
		return 1
	fi

	DOCKER_SUDO=false
	DOCKER_USE_SUDO=false
	export DOCKER_USE_SUDO
}

init_state() {
	mkdir -p "$STATE_DIR"
	chmod 700 "$STATE_DIR"
	if [ ! -O "$STATE_DIR" ]; then
		error "Каталог состояния не принадлежит текущему пользователю: $STATE_DIR"
		exit 1
	fi
}

acquire_lock() {
	exec {LOCK_FD}>"$LOCK_FILE"
	flock -n "$LOCK_FD" || {
		error "Другой экземпляр объединённого скрипта уже выполняет операцию."
		exit 1
	}
}

release_lock() {
	if [ -n "$LOCK_FD" ]; then
		eval "exec ${LOCK_FD}>&-"
		LOCK_FD=""
	fi
}

check_dependencies() {
	[ "$EUID" -ne 0 ] || {
		error "Запуск напрямую от root запрещён. Скрипт запросит sudo самостоятельно."
		exit 1
	}

	case "$STOP_CONFLICTING_AMNEZIA" in
		true|false) ;;
		*)
			error "STOP_CONFLICTING_AMNEZIA должен быть true или false."
			exit 1
			;;
	esac
	[[ "$AMNEZIA_STOP_TIMEOUT" =~ ^[0-9]+$ ]] || {
		error "AMNEZIA_STOP_TIMEOUT должен быть неотрицательным числом."
		exit 1
	}

	local command_name
	for command_name in flock ip ps sudo systemctl; do
		command -v "$command_name" >/dev/null 2>&1 || {
			error "Отсутствует необходимая утилита: $command_name"
			exit 1
		}
	done
	if ! type -P docker >/dev/null 2>&1; then
		error "Отсутствует необходимая утилита: docker"
		exit 1
	fi

	[[ "$AWG_ROUTE_TABLE" =~ ^[0-9]+$ && "$HOST_ROUTE_TABLE" =~ ^[0-9]+$ ]] || {
		error "AWG_ROUTE_TABLE и HOST_ROUTE_TABLE должны быть числами."
		exit 1
	}
	[[ "$AWG_RULE_PRIORITY" =~ ^[0-9]+$ && "$HOST_ROUTE_RULE_PRIORITY" =~ ^[0-9]+$ ]] || {
		error "AWG_RULE_PRIORITY и HOST_ROUTE_RULE_PRIORITY должны быть числами."
		exit 1
	}
	[[ "$BRIDGE_START_CHECK_SECONDS" =~ ^[0-9]+$ ]] || {
		error "BRIDGE_START_CHECK_SECONDS должен быть неотрицательным числом."
		exit 1
	}
	if [ "$AWG_ROUTE_TABLE" = "$HOST_ROUTE_TABLE" ]; then
		error "Таблицы маршрутизации AmneziaWG и bridge должны различаться."
		exit 1
	fi
	if (( HOST_ROUTE_RULE_PRIORITY >= AWG_RULE_PRIORITY )); then
		error "HOST_ROUTE_RULE_PRIORITY должен быть меньше AWG_RULE_PRIORITY, иначе corporate-маршруты попадут в AmneziaWG."
		exit 1
	fi

	sudo -v || {
		error "Не удалось получить права sudo."
		exit 1
	}
	configure_docker || exit 1
}

conflicting_amnezia_interfaces() {
	ip -o link show 2>/dev/null | awk -F': ' -v configured="$AWG_IF_NAME" '
	{
		split($2, names, "@")
		name = names[1]
		if (name != configured && (name ~ /^amn/ || name ~ /^amnezia/)) print name
	}'
}

amnezia_service_active() {
	[ -n "$AMNEZIA_SERVICE_NAME" ] && systemctl is-active --quiet "$AMNEZIA_SERVICE_NAME"
}

amnezia_existing_ready() {
	amnezia_service_active && ip -o link show dev "$AMNEZIA_INTERFACE" >/dev/null 2>&1
}

select_amnezia_mode() {
	case "$AMNEZIA_MODE" in
		auto|existing|script) ;;
		*)
			error "AMNEZIA_MODE должен быть auto, existing или script."
			return 1
			;;
	esac

	AMNEZIA_START_EXISTING=false
	if [ "$AMNEZIA_MODE" = existing ]; then
		if ! amnezia_existing_ready; then
			error "AMNEZIA_MODE=existing, но $AMNEZIA_SERVICE_NAME не активен или отсутствует интерфейс $AMNEZIA_INTERFACE."
			return 1
		fi
		AMNEZIA_START_EXISTING=true
	elif [ "$AMNEZIA_MODE" = auto ] && amnezia_existing_ready; then
		AMNEZIA_START_EXISTING=true
	fi
}

stop_conflicting_amnezia() {
	local interfaces
	interfaces=$(conflicting_amnezia_interfaces || true)

	if [ "$STOP_CONFLICTING_AMNEZIA" = false ]; then
		if amnezia_service_active || [ -n "$interfaces" ]; then
			error "Обнаружен другой AmneziaVPN (${AMNEZIA_SERVICE_NAME:-service} или интерфейс ${interfaces:-amn*}). Остановите его или установите STOP_CONFLICTING_AMNEZIA=true."
			return 1
		fi
		return 0
	fi

	if amnezia_service_active; then
		info "Остановка конфликтующего $AMNEZIA_SERVICE_NAME (интерфейс amn0)..."
		if ! sudo systemctl stop "$AMNEZIA_SERVICE_NAME"; then
			error "Не удалось остановить $AMNEZIA_SERVICE_NAME."
			return 1
		fi
	fi

	local attempt
	for ((attempt = 0; attempt < AMNEZIA_STOP_TIMEOUT * 10; attempt++)); do
		interfaces=$(conflicting_amnezia_interfaces || true)
		[ -z "$interfaces" ] && return 0
		sleep 0.1
	done

	interfaces=$(conflicting_amnezia_interfaces || true)
	if [ -n "$interfaces" ]; then
		error "Конфликтующий интерфейс Amnezia всё ещё существует: $interfaces"
		return 1
	fi
}

load_state() {
	BRIDGE_PID=""
	[ -r "$STATE_FILE" ] || return 1

	local key value
	while IFS='=' read -r key value; do
		case "$key" in
			bridge_pid)
				if [[ "$value" =~ ^[0-9]+$ ]]; then
					BRIDGE_PID="$value"
				fi
				;;
		esac
	done <"$STATE_FILE"

	[ -n "$BRIDGE_PID" ]
}

save_state() {
	local temporary="$STATE_DIR/state.tmp"
	printf 'bridge_pid=%s\n' "$BRIDGE_PID" >"$temporary"
	chmod 600 "$temporary"
	mv -f "$temporary" "$STATE_FILE"
}

clear_state() {
	rm -f "$STATE_FILE"
}

bridge_process_alive() {
	[ -n "$BRIDGE_PID" ] || return 1
	kill -0 "$BRIDGE_PID" 2>/dev/null || return 1

	local command_line
	command_line=$(ps -p "$BRIDGE_PID" -o args= 2>/dev/null || true)
	[[ "$command_line" == *"$(basename "$0")"* ]]
}

bridge_descendants() {
	local pid="$1"
	local child

	while read -r child; do
		[[ "$child" =~ ^[0-9]+$ ]] || continue
		printf '%s\n' "$child"
		bridge_descendants "$child"
	done < <(ps -o pid= --ppid "$pid" 2>/dev/null)
}

bridge_container_running() {
	command -v docker >/dev/null 2>&1 || return 1
	[ "$(docker inspect -f '{{.State.Running}}' "$BRIDGE_CONTAINER_NAME" 2>/dev/null || true)" = true ]
}

bridge_tunnel_ready() {
	bridge_container_running || return 1
	docker exec "$BRIDGE_CONTAINER_NAME" ip link show "$IF_NAME" >/dev/null 2>&1
}

cleanup_bridge_resources() {
	local has_resources=false
	if bridge_container_running || ip -4 -o rule show 2>/dev/null | grep -Fq "lookup $HOST_ROUTE_TABLE"; then
		has_resources=true
	fi

	if [ "$has_resources" = true ]; then
		info "Принудительная очистка ресурсов Check Point..."
		if ! bridge_module cleanup; then
			warn "Не удалось полностью очистить ресурсы Check Point."
		fi
	fi
}

stop_bridge_process() {
	if [ -z "$BRIDGE_PID" ]; then
		return 0
	fi

	if bridge_process_alive; then
		info "Остановка Check Point bridge (PID $BRIDGE_PID)..."

		local descendants
		descendants=$(bridge_descendants "$BRIDGE_PID" || true)
		kill -TERM "$BRIDGE_PID" 2>/dev/null || true
		local child
		for child in $descendants; do
			kill -TERM "$child" 2>/dev/null || true
		done

		local attempt
		local active
		for ((attempt = 0; attempt < 100; attempt++)); do
			active=false
			if kill -0 "$BRIDGE_PID" 2>/dev/null; then
				active=true
			fi
			for child in $descendants; do
				if kill -0 "$child" 2>/dev/null; then
					active=true
					break
				fi
			done
			[ "$active" = false ] && break
			sleep 0.1
		done

		active=false
		if kill -0 "$BRIDGE_PID" 2>/dev/null; then
			active=true
		fi
		for child in $descendants; do
			if kill -0 "$child" 2>/dev/null; then
				active=true
				break
			fi
		done
		if [ "$active" = true ]; then
			warn "Bridge не завершился по SIGTERM; используется SIGKILL."
			kill -KILL "$BRIDGE_PID" 2>/dev/null || true
			for child in $descendants; do
				kill -KILL "$child" 2>/dev/null || true
			done
		fi
		wait "$BRIDGE_PID" 2>/dev/null || true
	else
		warn "Процесс bridge из состояния запуска уже не найден."
	fi

	BRIDGE_PID=""
}

stop_amnezia() {
	info "Остановка AmneziaWG..."
	if ! awg_module stop; then
		warn "Не удалось штатно остановить AmneziaWG."
	fi
}

cleanup_started_vpns() {
	local exit_code=$?
	trap - EXIT INT TERM

	if [ "$CLEANUP_DONE" = true ]; then
		exit "$exit_code"
	fi
	CLEANUP_DONE=true

	printf '\n%bЗапущена очистка объединённого VPN...%b\n' "$YELLOW" "$NC"
	stop_bridge_process
	cleanup_bridge_resources
	if [ "$AWG_STARTED" = true ]; then
		stop_amnezia
	fi
	clear_state
	release_lock

	exit "$exit_code"
}

start_action() {
	check_dependencies
	init_state
	acquire_lock

	if load_state && bridge_process_alive; then
		release_lock
		error "Объединённый VPN уже запущен (bridge PID $BRIDGE_PID)."
		return 1
	fi
	clear_state

	if bridge_container_running; then
		release_lock
		error "Контейнер $BRIDGE_CONTAINER_NAME уже запущен. Сначала остановите старый bridge."
		return 1
	fi
	if ! select_amnezia_mode; then
		release_lock
		return 1
	fi

	trap cleanup_started_vpns EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	if [ "$AMNEZIA_START_EXISTING" = true ]; then
		info "Используется уже подключённый AmneziaVPN через $AMNEZIA_INTERFACE."
		if [ "$#" -gt 0 ]; then
			warn "Опции профиля AmneziaWG игнорируются в режиме existing."
		fi
	else
		if ! stop_conflicting_amnezia; then
			return 1
		fi
		info "Запуск AmneziaWG первым, чтобы его endpoint сразу использовал обычный uplink."
		if ! awg_module start "$@"; then
			error "Не удалось запустить AmneziaWG."
			return 1
		fi
		AWG_STARTED=true
	fi

	if [ "$AMNEZIA_START_EXISTING" = true ]; then
		info "Запуск Check Point bridge поверх AmneziaVPN..."
	else
		info "Запуск Check Point bridge поверх AmneziaWG..."
	fi
	(
		eval "exec ${LOCK_FD}>&-"
		bridge_module
	) &
	BRIDGE_PID=$!
	save_state
	release_lock

	local attempt
	for ((attempt = 0; attempt < BRIDGE_START_CHECK_SECONDS; attempt++)); do
		if ! bridge_process_alive; then
			error "Скрипт Check Point bridge завершился сразу после запуска."
			return 1
		fi
		sleep 1
	done

	if bridge_tunnel_ready; then
		success "Оба VPN готовы. Bridge-маршруты имеют приоритет над default route AmneziaWG."
	else
		warn "Процесс bridge запущен, но Check Point-туннель ещё не готов. Ожидается аутентификация или handshake; состояние можно проверить через status."
	fi
	info "Для остановки нажмите Ctrl-C или выполните: $(basename "$0") stop"

	local bridge_exit_code
	if wait "$BRIDGE_PID"; then
		bridge_exit_code=0
	else
		bridge_exit_code=$?
	fi
	return "$bridge_exit_code"
}

stop_action() {
	check_dependencies
	init_state
	acquire_lock
	load_state || true

	stop_bridge_process
	cleanup_bridge_resources
	clear_state
	release_lock

	if [ -r "$AWG_STATE_DIR/state" ]; then
		stop_amnezia
	fi
	if amnezia_existing_ready; then
		info "AmneziaVPN оставлен подключённым."
	fi
	success "Объединённый VPN остановлен, состояние и маршруты очищены."
}

status_action() {
	check_dependencies
	init_state
	load_state || true

	printf '%b=== AmneziaWG ===%b\n' "$BLUE" "$NC"
	if amnezia_existing_ready; then
		printf 'AmneziaVPN: active, интерфейс %s готов\n' "$AMNEZIA_INTERFACE"
	fi
	awg_module status || true

	printf '\n%b=== Check Point bridge ===%b\n' "$BLUE" "$NC"
	if bridge_process_alive; then
		printf 'Процесс bridge: running (PID %s)\n' "$BRIDGE_PID"
	else
		printf 'Процесс bridge: не запущен объединённым скриптом\n'
	fi
	if bridge_container_running; then
		printf 'Контейнер %s: running\n' "$BRIDGE_CONTAINER_NAME"
		if bridge_tunnel_ready; then
			printf 'Check Point-интерфейс %s: ready\n' "$IF_NAME"
		else
			printf 'Check Point-интерфейс %s: not ready\n' "$IF_NAME"
		fi
	else
		printf 'Контейнер %s: stopped или отсутствует\n' "$BRIDGE_CONTAINER_NAME"
	fi

	printf '\nPolicy rules:\n'
	ip -4 rule show 2>/dev/null | grep -E "lookup ($HOST_ROUTE_TABLE|$AWG_ROUTE_TABLE)" || true
}

logs_action() {
	local target="${1:-both}"
	[ "$#" -le 1 ] || {
		error "Команда logs принимает только: both, amnezia или bridge."
		return 2
	}

	case "$target" in
		amnezia)
			tail -F "$AWG_LOG_FILE"
			;;
		bridge)
			tail -F "$BRIDGE_LOG_FILE"
			;;
		both)
			tail -F "$AWG_LOG_FILE" "$BRIDGE_LOG_FILE"
			;;
		*)
			error "Неизвестный источник логов: $target"
			return 2
			;;
	esac
}

main() {
	local action="${1:-start}"
	if [ "$action" = "-h" ] || [ "$action" = "--help" ]; then
		usage
		return 0
	fi
	embed_awg_helper || return 1
	shift || true

	case "$action" in
		start)
			start_action "$@"
			;;
		stop)
			[ "$#" -eq 0 ] || { usage; return 2; }
			stop_action
			;;
		restart)
			stop_action
			start_action "$@"
			;;
		status)
			[ "$#" -eq 0 ] || { usage; return 2; }
			status_action
			;;
		logs)
			logs_action "$@"
			;;
		amnezia)
			awg_module "$@"
			;;
		bridge)
			bridge_module "$@"
			;;
		profiles|config)
			awg_module "$action" "$@"
			;;
		*)
			usage
			return 2
			;;
	esac
}

main "$@"
