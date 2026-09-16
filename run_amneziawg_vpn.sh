#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
HELPER="$SCRIPT_DIR/amneziawg_terminal.py"
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
AWG_FALLBACK_DNS="${AWG_FALLBACK_DNS:-1.1.1.1,8.8.8.8}"
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
  AWG_FALLBACK_DNS      Резервные DNS через запятую, если в профиле их нет или они некорректны (по умолчанию 1.1.1.1,8.8.8.8)
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
