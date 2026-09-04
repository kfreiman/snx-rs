#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-$SCRIPT_DIR/.env}"
if [ -f "$ENV_FILE" ]; then
	set -a
	# shellcheck disable=SC1090
	. "$ENV_FILE"
	set +a
fi

AWG_SCRIPT="${AWG_SCRIPT:-$SCRIPT_DIR/run_amneziawg_vpn.sh}"
BRIDGE_SCRIPT="${BRIDGE_SCRIPT:-$SCRIPT_DIR/run_bridge_vpn.sh}"
AWG_IF_NAME="${AWG_IF_NAME:-amneziawg0}"
IF_NAME="${IF_NAME:-etg_vpn}"
BRIDGE_CONTAINER_NAME="${BRIDGE_CONTAINER_NAME:-${CONTAINER_NAME:-snx-rs-vpn}}"
AMNEZIA_SERVICE_NAME="${AMNEZIA_SERVICE_NAME:-AmneziaVPN.service}"
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
export CONTAINER_NAME AWG_IF_NAME IF_NAME AWG_ROUTE_TABLE AWG_RULE_PRIORITY HOST_ROUTE_TABLE HOST_ROUTE_RULE_PRIORITY HOST_ACCESS_NETWORKS LOG_FILE

BRIDGE_PID=""
LOCK_FD=""
AWG_STARTED=false
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
  start [опции]  Сначала запустить AmneziaWG, затем Check Point bridge
  stop           Остановить оба VPN и удалить состояние запуска
  restart        Перезапустить оба VPN
  status         Показать состояние обоих VPN
  logs [какой]   Показать логи: both, amnezia или bridge

Опции после start/restart передаются в run_amneziawg_vpn.sh:
  --profile VALUE       Индекс или название профиля AmneziaWG
  --config PATH         Путь к AmneziaVPN.conf
  --interface NAME      Имя интерфейса AmneziaWG
  --engine PATH         Путь к amneziawg-go
  --no-dns              Не менять DNS в скрипте AmneziaWG

Порядок запуска важен: AmneziaWG устанавливает default route, а bridge
после него добавляет корпоративные маршруты с более высоким приоритетом.
Локальные подключённые сети автоматически обходят AmneziaWG, чтобы сохранять
доступ к компьютеру по SSH. Дополнительные сети можно задать через
HOST_ACCESS_NETWORKS=сеть1,сеть2 в .env.

Перед запуском скрипт останавливает активный AmneziaVPN.service, который
создаёт конфликтующий интерфейс amn0. Отключить это можно через
STOP_CONFLICTING_AMNEZIA=false, но тогда конфликт нужно устранить вручную.
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

	[ -x "$AWG_SCRIPT" ] || {
		error "Не найден исполняемый скрипт AmneziaWG: $AWG_SCRIPT"
		exit 1
	}
	[ -x "$BRIDGE_SCRIPT" ] || {
		error "Не найден исполняемый скрипт bridge: $BRIDGE_SCRIPT"
		exit 1
	}

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
	[[ "$command_line" == *run_bridge_vpn.sh* ]]
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
		if ! "$BRIDGE_SCRIPT" cleanup; then
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
	if ! "$AWG_SCRIPT" stop; then
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

	printf '\n%bЗапущена очистка обоих VPN...%b\n' "$YELLOW" "$NC"
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
		error "Контейнер $BRIDGE_CONTAINER_NAME уже запущен. Сначала остановите старый run_bridge_vpn.sh."
		return 1
	fi
	if ! stop_conflicting_amnezia; then
		release_lock
		return 1
	fi

	trap cleanup_started_vpns EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM

	info "Запуск AmneziaWG первым, чтобы его endpoint сразу использовал обычный uplink."
	if ! "$AWG_SCRIPT" start "$@"; then
		error "Не удалось запустить AmneziaWG."
		return 1
	fi
	AWG_STARTED=true

	info "Запуск Check Point bridge поверх AmneziaWG..."
	(
		eval "exec ${LOCK_FD}>&-"
		exec "$BRIDGE_SCRIPT"
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

	stop_amnezia
	success "Оба VPN остановлены, состояние и маршруты очищены."
}

status_action() {
	check_dependencies
	init_state
	load_state || true

	printf '%b=== AmneziaWG ===%b\n' "$BLUE" "$NC"
	"$AWG_SCRIPT" status || true

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
		*)
			usage
			return 2
			;;
	esac
}

main "$@"
