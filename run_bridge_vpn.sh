#!/usr/bin/env bash

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

	if [ -n "$UPLINK_INTERFACE" ]; then
		route=$(ip -4 route show table main default dev "$UPLINK_INTERFACE" 2>/dev/null | head -n 1)
	else
		while IFS= read -r candidate; do
			candidate_interface=$(awk '{for (i = 1; i <= NF; i++) if ($i == "dev") {print $(i + 1); exit}}' <<<"$candidate")
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
	fi

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
	for cmd in docker resolvectl awk getent ip curl sudo grep; do
		if ! command -v "$cmd" &>/dev/null; then
			error "Отсутствует необходимая утилита: '$cmd'."
			exit 1
		fi
	done

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
		--volume=/opt/snx/sessions:/var/cache/snx-rs/sessions \
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
	BRIDGE_NAME=$(docker network inspect bridge -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null)
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
	GATEWAY_IP=$(getent ahostsv4 "$SERVER_NAME" | head -n 1 | awk '{print $1}')
	if [ -z "$GATEWAY_IP" ]; then
		warn "Не удалось разрешить $SERVER_NAME. Используется резервный IP 87.228.66.146."
		GATEWAY_IP="87.228.66.146"
	fi

	BRIDGE_NAME=$(docker network inspect bridge -f '{{index .Options "com.docker.network.bridge.name"}}' 2>/dev/null)
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
