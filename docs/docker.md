# Docker Usage

Check [this repository](https://github.com/leleobhz/snx-rs-docker) for a docker container.

## `run_bridge_vpn.sh` IdP authentication

`run_bridge_vpn.sh` watches the standalone container logs for an identity-provider challenge. When the challenge URL is printed, it starts a separate Playwright Docker container with host networking. The Playwright container follows the redirect to the published `127.0.0.1:7779` callback, so the VPN container receives the authentication result without opening a host browser.

The helper image is built lazily from `docker/playwright/Dockerfile`. The script automatically loads `./.env` (or the file specified by `ENV_FILE`). Configure the identity-provider credentials before starting the bridge:

```sh
export PLAYWRIGHT_USERNAME='user@example.com'
export PLAYWRIGHT_PASSWORD='password'
./run_bridge_vpn.sh
```

`PLAYWRIGHT_OTP` can contain a one-time code when the provider exposes a compatible OTP input. A named Docker volume, `snx-rs-playwright-profile` by default, keeps the browser session between authentication attempts. The normal combined-VPN stop does not remove this volume, so it can be reused after a restart. Set `PLAYWRIGHT_PROFILE_VOLUME=` to disable it, or remove the volume to force a new login.

For Google Prompt, approve the sign-in notification on the phone while the worker is waiting. The worker can resend the prompt when Google exposes a `Resend it` button, but it cannot force a prompt when Google reports that the device cannot be reached. The worker is headless and does not bypass CAPTCHA, security-key prompts, or MFA policies. If those are required, the flow fails instead of falling back to a host browser. Set `PLAYWRIGHT_ENABLED=false` to disable the watcher and use the existing manual flow.

## Check Point вместе с AmneziaVPN

`run_bridge_vpn.sh` не добавляет маршруты Check Point только в основную таблицу Linux. Он создаёт отдельную таблицу policy routing (по умолчанию `18001`) и правила с приоритетом `50`: адрес Check Point отправляется через обычный физический интерфейс, а корпоративные подсети — в Docker bridge. Поэтому включение или выключение AmneziaVPN не перехватывает ни IPsec-соединение, ни трафик через Check Point.

При необходимости таблицу и приоритет можно изменить через `HOST_ROUTE_TABLE` и `HOST_ROUTE_RULE_PRIORITY`. Скрипт повторно применяет policy-маршруты во время health-check, а при завершении удаляет только правила своей таблицы.

Чтобы AmneziaVPN могла установить handshake после включения Check Point, скрипт также закрепляет IPv4 endpoints Amnezia через физический uplink. По умолчанию endpoints читаются из `~/.config/AmneziaVPN.ORG/AmneziaVPN.conf`. Их можно явно задать через `AMNEZIA_ENDPOINTS` — список IPv4-адресов через пробел или запятую. Путь к конфигурации можно изменить через `AMNEZIA_CONFIG_FILE`.

## Единый запуск двух VPN

Для одновременной работы AmneziaWG и Check Point bridge используйте новый
оркестратор:

```sh
./run_combined_vpn.sh start
```

Он намеренно запускает AmneziaWG первым, а `run_bridge_vpn.sh` вторым. После
поднятия AmneziaWG bridge создаёт правила с приоритетом `50`, поэтому
корпоративные подсети идут в Check Point, а остальной трафик — через
AmneziaWG. В эту же policy-таблицу добавляется правило для Docker bridge
subnet: ответы от Check Point возвращаются в контейнер, а не попадают в
full-tunnel AmneziaWG. Bridge также закрепляет адреса endpoint-ов Amnezia за
обычным физическим интерфейсом, чтобы туннели не зацикливались.

Управление:

```sh
./run_combined_vpn.sh status
./run_combined_vpn.sh logs both
./run_combined_vpn.sh stop
./run_combined_vpn.sh restart
```

Опции выбора профиля AmneziaWG передаются после `start` или `restart`,
например `./run_combined_vpn.sh start --profile 0`. Скрипт не нужно запускать
от root; оба исходных скрипта сами используют `sudo` для сетевых операций.

DNS для общего трафика настраивается на интерфейсе AmneziaWG с routing-доменом `~.`.
Если в выбранном профиле нет корректных DNS-серверов (например, `AmneziaVPN.conf`
не содержит `primaryDns`/`secondaryDns` и в профиле остаются плейсхолдеры), используются
резервные серверы из `AWG_FALLBACK_DNS` (по умолчанию `1.1.1.1,8.8.8.8`), чтобы DNS-запросы
не уходили на фильтрующий DNS физического провайдера. Пустое `AWG_FALLBACK_DNS=`
отключает резерв и оставляет DNS без изменений.

Для IPsec bridge нужен rootful Docker, потому что контейнеру необходимы сетевые
привилегии. Если текущий Docker CLI подключён к rootless daemon, скрипт
автоматически переключается на системный Docker через `sudo`. Это можно явно
настроить через `DOCKER_USE_SUDO=auto|true|false`; значение `false` оставляет
текущий daemon и завершает запуск с понятной ошибкой для rootless Docker.

Состояние IKE по умолчанию хранится в именованном Docker volume
`snx-rs-sessions`, поэтому запуск не зависит от существования `/opt/snx` и прав
другого пользователя. Для bind mount можно задать `SNX_SESSIONS_VOLUME`,
например `SNX_SESSIONS_VOLUME="$HOME/.local/share/snx-rs"`.

Если установлен обычный клиент AmneziaVPN, объединённый скрипт перед запуском
останавливает `AmneziaVPN.service` и удаляет конфликтующий интерфейс `amn0`.
Это необходимо: одновременно работающие `amn0` и `amneziawg0` могут менять
маршрутизацию и блокировать forwarding Docker-контейнера. Чтобы запретить
автоматическую остановку сервиса, используйте `STOP_CONFLICTING_AMNEZIA=false`;
в этом случае старый клиент и его интерфейс нужно остановить вручную.
