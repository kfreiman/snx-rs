# Архитектура dual-vpn

## Принципы

1. **Оболочка ≠ провайдеры.** Оркестратор умеет только порядок, блокировки, откат и
   статусы. Технология VPN — деталь провайдера.
2. **Каждый VPN — свой конфиг-файл.** Главный YAML ссылается на файлы провайдеров;
   замена технологии (xray → wg, snx-docker → snx-native) = новый модуль + новый файл,
   без правок оркестратора и сети.
3. **Код snx-rs не трогаем.** Upstream `ancwrd1/snx-rs` используется как есть через
   Docker-образ `ghcr.io/leleobhz/snx-rs-docker` (собирается из релизного тега ancwrd1).
4. **Переиспользуем `xray_cli`.** Netlink, DNS через systemd-resolved D-Bus, атомарные
   state-файлы, detached worker — импортируем, не копируем.

## Компоненты

```text
dual-vpn (cli.py) ─► Orchestrator ─► ProviderRegistry
                                          ├─ XrayProvider (xray_cli, OneXrayCore, xraycli0)
                                          └─ SnxDockerProvider (docker + snx-rs, etg_vpn)
Orchestrator: порядок [corp, personal], global flock, откат при ошибке,
              status/doctor/logs, health-циклы.
NetLinux: обёртки над xray_cli.platform.linux (route_interface, checkpoint, resolved).
Config: YAML (PyYAML) + строгая валидация, секреты вне YAML.
```

## Интерфейс провайдера

```python
class VpnProvider:
    name: str
    def check(ctx) -> list[str]: ...            # проблемы preflight
    def validate(cfg) -> None: ...              # ошибки конфигурации
    def start(ctx, bypasses: list[IPv4Network]): ...   # поднять, вернуть статус
    def stop(ctx) -> None: ...                  # идемпотентная остановка
    def status(ctx) -> ProviderStatus: ...      # running + детали
    def endpoints(ctx) -> list[IPv4Address]: ...# IP, которые.peer должен обойти
    def interfaces(ctx) -> list[str]: ...
    def owns_default_route() -> bool: ...
```

Сеть/оболочка знают только этот интерфейс и список bypass-сетей, которые оркестратор
собирает из `endpoints()` уже поднятых провайдеров и передаёт следующему.

## Сетевая модель (порядок важен)

| Слой | Механизм | Почему так |
|---|---|---|
| Corp, split | Policy-routing: таблица `18001`, правила prio `50`. Шлюз/bridge/endpoints — через uplink; корпоративные подсети (из таблицы `18000` контейнера) — на IP контейнера через `docker0` | Правила prio 50 раньше, чем main/default; full-tunnel не может их перехватить |
| Personal, full | `xraycli0`, маршруты `0.0.0.0/0` минус исключения (локальные сети, `198.18.0.0/30`, IP серверов) + `::/0` при IPv6 | Остальной интернет идёт в Xray; конкретнее маршруты остаются вне |
| DNS | `systemd-resolved` split: corp домены (~ostrovok-team.ru, ~etg.team, …) — на `10.40.22.100/101` через `docker0`; `~.` — на `198.18.0.2` через `xraycli0` | Более специфичные домены выигрывают по правилам resolved |
| IdP-авторизация | Playwright-контейнер (host network) открывает challenge-URL; callback `127.0.0.1:7779` пробрасывается DNAT-ом в контейнер snx-rs | Headless, без GUI-браузера хоста; OTP/промпт — как в `run_combined_vpn.sh` |

Инварианты старта: corp первым (uplink ещё в main), personal вторым с bypass
[IP шлюза Check Point]. Ошибка второго → откат первого. Стоп — в обратном порядке.
Третьи VPN (Tailscale/ZeroTier с default route) обнаруживаются в `doctor`: они ломают
детект uplink, поэтому поднятие запрещено, пока их правила не убраны или не добавлены
в bypass вручную.

## Конфиги

- `~/.config/dual-vpn/dual-vpn.yaml` — порядок, ссылки на провайдеры, health, лог.
- `~/.config/dual-vpn/providers/*.yaml` — параметры провайдера (без секретов).
- Секреты: `~/.config/xray-vpn/profile.json` (VLESS UUID), `.env` (`PLAYWRIGHT_*`),
  Docker volume `snx-rs-sessions` (IKE persist). В репозитории только `*.example`.

## Состояние

`~/.local/state/dual-vpn/`: `state.json` (порядок, поколения, PID оркестратора),
`*.log`, flock-файл. Файлы state — `600`, каталоги — `700`, запись атомарная
(паттерн `xray_cli.cli.atomic_json`). Чужие интерфейсы/контейнеры не удаляем —
только то, что создала наша генерация.
