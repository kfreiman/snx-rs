# dual-vpn — xray + Check Point одновременно

Оркестратор для одновременной работы персонального Xray (full-tunnel) и корпоративного
Check Point `snx-rs` (split-tunnel). Отдельная директория; код `snx-rs` не модифицируется,
используется готовый Docker-образ upstream-сборки `ghcr.io/leleobhz/snx-rs-docker`,
собираемой из актуального `https://github.com/ancwrd1/snx-rs`.

## Быстрый старт

```bash
cp config/dual-vpn.yaml.example ~/.config/dual-vpn/dual-vpn.yaml
cp config/personal-xray.yaml.example ~/.config/dual-vpn/providers/personal.yaml
cp config/corp-snx-docker.yaml.example ~/.config/dual-vpn/providers/corp.yaml
# отредактируйте три файла; секреты — только в ~/.config/xray-vpn/profile.json и .env
./dual-vpn --config ~/.config/dual-vpn/dual-vpn.yaml doctor
./dual-vpn --config ~/.config/dual-vpn/dual-vpn.yaml start
./dual-vpn --config ~/.config/dual-vpn/dual-vpn.yaml status
./dual-vpn --config ~/.config/dual-vpn/dual-vpn.yaml stop
```

Запуск — **не** от root и не через `sudo`: CLI сам запросит права для сетевых операций.
Команды: `start`, `stop`, `restart`, `reload-domains`, `status`, `doctor`, `logs [--provider NAME]`.

## Дополнительные домены через корпоративный VPN

В `~/.config/dual-vpn/providers/corp.yaml` можно указать доменные суффиксы:

```yaml
route_domains: [ovh.net]
```

Это включает `ovh.net` и все поддомены, в том числе `s3.rbx.io.cloud.ovh.net`.
Применить к уже запущенным туннелям без переподключения:

```bash
./dual-vpn reload-domains
./dual-vpn status
```

Для этого нужны `systemd-resolved`, `python3-dbus`, `dnsmasq` с поддержкой `nftset` и
`libnftables`. Оркестратор запускает отдельный Docker-контейнер с сетевыми правами и
доступом к системному D-Bus; для D-Bus ему требуется `apparmor=unconfined`. Сам `dnsmasq`
запускается в отдельном файловом окружении без доступа к D-Bus. Маршрутизатор добавляет
временные DNS- и policy-routing-правила и убирает их при `stop`.

Домены разрешаются через корпоративные DNS, и запросы к этим DNS-серверам тоже идут через
туннель. Не добавляйте те же суффиксы или их поддомены в `dns_domains` и другие DNS-link:
более специфичное или совпадающее правило может обойти доменный маршрутизатор.
Корпоративный IPsec-туннель поддерживает только IPv4, поэтому для этих доменов
отфильтровываются AAAA и SVCB/HTTPS-записи.
Маршрутизация действует для DNS-запросов через `systemd-resolved`; приложения со своим
DNS/DoH, сохранёнными адресами или прямым IPv6 могут её обойти. Если DNS вернул только
CNAME без итогового A-адреса, отдельное разрешение цели вне суффикса тоже может обойти
правило. После изменения настроек может потребоваться очистить DNS-кэш приложения.
Маршрут выбирается по IP: если адрес
используется другими сайтами, они тоже могут пойти через VPN. Полученные адреса сохраняются
до остановки доменного маршрутизатора, чтобы не прерывать действующие соединения.
Для проверки policy route используйте `ip route get <IPv4> mark 0xd5000000`: запрос без
метки не показывает правило nftables. Доступ к конкретному ресурсу всё равно зависит
от политики корпоративного шлюза и прав S3.

## Смена личного Xray-сервера

Провайдер Xray не читает сервер, выбранный в OneXray GUI: он загружает профиль,
указанный в `~/.config/dual-vpn/providers/personal.yaml` (обычно
`~/.config/xray-vpn/profile.json`). Чтобы сменить профиль, из корня репозитория
выполните `./xray-vpn import` и вставьте ссылку VLESS в скрытый запрос. Затем
отключите и закройте OneXray GUI. Проверьте `./dual-vpn/dual-vpn status`; если
Xray уже работает, используйте `./dual-vpn/dual-vpn restart`, иначе —
`./dual-vpn/dual-vpn start`. Простой `start` не переключает уже работающий Core.
Перезапуск затрагивает все VPN-провайдеры, включая Check Point. Команды запускайте
от обычного пользователя; ссылка и сохранённый профиль содержат секреты.

Импорт поддерживает только VLESS TCP/RAW + REALITY. Инструкции для текущего
сервера и безопасного получения ссылки: [инфраструктура tunnel1](../../docs/tunnel1-infrastructure.md).

## Что внутри

- `dual-vpn` — точка входа (`python3`, переиспользует пакет `xray_cli` из корня репозитория).
- `dual_vpn/` — оркестратор, YAML-конфиг, провайдеры (`xray`, `snx-docker`), сетевой слой.
- `config/*.yaml.example` — примеры; реальные файлы — в `~/.config/dual-vpn/`.
- `docs/` — архитектура, план, журнал работ, версии, процедура VM-тестов.
- `tests/` — юнит-тесты без root (`python3 -m unittest`).
- `vm/` — скрипты Multipass (Ubuntu 24.04 VM для изоляции).

По умолчанию сначала поднимается персональный Xray, затем корпоративный split-tunnel
(таблица `18001`, приоритет `50`). При `gateway_via: default` шлюз Check Point
доступен через Xray; корпоративные подсети идут через контейнер `snx-rs`, остальной
интернет — через `xraycli0`. Детали — в `ARCHITECTURE.md`.

Не коммитить: `~/.config/dual-vpn/` с реальными файлами, `profile.json`, `.env`,
состояние в `~/.local/state/dual-vpn/`, логи с challenge-URL.
