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
Команды: `start`, `stop`, `restart`, `status`, `doctor`, `logs [--provider NAME]`.

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

Сеть: корпоративный split-tunnel (policy-routing таблица `18001`, приоритет правил `50`)
поднимается первым, персональный full-tunnel — вторым. Шлюз Check Point и IP сервера
Xray остаются на физическом uplink, корпоративные подсети идут через контейнер
`snx-rs`, остальной интернет — через `xraycli0`. DNS для корпоративных доменов —
на корпоративные серверы, остальное — через Xray. Детали — в `ARCHITECTURE.md`.

Не коммитить: `~/.config/dual-vpn/` с реальными файлами, `profile.json`, `.env`,
состояние в `~/.local/state/dual-vpn/`, логи с challenge-URL.
