# Ход работ

## Разведка и каркас

- Прочитаны `xray_cli/cli.py|config.py|platform/linux.py`, `tests/test_xray_vpn.py`,
  `run_combined_vpn.sh` (bridge-модуль), `bridge.md`, `docs/xray-vpn.md`,
  `docs/docker.md`, `crates/snxcore/src/platform/linux/routing.rs|resolver.rs`.
- Хост Ubuntu 24.04; `xraycli0` поднят, tailscale/ZeroTier присутствуют; corp
  остановлен; upstream ancwrd1/snx-rs — 6.2.4 без правок, образ
  `ghcr.io/leleobhz/snx-rs-docker` — новейший релиз ancwrd1 (пиним тег `:6.2.4`);
  `/usr/bin/snx-rs` — старый deb 6.2.1; `sudo` требует пароль.
- Создан каркас `dual-vpn/`: README/ARCHITECTURE/PLAN/PROGRESS/VERSIONS/VM-TESTING,
  примеры YAML, `.gitignore` (секреты не утекают, `profile.json` в root-ignore).

## Первая реализация и проверка на хосте

- Написаны `dual_vpn/config.py` (YAML + валидация, запрет секретов в YAML),
  `providers/base.py` (интерфейс), `providers/xray.py` (поверх xray_cli),
  `providers/snx_docker.py` (порт bridge: table 18001/prio 50, NAT/DNAT 7779,
  split DNS, Playwright watcher, health), `orchestrator.py` (порядок, bypass-синтез,
  откат, doctor, monitor), `cli.py`, точка входа `dual-vpn`.
- Тесты: `dual-vpn/tests/test_dual_vpn.py` — 7/7; существующие
  `tests/test_xray_vpn.py` — 18/18 (без регрессии).
- Хост: `doctor` — OK; `status` — corp stopped, personal running;
  `start --dry-run` — план без изменений. Реальный `start` на хосте не запускался.

## Исправления по живому запуску

- Фикс затенения `_bridge_name`: атрибут кэша переименован в `_bridge`; добавлены
  регрессионные тесты (сейчас 11 dual + 18 xray).
- Прямой путь к шлюзу заблокирован DPI: `curl` напрямую на `https://achird.../clients/`
  — тайм-аут, через `xraycli0` — `404` (сервер отвечает). Поэтому в `corp.yaml`
  добавлен `gateway_via: default` (шлюз идёт через personal, без пина за uplink),
  порядок по умолчанию — `[personal, corp]`, `doctor` предупреждает о противном.
- Исправлена health-проба: corp-URL теперь проверяется один раз после старта всех
  провайдеров (раньше — после первого, поэтому corp вообще не стартовал и откат
  гасил уже работавший Xray). Откат теперь не трогает провайдеров, которые были
  запущены до `start`. Добавились `probe()` в провайдерах (контейнер+интерфейс для
  snx-docker, маршрут `1.1.1.1` для xray).
- Референс: GUI snx-rs на thinkpad_local подключается (corp-протокол исправен).
- Дальше: повторный `start` на хосте; VM E2E уровня 2.
- Split DNS не применился: вызовы `resolvectl` уходили через `_ip()` как
  `ip resolvectl ...` и молча падали. Добавлен `_resolvectl()`, проверки кодов
  возврата, тест `test_resolvectl_called_directly_not_via_ip`. Хост сейчас в
  состоянии «corp без DNS»: лечится повторным `start` (контейнер переиспользуется).
