# План работ dual-vpn

- [x] 1. Разведка: xray_cli, `run_combined_vpn.sh` bridge-модуль, upstream ancwrd1/snx-rs,
      образ leleobhz, Playwright, версии, хост (xraycli0 поднят, sudo требует пароль).
- [x] 2. Каркас директории `dual-vpn/` + документация + примеры YAML.
- [x] 3. Конфиг-слой: загрузка/валидация YAML, пути XDG, запрет секретов в конфиге,
      тесты валидации.
- [x] 4. `VpnProvider` + реестр; `XrayProvider` над `xray_cli` (import, не subprocess).
- [x] 5. `SnxDockerProvider`: порт сетевой части `bridge_module` (policy routing 18001/50,
      NAT/DNAT 7779, split DNS, Playwright watcher, healthcheck) в Python.
- [x] 6. Оркестратор: `start/stop/status/doctor/logs`, flock, порядок, откат, bypass-синтез.
- [x] 7. Юнит-тесты без root (`tests/`): конфиг, порядок, bypass, конфликты, stale-state.
- [x] 8. Multipass: скрипты готовы (`setup-multipass.sh`, `run-tests.sh`, VM-TESTING);
      установка multipass — ручной интерактивный шаг.
- [x] 9. Ревью на хосте: `doctor` OK, `status` корректен, `dry-run` с bypass шлюза.
      Полный `start` — на VM (уровень 2).
- [ ] 10. VM E2E с секретами (Google Prompt вручную), обновить VERSIONS при смене тегов.

Критерии готовности: `python3 -m unittest discover` зелёный (7 dual + 18 xray);
`dual-vpn doctor` на хосте OK; `start`/`stop` идемпотентны; откат не оставляет
полу-состояния; секреты не попадают в репозиторий.
