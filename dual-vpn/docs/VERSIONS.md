# Версии (обновлять при каждой смене)

| Компонент | Пинится как | Текущее значение | Проверка |
|---|---|---|---|
| snx-rs (upstream) | релизный тег ancwrd1/snx-rs | 6.2.4 (репозиторий), 6.2.1 (deb на хосте — обновить) | `snx-rs --version` |
| snx-rs-docker образ | `ghcr.io/leleobhz/snx-rs-docker:<X.Y.Z>` (не `:latest`) | `6.2.4` в примере | `docker image inspect` + digest |
| Playwright base | `mcr.microsoft.com/playwright:v1.52.0-noble` | 1.52.0 (проверить свежий релиз) | `docker/playwright/Dockerfile` |
| OneXrayCore | путь `~/.local/bin/OneXrayCore` | бинарь 32 МБ, дата файла 5 Nov | `doctor` ( наличие + exec ) |
| Python | системный python3 (Ubuntu 24.04) | 3.12.3, PyYAML 6.0.1, python3-dbus | `python3 --version` |
| Multipass | snap `multipass` (latest) | не установлен, установка ручная | `multipass --version` |

Правила: образ и Playwright — только версионные теги/digest, без `:latest`;
`latest` допустим только как временный fallback с предупреждением в `doctor`.
