# Терминальное управление AmneziaWG

`run_amneziawg_vpn.sh` подключает AmneziaWG через userspace
`amneziawg-go`. Для одновременной работы с Check Point bridge используйте
`run_combined_vpn.sh`: он запускает AmneziaWG первым, а затем настраивает
корпоративные маршруты bridge поверх него. Перед этим он останавливает
`AmneziaVPN.service`, если обычный клиент уже создал интерфейс `amn0`.

`run_amneziawg_vpn.sh` по-прежнему можно запускать отдельно. В таком случае
перед тестом остановите другой основной VPN-клиент и убедитесь, что его
маршруты и DNS очищены.

## Быстрый запуск

Для подключения обоих VPN используйте единый скрипт:

```bash
./run_combined_vpn.sh start
./run_combined_vpn.sh status
./run_combined_vpn.sh stop
```

Для запуска только AmneziaWG используется `run_amneziawg_vpn.sh`.

Скрипт читает тот же файл, который использует AmneziaVPN:

```text
~/.config/AmneziaVPN.ORG/AmneziaVPN.conf
```

Профиль по умолчанию определяется значением `defaultServerIndex`. Доступные
профили можно посмотреть без вывода ключей:

```bash
./run_amneziawg_vpn.sh profiles
./run_amneziawg_vpn.sh config
```

Подключение, проверка состояния и отключение:

```bash
./run_amneziawg_vpn.sh start
./run_amneziawg_vpn.sh status
./run_amneziawg_vpn.sh stop
```

Дополнительные команды:

```bash
./run_amneziawg_vpn.sh restart
./run_amneziawg_vpn.sh logs
```

Для выбора другого сохранённого профиля используется его индекс или точное
название:

```bash
./run_amneziawg_vpn.sh start --profile 0
./run_amneziawg_vpn.sh start --profile Stockholm_BooLoo_1
```

Первый запуск получает права через `sudo`. Сам скрипт не нужно запускать от
`root`: так сохраняется доступ к конфигурации текущего пользователя и к его
каталогу состояния.

## Что делает скрипт

1. Разбирает Qt/QSettings-формат `serversList` из `AmneziaVPN.conf`.
2. Берёт `last_config` выбранного AWG-контейнера и создаёт временный файл с
   конфигурацией только в каталоге состояния.
3. Если бинарник не найден, собирает его из
   `~/src/github.com/amnezia-vpn/amneziawg-go` командой `make`.
4. Запускает `amneziawg-go` на интерфейсе `amneziawg0` и передаёт ему настройки
   через UAPI. Отдельный `awg`/`wg` для конфигурирования не требуется.
5. Создаёт отдельную таблицу маршрутизации и policy rules для full-tunnel
   профиля. Маркированный UDP-трафик самого AWG остаётся на обычном uplink,
   поэтому endpoint не зацикливается через туннель.
6. Настраивает DNS через `systemd-resolved`, если `resolvectl` доступен.

Маршруты формируются из `AllowedIPs` выбранного профиля, как это делает
`awg-quick`. Для полного туннеля (`0.0.0.0/0, ::/0`) в отдельную таблицу
добавляются default-маршруты обеих семей, а IPv6-маркированный UDP-трафик
самого AWG остаётся на обычном uplink через firewall mark, поэтому endpoint
не зацикливается через туннель.

Если у интерфейса нет IPv6-адреса (как в большинстве сохранённых профилей),
IPv6-трафик направляется в туннель и мгновенно отклоняется ядром: утечки
реального IPv6-адреса провайдера не происходит, а браузеры быстро
переключаются на IPv4 через туннель. Это соответствует поведению клиента
AmneziaVPN, когда публичный адрес определяется как IPv4. IPv6 можно
исключить из маршрутизации явно:

```bash
AWG_ENABLE_IPV6=false ./run_amneziawg_vpn.sh start
```

## Настройка без изменения файла конфигурации

Все основные параметры можно переопределить переменными окружения:

| Переменная | Значение по умолчанию | Назначение |
| --- | --- | --- |
| `AMNEZIA_CONFIG_FILE` | `~/.config/AmneziaVPN.ORG/AmneziaVPN.conf` | Файл профилей |
| `AWG_SOURCE_DIR` | `~/src/github.com/amnezia-vpn/amneziawg-go` | Исходники `amneziawg-go` |
| `AWG_BIN` | `$AWG_SOURCE_DIR/amneziawg-go` | Готовый бинарник |
| `AWG_IF_NAME` | `amneziawg0` | Имя интерфейса |
| `AWG_PROFILE_INDEX` | `defaultServerIndex` | Индекс профиля |
| `AWG_PROFILE_NAME` | пусто | Точное имя профиля |
| `AWG_SET_DNS` | `true` | Настраивать ли `systemd-resolved` |
| `AWG_ENABLE_IPV6` | `auto` | `auto`, `true` или `false` |
| `AWG_LOG_LEVEL` | `error` | Уровень логов `amneziawg-go` |
| `AWG_STATE_DIR` | `$XDG_RUNTIME_DIR/amneziawg-terminal-$UID` | PID, временный конфиг и лог |

Например, отдельный профиль и отключённый DNS:

```bash
AWG_PROFILE_INDEX=0 AWG_SET_DNS=false ./run_amneziawg_vpn.sh start
```

Скрипт не сохраняет импортированную конфигурацию в репозитории и не выводит
ключи в командах `profiles`, `config` и `status`. При остановке временный файл
с ключами удаляется вместе с состоянием запуска.

## Проверка и ограничения

Состояние `handshake`, счётчики RX/TX и endpoint видны в `status`. Первый
handshake может появиться не мгновенно — `PersistentKeepalive` берётся из
сохранённого профиля.

В отличие от `run_bridge_vpn.sh`, этот вариант не запускает Docker и не
настраивает корпоративные маршруты SNX-RS. Его задача — самостоятельно
поднять основной AWG-клиент на хосте и дать ему управляемый из терминала
lifecycle.

Импортируется сетевой `last_config` AWG-профиля. Дополнительные функции GUI
AmneziaVPN, такие как kill switch, список `ExceptSites` и маршрутизация по
приложениям, этим скриптом отдельно не воспроизводятся.
