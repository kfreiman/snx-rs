# Тестирование в Multipass VM

Хост не трогаем: сеть проверяется в чистой Ubuntu 24.04 VM. На хосте `sudo` требует
пароль, поэтому установка multipass — ручной интерактивный шаг:

```bash
sudo snap install multipass --classic
cd dual-vpn
./vm/setup-multipass.sh
multipass mount "$(pwd)" dual-vpn-test:/mnt/dual-vpn
./vm/run-tests.sh          # unit-тесты + doctor внутри VM
```

## Что проверяется без секретов (уровень 1)

- `python3 -m unittest discover -s tests` — конфиг, порядок, bypass, откат.
- `dual-vpn start --dry-run` — план без изменений сети.
- `dual-vpn doctor` — зависимости, Docker, systemd-resolved stub `127.0.0.53`.

## Что проверяется с секретами (уровень 2, вручную)

```bash
multipass exec dual-vpn-test -- sudo apt-get install -y docker.io iptables iproute2 curl dnsmasq-base nftables python3-dbus
# скопировать секреты в VM и в каталог ~/.config/dual-vpn/ (600):
#   ~/.config/xray-vpn/profile.json, .env (PLAYWRIGHT_*), конфиги из ~/.config/dual-vpn/
multipass exec dual-vpn-test -- /mnt/dual-vpn/dual-vpn doctor
multipass exec dual-vpn-test -- /mnt/dual-vpn/dual-vpn start
```

Корпоративная авторизация (Google IdP) в VM идёт через Playwright headless; при
Google Prompt подтвердите вход на телефоне. Полный E2E (xray + corp) в VM подтверждает:
`status` (оба `running`), `curl https://llmgate.etg.team` через corp,
`curl https://api.ipify.org` через xray, split DNS corp-доменов.

Для проверки `route_domains: [ovh.net]` выполните `dual-vpn reload-domains` и проверьте:

- `resolvectl query -4 s3.rbx.io.cloud.ovh.net` использует link `dvpnd...`;
- `ip route get <IPv4-адрес> mark 0xd5000000` указывает на корпоративный контейнер;
- несколько `curl -4 -I https://s3.rbx.io.cloud.ovh.net/` подряд получают HTTP-ответ
  (у корневого S3-URL HEAD может вернуть 405), а не тайм-аут;
- после `stop` исчезают DNS-link, таблица и принадлежащие helper-контейнеру правила;
  после `start` они восстанавливаются, не захватывая трафик остальных доменов.

## Ограничения

- Multipass VM ходит в интернет через NAT хоста; если хост в закрытой сети, E2E
  уровня 2 недоступен — остаются unit и dry-run.
- VM не имеет GUI; ручной браузерный IdP-флоу недоступен — только Playwright.
- `run-tests.sh` монтирует репозиторий read-write неявно через `multipass mount`;
  секреты в VM не пушить и не коммитить.
