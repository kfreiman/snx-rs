import ipaddress
import os
import re
import shutil
import socket
import subprocess
import threading
from pathlib import Path

from dual_vpn.providers.base import ProviderStatus, VpnProvider

DEFAULT_DNS_DOMAINS = ["ostrovok-team.ru", "ostrovok.in", "ostrovok.ru", "emergingtravel.in", "etg.team",
                       "srv.team", "trv.team", "ostrovok.team", "ozon.ru", "wb.ru"]
ENV_FILE = Path(__file__).resolve().parents[3] / ".env"
PLAYWRIGHT_CONTEXT = Path(__file__).resolve().parents[3] / "docker" / "playwright"
PLAYWRIGHT_IMAGE = "snx-rs-playwright:local"


class AuthPendingError(RuntimeError):
    pass


def _run(cmd, check=False):
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _sudo():
    if os.geteuid() == 0:
        return []
    if not shutil.which("sudo"):
        raise RuntimeError("Для сети нужен sudo")
    if _run(["sudo", "-n", "true"]).returncode != 0:
        if _run(["sudo", "-v"]).returncode != 0:
            raise RuntimeError("Не удалось получить права sudo")
    return ["sudo", "-n"]


def _docker_sudo():
    if _run(["docker", "info"]).returncode == 0:
        return []
    if os.geteuid() != 0 and _run(["sudo", "-n", "docker", "info"]).returncode == 0:
        return ["sudo", "-n"]
    raise RuntimeError("Нужен rootful Docker (системный docker через sudo)")


def _ip(*args):
    return _run([*_sudo(), "ip", *args])


def _resolvectl(*args):
    return _run([*_sudo(), "resolvectl", *args])


def _is_cidr(text):
    try:
        ipaddress.IPv4Network(text, strict=False)
        return "/" in text
    except ValueError:
        return False


class SnxDockerProvider(VpnProvider):
    NAME = "snx-docker"

    def __init__(self, name, cfg):
        super().__init__(name, cfg)
        self.cfg = cfg
        self._watcher = None
        self._watcher_stop = None
        self._docker = None
        self._gateway_ip = None
        self._bridge = None

    def _docker_prefix(self):
        if self._docker is None:
            self._docker = _docker_sudo()
        return self._docker

    def _docker_run(self, *args, **kwargs):
        return subprocess.run([*self._docker_prefix(), "docker", *args], **kwargs)

    def _docker_cmd(self, *args):
        try:
            prefix = self._docker_prefix()
        except RuntimeError:
            prefix = []
        return _run([*prefix, "docker", *args])

    def _corp_dir(self, ctx):
        return Path(ctx.state_dir) / "corp"

    def _load_env(self):
        values = dict(os.environ)
        env_file = Path(__import__("os").environ.get("ENV_FILE", str(ENV_FILE)))
        if env_file.is_file():
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values.setdefault(key.strip(), value.strip())
        return values

    def check(self, ctx):
        problems = []
        for cmd in ("docker", "ip", "curl", "resolvectl"):
            if not shutil.which(cmd):
                problems.append(f"нет утилиты: {cmd}")
        try:
            self._docker_prefix()
        except RuntimeError as exc:
            problems.append(str(exc))
        if self.cfg.playwright_enabled:
            env = self._load_env()
            if not env.get("PLAYWRIGHT_USERNAME") or not env.get("PLAYWRIGHT_PASSWORD"):
                problems.append("PLAYWRIGHT_* не заданы в .env; IdP-авторизация будет недоступна без ручного шага")
        if self.cfg.image.strip().endswith(":latest"):
            problems.append("образ :latest не зашифрирован; задайте версионный тег или digest (см. VERSIONS.md)")
        return problems

    def validate(self):
        if not self.cfg.server_name or not self.cfg.login_type:
            raise RuntimeError("snx-docker: server_name и login_type обязательны")

    def _resolve_gateway(self):
        try:
            infos = socket.getaddrinfo(self.cfg.server_name, 443, socket.AF_INET, socket.SOCK_STREAM)
        except OSError:
            raise RuntimeError(f"Не удалось разрешить {self.cfg.server_name}") from None
        if not infos:
            raise RuntimeError(f"Нет IPv4 для {self.cfg.server_name}")
        return str(ipaddress.IPv4Address(infos[0][4][0]))

    def _bridge_name(self):
        out = self._docker_cmd("network", "inspect", "bridge", "--format", '{{index .Options "com.docker.network.bridge.name"}}')
        return (out.stdout.strip() or "docker0") if out.returncode == 0 else "docker0"

    def _container_running(self):
        out = self._docker_cmd("inspect", "-f", "{{.State.Running}}", self.cfg.container_name)
        return out.stdout.strip() == "true"

    def _container_ip(self):
        out = self._docker_cmd("inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", self.cfg.container_name)
        return out.stdout.strip()

    def _uplink(self, destination):
        out = _ip("-4", "route", "get", destination)
        if out.returncode != 0:
            raise RuntimeError(f"ip route get {destination} не удался")
        parts = out.stdout.split()
        gateway, device, source = "", "", ""
        for i, part in enumerate(parts):
            if part == "via" and i + 1 < len(parts):
                gateway = parts[i + 1]
            if part == "dev" and i + 1 < len(parts):
                device = parts[i + 1]
            if part == "src" and i + 1 < len(parts):
                source = parts[i + 1]
        if not device:
            raise RuntimeError("Не найден физический интерфейс uplink")
        return gateway, device, source

    def _clear_policy(self):
        _ip("rule", "flush", "table", str(self.cfg.route_table))
        out = _ip("-4", "-o", "rule", "show")
        for line in out.stdout.splitlines():
            if f"lookup {self.cfg.route_table}" not in line:
                continue
            pref = line.split(":", 1)[0].strip()
            _ip("rule", "del", "pref", pref, "lookup", str(self.cfg.route_table))

    def _add_policy_route(self, dest, via=None, dev=None, src=None):
        args = ["route", "replace", dest]
        if via:
            args += ["via", via]
        if src:
            args += ["src", src]
        if dev:
            args += ["dev", dev]
        args += ["table", str(self.cfg.route_table)]
        ret = _ip("-4", *args)
        if ret.returncode != 0:
            raise RuntimeError(f"Не удалось добавить маршрут {dest} в таблицу {self.cfg.route_table}: {ret.stderr.strip()}")
        ret = _ip("rule", "add", "pref", str(self.cfg.rule_priority), "to", dest, "lookup", str(self.cfg.route_table))
        if ret.returncode != 0 and "File exists" not in ret.stderr:
            raise RuntimeError(f"Не удалось добавить правило для {dest}: {ret.stderr.strip()}")

    def _policy_gateway(self):
        # gateway_via=default: шлюз идёт по обычному default (через personal при dual).
        # Прямой пин за uplink в сети с DPI даёт тайм-аут CCC, поэтому не закрепляем.
        if self.cfg.gateway_via == "uplink":
            gw = ipaddress.IPv4Address(self._gateway_ip)
            via, dev, src = self._uplink(str(gw))
            dest = f"{gw}/32"
            try:
                self._add_policy_route(dest, via=via or None, dev=dev, src=src)
            except RuntimeError:
                self._add_policy_route(dest, dev=dev, src=src)
        bridge_subnet = ""
        out = _ip("-4", "route", "show", "dev", self._bridge, "scope", "link")
        if out.stdout.strip():
            bridge_subnet = out.stdout.split()[0]
        if bridge_subnet:
            try:
                self._add_policy_route(bridge_subnet, dev=self._bridge)
            except RuntimeError:
                pass

    def _start_container(self, ctx):
        if self._container_running():
            return
        self._docker_run("rm", "-f", self.cfg.container_name)
        log_path = self._corp_dir(ctx) / "snx-rs-container.log"
        with open(log_path, "ab") as log:
            proc = self._docker_run(
                "run", "-d", "--privileged", "--device=/dev/net/tun",
                "--cap-add=NET_ADMIN", "--cap-add=SYS_ADMIN", "-p", "7779:7779",
                "--name", self.cfg.container_name,
                "--label", "dual-vpn.provider=corp",
                f"--volume={self.cfg.sessions_volume}:/var/cache/snx-rs",
                "-v", "/lib/modules:/lib/modules:ro",
                self.cfg.image, "/usr/bin/snx-rs",
                "--mode", "standalone", "--login-type", self.cfg.login_type,
                "--tunnel-type", "ipsec", "--ike-persist", str(self.cfg.ike_persist).lower(),
                "--default-route", "false", "--no-dns", "true",
                "--no-keepalive", str(not self.cfg.keepalive).lower(),
                "--allow-forwarding", "true", "--if-name", self.cfg.if_name,
                "--server-name", self.cfg.server_name, "--log-level", self.cfg.log_level,
                "--client-mode", "endpoint_security",
                stdout=log, stderr=log)
        if proc.returncode != 0:
            raise RuntimeError(f"Не удалось запустить контейнер {self.cfg.container_name}")
        if proc.stdout and proc.stdout.strip():
            try:
                proc.stdout.close()
            except Exception:
                pass

    def _container_network(self):
        for _ in range(20):
            if not self._container_running():
                raise RuntimeError("Контейнер остановился при старте")
            out = self._docker_cmd("exec", self.cfg.container_name, "iptables", "-t", "nat", "-L")
            if out.returncode == 0:
                break
            import time
            time.sleep(0.5)
        self._docker_cmd("exec", self.cfg.container_name, "sysctl", "-w", "net.ipv4.conf.all.route_localnet=1")
        self._docker_cmd("exec", self.cfg.container_name, "sysctl", "-w", "net.ipv4.conf.default.route_localnet=1")
        self._docker_cmd("exec", self.cfg.container_name, "iptables", "-t", "nat", "-A", "PREROUTING", "-p", "tcp",
                         "--dport", "7779", "-j", "DNAT", "--to-destination", "127.0.0.1:7779")

    def _setup_host_network(self, ctx):
        import time
        deadline = time.monotonic() + self.cfg.tunnel_timeout
        while time.monotonic() < deadline:
            if not self._container_running():
                raise RuntimeError("Контейнер остановился до появления интерфейса")
            out = self._docker_cmd("exec", self.cfg.container_name, "ip", "link", "show", self.cfg.if_name)
            if out.returncode == 0:
                break
            time.sleep(0.5)
        else:
            raise AuthPendingError(f"Интерфейс {self.cfg.if_name} не появился за {self.cfg.tunnel_timeout:.0f} с (ожидается IdP-авторизация)")
        self._docker_cmd("exec", self.cfg.container_name, "sysctl", "-w", "net.ipv4.ip_forward=1")
        self._docker_cmd("exec", self.cfg.container_name, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", self.cfg.if_name, "-j", "MASQUERADE")
        container_ip = self._container_ip()
        if not container_ip:
            raise RuntimeError("Не удалось определить IP контейнера")
        out = self._docker_cmd("exec", self.cfg.container_name, "ip", "route", "show", "table", "18000")
        routes_file = self._corp_dir(ctx) / "routes.txt"
        routes_file.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        lines = []
        for line in out.stdout.splitlines():
            subnet = line.split()[0] if line.split() else ""
            if _is_cidr(subnet) and not subnet.startswith(self._gateway_ip):
                self._add_policy_route(subnet, via=container_ip, dev=self._bridge)
                lines.append(subnet)
        for net in self.cfg.host_access_networks:
            self._add_policy_route(str(net), via=container_ip, dev=self._bridge)
            lines.append(str(net))
        out2 = _ip("-4", "route", "show", "dev", self._bridge, "scope", "link")
        if out2.stdout.strip():
            bridge_subnet = out2.stdout.split()[0]
            try:
                self._add_policy_route(bridge_subnet, dev=self._bridge)
            except RuntimeError:
                pass
        routes_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        (self._corp_dir(ctx) / "gateway_ip.txt").write_text(self._gateway_ip + "\n", encoding="utf-8")
        servers = self.cfg.dns_servers or [ipaddress.IPv4Address("10.40.22.100"), ipaddress.IPv4Address("10.40.22.101")]
        domains = self.cfg.dns_domains or DEFAULT_DNS_DOMAINS
        ret = _resolvectl("dns", self._bridge, *[str(s) for s in servers])
        if ret.returncode != 0:
            raise RuntimeError(f"resolvectl dns не удался: {ret.stderr.strip()}")
        ret = _resolvectl("domain", self._bridge, *[f"~{d}" for d in domains])
        if ret.returncode != 0:
            raise RuntimeError(f"resolvectl domain не удался: {ret.stderr.strip()}")

    def _ensure_playwright_image(self, ctx):
        out = self._docker_cmd("image", "inspect", PLAYWRIGHT_IMAGE)
        if out.returncode == 0:
            return
        log_path = self._corp_dir(ctx) / "playwright-build.log"
        with open(log_path, "ab") as log:
            proc = self._docker_run("build", "--tag", PLAYWRIGHT_IMAGE, str(PLAYWRIGHT_CONTEXT), stdout=log, stderr=log)
        if proc.returncode != 0:
            raise RuntimeError("Не удалось собрать Playwright-образ")

    def _run_playwright_auth(self, url, ctx):
        env = self._load_env()
        env_file = self._corp_dir(ctx) / "playwright.env"
        env_file.write_text("\n".join([
            f"PLAYWRIGHT_TIMEOUT={env.get('PLAYWRIGHT_TIMEOUT', '110')}",
            "PLAYWRIGHT_CALLBACK_PORT=7779",
            f"PLAYWRIGHT_USERNAME={env.get('PLAYWRIGHT_USERNAME', '')}",
            f"PLAYWRIGHT_PASSWORD={env.get('PLAYWRIGHT_PASSWORD', '')}",
            f"PLAYWRIGHT_OTP={env.get('PLAYWRIGHT_OTP', '')}",
            f"PLAYWRIGHT_DEBUG={env.get('PLAYWRIGHT_DEBUG', 'false')}",
        ]) + "\n", encoding="utf-8")
        os.chmod(env_file, 0o600)
        args = ["run", "--rm", "--interactive", "--init", "--ipc=host", "--network=host",
                "--name", f"{self.cfg.container_name}-playwright", "--env-file", str(env_file)]
        volume = env.get("PLAYWRIGHT_PROFILE_VOLUME", "snx-rs-playwright-profile")
        if volume:
            args += [f"--volume={volume}:/tmp/playwright-profile"]
        args += [PLAYWRIGHT_IMAGE]
        proc = subprocess.run([*self._docker_prefix(), "docker", *args], input=url + "\n", capture_output=True, text=True)
        env_file.unlink(missing_ok=True)
        if proc.returncode != 0:
            raise RuntimeError("Playwright не завершил IdP-авторизацию")

    def _start_watcher(self, ctx):
        if not self.cfg.playwright_enabled:
            return
        if self._watcher is not None and self._watcher.is_alive():
            return
        stop_event = threading.Event()
        self._watcher_stop = stop_event

        def watch():
            started = self._docker_cmd("inspect", "-f", "{{.State.StartedAt}}", self.cfg.container_name).stdout.strip()
            proc = subprocess.Popen([*self._docker_prefix(), "docker", "logs", "--since", started or "1h", "-f", self.cfg.container_name],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            pending, last_url = False, ""
            try:
                for line in proc.stdout:
                    if stop_event.is_set():
                        break
                    text = line.strip()
                    if "identity" in text.lower() or "провайдер" in text.lower():
                        pending = True
                        continue
                    if pending and re.match(r"^https?://\S+$", text) and text != last_url:
                        last_url = text
                        pending = False
                        self._ensure_playwright_image(ctx)
                        self._run_playwright_auth(text, ctx)
            finally:
                proc.terminate()

        self._watcher = threading.Thread(target=watch, daemon=True)
        self._watcher.start()

    def start(self, ctx, bypasses):
        if ctx.dry_run:
            return ProviderStatus(self.name, False, "dry-run")
        corp_dir = self._corp_dir(ctx)
        corp_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._docker_prefix()
        _sudo()
        self._gateway_ip = self._resolve_gateway()
        self._bridge = self._bridge_name()
        self._clear_policy()
        self._policy_gateway()
        self._start_container(ctx)
        self._container_network()
        self._start_watcher(ctx)
        try:
            self._setup_host_network(ctx)
        except AuthPendingError:
            print("corp: контейнер запущен, ожидается IdP-авторизация. Подтвердите Google Prompt и запустите start ещё раз.")
            raise
        return self.status(ctx)

    def stop(self, ctx):
        corp_dir = self._corp_dir(ctx)
        if self._watcher_stop is not None:
            self._watcher_stop.set()
            self._watcher_stop = None
        if self._watcher is not None and self._watcher.is_alive():
            self._watcher.join(timeout=2)
        self._watcher = None
        _resolvectl("revert", self._bridge or "docker0")
        self._clear_policy()
        self._docker_cmd("rm", "-f", f"{self.cfg.container_name}-playwright")
        self._docker_cmd("rm", "-f", self.cfg.container_name)
        for name in ("routes.txt", "gateway_ip.txt"):
            (corp_dir / name).unlink(missing_ok=True)

    def status(self, ctx):
        running = self._container_running()
        interfaces = []
        if running:
            interfaces.append(self._bridge or "docker0")
            out = self._docker_cmd("exec", self.cfg.container_name, "ip", "link", "show", self.cfg.if_name)
            if out.returncode == 0:
                interfaces.append(self.cfg.if_name)
        endpoints = []
        gateway_file = self._corp_dir(ctx) / "gateway_ip.txt"
        if gateway_file.is_file():
            try:
                endpoints.append(ipaddress.IPv4Address(gateway_file.read_text().strip()))
            except ValueError:
                pass
        if not endpoints and self._gateway_ip:
            try:
                endpoints.append(ipaddress.IPv4Address(self._gateway_ip))
            except ValueError:
                pass
        return ProviderStatus(self.name, running, "container=" + ("up" if running else "down"), interfaces, endpoints)

    def endpoints(self, ctx):
        if self.cfg.gateway_via == "default":
            return []
        gateway_file = self._corp_dir(ctx) / "gateway_ip.txt"
        if gateway_file.is_file():
            try:
                return [ipaddress.IPv4Address(gateway_file.read_text().strip())]
            except ValueError:
                return []
        try:
            return [ipaddress.IPv4Address(self._resolve_gateway())]
        except RuntimeError:
            return []

    def interfaces(self, ctx):
        return [self._bridge or "docker0"]

    def owns_default_route(self):
        return False

    def probe(self, ctx):
        if not self._container_running():
            raise RuntimeError("контейнер snx-rs остановлен")
        out = self._docker_cmd("exec", self.cfg.container_name, "ip", "link", "show", self.cfg.if_name)
        if out.returncode != 0:
            raise RuntimeError(f"интерфейс {self.cfg.if_name} не поднят (ожидается IdP-авторизация)")
        return True
