import ctypes
import fcntl
import hashlib
import ipaddress
import json
import re
import secrets
import shutil
import socket
import struct
import subprocess
import time
from pathlib import Path


OWNER = "dual-vpn-domain-v1"
LABEL = "dual-vpn.domain."
SERVICE = "/opt/dual-vpn/dual_vpn/platform/domain_service.py"
DEFAULT_DNS = ["10.40.22.100", "10.40.22.101"]


def bridge_network(name):
    request = struct.pack("256s", name.encode("ascii"))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        address = socket.inet_ntoa(fcntl.ioctl(conn.fileno(), 0x8915, request)[20:24])
        mask = socket.inet_ntoa(fcntl.ioctl(conn.fileno(), 0x891B, request)[20:24])
    return ipaddress.IPv4Network(f"{address}/{mask}", strict=False)


def dns_address(token):
    return ipaddress.IPv4Address(f"169.254.{int(token[:2], 16) % 253 + 1}.{int(token[2:4], 16) % 253 + 1}")


def requirements():
    problems = []
    dnsmasq = shutil.which("dnsmasq")
    if not dnsmasq:
        problems.append("для route_domains нужен dnsmasq с поддержкой nftset")
    else:
        version = subprocess.run([dnsmasq, "--version"], capture_output=True, text=True)
        if version.returncode or "nftset" not in version.stdout or "no-nftset" in version.stdout:
            problems.append("dnsmasq собран без поддержки nftset")
        if not Path(dnsmasq).resolve().is_relative_to("/usr"):
            problems.append("dnsmasq должен находиться в /usr")
    try:
        ctypes.CDLL("libnftables.so.1")
    except OSError:
        problems.append("для route_domains нужна libnftables.so.1")
    if not Path("/usr/bin/python3").is_file():
        problems.append("для route_domains нужен системный /usr/bin/python3")
    else:
        test = subprocess.run(["/usr/bin/python3", "-c", "import dbus"], capture_output=True, text=True)
        if test.returncode:
            problems.append("для route_domains нужен python3-dbus")
    if not Path("/run/dbus/system_bus_socket").exists():
        problems.append("не найден системный D-Bus")
    return problems


def _mounts(bus=False):
    sources = [
        ("/usr", "/host/usr", True),
        ("/lib", "/host/lib", True),
        ("/lib64", "/host/lib64", True),
        ("/etc/passwd", "/host/etc/passwd", True),
        ("/etc/group", "/host/etc/group", True),
        ("/etc/nsswitch.conf", "/host/etc/nsswitch.conf", True),
        ("/etc/ld.so.cache", "/host/etc/ld.so.cache", True),
        ("/dev/null", "/host/dev/null", False),
        ("/dev/urandom", "/host/dev/urandom", True),
        (str(Path(__file__).resolve().parents[1]), "/host/opt/dual-vpn", True),
    ]
    if bus:
        sources += [(source, "/host/dnsroot" + destination[len("/host"):], readonly)
                    for source, destination, readonly in sources if destination != "/host/opt/dual-vpn"]
        sources.append(("/run/dbus/system_bus_socket", "/host/run/dbus/system_bus_socket", False))
    result = []
    for source, destination, readonly in sources:
        if not Path(source).exists():
            if source in ("/lib64", "/etc/nsswitch.conf", "/etc/ld.so.cache"):
                continue
            raise RuntimeError(f"Для domain routes не найден {source}")
        if "," in source:
            raise RuntimeError("Путь dual-vpn не должен содержать запятую")
        spec = f"type=bind,src={source},dst={destination}"
        result += ["--mount", spec + (",readonly" if readonly else "")]
    return result


def _container_args(network, bus=False):
    args = ["--network", network, "--cap-drop", "ALL", "--cap-add", "NET_ADMIN", "--cap-add", "SYS_CHROOT",
            "--cap-add", "NET_BIND_SERVICE"]
    if bus:
        args += ["--security-opt", "apparmor=unconfined"]
    return [*args, *_mounts(bus=bus), "--entrypoint", "/usr/sbin/chroot"]


def _service(action, token, **values):
    command = ["/host", "/usr/bin/python3", "-B", SERVICE, action, "--token", token]
    for name, value in values.items():
        if isinstance(value, (list, tuple)):
            for item in value:
                command += ["--" + name.replace("_", "-"), str(item)]
        elif value is not None:
            command += ["--" + name.replace("_", "-"), str(value)]
    return command


class DomainRouter:
    def __init__(self, provider):
        self.provider = provider
        self.cfg = provider.cfg
        self.name = f"{self.cfg.container_name}-domain-router"

    def _command(self, *args):
        result = self.provider._docker_cmd(*args)
        if result.returncode:
            detail = (result.stderr or result.stdout or "").strip()[-800:]
            raise RuntimeError(f"Ошибка Docker domain routes: {detail or result.returncode}")
        return (result.stdout or "").strip()

    def _labels(self):
        result = self.provider._docker_cmd("inspect", "--type", "container", "-f", "{{json .Config.Labels}}", self.name)
        if result.returncode:
            if "No such" in (result.stderr or ""):
                return None
            raise RuntimeError(f"Не удалось проверить {self.name}: {(result.stderr or '').strip()}")
        try:
            labels = json.loads(result.stdout or "{}") or {}
        except ValueError:
            raise RuntimeError(f"Некорректные метки контейнера {self.name}") from None
        if labels.get(LABEL + "owner") != OWNER:
            raise RuntimeError(f"Контейнер {self.name} не принадлежит dual-vpn; он не будет изменён")
        return labels

    def _running(self, name):
        result = self.provider._docker_cmd("inspect", "-f", "{{.State.Running}}", name)
        return result.returncode == 0 and result.stdout.strip() == "true"

    def running(self):
        try:
            labels = self._labels()
            if labels is None or not self._running(self.name) or not self._running(self.cfg.container_name):
                return False
            meta = self._metadata(labels)
            if (not meta["corp_started"] or self._corp_id() != meta["corp_id"]
                    or self._corp_started() != meta["corp_started"]
                    or self.provider._container_ip() != meta["container_ip"]):
                return False
            if not _interface_exists("dvpnd" + meta["token"]):
                return False
            rules = self._command("exec", self.cfg.container_name, "ip", "-4", "rule", "show").splitlines()
            route = self._command("exec", self.cfg.container_name, "ip", "-4", "route", "show", "table", "18002")
            if not any(line.startswith("17998:") and f'iif {meta["tunnel"]} lookup main' in line for line in rules):
                return False
            if not any(line.startswith("17999:") and f'iif {meta["uplink"]} lookup 18002' in line for line in rules):
                return False
            if not any(line.startswith(f'default dev {meta["tunnel"]} ') for line in route.splitlines()):
                return False
            self._helper("container:" + meta["corp_id"], meta["image"], "corp-check", meta["token"],
                         tunnel=meta["tunnel"], uplink=meta["uplink"])
            check = _service("host-check", meta["token"], bridge=meta["bridge"], container_ip=meta["container_ip"],
                             dns_ip=dns_address(meta["token"]), domain=self.cfg.route_domains)
            return self.provider._docker_cmd("exec", self.name, "/usr/sbin/chroot", *check).returncode == 0
        except (OSError, RuntimeError, ValueError):
            return False

    def _corp_id(self):
        return self._command("inspect", "-f", "{{.Id}}", self.cfg.container_name)

    def _corp_started(self):
        return self._command("inspect", "-f", "{{.State.StartedAt}}", self.cfg.container_name)

    def _uplink(self):
        output = self._command("exec", self.cfg.container_name, "ip", "-4", "route", "show", "default")
        for line in output.splitlines():
            parts = line.split()
            if "dev" in parts and parts.index("dev") + 1 < len(parts):
                return parts[parts.index("dev") + 1]
        raise RuntimeError("Не найден Docker-интерфейс корпоративного контейнера")

    def _helper(self, network, image, action, token, **values):
        return self._command("run", "--rm", "--pull=never", *_container_args(network), image,
                             *_service(action, token, **values))

    def _metadata(self, labels):
        def value(key):
            result = labels.get(LABEL + key, "")
            if not result:
                raise RuntimeError(f"У {self.name} отсутствует метка {key}; автоматическая очистка невозможна")
            return result

        token = value("token")
        bridge, tunnel, uplink = (value(key) for key in ("bridge", "tunnel", "uplink"))
        if not re.fullmatch(r"[0-9a-f]{8}", token):
            raise RuntimeError("Некорректный идентификатор domain routes")
        if not all(re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", name) for name in (bridge, tunnel, uplink)):
            raise RuntimeError("Некорректные имена интерфейсов domain routes")
        try:
            container_ip = str(ipaddress.IPv4Address(value("container-ip")))
        except ValueError:
            raise RuntimeError("Некорректный IP корпоративного контейнера") from None
        return {"token": token, "bridge": bridge, "tunnel": tunnel, "uplink": uplink,
                "container_ip": container_ip, "corp_id": value("corp-id"), "image": value("image"),
                "corp_started": labels.get(LABEL + "corp-started", "")}

    def stop(self):
        labels = self._labels()
        if labels is None:
            return
        meta = self._metadata(labels)
        if self._running(self.name):
            self._command("stop", "--time", "10", self.name)
        errors = []
        try:
            self._helper("host", meta["image"], "host-cleanup", meta["token"],
                         bridge=meta["bridge"], container_ip=meta["container_ip"])
        except RuntimeError as exc:
            errors.append(str(exc))
        if (self._running(self.cfg.container_name) and self._corp_id() == meta["corp_id"]
                and (not meta["corp_started"] or self._corp_started() == meta["corp_started"])):
            try:
                self._helper("container:" + meta["corp_id"], meta["image"], "corp-cleanup", meta["token"],
                             tunnel=meta["tunnel"], uplink=meta["uplink"])
            except RuntimeError as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError("; ".join(errors))
        self._command("rm", self.name)

    def start(self, ctx, bypasses):
        if not self.cfg.route_domains:
            self.stop()
            return
        problems = requirements()
        if problems:
            raise RuntimeError("; ".join(problems))
        if not self._running(self.cfg.container_name):
            raise RuntimeError("Корпоративный VPN-контейнер не запущен")
        corp_id = self._corp_id()
        corp_started = self._corp_started()
        bridge = self.provider._bridge or self.provider._bridge_name()
        container_ip = str(ipaddress.IPv4Address(self.provider._container_ip()))
        uplink = self._uplink()
        dns_servers = [str(server) for server in self.cfg.dns_servers] or DEFAULT_DNS
        gateway = self.provider._gateway_ip
        gateway_file = self.provider._corp_dir(ctx) / "gateway_ip.txt"
        if not gateway and gateway_file.is_file():
            gateway = gateway_file.read_text(encoding="utf-8").strip()
        if not gateway:
            gateway = self.provider._resolve_gateway()
        exclusions = [ipaddress.IPv4Network("127.0.0.0/8"), ipaddress.IPv4Network("169.254.0.0/16"),
                      bridge_network(bridge), ipaddress.IPv4Network(f"{ipaddress.IPv4Address(gateway)}/32"),
                      *bypasses]
        exclusions = list(dict.fromkeys(str(ipaddress.IPv4Network(net, strict=False)) for net in exclusions))
        for server in dns_servers:
            if any(ipaddress.IPv4Address(server) in ipaddress.IPv4Network(network) for network in exclusions):
                raise RuntimeError(f"Корпоративный DNS {server} находится в сети исключения VPN")
        config = {"format": 6, "corp_id": corp_id, "corp_started": corp_started, "bridge": bridge,
                  "container_ip": container_ip, "tunnel": self.cfg.if_name, "uplink": uplink,
                  "servers": dns_servers, "domains": self.cfg.route_domains,
                  "exclusions": exclusions, "image": self.cfg.image}
        fingerprint = hashlib.sha256(json.dumps(config, sort_keys=True).encode()).hexdigest()
        previous = self._labels()
        if previous is not None:
            if previous.get(LABEL + "fingerprint") == fingerprint and self.running():
                return
            self.stop()
        token = secrets.token_hex(4)
        address = dns_address(token)
        dnsmasq = str(Path(shutil.which("dnsmasq")).resolve())
        labels = {"owner": OWNER, "token": token, "bridge": bridge, "container-ip": container_ip,
                  "tunnel": self.cfg.if_name, "uplink": uplink, "corp-id": corp_id,
                  "corp-started": corp_started, "image": self.cfg.image, "fingerprint": fingerprint}
        label_args = [item for key, value in labels.items() for item in ("--label", LABEL + key + "=" + value)]
        command = _service("host-run", token, bridge=bridge, container_ip=container_ip, dns_ip=address,
                           dnsmasq=dnsmasq, dns_server=dns_servers, domain=self.cfg.route_domains, exclude=exclusions)
        self._command("create", "--pull=never", "--name", self.name, *label_args,
                      *_container_args("host", bus=True), self.cfg.image, *command)
        try:
            self._helper("container:" + corp_id, self.cfg.image, "corp-setup", token,
                         tunnel=self.cfg.if_name, uplink=uplink)
            self._command("start", self.name)
            self._wait_ready()
        except BaseException:
            try:
                self.stop()
            except Exception as exc:
                print(f"Предупреждение: не удалось полностью откатить domain routes: {exc}", flush=True)
            raise

    def _wait_ready(self):
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            result = self.provider._docker_cmd("logs", self.name)
            output = (result.stdout or "") + (result.stderr or "")
            if "DOMAIN_ROUTER_READY" in output and self._running(self.name):
                return
            if not self._running(self.name):
                raise RuntimeError(f"Не запустился domain router: {output.strip()[-800:]}")
            time.sleep(0.2)
        raise RuntimeError("Не удалось дождаться DNS и маршрутов domain router")


def _interface_exists(name):
    try:
        socket.if_nametoindex(name)
        return True
    except OSError:
        return False
