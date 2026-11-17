import base64
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, unquote, urlsplit


class ProfileError(ValueError):
    pass


def _hostname(value):
    if not isinstance(value, str) or not value or len(value) > 253:
        raise ProfileError("Некорректное имя сервера или SNI")
    try:
        value = value.encode("idna").decode("ascii").lower().rstrip(".")
        ipaddress.IPv4Address(value)
        return value
    except (UnicodeError, ipaddress.AddressValueError):
        pass
    labels = value.split(".")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ProfileError("Некорректное имя сервера или SNI")
    return value


@dataclass(frozen=True)
class Profile:
    host: str
    port: int
    server_name: str
    fingerprint: str
    user_id: str = field(repr=False)
    public_key: str = field(repr=False)
    short_id: str = field(repr=False)
    spider_x: str = field(repr=False)
    flow: str = ""
    name: str = ""

    def validated(self):
        host = _hostname(self.host)
        sni = _hostname(self.server_name)
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65535:
            raise ProfileError("Некорректный порт сервера")
        try:
            user_id = str(uuid.UUID(self.user_id))
        except (ValueError, AttributeError, TypeError):
            raise ProfileError("Некорректный UUID VLESS") from None
        if not isinstance(self.public_key, str):
            raise ProfileError("Некорректный публичный ключ REALITY")
        key = self.public_key.rstrip("=")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", key):
            raise ProfileError("Некорректный публичный ключ REALITY")
        try:
            decoded = base64.urlsafe_b64decode(key + "=")
        except ValueError:
            raise ProfileError("Некорректный публичный ключ REALITY") from None
        if len(decoded) != 32 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != key:
            raise ProfileError("Некорректный публичный ключ REALITY")
        if not isinstance(self.short_id, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2}){0,8}", self.short_id):
            raise ProfileError("Некорректный short ID REALITY")
        if not isinstance(self.fingerprint, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", self.fingerprint):
            raise ProfileError("Некорректный TLS fingerprint")
        if (
            not isinstance(self.spider_x, str)
            or not self.spider_x.startswith("/")
            or len(self.spider_x) > 2048
            or any(ord(c) < 32 or ord(c) == 127 for c in self.spider_x)
        ):
            raise ProfileError("Некорректный spiderX REALITY")
        if self.flow not in ("", "xtls-rprx-vision"):
            raise ProfileError("Неподдерживаемый flow VLESS")
        if not isinstance(self.name, str) or len(self.name) > 256 or any(ord(c) < 32 or ord(c) == 127 for c in self.name):
            raise ProfileError("Некорректное название профиля")
        return Profile(host, self.port, sni, self.fingerprint.lower(), user_id, key, self.short_id.lower(), self.spider_x, self.flow, self.name)

    @classmethod
    def from_dict(cls, value):
        try:
            if not isinstance(value, dict):
                raise TypeError
            return cls(**value).validated()
        except (TypeError, KeyError):
            raise ProfileError("Некорректный файл профиля") from None


def parse_vless(uri):
    if not isinstance(uri, str) or len(uri) > 16384 or any(ord(c) < 32 or ord(c) == 127 for c in uri):
        raise ProfileError("Некорректная VLESS-ссылка")
    try:
        parsed = urlsplit(uri.strip())
        if parsed.scheme.lower() != "vless" or not parsed.hostname or not parsed.username or parsed.password is not None:
            raise ProfileError("Ожидается ссылка vless:// с UUID и сервером")
        if parsed.path not in ("", "/"):
            raise ProfileError("Путь сервера в VLESS-ссылке не поддерживается")
        port = parsed.port
        items = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True, errors="strict")
    except (ValueError, UnicodeError):
        raise ProfileError("Некорректная VLESS-ссылка") from None
    query = {}
    for key, value in items:
        if key in query:
            raise ProfileError("Повторяющийся параметр VLESS-ссылки")
        query[key] = value
    allowed = {"encryption", "security", "type", "fp", "pbk", "sid", "sni", "spx", "flow"}
    if set(query) - allowed:
        raise ProfileError("VLESS-ссылка содержит неподдерживаемые параметры")
    if query.get("security") != "reality" or query.get("type", "tcp") not in ("tcp", "raw"):
        raise ProfileError("Поддерживается только VLESS TCP/REALITY")
    if query.get("encryption", "none") != "none":
        raise ProfileError("Поддерживается только encryption=none")
    return Profile(
        host=parsed.hostname,
        port=port,
        server_name=query.get("sni", parsed.hostname),
        fingerprint=query.get("fp", "chrome"),
        user_id=unquote(parsed.username),
        public_key=query.get("pbk", ""),
        short_id=query.get("sid", ""),
        spider_x=query.get("spx", "/"),
        flow=query.get("flow", ""),
        name=unquote(parsed.fragment),
    ).validated()


def tunnel_routes(excluded):
    networks = [ipaddress.IPv4Network("0.0.0.0/0")]
    for item in ipaddress.collapse_addresses(ipaddress.IPv4Network(value, strict=False) for value in excluded):
        if item.prefixlen == 0:
            raise ValueError("Нельзя исключить весь IPv4-интернет")
        next_networks = []
        for network in networks:
            if network.subnet_of(item):
                continue
            if item.subnet_of(network):
                next_networks.extend(network.address_exclude(item))
            else:
                next_networks.append(network)
        networks = next_networks
        if len(networks) > 8192:
            raise ValueError("Слишком много исключений маршрутов")
    return [str(network) for network in sorted(networks)]


def build_xray_config(profile, server_ip, excluded, interface="xraycli0", ipv6=True):
    profile = profile.validated()
    server_ip = str(ipaddress.IPv4Address(server_ip))
    routes = tunnel_routes([*excluded, f"{server_ip}/32", "198.18.0.0/30"])
    gateways = ["198.18.0.1/30"]
    if ipv6:
        gateways.append("fd42:198:18::1/126")
        routes.append("::/0")
    user = {"id": profile.user_id, "encryption": "none"}
    if profile.flow:
        user["flow"] = profile.flow
    return {
        "log": {"loglevel": "warning", "access": "none"},
        "dns": {"servers": ["tcp://1.1.1.1"]},
        "inbounds": [{
            "tag": "tun",
            "protocol": "tun",
            "settings": {
                "name": interface,
                "mtu": 1400,
                "gateway": gateways,
                "autoSystemRoutingTable": routes,
                "autoOutboundsInterface": "auto",
            },
        }],
        "outbounds": [
            {
                "tag": "proxy",
                "protocol": "vless",
                "settings": {"vnext": [{"address": server_ip, "port": profile.port, "users": [user]}]},
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "fingerprint": profile.fingerprint,
                        "serverName": profile.server_name,
                        "publicKey": profile.public_key,
                        "shortId": profile.short_id,
                        "spiderX": profile.spider_x,
                    },
                },
            },
            {
                "tag": "dns-out",
                "protocol": "dns",
                "settings": {"network": "tcp", "address": "1.1.1.1", "port": 53, "rules": [{"action": "direct"}]},
                "streamSettings": {"sockopt": {"dialerProxy": "proxy"}},
            },
        ],
        "routing": {"rules": [{"type": "field", "inboundTag": ["tun"], "port": 53, "outboundTag": "dns-out"}]},
    }
