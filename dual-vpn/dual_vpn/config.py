import ipaddress
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

SECRET_KEYS = {"password", "passwd", "secret", "token", "uuid", "user_id", "private_key", "psk"}


class ConfigError(ValueError):
    pass


def _yaml():
    try:
        import yaml
    except ImportError:
        raise ConfigError("Нужен PyYAML (python3 -c 'import yaml' не должен падать)") from None
    return yaml


def _check_secrets(mapping, where):
    if isinstance(mapping, dict):
        for key, value in mapping.items():
            if str(key).lower() in SECRET_KEYS and value not in (None, "", False):
                raise ConfigError(f"Секрет {key!r} не должен лежать в YAML ({where}); используйте profile.json/.env")
            _check_secrets(value, where)
    elif isinstance(mapping, list):
        for item in mapping:
            _check_secrets(item, where)


def _load_yaml(path):
    path = Path(path).expanduser()
    if not path.is_file():
        raise ConfigError(f"Конфиг не найден: {path}")
    yaml = _yaml()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise ConfigError(f"Не удалось разобрать YAML {path}: {exc}") from None
    if not isinstance(data, dict):
        raise ConfigError(f"Конфиг должен быть YAML-объектом: {path}")
    _check_secrets(data, str(path))
    return data


@dataclass
class ProviderRef:
    type: str
    config: Path


@dataclass
class HealthConfig:
    url: str = ""
    interval: float = 20
    timeout: float = 8
    failure_threshold: int = 3


@dataclass
class DualConfig:
    path: Path
    providers: dict
    start_order: list
    health: HealthConfig
    log_file: Path
    _raw: dict = field(default_factory=dict, repr=False)

    def provider_path(self, name):
        return self.providers[name].config


def default_config_path():
    return Path.home() / ".config" / "dual-vpn" / "dual-vpn.yaml"


def _expand(value, where):
    if not isinstance(value, str) or not value:
        raise ConfigError(f"Пустой путь в {where}")
    return Path(value).expanduser()


def load_dual_config(path=None):
    config_path = Path(path).expanduser() if path else default_config_path()
    data = _load_yaml(config_path)
    if data.get("version") != 1:
        raise ConfigError("dual-vpn.yaml: version должен быть 1")
    providers_raw = data.get("providers")
    if not isinstance(providers_raw, dict) or not providers_raw:
        raise ConfigError("dual-vpn.yaml: providers не задан")
    providers = {}
    for name, ref in providers_raw.items():
        if not isinstance(ref, dict) or not isinstance(ref.get("type"), str):
            raise ConfigError(f"dual-vpn.yaml: провайдер {name!r} должен иметь type")
        providers[str(name)] = ProviderRef(ref["type"], _expand(ref.get("config"), f"providers.{name}.config"))
    order_raw = data.get("start_order") or list(providers)
    if sorted(order_raw) != sorted(providers):
        raise ConfigError("dual-vpn.yaml: start_order должен перечислять всех провайдеров ровно раз")
    health_raw = data.get("health") or {}
    if not isinstance(health_raw, dict):
        raise ConfigError("dual-vpn.yaml: health должен быть объектом")
    health = HealthConfig(
        url=str(health_raw.get("url") or ""),
        interval=_num(health_raw.get("interval", 20), "health.interval", positive=True),
        timeout=_num(health_raw.get("timeout", 8), "health.timeout", positive=True),
        failure_threshold=_int(health_raw.get("failure_threshold", 3), "health.failure_threshold", minimum=1),
    )
    log_raw = data.get("log") or {}
    log_file = _expand(log_raw.get("file", "~/.local/state/dual-vpn/dual-vpn.log"), "log.file")
    return DualConfig(config_path, providers, list(order_raw), health, log_file, data)


def _num(value, where, positive=False):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{where} должно быть числом") from None
    if positive and number <= 0:
        raise ConfigError(f"{where} должно быть > 0")
    return number


def _int(value, where, minimum=None):
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{where} должно быть целым") from None
    if isinstance(value, bool):
        raise ConfigError(f"{where} должно быть целым")
    if minimum is not None and number < minimum:
        raise ConfigError(f"{where} должно быть >= {minimum}")
    return number


def _str(data, key, where, required=False, default=""):
    value = data.get(key, default)
    if value is None:
        value = default
    if not isinstance(value, str):
        raise ConfigError(f"{where}.{key} должен быть строкой")
    if required and not value:
        raise ConfigError(f"{where}.{key} обязателен")
    return value


def _bool(data, key, where, default=False):
    value = data.get(key, default)
    if not isinstance(value, bool):
        raise ConfigError(f"{where}.{key} должен быть true/false")
    return value


def _ip_list(data, key, where):
    value = data.get(key) or []
    if not isinstance(value, list):
        raise ConfigError(f"{where}.{key} должен быть списком IPv4")
    result = []
    for item in value:
        try:
            result.append(ipaddress.IPv4Address(str(item)))
        except ValueError:
            raise ConfigError(f"{where}.{key}: некорректный IPv4 {item!r}") from None
    return result


def _net_list(data, key, where):
    value = data.get(key) or []
    if not isinstance(value, list):
        raise ConfigError(f"{where}.{key} должен быть списком CIDR")
    result = []
    for item in value:
        try:
            result.append(ipaddress.IPv4Network(str(item), strict=False))
        except ValueError:
            raise ConfigError(f"{where}.{key}: некорректный CIDR {item!r}") from None
    return result


def _str_list(data, key, where):
    value = data.get(key) or []
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ConfigError(f"{where}.{key} должен быть списком строк")
    return value


def _domain_list(data, key, where):
    result = []
    for value in _str_list(data, key, where):
        try:
            domain = value.removesuffix(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise ConfigError(f"{where}.{key}: некорректный домен {value!r}") from None
        labels = domain.split(".")
        if (len(domain) > 253 or len(labels) < 2 or labels[-1].isdigit()
                or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels)):
            raise ConfigError(f"{where}.{key}: некорректный домен {value!r}; укажите суффикс без *.")
        if domain not in result:
            result.append(domain)
    return result


def load_provider_config(path, expected_type=None):
    data = _load_yaml(path)
    actual = data.get("type")
    if not isinstance(actual, str) or not actual:
        raise ConfigError(f"{path}: поле type обязательно")
    if expected_type and actual != expected_type:
        raise ConfigError(f"{path}: type {actual!r} не совпадает с ожидаемым {expected_type!r}")
    return data


@dataclass
class XrayProviderConfig:
    profile: Path
    core: str = ""
    ipv6: str = "auto"
    bypass: list = field(default_factory=list)
    skip_probe: bool = False


def parse_xray_config(path):
    data = load_provider_config(path, "xray")
    where = str(path)
    cfg = XrayProviderConfig(
        profile=_expand(data.get("profile", "~/.config/xray-vpn/profile.json"), f"{where}.profile"),
        core=_str(data, "core", where),
        ipv6=_str(data, "ipv6", where, default="auto"),
        bypass=_net_list(data, "bypass", where),
        skip_probe=_bool(data, "skip_probe", where),
    )
    if cfg.ipv6 not in ("auto", "true", "false"):
        raise ConfigError(f"{where}.ipv6 должен быть auto/true/false")
    return cfg


@dataclass
class SnxDockerConfig:
    server_name: str
    login_type: str
    if_name: str = "etg_vpn"
    image: str = "ghcr.io/leleobhz/snx-rs-docker:6.2.4"
    container_name: str = "snx-rs-vpn"
    sessions_volume: str = "snx-rs-sessions"
    route_table: int = 18001
    rule_priority: int = 50
    host_access_networks: list = field(default_factory=list)
    dns_servers: list = field(default_factory=list)
    dns_domains: list = field(default_factory=list)
    route_domains: list = field(default_factory=list)
    playwright_enabled: bool = True
    keepalive: bool = False
    ike_persist: bool = True
    log_level: str = "debug"
    gateway_via: str = "default"
    tunnel_timeout: float = 90


def parse_snx_docker_config(path):
    data = load_provider_config(path, "snx-docker")
    where = str(path)
    cfg = SnxDockerConfig(
        server_name=_str(data, "server_name", where, required=True),
        login_type=_str(data, "login_type", where, required=True),
        if_name=_str(data, "if_name", where, default="etg_vpn") or "etg_vpn",
        image=_str(data, "image", where, default="ghcr.io/leleobhz/snx-rs-docker:6.2.4"),
        container_name=_str(data, "container_name", where, default="snx-rs-vpn"),
        sessions_volume=_str(data, "sessions_volume", where, default="snx-rs-sessions"),
        route_table=_int(data.get("route_table", 18001), f"{where}.route_table", minimum=1),
        rule_priority=_int(data.get("rule_priority", 50), f"{where}.rule_priority", minimum=1),
        host_access_networks=_net_list(data, "host_access_networks", where),
        dns_servers=_ip_list(data, "dns_servers", where),
        dns_domains=_str_list(data, "dns_domains", where),
        route_domains=_domain_list(data, "route_domains", where),
        playwright_enabled=_bool(data, "playwright_enabled", where, default=True),
        keepalive=_bool(data, "keepalive", where),
        ike_persist=_bool(data, "ike_persist", where, default=True),
        log_level=_str(data, "log_level", where, default="debug"),
        gateway_via=_str(data, "gateway_via", where, default="default"),
        tunnel_timeout=_num(data.get("tunnel_timeout", 90), f"{where}.tunnel_timeout", positive=True),
    )
    if cfg.gateway_via not in ("default", "uplink"):
        raise ConfigError(f"{where}.gateway_via должен быть default или uplink")
    if len(cfg.if_name) > 15 or not cfg.if_name:
        raise ConfigError(f"{where}.if_name: имя интерфейса должно быть 1..15 символов")
    if cfg.rule_priority >= 1000:
        raise ConfigError(f"{where}.rule_priority: должен быть < 1000, иначе corp потеряет приоритет над full-tunnel")
    return cfg
