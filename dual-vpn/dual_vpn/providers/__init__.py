from dual_vpn.config import ConfigError, parse_snx_docker_config, parse_xray_config
from dual_vpn.providers.snx_docker import SnxDockerProvider
from dual_vpn.providers.xray import XrayProvider


def build_provider(name, provider_type, config_path):
    if provider_type == "xray":
        return XrayProvider(name, parse_xray_config(config_path))
    if provider_type == "snx-docker":
        return SnxDockerProvider(name, parse_snx_docker_config(config_path))
    raise ConfigError(f"Неизвестный тип провайдера {provider_type!r} для {name!r}; варианты: xray, snx-docker")
